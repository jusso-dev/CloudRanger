import type {
  ControlCoverage,
  ControlDefinition,
  CollectorDefinition,
  EvaluationResult,
  EvaluationStatus,
  EvidenceBundle,
  EvidenceRecord,
  Expression,
} from "./types.js";
import { evaluateExpression, type ExprContext } from "./expr.js";
import { flattenPath, getPath } from "./path.js";
import { decodeEvidenceRecord } from "./csv.js";
import {
  effectiveParameterValues,
  resolveExpression,
  validateParameterOverrides,
} from "./params.js";

export interface EvaluateOptions {
  now?: Date;
  /** Restrict evaluation to these control IDs (default: all supplied). */
  controlIds?: string[];
  /**
   * Per-control parameter overrides (controlId → name → value), validated
   * against each control's declarations. Invalid overrides throw — callers
   * validate at intake, so reaching here with bad values is a bug.
   */
  parameters?: Record<string, Record<string, unknown>>;
}

interface ResourceUnit {
  resource: unknown;
  region?: string;
  errorText?: string;
  exitCode: number;
  resourceKey?: string;
}

/**
 * Extract the resources a control evaluates from the evidence bundle.
 * - single collectors: resourcesPath indexes into each record's output
 *   ("$" = the whole output object is one account-level resource).
 * - per_resource collectors: each evidence record IS one resource.
 */
function resolveResources(
  control: ControlDefinition,
  collector: CollectorDefinition,
  records: EvidenceRecord[],
): ResourceUnit[] {
  const units: ResourceUnit[] = [];
  for (const record of records) {
    if (collector.kind === "per_resource") {
      units.push({
        resource: record.output,
        region: record.region,
        errorText: record.errorText,
        exitCode: record.exitCode,
        resourceKey: record.resourceKey,
      });
      continue;
    }
    if (record.exitCode !== 0 || record.output === null || record.output === undefined) {
      units.push({
        resource: null,
        region: record.region,
        errorText: record.errorText ?? "collector command failed",
        exitCode: record.exitCode,
      });
      continue;
    }
    // Aggregate (account/subscription/project-level) checks: the ENTIRE output
    // is one resource unit, even when the CLI returns a top-level array. This
    // lets a $scope control quantify over the whole inventory with
    // anyItem/noneItem/allItems over path "$" (e.g. "does any log profile
    // capture all activity categories"). Without this, a top-level array is
    // split into per-item units below and no expression can see the whole set.
    if (control.aggregate) {
      units.push({ resource: record.output, region: record.region, exitCode: 0 });
      continue;
    }
    const path = control.resourcesPath ?? "$";
    if (path === "$") {
      // "$" means: the whole output. If the CLI returned a top-level array
      // (az/gcloud list style), each element is a resource; otherwise the
      // output object itself is a single (account-level) resource.
      if (Array.isArray(record.output)) {
        for (const item of record.output) {
          units.push({ resource: item, region: record.region, exitCode: 0 });
        }
      } else {
        units.push({ resource: record.output, region: record.region, exitCode: 0 });
      }
    } else {
      for (const item of flattenPath(record.output, path)) {
        units.push({ resource: item, region: record.region, exitCode: 0 });
      }
    }
    // Missing/empty arrays yield no units: nothing to evaluate in that region.
  }
  return units;
}

function resourceIdOf(control: ControlDefinition, unit: ResourceUnit, scopeId: string): string {
  if (unit.resourceKey) return unit.resourceKey;
  const id = getPath(unit.resource, control.resourceIdField);
  if (typeof id === "string" && id.length > 0) return id;
  if (typeof id === "number") return String(id);
  // Account-level checks fall back to the scan scope.
  return scopeId;
}

function classifyError(
  control: ControlDefinition,
  errorText: string,
): { status: EvaluationStatus; message: string } {
  for (const rule of control.onError ?? []) {
    if (errorText.toLowerCase().includes(rule.contains.toLowerCase())) {
      return { status: rule.status, message: rule.message ?? errorText.slice(0, 300) };
    }
  }
  return { status: "error", message: errorText.slice(0, 300) };
}

/** Collect the evidence values referenced by an expression, for storage. */
function extractEvidence(expr: Expression, resource: unknown, acc: Record<string, unknown>): void {
  if (
    "path" in expr &&
    typeof expr.path === "string" &&
    expr.op !== "anyItem" &&
    expr.op !== "allItems" &&
    expr.op !== "noneItem"
  ) {
    acc[expr.path] = getPath(resource, expr.path);
  }
  if ("fromPath" in expr) {
    acc[expr.fromPath] = getPath(resource, expr.fromPath);
    acc[expr.toPath] = getPath(resource, expr.toPath);
  }
  if (expr.op === "and" || expr.op === "or") {
    for (const e of expr.exprs) extractEvidence(e, resource, acc);
  }
  if (expr.op === "not") extractEvidence(expr.expr, resource, acc);
  if (expr.op === "anyItem" || expr.op === "allItems" || expr.op === "noneItem") {
    acc[expr.path] = getPath(resource, expr.path);
  }
  if (expr.op === "relationshipExists") {
    acc[expr.localPath] = getPath(resource, expr.localPath);
  }
}

export function evaluateControls(
  controls: ControlDefinition[],
  collectors: Map<string, CollectorDefinition>,
  bundle: EvidenceBundle,
  options: EvaluateOptions = {},
): { results: EvaluationResult[]; coverage: ControlCoverage[] } {
  const now = options.now ?? new Date();
  const ctx: ExprContext = { now };
  const evaluatedAt = now.toISOString();
  const wanted = options.controlIds ? new Set(options.controlIds) : null;

  const byCollector = new Map<string, EvidenceRecord[]>();
  for (const record of bundle.records) {
    const list = byCollector.get(record.collectorId) ?? [];
    list.push(record);
    byCollector.set(record.collectorId, list);
  }
  // Apply declared evidence decoding (e.g. base64 CSV credential reports)
  // once per record, before any control looks at the output.
  for (const [collectorId, records] of byCollector) {
    const collector = collectors.get(collectorId);
    if (!collector?.decode) continue;
    byCollector.set(
      collectorId,
      records.map((record) => decodeEvidenceRecord(collector, record)),
    );
  }

  const results: EvaluationResult[] = [];
  const coverage: ControlCoverage[] = [];

  for (const control of controls) {
    if (control.provider !== bundle.provider) continue;
    if (wanted && !wanted.has(control.id)) continue;

    const collector = collectors.get(control.collector);
    if (!collector) {
      coverage.push({
        controlId: control.id,
        status: "missing_evidence",
        missingCollectors: [control.collector],
      });
      continue;
    }
    const records = byCollector.get(control.collector) ?? [];
    const missingCollectors = [
      control.collector,
      ...(control.relatedCollectors ?? []).map((r) => r.collector),
    ].filter((id) => (byCollector.get(id) ?? []).length === 0);
    if (missingCollectors.length > 0) {
      coverage.push({
        controlId: control.id,
        status: "missing_evidence",
        missingCollectors,
      });
      continue;
    }

    coverage.push({ controlId: control.id, status: "evaluated", missingCollectors: [] });

    // Resolve declared parameters (defaults ⊕ overrides) into concrete
    // expressions before any resource is evaluated.
    let applicableWhen = control.applicableWhen as Expression | undefined;
    let passWhen = control.passWhen as Expression;
    let effectiveParameters: Record<string, number | string | boolean> | undefined;
    if (control.parameters && Object.keys(control.parameters).length > 0) {
      const overrides = options.parameters?.[control.id];
      if (overrides) {
        const issues = validateParameterOverrides(control, overrides);
        if (issues.length > 0) {
          throw new Error(`invalid parameter overrides for ${control.id}: ${issues.join("; ")}`);
        }
      }
      effectiveParameters = effectiveParameterValues(control, overrides);
      passWhen = resolveExpression(passWhen, effectiveParameters);
      if (applicableWhen) applicableWhen = resolveExpression(applicableWhen, effectiveParameters);
    }

    const relatedError = (control.relatedCollectors ?? [])
      .flatMap((related) => byCollector.get(related.collector) ?? [])
      .find((record) => record.exitCode !== 0 || record.output === null);
    const related = Object.fromEntries(
      (control.relatedCollectors ?? []).map((related) => [
        related.as,
        (byCollector.get(related.collector) ?? []).flatMap((record) =>
          Array.isArray(record.output)
            ? record.output
            : record.output === null
              ? []
              : [record.output],
        ),
      ]),
    );
    for (const rawUnit of resolveResources(control, collector, records)) {
      const unit = control.relatedCollectors
        ? {
            ...rawUnit,
            resource: { primary: rawUnit.resource, related },
            errorText: relatedError?.errorText ?? rawUnit.errorText,
            exitCode: relatedError ? relatedError.exitCode : rawUnit.exitCode,
          }
        : rawUnit;
      const resourceId = resourceIdOf(control, unit, bundle.scopeId);
      const base = {
        controlId: control.id,
        controlVersion: control.version,
        provider: control.provider,
        service: control.service,
        severity: control.severity,
        resourceId,
        region: unit.region,
        effectiveParameters,
        evaluatedAt,
      };
      const nameRaw = control.resourceNameField
        ? getPath(unit.resource, control.resourceNameField)
        : undefined;
      const resourceName = typeof nameRaw === "string" ? nameRaw : undefined;

      if (unit.exitCode !== 0 || (unit.errorText && unit.resource === null)) {
        const { status, message } = classifyError(control, unit.errorText ?? "command failed");
        results.push({
          ...base,
          resourceName,
          status,
          message,
          evidence: { error: (unit.errorText ?? "").slice(0, 500) },
        });
        continue;
      }

      if (applicableWhen && !evaluateExpression(applicableWhen, unit.resource, ctx)) {
        results.push({
          ...base,
          resourceName,
          status: "not_applicable",
          message: "Resource is out of scope for this control.",
          evidence: {},
        });
        continue;
      }

      const passed = evaluateExpression(passWhen, unit.resource, ctx);
      const evidence: Record<string, unknown> = {};
      extractEvidence(passWhen, unit.resource, evidence);
      results.push({
        ...base,
        resourceName,
        status: passed ? "pass" : "fail",
        message: passed ? control.passMessage : control.failMessage,
        evidence,
      });
    }
  }

  return { results, coverage };
}

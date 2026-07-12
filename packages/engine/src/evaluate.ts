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
import { getPath } from "./path.js";

export interface EvaluateOptions {
  now?: Date;
  /** Restrict evaluation to these control IDs (default: all supplied). */
  controlIds?: string[];
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
      for (const item of resolveArrayPath(record.output, path)) {
        units.push({ resource: item, region: record.region, exitCode: 0 });
      }
    }
    // Missing/empty arrays yield no units: nothing to evaluate in that region.
  }
  return units;
}

/**
 * Resolve a resources path that may flatten nested arrays with "[]", e.g.
 * "Reservations[].Instances" — for each element of Reservations, collect the
 * Instances array. A trailing plain segment must resolve to an array.
 */
function resolveArrayPath(output: unknown, path: string): unknown[] {
  const segments = path.split("[].");
  let current: unknown[] = [output];
  for (const [i, segment] of segments.entries()) {
    const next: unknown[] = [];
    for (const item of current) {
      const v = getPath(item, segment);
      if (Array.isArray(v)) next.push(...v);
      else if (i < segments.length - 1 && v !== undefined && v !== null) next.push(v);
    }
    current = next;
  }
  return current;
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
    if (records.length === 0) {
      coverage.push({
        controlId: control.id,
        status: "missing_evidence",
        missingCollectors: [control.collector],
      });
      continue;
    }

    coverage.push({ controlId: control.id, status: "evaluated", missingCollectors: [] });

    for (const unit of resolveResources(control, collector, records)) {
      const resourceId = resourceIdOf(control, unit, bundle.scopeId);
      const base = {
        controlId: control.id,
        controlVersion: control.version,
        provider: control.provider,
        service: control.service,
        severity: control.severity,
        resourceId,
        region: unit.region,
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

      if (
        control.applicableWhen &&
        !evaluateExpression(control.applicableWhen as Expression, unit.resource, ctx)
      ) {
        results.push({
          ...base,
          resourceName,
          status: "not_applicable",
          message: "Resource is out of scope for this control.",
          evidence: {},
        });
        continue;
      }

      const passed = evaluateExpression(control.passWhen as Expression, unit.resource, ctx);
      const evidence: Record<string, unknown> = {};
      extractEvidence(control.passWhen as Expression, unit.resource, evidence);
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

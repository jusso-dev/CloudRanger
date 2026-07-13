import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import type { ControlDefinition, Provider } from "@cloudranger/engine";
import { catalogDir } from "./index.js";

/**
 * Coverage-aware compliance rollup. Two mapping sources feed it:
 *  - the curated registry (catalog/mappings/frameworks.yaml), where every
 *    entry carries an automation status and rationale;
 *  - control document `compliance` fields (CIS benchmarks etc.), treated as
 *    automated technical mappings.
 * The rollup never overstates coverage: requirements without mappings are
 * reported as unassessed, and coverage ratios are only emitted when the
 * framework's total requirement count is actually known.
 */

export type MappingStatus = "automated" | "partial" | "manual" | "unsupported";

export interface FrameworkInfo {
  id: string;
  title: string;
  version: string;
  source?: string;
}

export interface RequirementMapping {
  framework: string;
  requirement: string;
  controlId: string;
  status: MappingStatus;
  rationale?: string;
}

export interface FrameworkRegistry {
  frameworks: FrameworkInfo[];
  mappings: RequirementMapping[];
}

export function loadFrameworkRegistry(): FrameworkRegistry {
  const doc = parseYaml(
    readFileSync(join(catalogDir(), "mappings", "frameworks.yaml"), "utf8"),
  ) as Partial<FrameworkRegistry>;
  return { frameworks: doc.frameworks ?? [], mappings: doc.mappings ?? [] };
}

/**
 * Total requirement counts for frameworks whose full requirement list is
 * vendored in this repository. Only these frameworks get a coverage ratio —
 * everything else reports totalRequirements: null rather than a made-up
 * denominator.
 */
export function frameworkRequirementTotals(): Record<string, number> {
  const totals: Record<string, number> = {};
  const ismPath = join(catalogDir(), "mappings", "upstream", "ism-oscal-v2026.06.18.json");
  if (existsSync(ismPath)) {
    const ism = JSON.parse(readFileSync(ismPath, "utf8")) as { controls?: unknown[] };
    if (Array.isArray(ism.controls)) totals["ism"] = ism.controls.length;
  }
  return totals;
}

/** Mappings derived from control documents' own `compliance` fields. */
export function derivedMappingsFromControls(controls: ControlDefinition[]): RequirementMapping[] {
  const mappings: RequirementMapping[] = [];
  for (const control of controls) {
    for (const entry of control.compliance) {
      for (const requirement of entry.controls) {
        mappings.push({
          framework: entry.framework,
          requirement,
          controlId: control.id,
          status: "automated",
          rationale: "Technical mapping declared on the control document.",
        });
      }
    }
  }
  return mappings;
}

/** Registry frameworks plus entries synthesised for control-declared ones. */
export function allFrameworks(
  controls: ControlDefinition[],
  registry: FrameworkRegistry,
): FrameworkInfo[] {
  const known = new Map(registry.frameworks.map((f) => [f.id, f]));
  for (const control of controls) {
    for (const entry of control.compliance) {
      if (!known.has(entry.framework)) {
        known.set(entry.framework, {
          id: entry.framework,
          title: entry.framework,
          version: entry.version ?? "unversioned",
        });
      }
    }
  }
  return [...known.values()];
}

export interface ControlEvaluationCounts {
  pass: number;
  fail: number;
  error: number;
  notApplicable: number;
}

export type RequirementStatus = "compliant" | "non_compliant" | "error" | "not_assessed";
export type RequirementAutomation = "direct" | "partial" | "manual";

export interface RequirementRollup {
  requirement: string;
  /** direct = fully automated evidence; partial = needs manual assessment on top; manual = no automated evidence. */
  automation: RequirementAutomation;
  status: RequirementStatus;
  /** False when some mapped controls had no evaluation in the scan. */
  fullyAssessed: boolean;
  controls: Array<{
    controlId: string;
    mappingStatus: MappingStatus;
    scanStatus: RequirementStatus;
    pass: number;
    fail: number;
    error: number;
  }>;
}

export interface FrameworkRollup {
  framework: string;
  title: string;
  version: string;
  requirements: RequirementRollup[];
  totals: {
    mappedRequirements: number;
    compliant: number;
    nonCompliant: number;
    error: number;
    notAssessed: number;
    /** Full requirement count when the framework's list is vendored; else null. */
    totalRequirements: number | null;
    /** mappedRequirements / totalRequirements, or null when total unknown. */
    mappedRatio: number | null;
  };
  note: string;
}

function automationOf(statuses: MappingStatus[]): RequirementAutomation {
  if (statuses.includes("automated")) return "direct";
  if (statuses.includes("partial")) return "partial";
  return "manual";
}

function controlScanStatus(counts: ControlEvaluationCounts | undefined): RequirementStatus {
  if (!counts || counts.pass + counts.fail + counts.error + counts.notApplicable === 0) {
    return "not_assessed";
  }
  if (counts.fail > 0) return "non_compliant";
  if (counts.error > 0) return "error";
  if (counts.pass > 0) return "compliant";
  return "not_assessed"; // only not_applicable results: nothing in scope
}

export function complianceStatus(input: {
  controls: ControlDefinition[];
  registry: FrameworkRegistry;
  /** Per-control evaluation counts from the scan(s) being rolled up. */
  evaluations: Map<string, ControlEvaluationCounts>;
  framework?: string;
  provider?: Provider;
}): FrameworkRollup[] {
  const controls = input.controls.filter((c) => !input.provider || c.provider === input.provider);
  const controlIds = new Set(controls.map((c) => c.id));
  const totalsByFramework = frameworkRequirementTotals();
  const mappings = [...input.registry.mappings, ...derivedMappingsFromControls(controls)].filter(
    (m) => controlIds.has(m.controlId),
  );

  return allFrameworks(controls, input.registry)
    .filter((f) => !input.framework || f.id === input.framework)
    .map((framework) => {
      const byRequirement = new Map<string, RequirementMapping[]>();
      for (const mapping of mappings) {
        if (mapping.framework !== framework.id) continue;
        const list = byRequirement.get(mapping.requirement) ?? [];
        list.push(mapping);
        byRequirement.set(mapping.requirement, list);
      }

      const requirements: RequirementRollup[] = [...byRequirement.entries()]
        .sort(([a], [b]) => a.localeCompare(b, undefined, { numeric: true }))
        .map(([requirement, reqMappings]) => {
          const controlsDetail = reqMappings.map((mapping) => {
            const counts = input.evaluations.get(mapping.controlId);
            return {
              controlId: mapping.controlId,
              mappingStatus: mapping.status,
              scanStatus: controlScanStatus(counts),
              pass: counts?.pass ?? 0,
              fail: counts?.fail ?? 0,
              error: counts?.error ?? 0,
            };
          });
          const scanStatuses = controlsDetail.map((c) => c.scanStatus);
          const status: RequirementStatus = scanStatuses.includes("non_compliant")
            ? "non_compliant"
            : scanStatuses.includes("error")
              ? "error"
              : scanStatuses.includes("compliant")
                ? "compliant"
                : "not_assessed";
          return {
            requirement,
            automation: automationOf(reqMappings.map((m) => m.status)),
            status,
            fullyAssessed: !scanStatuses.includes("not_assessed"),
            controls: controlsDetail,
          };
        });

      const count = (status: RequirementStatus) =>
        requirements.filter((r) => r.status === status).length;
      const totalRequirements = totalsByFramework[framework.id] ?? null;
      const mappedRatio =
        totalRequirements && totalRequirements > 0 ? requirements.length / totalRequirements : null;
      const note =
        totalRequirements === null
          ? "Total requirement count for this framework is not vendored; unmapped requirements exist beyond the ones listed here. Never treat this rollup as a certification."
          : `${requirements.length} of ${totalRequirements} requirements have any CloudRanger mapping; the remainder are unassessed. Never treat this rollup as a certification.`;

      return {
        framework: framework.id,
        title: framework.title,
        version: framework.version,
        requirements,
        totals: {
          mappedRequirements: requirements.length,
          compliant: count("compliant"),
          nonCompliant: count("non_compliant"),
          error: count("error"),
          notAssessed: count("not_assessed"),
          totalRequirements,
          mappedRatio,
        },
        note,
      };
    })
    .filter((rollup) => rollup.requirements.length > 0 || input.framework === rollup.framework);
}

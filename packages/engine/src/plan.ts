import type { CollectorDefinition, ControlDefinition, Provider } from "./types.js";
import { validateParamValue, validateReadOnlyCommand } from "./safety.js";

/**
 * Collection plan builder. Given the controls a scan should evaluate, resolve
 * the set of collectors required and render the exact commands the agent must
 * run — including region expansion and per-resource iteration instructions.
 */

export interface PlanStep {
  stepId: string;
  collectorId: string;
  description: string;
  /** Rendered command, or command template for per_resource steps. */
  command: string;
  regional: boolean;
  region?: string;
  kind: "single" | "per_resource";
  /** For per_resource steps: how to derive {resource} values. */
  iterate?: {
    fromStepCollector: string;
    itemsPath: string;
    resourceField: string;
    instruction: string;
  };
  outputFormat: "json";
  runtime: {
    timeoutMs: number;
    maxAttempts: number;
    initialBackoffMs: number;
    maxBackoffMs: number;
  };
  notes?: string;
}

export interface CollectionPlan {
  provider: Provider;
  regions: string[];
  controlIds: string[];
  steps: PlanStep[];
  instructions: string;
}

const PLAN_INSTRUCTIONS = `Run each step's command exactly as given using your shell. All commands are read-only (list/describe/get/show). Do not modify any command or run any mutating command. Apply each step's runtime policy: stop an attempt at timeoutMs, retry only transient/throttling/timeout failures up to maxAttempts, and use exponential backoff capped at maxBackoffMs. For regional steps, the command is already rendered per region. For per_resource steps, first look at the referenced parent step's JSON output, extract the resource identifiers at itemsPath/resourceField, then run the command once per resource substituting {resource}. Submit every attempt's final parsed JSON output via evidence_submit, including the exact error text plus exit code when a command fails. Never omit failed commands — coverage accounting depends on them.`;

export function buildPlan(
  controls: ControlDefinition[],
  collectors: Map<string, CollectorDefinition>,
  options: { provider: Provider; regions: string[]; controlIds?: string[]; scopeId?: string },
): CollectionPlan {
  if (options.scopeId !== undefined && !validateParamValue(options.scopeId)) {
    throw new Error(`invalid scope value: ${JSON.stringify(options.scopeId)}`);
  }
  const wanted = options.controlIds ? new Set(options.controlIds) : null;
  const selected = controls.filter(
    (c) => c.provider === options.provider && (!wanted || wanted.has(c.id)),
  );

  for (const region of options.regions) {
    if (!validateParamValue(region)) {
      throw new Error(`invalid region value: ${JSON.stringify(region)}`);
    }
  }

  // Resolve collectors: control collectors plus parents of per_resource ones.
  const needed = new Map<string, CollectorDefinition>();
  const queue = selected.flatMap((c) => [
    c.collector,
    ...(c.relatedCollectors ?? []).map((r) => r.collector),
  ]);
  while (queue.length > 0) {
    const id = queue.pop()!;
    if (needed.has(id)) continue;
    const collector = collectors.get(id);
    if (!collector) throw new Error(`unknown collector: ${id}`);
    needed.set(id, collector);
    if (collector.parent) queue.push(collector.parent.collector);
  }

  // Parents before children.
  const ordered = [...needed.values()].sort((a, b) => {
    if (a.parent?.collector === b.id) return 1;
    if (b.parent?.collector === a.id) return -1;
    return a.id.localeCompare(b.id);
  });

  const steps: PlanStep[] = [];
  let n = 0;
  for (const collector of ordered) {
    const safety = validateReadOnlyCommand(collector.command);
    if (!safety.safe) {
      throw new Error(`collector ${collector.id} failed safety validation: ${safety.reason}`);
    }
    const expandRegions = collector.regional ? options.regions : [undefined];
    for (const region of expandRegions) {
      n += 1;
      let command = region ? collector.command.replaceAll("{region}", region) : collector.command;
      if (options.scopeId) {
        command = command
          .replaceAll("{project}", options.scopeId)
          .replaceAll("{account}", options.scopeId)
          .replaceAll("{subscription}", options.scopeId);
      }
      steps.push({
        stepId: `step-${String(n).padStart(3, "0")}`,
        collectorId: collector.id,
        description: collector.description,
        command,
        regional: collector.regional,
        region,
        kind: collector.kind,
        iterate: collector.parent
          ? {
              fromStepCollector: collector.parent.collector,
              itemsPath: collector.parent.itemsPath,
              resourceField: collector.parent.resourceField,
              instruction: `Run once per resource: substitute {resource} with each value of "${collector.parent.resourceField}" from items at "${collector.parent.itemsPath}" in the output of collector ${collector.parent.collector}${collector.regional ? " for the same region" : ""}.`,
            }
          : undefined,
        outputFormat: "json",
        runtime: {
          timeoutMs: collector.timeoutMs ?? 120_000,
          maxAttempts: collector.maxAttempts ?? 3,
          initialBackoffMs: collector.initialBackoffMs ?? 250,
          maxBackoffMs: collector.maxBackoffMs ?? 5_000,
        },
        notes: collector.notes,
      });
    }
  }

  return {
    provider: options.provider,
    regions: options.regions,
    controlIds: selected.map((c) => c.id),
    steps,
    instructions: PLAN_INSTRUCTIONS,
  };
}

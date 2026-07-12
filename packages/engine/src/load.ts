import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { collectorSchema, controlSchema } from "./schema.js";
import type { CollectorDefinition, ControlDefinition } from "./types.js";
import { validateReadOnlyCommand } from "./safety.js";

export interface CatalogIssue {
  file: string;
  message: string;
}

export interface LoadedCatalog {
  controls: ControlDefinition[];
  collectors: Map<string, CollectorDefinition>;
  issues: CatalogIssue[];
}

function yamlFilesUnder(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const entry of readdirSync(d)) {
      const full = join(d, entry);
      if (statSync(full).isDirectory()) walk(full);
      else if (entry.endsWith(".yaml") || entry.endsWith(".yml")) out.push(full);
    }
  };
  walk(dir);
  return out.sort();
}

/**
 * Load a catalog directory tree:
 *   <root>/collectors/**.yaml — documents each holding a list of collectors
 *   <root>/controls/**.yaml   — documents each holding a list of controls
 * Returns everything valid plus a list of issues; callers decide whether
 * issues are fatal (CLI validate) or skippable (server startup warns).
 */
export function loadCatalog(rootDir: string): LoadedCatalog {
  const issues: CatalogIssue[] = [];
  const collectors = new Map<string, CollectorDefinition>();
  const controls: ControlDefinition[] = [];

  for (const file of yamlFilesUnder(join(rootDir, "collectors"))) {
    const doc = parseYaml(readFileSync(file, "utf8"));
    const list = Array.isArray(doc) ? doc : (doc?.collectors ?? []);
    for (const entry of list) {
      const parsed = collectorSchema.safeParse(entry);
      if (!parsed.success) {
        issues.push({
          file,
          message: parsed.error.issues
            .map((i) => `${entry?.id ?? "?"}: ${i.path.join(".")} ${i.message}`)
            .join("; "),
        });
        continue;
      }
      const safety = validateReadOnlyCommand(parsed.data.command);
      if (!safety.safe) {
        issues.push({ file, message: `${parsed.data.id}: unsafe command — ${safety.reason}` });
        continue;
      }
      if (collectors.has(parsed.data.id)) {
        issues.push({ file, message: `${parsed.data.id}: duplicate collector id` });
        continue;
      }
      collectors.set(parsed.data.id, parsed.data as CollectorDefinition);
    }
  }

  const seenControls = new Set<string>();
  for (const file of yamlFilesUnder(join(rootDir, "controls"))) {
    const doc = parseYaml(readFileSync(file, "utf8"));
    const list = Array.isArray(doc) ? doc : (doc?.controls ?? []);
    for (const entry of list) {
      const parsed = controlSchema.safeParse(entry);
      if (!parsed.success) {
        issues.push({
          file,
          message: parsed.error.issues
            .map((i) => `${entry?.id ?? "?"}: ${i.path.join(".")} ${i.message}`)
            .join("; "),
        });
        continue;
      }
      if (seenControls.has(parsed.data.id)) {
        issues.push({ file, message: `${parsed.data.id}: duplicate control id` });
        continue;
      }
      seenControls.add(parsed.data.id);
      controls.push(parsed.data as unknown as ControlDefinition);
    }
  }

  // Referential integrity: control collectors and collector parents exist.
  for (const control of controls) {
    if (!collectors.has(control.collector)) {
      issues.push({
        file: "controls",
        message: `${control.id}: unknown collector ${control.collector}`,
      });
    }
  }
  for (const collector of collectors.values()) {
    if (collector.parent && !collectors.has(collector.parent.collector)) {
      issues.push({
        file: "collectors",
        message: `${collector.id}: unknown parent collector ${collector.parent.collector}`,
      });
    }
  }

  return { controls, collectors, issues };
}

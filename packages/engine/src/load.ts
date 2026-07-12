import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
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
  if (!existsSync(dir)) return [];
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
 * Load a catalog from one or more directory trees:
 *   <root>/collectors/**.yaml — documents each holding a list of collectors
 *   <root>/controls/**.yaml   — documents each holding a list of controls
 * Later roots override earlier ones by ID (bundled catalog first, operator
 * custom catalog last). Within a single root, duplicate IDs are an issue.
 * Returns everything valid plus a list of issues; callers decide whether
 * issues are fatal (CLI validate) or skippable (server startup warns).
 */
export function loadCatalog(rootDirs: string | string[]): LoadedCatalog {
  const roots = Array.isArray(rootDirs) ? rootDirs : [rootDirs];
  const issues: CatalogIssue[] = [];
  const collectors = new Map<string, CollectorDefinition>();
  const controlsById = new Map<string, ControlDefinition>();

  for (const root of roots) {
    // IDs already seen in THIS root; a repeat within one root is an error,
    // while a repeat across roots is an intentional override.
    const rootCollectorIds = new Set<string>();
    const rootControlIds = new Set<string>();

    const collectorFiles = yamlFilesUnder(join(root, "collectors"));
    const controlFiles = yamlFilesUnder(join(root, "controls"));
    // A document may declare both keys regardless of which subdirectory it
    // lives in (custom documents bundle a control with its collector). Bare
    // top-level arrays are interpreted by their directory.
    const docs = [...new Set([...collectorFiles, ...controlFiles])].map((file) => ({
      file,
      doc: parseYaml(readFileSync(file, "utf8")),
      inCollectorsDir: collectorFiles.includes(file),
    }));

    for (const { file, doc, inCollectorsDir } of docs) {
      const list = Array.isArray(doc) ? (inCollectorsDir ? doc : []) : (doc?.collectors ?? []);
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
        if (rootCollectorIds.has(parsed.data.id)) {
          issues.push({ file, message: `${parsed.data.id}: duplicate collector id` });
          continue;
        }
        rootCollectorIds.add(parsed.data.id);
        collectors.set(parsed.data.id, parsed.data as CollectorDefinition);
      }
    }

    for (const { file, doc, inCollectorsDir } of docs) {
      const list = Array.isArray(doc) ? (inCollectorsDir ? [] : doc) : (doc?.controls ?? []);
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
        if (rootControlIds.has(parsed.data.id)) {
          issues.push({ file, message: `${parsed.data.id}: duplicate control id` });
          continue;
        }
        rootControlIds.add(parsed.data.id);
        controlsById.set(parsed.data.id, parsed.data as unknown as ControlDefinition);
      }
    }
  }

  const controls = [...controlsById.values()];

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

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { catalogDir, loadDefaultCatalog } from "@cloudranger/catalog";

type Mapping = {
  framework: string;
  requirement: string;
  controlId: string;
  status: "automated" | "partial" | "manual" | "unsupported";
};
type Framework = { id: string; title: string; version: string };
type Registry = { frameworks?: Framework[]; mappings?: Mapping[] };

export function complianceCoverage(options: { framework?: string; provider?: string }) {
  const registry = parse(
    readFileSync(join(catalogDir(), "mappings", "frameworks.yaml"), "utf8"),
  ) as Registry;
  const controls = loadDefaultCatalog().controls.filter(
    (control) => !options.provider || control.provider === options.provider,
  );
  const controlIds = new Set(controls.map((control) => control.id));
  return (registry.frameworks ?? [])
    .filter((framework) => !options.framework || framework.id === options.framework)
    .map((framework) => {
      const mappings = (registry.mappings ?? []).filter(
        (mapping) => mapping.framework === framework.id && controlIds.has(mapping.controlId),
      );
      const controlsCovered = new Set(mappings.map((mapping) => mapping.controlId));
      return {
        framework: framework.id,
        title: framework.title,
        version: framework.version,
        mappedControls: controlsCovered.size,
        totalControls: controls.length,
        coverageRatio: controls.length === 0 ? 0 : controlsCovered.size / controls.length,
        uniqueRequirements: new Set(mappings.map((mapping) => mapping.requirement)).size,
        statuses: Object.fromEntries(
          ["automated", "partial", "manual", "unsupported"].map((status) => [
            status,
            mappings.filter((mapping) => mapping.status === status).length,
          ]),
        ),
      };
    });
}

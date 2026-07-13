import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { loadBundledCatalog } from "../packages/catalog/dist/index.js";

const doc = parse(readFileSync("packages/catalog/catalog/mappings/frameworks.yaml", "utf8"));
const ismIndex = JSON.parse(
  readFileSync("packages/catalog/catalog/mappings/upstream/ism-oscal-v2026.06.18.json", "utf8"),
);
const ismRequirements = new Set(ismIndex.controls.map((control) => control.id));
const frameworks = new Set((doc.frameworks ?? []).map((framework) => framework.id));
const controls = new Set(loadBundledCatalog().controls.map((control) => control.id));
const statuses = new Set(["automated", "partial", "manual", "unsupported"]);
const errors = [];
const seen = new Set();
for (const mapping of doc.mappings ?? []) {
  if (!frameworks.has(mapping.framework)) errors.push(`unknown framework ${mapping.framework}`);
  if (!controls.has(mapping.controlId)) errors.push(`unknown control ${mapping.controlId}`);
  if (!statuses.has(mapping.status)) errors.push(`invalid status ${mapping.status}`);
  if (!mapping.requirement || !mapping.rationale)
    errors.push(`mapping ${mapping.controlId} requires requirement and rationale`);
  const key = `${mapping.framework}/${mapping.requirement}/${mapping.controlId}`;
  if (seen.has(key)) errors.push(`duplicate mapping ${key}`);
  seen.add(key);
  if (mapping.framework === "ism" && !/^ism-\d{4}$/.test(mapping.requirement))
    errors.push(`invalid ISM OSCAL requirement ${mapping.requirement}`);
  if (mapping.framework === "ism" && !ismRequirements.has(mapping.requirement))
    errors.push(`unknown ISM OSCAL requirement ${mapping.requirement}`);
  if (
    mapping.framework === "azure-security-benchmark" &&
    !/^(DP|GS|IM|LT|NS|PA)-\d+$/.test(mapping.requirement)
  )
    errors.push(`invalid Azure Security Benchmark requirement ${mapping.requirement}`);
}
if (errors.length) throw new Error(errors.join("\n"));
console.log(`OK — ${frameworks.size} frameworks, ${(doc.mappings ?? []).length} mappings`);

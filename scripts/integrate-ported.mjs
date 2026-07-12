#!/usr/bin/env node
/**
 * Integrate ported-control workflow output into the catalog, salvaging per
 * control (not per slice).
 *
 * Input: JSON file = workflow result array of
 *   { slice, generation: { service, collectorsYaml, controlsYaml, fixturesJson, controlIds, excludedChecks }, verdict }
 *
 * Pipeline per slice:
 *   1. Parse controls/collectors YAML and fixtures JSON (slice dropped whole
 *      only if controlsYaml is unparseable).
 *   2. Auto-fix the one safe mechanical defect: drop compliance entries whose
 *      controls list is empty (schema requires >=1; this changes no logic).
 *   3. Load the slice merged with the bundled catalog and run every fixture.
 *   4. KEEP a control only if: it is schema-valid, its collector resolves, it
 *      has >=1 pass and >=1 fail fixture, and ALL its fixtures pass
 *      deterministically, and its id collides with nothing. Otherwise DROP it
 *      (reason recorded).
 *   5. Emit cleaned controls/collectors/fixtures containing only kept controls.
 *
 * Usage: node scripts/integrate-ported.mjs <result.json> <provider> [--apply]
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { loadCatalog, runFixtureFile, fixtureFileSchema } from "../packages/engine/dist/index.js";
import { catalogDir } from "../packages/catalog/dist/index.js";

const [resultPath, provider] = process.argv.slice(2);
const apply = process.argv.includes("--apply");
if (!resultPath || !provider) {
  console.error("usage: integrate-ported.mjs <result.json> <provider> [--apply]");
  process.exit(1);
}
const PREFIX = `CR-${provider.toUpperCase()}-`;

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const bundled = catalogDir();
const realControlsDir = join(bundled, "controls");
const realCollectorsDir = join(bundled, "collectors");
const realFixturesDir = join(repoRoot, "packages/catalog/fixtures");

const bundledCatalog = loadCatalog(bundled);
const bundledCollectorIds = new Set(bundledCatalog.collectors.keys());
const bundledControlIds = new Set(bundledCatalog.controls.map((c) => c.id));

const raw = JSON.parse(readFileSync(resultPath, "utf8"));
const sliceResults = Array.isArray(raw) ? raw : raw.result || raw.results || [];

const claimedIds = new Set();
const emittedCollectorIds = new Set(bundledCollectorIds); // catalog-wide dedup
let totalKept = 0;
let totalDropped = 0;
let totalFixtures = 0;
const sliceReports = [];
const appliedSlices = [];

/**
 * Repair the common LLM YAML defect where an unquoted scalar contains a
 * colon-space or quotes, which YAML then misreads as a nested mapping.
 * Scoped to (a) known free-text string fields and (b) prose sequence items,
 * leaving structured/flow lines (expressions, flow maps/seqs) untouched.
 */
const TEXT_KEYS = new Set([
  "title",
  "description",
  "rationale",
  "failMessage",
  "passMessage",
  "summary",
  "notes",
  "message",
]);

function needsQuote(value) {
  const v = value.trim();
  if (v.length === 0) return false;
  if (/^["'[{>|&*!]/.test(v)) return false; // already quoted / block / flow
  return /:\s/.test(v) || v.includes('"') || v.includes(" #");
}

function dq(value) {
  return `"${value.trim().replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function sanitizeYaml(text) {
  return text
    .split("\n")
    .map((line) => {
      // Free-text mapping value: `<indent><key>: <value>`
      const kv = line.match(/^(\s*)([A-Za-z]+):\s(.+)$/);
      if (kv && TEXT_KEYS.has(kv[2]) && needsQuote(kv[3])) {
        return `${kv[1]}${kv[2]}: ${dq(kv[3])}`;
      }
      // Prose sequence item: `<indent>- <text>` where text is NOT a mapping
      // entry (first token is not `key:`) and not a flow char.
      const seq = line.match(/^(\s+- )((?![A-Za-z0-9_]+:\s)[A-Za-z][^\n]*)$/);
      if (seq && needsQuote(seq[2])) {
        return `${seq[1]}${dq(seq[2])}`;
      }
      return line;
    })
    .join("\n");
}

/** Drop compliance entries with empty/missing controls arrays. */
function normalizeControl(control) {
  if (Array.isArray(control.compliance)) {
    control.compliance = control.compliance.filter(
      (c) => c && Array.isArray(c.controls) && c.controls.length > 0,
    );
  }
  return control;
}

for (const entry of sliceResults) {
  const gen = entry.generation || entry;
  const service = gen.service || entry.slice || "unknown";
  const dropped = [];

  let controlsDoc, collectorsDoc, fixtures;
  try {
    controlsDoc = parseYaml(sanitizeYaml(gen.controlsYaml || ""));
  } catch (e) {
    sliceReports.push({ service, kept: 0, dropped: [`controlsYaml unparseable: ${String(e.message).split("\n")[0]}`] });
    continue;
  }
  try {
    collectorsDoc = gen.collectorsYaml ? parseYaml(gen.collectorsYaml) : { collectors: [] };
  } catch {
    collectorsDoc = { collectors: [] };
  }
  try {
    fixtures = JSON.parse(gen.fixturesJson || "[]");
  } catch (e) {
    sliceReports.push({ service, kept: 0, dropped: [`fixturesJson parse error: ${e.message}`] });
    continue;
  }

  const controls = Array.isArray(controlsDoc?.controls) ? controlsDoc.controls.map(normalizeControl) : [];
  const newCollectors = Array.isArray(collectorsDoc?.collectors) ? collectorsDoc.collectors : [];
  const fixtureByControl = new Map((Array.isArray(fixtures) ? fixtures : []).map((f) => [f.controlId, f]));

  // Load the full slice once to surface schema/ref issues, mapped to control ids.
  const tmp = mkdtempSync(join(tmpdir(), `cr-int-${service}-`));
  mkdirSync(join(tmp, "controls"), { recursive: true });
  mkdirSync(join(tmp, "collectors"), { recursive: true });
  if (newCollectors.length) writeFileSync(join(tmp, "collectors", "c.yaml"), stringifyYaml({ collectors: newCollectors }));
  writeFileSync(join(tmp, "controls", "c.yaml"), stringifyYaml({ controls }));
  let loaded;
  try {
    loaded = loadCatalog([bundled, tmp]);
  } catch (e) {
    sliceReports.push({ service, kept: 0, dropped: [`slice load error: ${String(e.message).split("\n")[0]}`] });
    rmSync(tmp, { recursive: true, force: true });
    continue;
  }
  const issueText = loaded.issues.map((i) => i.message).join("\n");

  const keptControls = [];
  for (const control of controls) {
    const id = control.id;
    const bad = [];
    if (!id || !id.startsWith(PREFIX)) bad.push(`bad id ${id}`);
    if (bundledControlIds.has(id)) bad.push("collides with bundled control");
    if (claimedIds.has(id)) bad.push("collides with another slice");
    // schema/ref issue mentioning this id
    if (issueText.split("\n").some((line) => line.startsWith(`${id}:`) || line.includes(` ${id} `) || line.includes(`${id}:`))) {
      bad.push("schema/reference issue");
    }
    // collector resolves in merged catalog
    if (control.collector && !loaded.collectors.has(control.collector)) bad.push(`unknown collector ${control.collector}`);
    // redefines a bundled collector?
    for (const nc of newCollectors) {
      if (bundledCollectorIds.has(nc.id)) bad.push(`redefines bundled collector ${nc.id}`);
    }
    // fixtures
    const f = fixtureByControl.get(id);
    if (!f) bad.push("no fixture");
    else {
      const parsed = fixtureFileSchema.safeParse(f);
      if (!parsed.success) bad.push(`fixture schema: ${parsed.error.issues[0]?.message}`);
      else {
        const exp = new Set(parsed.data.cases.map((c) => c.expected));
        if (!exp.has("pass")) bad.push("no pass fixture");
        if (!exp.has("fail")) bad.push("no fail fixture");
        for (const r of runFixtureFile(parsed.data, loaded.controls, loaded.collectors)) {
          if (!r.ok) bad.push(`fixture ${r.caseName}: expected ${r.expected} got ${r.actual}`);
        }
      }
    }
    if (bad.length === 0) {
      keptControls.push(control);
      claimedIds.add(id);
    } else {
      dropped.push(`${id}: ${bad.slice(0, 2).join("; ")}`);
    }
  }
  rmSync(tmp, { recursive: true, force: true });

  // Keep only collectors referenced by kept controls (transitively via parent).
  const keptControlCollectorIds = new Set(keptControls.map((c) => c.collector));
  const keepCollector = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    for (const nc of newCollectors) {
      if (keepCollector.has(nc.id)) continue;
      const referenced = keptControlCollectorIds.has(nc.id) || [...keepCollector].some((k) => {
        const kc = newCollectors.find((x) => x.id === k);
        return kc?.parent?.collector === nc.id;
      });
      if (referenced) {
        keepCollector.add(nc.id);
        changed = true;
      }
    }
  }
  // Emit each new collector at most once across the whole catalog; later
  // slices that reference an already-emitted collector just use it.
  const keptCollectors = newCollectors.filter((c) => {
    if (!keepCollector.has(c.id) || emittedCollectorIds.has(c.id)) return false;
    emittedCollectorIds.add(c.id);
    return true;
  });
  const keptFixtures = (Array.isArray(fixtures) ? fixtures : []).filter((f) =>
    keptControls.some((c) => c.id === f.controlId),
  );

  totalKept += keptControls.length;
  totalDropped += dropped.length;
  totalFixtures += keptFixtures.reduce((n, f) => n + f.cases.length, 0);
  sliceReports.push({ service, kept: keptControls.length, dropped });
  if (keptControls.length > 0) {
    appliedSlices.push({
      service,
      controlsYaml: stringifyYaml({ controls: keptControls }),
      collectorsYaml: keptCollectors.length ? stringifyYaml({ collectors: keptCollectors }) : "",
      fixturesJson: JSON.stringify(keptFixtures, null, 2),
    });
  }
}

console.log(`\n=== INTEGRATION REPORT (${provider}) ===`);
console.log(`controls kept: ${totalKept}, dropped: ${totalDropped}, fixtures kept: ${totalFixtures}\n`);
for (const s of sliceReports) {
  console.log(`${s.service}: kept ${s.kept}${s.dropped.length ? `, dropped ${s.dropped.length}` : ""}`);
  for (const d of s.dropped.slice(0, 20)) console.log(`   drop ${d}`);
}

if (apply) {
  // Final full-catalog validation happens after write via `catalog validate`.
  for (const s of appliedSlices) {
    if (s.collectorsYaml) writeFileSync(join(realCollectorsDir, `${provider}-gen-${s.service}.yaml`), s.collectorsYaml);
    writeFileSync(join(realControlsDir, `${provider}-gen-${s.service}.yaml`), s.controlsYaml);
    writeFileSync(join(realFixturesDir, `${provider}-gen-${s.service}.json`), s.fixturesJson);
  }
  console.log(`\napplied ${appliedSlices.length} slices (${totalKept} controls) to the catalog.`);
}

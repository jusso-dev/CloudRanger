#!/usr/bin/env node
/**
 * Pinned Prowler inventory and coverage validator.
 *
 * `sync` writes one record for every AWS, Azure and GCP Prowler metadata
 * check. Existing decisions are preserved, while exact source-id matches in
 * the bundled catalog are marked implemented automatically.
 *
 * `validate` makes the inventory actionable: every upstream check must have a
 * status, and every implemented mapping must point to a fixture-backed,
 * Prowler-attributed CloudRanger control. It intentionally does not let an
 * ungrounded metadata stub count as coverage.
 *
 * Usage:
 *   node scripts/prowler-coverage.mjs sync --prowler /path/to/prowler
 *   node scripts/prowler-coverage.mjs validate
 *   node scripts/prowler-coverage.mjs report
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { parseArgs } from "node:util";
import { parse as parseYaml } from "yaml";

const ROOT = new URL("..", import.meta.url).pathname;
const PROVIDERS = ["aws", "azure", "gcp"];
const STATUSES = new Set(["implemented", "superseded", "unsupported", "deprecated", "unmapped"]);
const DEFAULT_MANIFEST = join(ROOT, "packages/catalog/catalog/upstream/prowler-v5.34.0.json");
const CONTROLS_DIR = join(ROOT, "packages/catalog/catalog/controls");
const FIXTURES_DIR = join(ROOT, "packages/catalog/fixtures");

const { positionals, values } = parseArgs({
  // pnpm forwards a literal `--` before script arguments; it is not part of
  // this script's CLI and would otherwise terminate Node's option parsing.
  args: process.argv.slice(2).filter((arg) => arg !== "--"),
  options: {
    prowler: { type: "string" },
    manifest: { type: "string" },
  },
  allowPositionals: true,
});
const command = positionals[0];
const manifestPath = values.manifest ? resolveFromRoot(values.manifest) : DEFAULT_MANIFEST;

function resolveFromRoot(path) {
  return path.startsWith("/") ? path : join(ROOT, path);
}

function walk(dir, predicate) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const file = join(dir, entry);
    if (statSync(file).isDirectory()) files.push(...walk(file, predicate));
    else if (predicate(file)) files.push(file);
  }
  return files;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function readCatalog() {
  const controls = [];
  for (const file of walk(CONTROLS_DIR, (path) => path.endsWith(".yaml"))) {
    const doc = parseYaml(readFileSync(file, "utf8"));
    for (const control of doc?.controls ?? []) controls.push(control);
  }

  const fixtures = new Map();
  for (const file of walk(FIXTURES_DIR, (path) => path.endsWith(".json"))) {
    for (const fixture of readJson(file)) {
      if (fixtures.has(fixture.controlId)) {
        throw new Error(`duplicate fixture definition for ${fixture.controlId}: ${relative(ROOT, file)}`);
      }
      fixtures.set(fixture.controlId, fixture);
    }
  }
  return { controls, fixtures };
}

function fixtureHasPassAndFail(fixture) {
  const expected = new Set(fixture?.cases?.map((testCase) => testCase.expected));
  return expected.has("pass") && expected.has("fail");
}

function prowlerVersion(prowlerRoot) {
  const pyproject = readFileSync(join(prowlerRoot, "pyproject.toml"), "utf8");
  const match = pyproject.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) throw new Error(`could not determine Prowler version from ${join(prowlerRoot, "pyproject.toml")}`);
  return match[1];
}

function prowlerRevision(prowlerRoot) {
  try {
    return execFileSync("git", ["-C", prowlerRoot, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
}

function loadUpstreamChecks(prowlerRoot, provider) {
  const services = join(prowlerRoot, "prowler", "providers", provider, "services");
  if (!existsSync(services)) throw new Error(`Prowler ${provider} services directory not found: ${services}`);
  const checks = [];
  for (const file of walk(services, (path) => path.endsWith(".metadata.json"))) {
    const metadata = readJson(file);
    if ((metadata.Provider ?? provider).toLowerCase() !== provider || !metadata.CheckID) continue;
    checks.push({
      id: metadata.CheckID,
      service: metadata.ServiceName ?? "unknown",
      title: metadata.CheckTitle ?? metadata.CheckID,
      severity: String(metadata.Severity ?? "medium").toLowerCase(),
      deprecated: /^\[DEPRECATED\]/i.test(metadata.CheckTitle ?? ""),
    });
  }
  checks.sort((a, b) => a.id.localeCompare(b.id));
  const duplicate = checks.find((check, index) => check.id === checks[index - 1]?.id);
  if (duplicate) throw new Error(`duplicate ${provider} Prowler check id: ${duplicate.id}`);
  return checks;
}

function sync() {
  if (!values.prowler) throw new Error("sync requires --prowler /path/to/prowler");
  const prowlerRoot = resolveFromRoot(values.prowler);
  const previous = existsSync(manifestPath) ? readJson(manifestPath) : null;
  const previousByKey = new Map(
    (previous?.checks ?? []).map((check) => [`${check.provider}:${check.id}`, check]),
  );
  const { controls, fixtures } = readCatalog();
  const exactControls = new Map();
  for (const control of controls) {
    if (control.source?.engine !== "prowler") continue;
    const key = `${control.provider}:${control.source.id}`;
    const list = exactControls.get(key) ?? [];
    list.push(control.id);
    exactControls.set(key, list);
  }

  const checks = [];
  for (const provider of PROVIDERS) {
    for (const upstream of loadUpstreamChecks(prowlerRoot, provider)) {
      const key = `${provider}:${upstream.id}`;
      const prior = previousByKey.get(key);
      const controlIds = (exactControls.get(key) ?? []).sort();
      const record = {
        provider,
        ...upstream,
        status: upstream.deprecated ? "deprecated" : "unmapped",
        controlIds: [],
      };
      if (upstream.deprecated) record.reason = "Prowler metadata marks this check as deprecated.";
      if (controlIds.length > 0 && controlIds.every((id) => fixtureHasPassAndFail(fixtures.get(id)))) {
        record.status = "implemented";
        record.controlIds = controlIds;
      } else if (prior) {
        // Preserve explicit non-executable decisions (and their justifications).
        record.status = prior.status;
        record.controlIds = prior.controlIds ?? [];
        if (prior.reason) record.reason = prior.reason;
        if (prior.requiredCapabilities) record.requiredCapabilities = prior.requiredCapabilities;
        if (prior.aliases) record.aliases = prior.aliases;
      }
      checks.push(record);
    }
  }
  checks.sort((a, b) => a.provider.localeCompare(b.provider) || a.id.localeCompare(b.id));
  const manifest = {
    schemaVersion: 1,
    upstream: {
      engine: "prowler",
      version: prowlerVersion(prowlerRoot),
      revision: prowlerRevision(prowlerRoot),
    },
    checks,
  };
  mkdirSync(dirname(manifestPath), { recursive: true });
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`wrote ${checks.length} checks to ${relative(ROOT, manifestPath)}`);
  report(manifest);
}

function validate() {
  if (!existsSync(manifestPath)) throw new Error(`manifest not found: ${manifestPath}`);
  const manifest = readJson(manifestPath);
  const errors = [];
  if (manifest.schemaVersion !== 1) errors.push("manifest schemaVersion must be 1");
  if (manifest.upstream?.engine !== "prowler") errors.push("manifest upstream.engine must be prowler");
  if (!Array.isArray(manifest.checks)) errors.push("manifest checks must be an array");
  const { controls, fixtures } = readCatalog();
  const byId = new Map(controls.map((control) => [control.id, control]));
  const seen = new Set();

  for (const check of manifest.checks ?? []) {
    const key = `${check.provider}:${check.id}`;
    if (!PROVIDERS.includes(check.provider)) errors.push(`${key}: invalid provider`);
    if (!check.id || typeof check.id !== "string") errors.push(`${key}: missing check id`);
    if (seen.has(key)) errors.push(`${key}: duplicate upstream record`);
    seen.add(key);
    if (!STATUSES.has(check.status)) errors.push(`${key}: invalid status ${check.status}`);
    if (!Array.isArray(check.controlIds)) errors.push(`${key}: controlIds must be an array`);
    if (check.aliases !== undefined && (!Array.isArray(check.aliases) || check.aliases.some((id) => typeof id !== "string"))) {
      errors.push(`${key}: aliases must be an array of source ids`);
    }
    if (check.aliases?.length > 0 && !check.reason) {
      errors.push(`${key}: aliases require a semantic-equivalence reason`);
    }

    if (["superseded", "unsupported", "deprecated"].includes(check.status) && !check.reason) {
      errors.push(`${key}: ${check.status} requires a reason`);
    }
    if (check.status === "unsupported" && !Array.isArray(check.requiredCapabilities)) {
      errors.push(`${key}: unsupported requires requiredCapabilities`);
    }
    if (check.status === "implemented" && check.controlIds.length === 0) {
      errors.push(`${key}: implemented requires at least one controlId`);
    }
    for (const controlId of check.controlIds ?? []) {
      const control = byId.get(controlId);
      if (!control) {
        errors.push(`${key}: references missing control ${controlId}`);
        continue;
      }
      if (control.provider !== check.provider) errors.push(`${key}: ${controlId} has a different provider`);
      if (!fixtureHasPassAndFail(fixtures.get(controlId))) {
        errors.push(`${key}: ${controlId} does not have both pass and fail fixtures`);
      }
      if (
        check.status === "implemented" &&
        control.source?.id !== check.id &&
        !check.aliases?.includes(control.source?.id)
      ) {
        errors.push(`${key}: implemented ${controlId} must use the exact upstream source id or a declared alias`);
      }
    }
  }

  if (errors.length > 0) {
    for (const error of errors) console.error(`ERROR ${error}`);
    throw new Error(`${errors.length} coverage validation error(s)`);
  }
  console.log(`OK — ${manifest.checks.length} upstream checks are explicitly tracked`);
  report(manifest);
}

function report(manifest = readJson(manifestPath)) {
  console.log(`Prowler ${manifest.upstream.version} (${manifest.upstream.revision.slice(0, 12)}) coverage:`);
  for (const provider of PROVIDERS) {
    const checks = manifest.checks.filter((check) => check.provider === provider);
    const counts = Object.fromEntries([...STATUSES].map((status) => [status, 0]));
    for (const check of checks) counts[check.status]++;
    console.log(
      `  ${provider.padEnd(5)} total=${String(checks.length).padStart(3)} implemented=${String(counts.implemented).padStart(3)} unmapped=${String(counts.unmapped).padStart(3)} unsupported=${String(counts.unsupported).padStart(3)} superseded=${String(counts.superseded).padStart(3)} deprecated=${String(counts.deprecated).padStart(3)}`,
    );
  }
}

try {
  if (command === "sync") sync();
  else if (command === "validate") validate();
  else if (command === "report") report();
  else throw new Error("usage: prowler-coverage.mjs <sync|validate|report> [--prowler PATH] [--manifest PATH]");
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}

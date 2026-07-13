#!/usr/bin/env node
/**
 * Catalog contribution gate (CI). Enforces the porting quality bar on the
 * whole bundled catalog:
 *   1. catalog loads with zero validation issues (schema, read-only safety,
 *      parameter coherence, referential integrity);
 *   2. EVERY control ships at least one pass and one fail fixture case;
 *   3. every remediation verifyCommand looks read-only (starts with a
 *      provider CLI + read verb, no shell chaining).
 * Run locally with: node scripts/catalog-pr-checks.mjs
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { loadCatalog } from "../packages/engine/dist/index.js";

const root = new URL("..", import.meta.url).pathname;
const catalogPath = join(root, "packages/catalog/catalog");
const fixturesPath = join(root, "packages/catalog/fixtures");

const errors = [];

const catalog = loadCatalog(catalogPath);
for (const issue of catalog.issues) errors.push(`${issue.file}: ${issue.message}`);

// Fixture coverage: one pass AND one fail case per control.
const coverage = new Map();
for (const file of readdirSync(fixturesPath).filter((f) => f.endsWith(".json"))) {
  for (const fixture of JSON.parse(readFileSync(join(fixturesPath, file), "utf8"))) {
    const entry = coverage.get(fixture.controlId) ?? { pass: 0, fail: 0 };
    for (const testCase of fixture.cases) {
      if (testCase.expected === "pass") entry.pass += 1;
      if (testCase.expected === "fail") entry.fail += 1;
    }
    coverage.set(fixture.controlId, entry);
  }
}
for (const control of catalog.controls) {
  const entry = coverage.get(control.id);
  if (!entry) {
    errors.push(`${control.id}: no fixtures — every control needs ≥1 pass and ≥1 fail case`);
  } else {
    if (entry.pass === 0) errors.push(`${control.id}: no pass fixture case`);
    if (entry.fail === 0) errors.push(`${control.id}: no fail fixture case`);
  }
}

// verifyCommand hygiene: read verb, no shell chaining. (Full metacharacter
// validation is not applied because verify commands legitimately contain
// <placeholders> for the operator to substitute.)
const READ_VERB =
  /^(aws\s+[a-z0-9-]+\s+(list|describe|get|lookup|search|batch-get)|az\s+.*\b(list|show)\b|gcloud\s+.*\b(list|describe|get)|gsutil\s+(iam\s+get|ls))/;
for (const control of catalog.controls) {
  const command = control.remediation?.verifyCommand;
  if (!command) continue;
  if (/[;|&`$]/.test(command)) {
    errors.push(`${control.id}: verifyCommand contains shell chaining characters`);
  } else if (!READ_VERB.test(command)) {
    errors.push(`${control.id}: verifyCommand does not start with a recognised read-only verb`);
  }
}

if (errors.length > 0) {
  for (const error of errors) console.error(`FAIL ${error}`);
  console.error(`\n${errors.length} catalog contribution check(s) failed`);
  process.exit(1);
}
console.log(
  `OK — ${catalog.controls.length} controls, all with pass+fail fixtures and read-only verify commands`,
);

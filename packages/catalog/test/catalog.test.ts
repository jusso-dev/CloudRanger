import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { fixtureFileSchema, runFixtureFile, validateReadOnlyCommand } from "@cloudranger/engine";
import { fixturesDir, loadDefaultCatalog } from "../src/index.js";

const catalog = loadDefaultCatalog();

function loadAllFixtures() {
  const files = readdirSync(fixturesDir()).filter((f) => f.endsWith(".json"));
  return files.flatMap((file) => {
    const parsed = JSON.parse(readFileSync(join(fixturesDir(), file), "utf8"));
    return (parsed as unknown[]).map((entry) => fixtureFileSchema.parse(entry));
  });
}

describe("bundled catalog", () => {
  it("loads without validation issues", () => {
    expect(catalog.issues).toEqual([]);
    expect(catalog.controls.length).toBeGreaterThanOrEqual(45);
    expect(catalog.collectors.size).toBeGreaterThanOrEqual(30);
  });

  it("covers all three providers", () => {
    for (const provider of ["aws", "azure", "gcp"] as const) {
      expect(catalog.controls.filter((c) => c.provider === provider).length).toBeGreaterThanOrEqual(
        13,
      );
    }
  });

  it("every collector command passes read-only safety validation", () => {
    for (const collector of catalog.collectors.values()) {
      expect(validateReadOnlyCommand(collector.command), collector.id).toEqual({ safe: true });
    }
  });

  it("every control has upstream source attribution", () => {
    for (const control of catalog.controls) {
      expect(control.source.engine, control.id).toBeTruthy();
      expect(control.source.id, control.id).toBeTruthy();
      expect(control.source.license, control.id).toBe("Apache-2.0");
    }
  });

  it("every control has remediation steps and at least one reference", () => {
    for (const control of catalog.controls) {
      expect(control.remediation.steps.length, control.id).toBeGreaterThan(0);
      expect(control.references.length, control.id).toBeGreaterThan(0);
    }
  });

  it("verify commands are read-only", () => {
    for (const control of catalog.controls) {
      const verify = control.remediation.verifyCommand;
      if (!verify) continue;
      const rendered = verify.replace(/<[a-z-]+>/g, "placeholder");
      expect(validateReadOnlyCommand(rendered), `${control.id}: ${verify}`).toEqual({ safe: true });
    }
  });
});

describe("control fixtures", () => {
  const fixtures = loadAllFixtures();

  it("every control has a fixture with at least one pass and one fail case", () => {
    const byControl = new Map(fixtures.map((f) => [f.controlId, f]));
    const missing: string[] = [];
    for (const control of catalog.controls) {
      const fixture = byControl.get(control.id);
      if (!fixture) {
        missing.push(`${control.id}: no fixture file`);
        continue;
      }
      const expectations = new Set(fixture.cases.map((c) => c.expected));
      if (!expectations.has("pass")) missing.push(`${control.id}: no pass case`);
      if (!expectations.has("fail")) missing.push(`${control.id}: no fail case`);
    }
    expect(missing).toEqual([]);
  });

  it("all fixture cases produce the expected deterministic outcome", () => {
    const failures: string[] = [];
    for (const fixture of fixtures) {
      for (const result of runFixtureFile(fixture, catalog.controls, catalog.collectors)) {
        if (!result.ok) {
          failures.push(
            `${result.controlId} / ${result.caseName}: expected ${result.expected}, got ${result.actual}${result.detail ? ` (${result.detail})` : ""}`,
          );
        }
      }
    }
    expect(failures).toEqual([]);
  });
});

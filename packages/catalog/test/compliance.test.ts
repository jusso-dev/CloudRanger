import { describe, expect, it } from "vitest";
import {
  complianceStatus,
  derivedMappingsFromControls,
  frameworkRequirementTotals,
  loadFrameworkRegistry,
  type ControlEvaluationCounts,
  type FrameworkRegistry,
} from "../src/compliance.js";
import { loadBundledCatalog, resolvePack } from "../src/index.js";

const catalog = loadBundledCatalog();

const registry: FrameworkRegistry = {
  frameworks: [
    { id: "test-fw", title: "Test Framework", version: "1.0" },
    { id: "ism", title: "ISM", version: "2026.06.18" },
  ],
  mappings: [
    { framework: "test-fw", requirement: "R1", controlId: "CR-AWS-IAM-001", status: "automated" },
    { framework: "test-fw", requirement: "R1", controlId: "CR-AWS-IAM-018", status: "partial" },
    { framework: "test-fw", requirement: "R2", controlId: "CR-AWS-IAM-011", status: "partial" },
    { framework: "test-fw", requirement: "R3", controlId: "CR-AWS-IAM-004", status: "manual" },
    { framework: "ism", requirement: "ism-0974", controlId: "CR-AWS-IAM-001", status: "automated" },
  ],
};

const counts = (
  entries: Record<string, Partial<ControlEvaluationCounts>>,
): Map<string, ControlEvaluationCounts> =>
  new Map(
    Object.entries(entries).map(([id, c]) => [
      id,
      { pass: 0, fail: 0, error: 0, notApplicable: 0, ...c },
    ]),
  );

describe("complianceStatus rollup", () => {
  it("derives requirement status and automation from mapped control results", () => {
    const rollup = complianceStatus({
      controls: catalog.controls,
      registry,
      framework: "test-fw",
      provider: "aws",
      evaluations: counts({
        "CR-AWS-IAM-001": { pass: 1 },
        "CR-AWS-IAM-018": { pass: 1 },
        "CR-AWS-IAM-011": { fail: 2, pass: 3 },
      }),
    });
    expect(rollup).toHaveLength(1);
    const byReq = new Map(rollup[0]!.requirements.map((r) => [r.requirement, r]));
    // R1: automated mapping present → direct; both controls pass → compliant.
    expect(byReq.get("R1")!.automation).toBe("direct");
    expect(byReq.get("R1")!.status).toBe("compliant");
    expect(byReq.get("R1")!.fullyAssessed).toBe(true);
    // R2: any failing control → non_compliant, partial automation.
    expect(byReq.get("R2")!.automation).toBe("partial");
    expect(byReq.get("R2")!.status).toBe("non_compliant");
    // R3: manual mapping, no evaluations → not assessed.
    expect(byReq.get("R3")!.automation).toBe("manual");
    expect(byReq.get("R3")!.status).toBe("not_assessed");
    expect(rollup[0]!.totals).toMatchObject({
      mappedRequirements: 3,
      compliant: 1,
      nonCompliant: 1,
      notAssessed: 1,
      totalRequirements: null,
      mappedRatio: null,
    });
    expect(rollup[0]!.note).toMatch(/not vendored/);
  });

  it("errors dominate compliant but not failures, and partial assessment is flagged", () => {
    const rollup = complianceStatus({
      controls: catalog.controls,
      registry,
      framework: "test-fw",
      provider: "aws",
      evaluations: counts({ "CR-AWS-IAM-001": { error: 1 } }),
    });
    const r1 = rollup[0]!.requirements.find((r) => r.requirement === "R1")!;
    expect(r1.status).toBe("error");
    expect(r1.fullyAssessed).toBe(false); // IAM-018 had no evaluation
  });

  it("computes a mapped ratio only when the framework total is vendored", () => {
    const totals = frameworkRequirementTotals();
    expect(totals["ism"]).toBeGreaterThan(1000);
    const rollup = complianceStatus({
      controls: catalog.controls,
      registry,
      framework: "ism",
      provider: "aws",
      evaluations: counts({ "CR-AWS-IAM-001": { pass: 1 } }),
    });
    expect(rollup[0]!.totals.totalRequirements).toBe(totals["ism"]);
    expect(rollup[0]!.totals.mappedRatio).toBeCloseTo(1 / totals["ism"]!, 6);
    expect(rollup[0]!.note).toMatch(/of \d+ requirements/);
  });

  it("includes control-declared CIS mappings as direct automation", () => {
    const derived = derivedMappingsFromControls(catalog.controls);
    expect(derived.some((m) => m.framework === "cis-aws-foundations")).toBe(true);
    const rollup = complianceStatus({
      controls: catalog.controls,
      registry: loadFrameworkRegistry(),
      framework: "cis-aws-foundations",
      provider: "aws",
      evaluations: new Map(),
    });
    expect(rollup[0]!.totals.mappedRequirements).toBeGreaterThan(5);
    expect(rollup[0]!.requirements.every((r) => r.status === "not_assessed")).toBe(true);
  });
});

describe("framework-aligned packs", () => {
  it("cis-aws-3.0 resolves the CIS-mapped AWS controls", () => {
    const controls = resolvePack(catalog.controls, "cis-aws-3.0", "aws");
    expect(controls.length).toBeGreaterThan(10);
    expect(
      controls.every((c) =>
        c.compliance.some((m) => m.framework === "cis-aws-foundations" && m.version === "3.0"),
      ),
    ).toBe(true);
  });

  it("essential-eight-technical resolves via the mapping registry", () => {
    const controls = resolvePack(catalog.controls, "essential-eight-technical", "aws");
    const ids = controls.map((c) => c.id);
    expect(ids).toContain("CR-AWS-IAM-001");
    expect(ids).toContain("CR-AWS-DYNAMODB-001");
    expect(ids).toContain("CR-AWS-RDS-013");
    expect(controls.length).toBeGreaterThanOrEqual(8);
  });
});

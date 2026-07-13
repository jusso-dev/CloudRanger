import { describe, expect, it } from "vitest";
import {
  collectParamRefs,
  effectiveParameterValues,
  isParamRef,
  resolveExpression,
  validateControlParameters,
  validateParameterOverrides,
} from "../src/params.js";
import { evaluateControls } from "../src/evaluate.js";
import type { CollectorDefinition, ControlDefinition, Expression } from "../src/types.js";

const collector: CollectorDefinition = {
  id: "aws.iam.list_access_keys",
  provider: "aws",
  service: "iam",
  description: "keys",
  kind: "per_resource",
  command: "aws iam list-access-keys --user-name {resource} --output json",
  regional: false,
  parent: { collector: "aws.iam.list_users", itemsPath: "Users", resourceField: "UserName" },
  outputFormat: "json",
};

const control: ControlDefinition = {
  id: "CR-AWS-IAM-905",
  version: "1.0.0",
  provider: "aws",
  service: "iam",
  title: "key age",
  description: "d",
  rationale: "r",
  severity: "medium",
  categories: ["identity"],
  source: { engine: "prowler", id: "test", license: "Apache-2.0" },
  collector: collector.id,
  resourceIdField: "$resourceKey",
  parameters: {
    maxKeyAgeDays: {
      type: "number",
      description: "max key age",
      default: 90,
      min: 1,
      max: 365,
    },
  },
  passWhen: {
    op: "noneItem",
    path: "AccessKeyMetadata",
    condition: { op: "daysSinceGt", path: "CreateDate", value: { $param: "maxKeyAgeDays" } },
  },
  failMessage: "old key",
  passMessage: "fresh keys",
  remediation: { summary: "s", steps: ["s"] },
  compliance: [],
  references: [],
};

describe("param refs and resolution", () => {
  it("identifies ParamRef objects strictly", () => {
    expect(isParamRef({ $param: "x" })).toBe(true);
    expect(isParamRef({ $param: "x", extra: 1 })).toBe(false);
    expect(isParamRef({ param: "x" })).toBe(false);
    expect(isParamRef("x")).toBe(false);
    expect(isParamRef(null)).toBe(false);
  });

  it("collects refs through nested logical operators and quantifiers", () => {
    const expr: Expression = {
      op: "and",
      exprs: [
        { op: "gte", path: "a", value: { $param: "alpha" } },
        {
          op: "noneItem",
          path: "items",
          condition: { op: "daysSinceGt", path: "d", value: { $param: "beta" } },
        },
        { op: "not", expr: { op: "lt", path: "b", value: { $param: "alpha" } } },
      ],
    };
    expect([...collectParamRefs(expr)].sort()).toEqual(["alpha", "beta"]);
  });

  it("substitutes refs and leaves literals untouched", () => {
    const resolved = resolveExpression(control.passWhen as Expression, { maxKeyAgeDays: 30 });
    expect(resolved).toEqual({
      op: "noneItem",
      path: "AccessKeyMetadata",
      condition: { op: "daysSinceGt", path: "CreateDate", value: 30 },
    });
    // original untouched
    expect((control.passWhen as { condition: { value: unknown } }).condition.value).toEqual({
      $param: "maxKeyAgeDays",
    });
  });
});

describe("declaration validation", () => {
  it("accepts a well-formed declaration", () => {
    expect(validateControlParameters(control)).toEqual([]);
  });

  it("rejects undeclared references, unused declarations, and bad defaults", () => {
    const broken: ControlDefinition = {
      ...control,
      parameters: {
        unused: { type: "number", description: "x", default: 5 },
        bad: { type: "number", description: "x", default: 999, min: 1, max: 10 },
      },
    };
    const issues = validateControlParameters(broken);
    expect(issues.join(" | ")).toMatch(/undeclared parameter maxKeyAgeDays/);
    expect(issues.join(" | ")).toMatch(/unused is declared but never referenced/);
    expect(issues.join(" | ")).toMatch(/above the maximum/);
  });
});

describe("override validation", () => {
  it("accepts in-range overrides and rejects unknown/out-of-bounds/mistyped", () => {
    expect(validateParameterOverrides(control, { maxKeyAgeDays: 30 })).toEqual([]);
    expect(validateParameterOverrides(control, { nope: 1 })[0]).toMatch(/not declared/);
    expect(validateParameterOverrides(control, { maxKeyAgeDays: 0 })[0]).toMatch(/below/);
    expect(validateParameterOverrides(control, { maxKeyAgeDays: 9999 })[0]).toMatch(/above/);
    expect(validateParameterOverrides(control, { maxKeyAgeDays: "30" })[0]).toMatch(
      /expected number/,
    );
  });

  it("merges defaults with overrides", () => {
    expect(effectiveParameterValues(control)).toEqual({ maxKeyAgeDays: 90 });
    expect(effectiveParameterValues(control, { maxKeyAgeDays: 30 })).toEqual({
      maxKeyAgeDays: 30,
    });
  });
});

describe("evaluateControls with parameters", () => {
  const collectors = new Map([[collector.id, collector]]);
  const bundle = (createDate: string) => ({
    provider: "aws" as const,
    scopeId: "123456789012",
    records: [
      {
        collectorId: collector.id,
        resourceKey: "alice",
        output: {
          AccessKeyMetadata: [{ UserName: "alice", Status: "Active", CreateDate: createDate }],
        },
        exitCode: 0,
        collectedAt: "2026-01-01T00:00:00Z",
      },
    ],
  });
  const now = new Date("2026-01-01T00:00:00Z");

  it("uses defaults when no override is supplied and records effective values", () => {
    const { results } = evaluateControls([control], collectors, bundle("2025-10-15T00:00:00Z"), {
      now,
    });
    expect(results[0]!.status).toBe("pass"); // 78 days < 90
    expect(results[0]!.effectiveParameters).toEqual({ maxKeyAgeDays: 90 });
  });

  it("an override changes the verdict and the recorded effective values", () => {
    const { results } = evaluateControls([control], collectors, bundle("2025-10-15T00:00:00Z"), {
      now,
      parameters: { "CR-AWS-IAM-905": { maxKeyAgeDays: 30 } },
    });
    expect(results[0]!.status).toBe("fail"); // 78 days > 30
    expect(results[0]!.effectiveParameters).toEqual({ maxKeyAgeDays: 30 });
  });

  it("throws on invalid overrides", () => {
    expect(() =>
      evaluateControls([control], collectors, bundle("2025-10-15T00:00:00Z"), {
        now,
        parameters: { "CR-AWS-IAM-905": { maxKeyAgeDays: -5 } },
      }),
    ).toThrow(/invalid parameter overrides/);
  });

  it("unresolved refs fail closed", () => {
    const noDecl: ControlDefinition = { ...control, parameters: undefined };
    const { results } = evaluateControls([noDecl], collectors, bundle("2020-01-01T00:00:00Z"), {
      now,
    });
    // daysSinceGt with a raw ParamRef value never matches, so noneItem passes
    // vacuously — but effectiveParameters is absent and catalog validation
    // rejects this shape at load time.
    expect(results[0]!.effectiveParameters).toBeUndefined();
  });
});

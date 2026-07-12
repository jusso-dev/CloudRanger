import { describe, expect, it } from "vitest";
import { evaluateExpression, isSafeRegex } from "../src/expr.js";
import type { Expression } from "../src/types.js";

const NOW = new Date("2026-07-12T00:00:00Z");
const ctx = { now: NOW };

const evaluate = (expr: Expression, resource: unknown) => evaluateExpression(expr, resource, ctx);

describe("expression evaluator", () => {
  it("equals with loose CLI-style coercion", () => {
    expect(evaluate({ op: "equals", path: "a", value: true }, { a: true })).toBe(true);
    expect(evaluate({ op: "equals", path: "a", value: true }, { a: "True" })).toBe(true);
    expect(evaluate({ op: "equals", path: "a", value: 1 }, { a: "1" })).toBe(true);
    expect(evaluate({ op: "equals", path: "a", value: true }, { a: false })).toBe(false);
    expect(evaluate({ op: "equals", path: "a", value: true }, {})).toBe(false);
  });

  it("missing data never satisfies positive predicates", () => {
    expect(evaluate({ op: "notEquals", path: "x", value: "y" }, {})).toBe(false);
    expect(evaluate({ op: "gt", path: "x", value: 1 }, {})).toBe(false);
    expect(evaluate({ op: "startsWith", path: "x", value: "a" }, {})).toBe(false);
    expect(evaluate({ op: "in", path: "x", values: ["a"] }, {})).toBe(false);
  });

  it("exists / notExists / isEmpty", () => {
    expect(evaluate({ op: "exists", path: "a.b" }, { a: { b: 0 } })).toBe(true);
    expect(evaluate({ op: "exists", path: "a.b" }, { a: {} })).toBe(false);
    expect(evaluate({ op: "notExists", path: "a.b" }, { a: { b: null } })).toBe(true);
    expect(evaluate({ op: "isEmpty", path: "a" }, { a: [] })).toBe(true);
    expect(evaluate({ op: "isEmpty", path: "a" }, { a: [1] })).toBe(false);
    expect(evaluate({ op: "isEmpty", path: "missing" }, {})).toBe(true);
  });

  it("nested paths and array indexes", () => {
    const resource = { Policy: { Statement: [{ Effect: "Allow" }] } };
    expect(
      evaluate({ op: "equals", path: "Policy.Statement.0.Effect", value: "Allow" }, resource),
    ).toBe(true);
  });

  it("daysSince comparisons", () => {
    const resource = { CreateDate: "2026-01-01T00:00:00Z" };
    expect(evaluate({ op: "daysSinceGt", path: "CreateDate", value: 90 }, resource)).toBe(true);
    expect(evaluate({ op: "daysSinceLt", path: "CreateDate", value: 90 }, resource)).toBe(false);
    expect(evaluate({ op: "daysSinceGt", path: "CreateDate", value: 400 }, resource)).toBe(false);
    expect(evaluate({ op: "daysSinceGt", path: "missing", value: 1 }, {})).toBe(false);
  });

  it("isPublicCidr recognises provider variants", () => {
    for (const v of ["0.0.0.0/0", "::/0", "*", "any", "Internet"]) {
      expect(evaluate({ op: "isPublicCidr", path: "c" }, { c: v })).toBe(true);
    }
    expect(evaluate({ op: "isPublicCidr", path: "c" }, { c: "10.0.0.0/8" })).toBe(false);
    expect(evaluate({ op: "isPublicCidr", path: "c" }, {})).toBe(false);
  });

  it("portIncludes handles ranges, wildcards and absent bounds", () => {
    const sgRule = { FromPort: 20, ToPort: 25 };
    expect(
      evaluate({ op: "portIncludes", fromPath: "FromPort", toPath: "ToPort", value: 22 }, sgRule),
    ).toBe(true);
    expect(
      evaluate({ op: "portIncludes", fromPath: "FromPort", toPath: "ToPort", value: 443 }, sgRule),
    ).toBe(false);
    expect(
      evaluate({ op: "portIncludes", fromPath: "FromPort", toPath: "ToPort", value: 22 }, {}),
    ).toBe(true); // all traffic
    expect(
      evaluate({ op: "portIncludes", fromPath: "p", toPath: "p", value: 22 }, { p: "*" }),
    ).toBe(true);
    expect(
      evaluate(
        { op: "portIncludes", fromPath: "FromPort", toPath: "ToPort", value: 22 },
        { FromPort: -1, ToPort: -1 },
      ),
    ).toBe(true);
    expect(
      evaluate({ op: "portIncludes", fromPath: "p", toPath: "p", value: 22 }, { p: "3389" }),
    ).toBe(false);
  });

  it("portStringIncludes handles Azure/GCP port syntax", () => {
    expect(evaluate({ op: "portStringIncludes", path: "p", value: 22 }, { p: "22" })).toBe(true);
    expect(evaluate({ op: "portStringIncludes", path: "p", value: 22 }, { p: "20-25" })).toBe(true);
    expect(evaluate({ op: "portStringIncludes", path: "p", value: 22 }, { p: "*" })).toBe(true);
    expect(evaluate({ op: "portStringIncludes", path: "p", value: 22 }, { p: 22 })).toBe(true);
    expect(
      evaluate({ op: "portStringIncludes", path: "p", value: 22 }, { p: ["443", "3389"] }),
    ).toBe(false);
    expect(evaluate({ op: "portStringIncludes", path: "p", value: 22 }, { p: ["443", "22"] })).toBe(
      true,
    );
    expect(evaluate({ op: "portStringIncludes", path: "p", value: 22 }, { p: "23" })).toBe(false);
    expect(evaluate({ op: "portStringIncludes", path: "p", value: 22 }, {})).toBe(false);
  });

  it("quantifiers over arrays with relative paths", () => {
    const sg = {
      IpPermissions: [
        { FromPort: 443, ToPort: 443, IpRanges: [{ CidrIp: "0.0.0.0/0" }] },
        { FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "10.0.0.0/8" }] },
      ],
    };
    const sshOpenToWorld: Expression = {
      op: "anyItem",
      path: "IpPermissions",
      condition: {
        op: "and",
        exprs: [
          { op: "portIncludes", fromPath: "FromPort", toPath: "ToPort", value: 22 },
          { op: "anyItem", path: "IpRanges", condition: { op: "isPublicCidr", path: "CidrIp" } },
        ],
      },
    };
    expect(evaluate(sshOpenToWorld, sg)).toBe(false);
    sg.IpPermissions[1]!.IpRanges[0]!.CidrIp = "0.0.0.0/0";
    expect(evaluate(sshOpenToWorld, sg)).toBe(true);
    // noneItem on missing array is vacuously true; anyItem false.
    expect(
      evaluate({ op: "noneItem", path: "nope", condition: { op: "exists", path: "x" } }, {}),
    ).toBe(true);
    expect(
      evaluate({ op: "anyItem", path: "nope", condition: { op: "exists", path: "x" } }, {}),
    ).toBe(false);
  });

  it("boolean composition", () => {
    const expr: Expression = {
      op: "or",
      exprs: [
        { op: "equals", path: "a", value: 1 },
        { op: "not", expr: { op: "exists", path: "b" } },
      ],
    };
    expect(evaluate(expr, { a: 2, b: 1 })).toBe(false);
    expect(evaluate(expr, { a: 1, b: 1 })).toBe(true);
    expect(evaluate(expr, { a: 2 })).toBe(true);
  });

  it("safe regex enforcement", () => {
    expect(isSafeRegex("^arn:aws:iam::\\d{12}:root$")).toBe(true);
    expect(isSafeRegex("(a+)+$")).toBe(false);
    expect(isSafeRegex("\\1")).toBe(false);
    expect(isSafeRegex("a".repeat(300))).toBe(false);
    expect(evaluate({ op: "matches", path: "a", pattern: "(x+)+$" }, { a: "xxxx" })).toBe(false);
  });
});

import { describe, expect, it } from "vitest";
import { reconcileOne } from "../src/reconcile.js";
import { findingFingerprint } from "../src/fingerprint.js";
import type { EvaluationResult } from "../src/types.js";

const result = (status: EvaluationResult["status"]): EvaluationResult => ({
  controlId: "CR-AWS-S3-001",
  controlVersion: "1.0.0",
  provider: "aws",
  service: "s3",
  severity: "high",
  status,
  resourceId: "my-bucket",
  message: "m",
  evidence: {},
  evaluatedAt: "2026-07-12T00:00:00Z",
});

const SCOPE = "123456789012";
const fp = findingFingerprint({
  provider: "aws",
  scopeId: SCOPE,
  controlId: "CR-AWS-S3-001",
  resourceId: "my-bucket",
});

describe("finding lifecycle reconciliation", () => {
  it("first failure creates", () => {
    expect(reconcileOne(SCOPE, result("fail"), undefined).type).toBe("create");
  });

  it("repeat failure recurs, preserving identity", () => {
    const action = reconcileOne(SCOPE, result("fail"), {
      fingerprint: fp,
      state: "open",
      occurrenceCount: 1,
      reopenCount: 0,
    });
    expect(action.type).toBe("recur");
    expect(action.fingerprint).toBe(fp);
  });

  it("pass after failure resolves", () => {
    expect(
      reconcileOne(SCOPE, result("pass"), {
        fingerprint: fp,
        state: "open",
        occurrenceCount: 3,
        reopenCount: 0,
      }).type,
    ).toBe("resolve");
    expect(
      reconcileOne(SCOPE, result("pass"), {
        fingerprint: fp,
        state: "reopened",
        occurrenceCount: 3,
        reopenCount: 1,
      }).type,
    ).toBe("resolve");
  });

  it("failure after resolution reopens", () => {
    expect(
      reconcileOne(SCOPE, result("fail"), {
        fingerprint: fp,
        state: "resolved",
        occurrenceCount: 3,
        reopenCount: 0,
      }).type,
    ).toBe("reopen");
  });

  it("error / not_applicable / not_assessed never resolve an open finding", () => {
    for (const status of ["error", "not_applicable", "not_assessed"] as const) {
      const action = reconcileOne(SCOPE, result(status), {
        fingerprint: fp,
        state: "open",
        occurrenceCount: 1,
        reopenCount: 0,
      });
      expect(action.type).toBe("none");
    }
  });

  it("pass with no prior finding is a no-op", () => {
    expect(reconcileOne(SCOPE, result("pass"), undefined).type).toBe("none");
  });

  it("fingerprint is stable and region-sensitive", () => {
    expect(fp).toBe(
      findingFingerprint({
        provider: "aws",
        scopeId: SCOPE,
        controlId: "CR-AWS-S3-001",
        resourceId: "my-bucket",
      }),
    );
    expect(fp).not.toBe(
      findingFingerprint({
        provider: "aws",
        scopeId: SCOPE,
        controlId: "CR-AWS-S3-001",
        resourceId: "my-bucket",
        region: "us-east-1",
      }),
    );
  });
});

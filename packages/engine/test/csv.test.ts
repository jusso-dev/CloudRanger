import { describe, expect, it } from "vitest";
import { decodeBase64Csv, decodeEvidenceRecord, parseCsv } from "../src/csv.js";
import { evaluateControls } from "../src/evaluate.js";
import type { CollectorDefinition, ControlDefinition, EvidenceRecord } from "../src/types.js";

const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");

describe("parseCsv", () => {
  it("parses a header + rows into objects", () => {
    const { rows, error } = parseCsv("a,b,c\n1,2,3\n4,5,6");
    expect(error).toBeUndefined();
    expect(rows).toEqual([
      { a: "1", b: "2", c: "3" },
      { a: "4", b: "5", c: "6" },
    ]);
  });

  it("handles quoted fields, embedded commas, escaped quotes and CRLF", () => {
    const { rows } = parseCsv('name,desc\r\n"smith, j","says ""hi"""\r\n');
    expect(rows).toEqual([{ name: "smith, j", desc: 'says "hi"' }]);
  });

  it("leaves missing trailing columns undefined and keeps empty fields", () => {
    const { rows } = parseCsv("a,b,c\n1,,3\n1");
    expect(rows?.[0]).toEqual({ a: "1", b: "", c: "3" });
    expect(rows?.[1]).toEqual({ a: "1" });
  });

  it("rejects rows wider than the header", () => {
    expect(parseCsv("a,b\n1,2,3").error).toMatch(/more fields/);
  });

  it("rejects unterminated quotes and empty documents", () => {
    expect(parseCsv('a,b\n"unterminated').error).toMatch(/unterminated/);
    expect(parseCsv("").error).toMatch(/empty/);
  });

  it("ignores a trailing newline", () => {
    const { rows } = parseCsv("a\n1\n");
    expect(rows).toEqual([{ a: "1" }]);
  });
});

describe("decodeBase64Csv", () => {
  it("decodes base64 CSV into rows", () => {
    const { rows, error } = decodeBase64Csv(b64("user,active\nalice,true"));
    expect(error).toBeUndefined();
    expect(rows).toEqual([{ user: "alice", active: "true" }]);
  });

  it("rejects non-string, empty, and non-base64 content", () => {
    expect(decodeBase64Csv(undefined).error).toBeDefined();
    expect(decodeBase64Csv(42).error).toBeDefined();
    expect(decodeBase64Csv("").error).toBeDefined();
    expect(decodeBase64Csv("%%%not-base64%%%").error).toMatch(/base64/);
  });

  it("rejects oversized payloads", () => {
    const big = b64("a".repeat(6_000_000));
    expect(decodeBase64Csv(big).error).toMatch(/exceeds/);
  });
});

const credentialCollector: CollectorDefinition = {
  id: "aws.iam.get_credential_report",
  provider: "aws",
  service: "iam",
  description: "credential report",
  kind: "single",
  command: "aws iam get-credential-report --output json",
  regional: false,
  outputFormat: "json",
  decode: { type: "base64Csv", contentPath: "Content" },
  prepareCommand: "aws iam generate-credential-report",
};

describe("decodeEvidenceRecord", () => {
  const record = (output: unknown): EvidenceRecord => ({
    collectorId: credentialCollector.id,
    output,
    exitCode: 0,
    collectedAt: "2026-01-01T00:00:00Z",
  });

  it("replaces output with decoded rows", () => {
    const decoded = decodeEvidenceRecord(
      credentialCollector,
      record({ Content: b64("user,mfa_active\nalice,true") }),
    );
    expect(decoded.output).toEqual([{ user: "alice", mfa_active: "true" }]);
  });

  it("turns decode failures into error records", () => {
    const decoded = decodeEvidenceRecord(credentialCollector, record({ Content: 7 }));
    expect(decoded.output).toBeNull();
    expect(decoded.errorText).toMatch(/decode/);
  });

  it("passes failed commands through untouched", () => {
    const failed: EvidenceRecord = {
      collectorId: credentialCollector.id,
      output: null,
      errorText: "ReportNotPresent",
      exitCode: 254,
      collectedAt: "2026-01-01T00:00:00Z",
    };
    expect(decodeEvidenceRecord(credentialCollector, failed)).toBe(failed);
  });
});

describe("evaluateControls with a decoded CSV collector", () => {
  const control: ControlDefinition = {
    id: "CR-AWS-IAM-900",
    version: "1.0.0",
    provider: "aws",
    service: "iam",
    title: "MFA active for all users",
    description: "d",
    rationale: "r",
    severity: "high",
    categories: ["identity"],
    source: { engine: "prowler", id: "test_check", license: "Apache-2.0" },
    collector: credentialCollector.id,
    resourcesPath: "$",
    resourceIdField: "arn",
    resourceNameField: "user",
    passWhen: { op: "equals", path: "mfa_active", value: "true" },
    failMessage: "no mfa",
    passMessage: "mfa on",
    remediation: { summary: "s", steps: ["s"] },
    compliance: [],
    references: [],
  };
  const collectors = new Map([[credentialCollector.id, credentialCollector]]);
  const csv = [
    "user,arn,mfa_active",
    "alice,arn:aws:iam::123456789012:user/alice,true",
    "bob,arn:aws:iam::123456789012:user/bob,false",
  ].join("\n");

  it("splits decoded rows into per-user resources", () => {
    const { results } = evaluateControls(
      [control],
      collectors,
      {
        provider: "aws",
        scopeId: "123456789012",
        records: [
          {
            collectorId: credentialCollector.id,
            output: { Content: b64(csv), ReportFormat: "text/csv" },
            exitCode: 0,
            collectedAt: "2026-01-01T00:00:00Z",
          },
        ],
      },
      { now: new Date("2026-01-01T00:00:00Z") },
    );
    expect(results).toHaveLength(2);
    const byId = new Map(results.map((r) => [r.resourceId, r.status]));
    expect(byId.get("arn:aws:iam::123456789012:user/alice")).toBe("pass");
    expect(byId.get("arn:aws:iam::123456789012:user/bob")).toBe("fail");
  });

  it("surfaces decode failure as an error result", () => {
    const { results } = evaluateControls(
      [control],
      collectors,
      {
        provider: "aws",
        scopeId: "123456789012",
        records: [
          {
            collectorId: credentialCollector.id,
            output: { Content: "%%%" },
            exitCode: 0,
            collectedAt: "2026-01-01T00:00:00Z",
          },
        ],
      },
      { now: new Date("2026-01-01T00:00:00Z") },
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.status).toBe("error");
    expect(results[0]!.message).toMatch(/decode/);
  });
});

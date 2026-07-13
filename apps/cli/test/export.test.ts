import { describe, expect, it } from "vitest";
import type { FindingRow } from "@cloudranger/db";
import { findingsToCsv, findingsToJsonl, findingsToSarif } from "../src/export.js";

const finding = (overrides: Partial<FindingRow> = {}): FindingRow => ({
  fingerprint: "abc123",
  provider: "aws",
  scopeId: "123456789012",
  controlId: "CR-AWS-S3-001",
  controlVersion: "1.0.0",
  severity: "high",
  service: "s3",
  resourceId: "my-bucket",
  state: "open",
  workflowState: "new",
  message: 'Bucket "x", public',
  firstSeenAt: "2026-07-01T00:00:00Z",
  lastSeenAt: "2026-07-13T00:00:00Z",
  occurrenceCount: 3,
  reopenCount: 0,
  lastScanId: "scan-1",
  ...overrides,
});

describe("findings export", () => {
  it("emits stable CSV with quoting for embedded commas and quotes", () => {
    const csv = findingsToCsv([finding()]);
    const [header, row] = csv.trim().split("\n");
    expect(header!.startsWith("fingerprint,provider,scopeId,controlId")).toBe(true);
    expect(row).toContain('"Bucket ""x"", public"');
    expect(row!.split(",")[0]).toBe("abc123");
  });

  it("emits one JSON object per line", () => {
    const jsonl = findingsToJsonl([finding(), finding({ fingerprint: "def456" })]);
    const lines = jsonl.trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[1]!).fingerprint).toBe("def456");
  });

  it("emits valid SARIF 2.1.0 with rules, levels, and fingerprints", () => {
    const sarif = JSON.parse(
      findingsToSarif(
        [finding(), finding({ severity: "low", controlId: "CR-AWS-S3-002" })],
        new Map([
          [
            "CR-AWS-S3-001",
            { title: "Block public access", description: "d", references: ["https://x"] },
          ],
        ]),
      ),
    );
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-schema-2.1.0");
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("CloudRanger");
    expect(run.tool.driver.rules.map((r: any) => r.id)).toEqual(["CR-AWS-S3-001", "CR-AWS-S3-002"]);
    expect(run.tool.driver.rules[0].helpUri).toBe("https://x");
    const [high, low] = run.results;
    expect(high.level).toBe("error");
    expect(low.level).toBe("note");
    expect(high.ruleIndex).toBe(0);
    expect(high.partialFingerprints.cloudRangerFinding).toBe("abc123");
    expect(high.locations[0].logicalLocations[0].fullyQualifiedName).toBe(
      "aws/123456789012/s3/my-bucket",
    );
  });
});

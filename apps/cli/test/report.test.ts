import { describe, expect, it } from "vitest";
import { renderExecutiveReport } from "../src/report.js";

describe("executive report", () => {
  it("includes historical trends and integrity metadata", () => {
    const html = renderExecutiveReport({
      generatedAt: "2026-07-13T00:00:00Z",
      windowDays: 30,
      filters: { provider: "aws", scopeId: "123" },
      openFindingsBySeverity: { high: 1 },
      openFindingsByService: [{ provider: "aws", service: "s3", count: 1 }],
      topFailingControls: [{ controlId: "CR-AWS-S3-001", severity: "high", count: 1 }],
      newFindingsInWindow: 1,
      resolvedFindingsInWindow: 0,
      currentlyReopened: 0,
      riskAccepted: 0,
      recentScans: [
        {
          id: "scan-2",
          provider: "aws",
          scopeId: "123",
          status: "evaluated",
          createdAt: "2026-07-13T00:00:00Z",
          summary: { coverageRatio: 1 },
        },
      ],
      scanTrends: [
        {
          scanId: "scan-1",
          evaluatedAt: "2026-07-12T00:00:00Z",
          coverageRatio: 0.8,
          pass: 8,
          fail: 2,
          error: 0,
          findingsCreated: 2,
          findingsRecurred: 0,
          findingsResolved: 0,
          findingsReopened: 0,
          findingsAccepted: 0,
        },
        {
          scanId: "scan-2",
          evaluatedAt: "2026-07-13T00:00:00Z",
          coverageRatio: 1,
          pass: 9,
          fail: 1,
          error: 0,
          findingsCreated: 0,
          findingsRecurred: 1,
          findingsResolved: 1,
          findingsReopened: 0,
          findingsAccepted: 1,
        },
      ],
    });
    expect(html).toContain("Posture trend");
    expect(html).toContain("Finding activity");
    expect(html).toContain("Recurring");
    expect(html).toContain("Accepted");
    expect(html).toContain("2026-07-12");
    expect(html).toContain("Latest scan: scan-2");
    expect(html).toMatch(/Integrity SHA-256: [a-f0-9]{64}/);
  });
});

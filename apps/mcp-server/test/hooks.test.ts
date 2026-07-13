import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildScanDigest, digestText, listDestinations, sendToDestination } from "../src/hooks.js";
import type { ScanRow } from "@cloudranger/db";

const scan: ScanRow = {
  id: "scan-1",
  provider: "aws",
  scopeId: "123456789012",
  regions: ["ap-southeast-2"],
  controlIds: ["CR-AWS-S3-001"],
  status: "evaluated",
  createdAt: "2026-07-13T00:00:00Z",
  evaluatedAt: "2026-07-13T00:05:00Z",
  summary: {
    pass: 10,
    fail: 2,
    error: 0,
    notApplicable: 1,
    coverageRatio: 1,
    findingsCreated: 2,
    findingsRecurred: 0,
    findingsResolved: 1,
    findingsReopened: 0,
  },
};
const finding = {
  controlId: "CR-AWS-S3-001",
  severity: "high",
  resourceId: "my-bucket",
  state: "open",
};

describe("notification hooks", () => {
  it("parses the destination allow-list and ignores malformed entries", () => {
    const destinations = listDestinations({
      CLOUDRANGER_SLACK_WEBHOOK_URL: "https://hooks.slack.example/T/B/x",
      CLOUDRANGER_NOTIFY_WEBHOOKS:
        "soc=https://soc.example/hook, bad entry, insecure=http://nope.example, ops=https://ops.example/x",
    });
    expect(destinations.map((d) => `${d.kind}:${d.name}`)).toEqual([
      "slack:slack",
      "webhook:soc",
      "webhook:ops",
    ]);
    expect(listDestinations({})).toEqual([]);
  });

  it("builds digests with finding references and no evidence", () => {
    const digest = buildScanDigest(scan, [
      { ...finding, evidence: { secret: "SHOULD-NEVER-APPEAR" } } as never,
    ]);
    expect(JSON.stringify(digest)).not.toContain("SHOULD-NEVER-APPEAR");
    expect(digest.topFindings[0]).toEqual(finding);
    expect(digestText(digest)).toContain("pass=10 fail=2");
  });

  it("sends slack text and HMAC-signed webhook JSON", async () => {
    const calls: Array<{ url: string; body: string; headers: Record<string, string> }> = [];
    const fetchImpl = (async (url: string, init: RequestInit) => {
      calls.push({
        url: url as string,
        body: init.body as string,
        headers: init.headers as Record<string, string>,
      });
      return { ok: true, status: 200 } as Response;
    }) as unknown as typeof fetch;
    const digest = buildScanDigest(scan, [finding]);

    const slack = await sendToDestination(
      { name: "slack", kind: "slack", url: "https://hooks.slack.example/x" },
      digest,
      { fetchImpl },
    );
    expect(slack.signed).toBe(false);
    expect(JSON.parse(calls[0]!.body)).toHaveProperty("text");

    const webhook = await sendToDestination(
      { name: "soc", kind: "webhook", url: "https://soc.example/hook" },
      digest,
      { fetchImpl, hmacSecret: "shh" },
    );
    expect(webhook.signed).toBe(true);
    const expected = "sha256=" + createHmac("sha256", "shh").update(calls[1]!.body).digest("hex");
    expect(calls[1]!.headers["x-cloudranger-signature"]).toBe(expected);
    expect(JSON.parse(calls[1]!.body).event).toBe("cloudranger.scan_digest");
  });

  it("surfaces delivery failures", async () => {
    const fetchImpl = (async () => ({ ok: false, status: 500 })) as unknown as typeof fetch;
    await expect(
      sendToDestination(
        { name: "soc", kind: "webhook", url: "https://soc.example/hook" },
        buildScanDigest(scan, []),
        { fetchImpl },
      ),
    ).rejects.toThrow(/HTTP 500/);
  });
});

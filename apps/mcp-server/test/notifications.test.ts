import { afterEach, describe, expect, it, vi } from "vitest";
import { createNotificationSender, notificationText } from "../src/notifications.js";
import type { ScanComparison } from "@cloudranger/db";

const comparison: ScanComparison = {
  baseline: {
    scanId: "before",
    provider: "aws",
    scopeId: "123",
    evaluatedAt: "2026-01-01T00:00:00Z",
  },
  current: {
    scanId: "after",
    provider: "aws",
    scopeId: "123",
    evaluatedAt: "2026-01-02T00:00:00Z",
  },
  coverage: {
    baseline: 1,
    current: 0.9,
    delta: -0.1,
    baselineEvaluated: 10,
    currentEvaluated: 9,
    baselineRequested: 10,
    currentRequested: 10,
  },
  controlChanges: [
    {
      controlId: "CR-AWS-S3-001",
      resourceId: "bucket-a",
      baseline: "pass",
      current: "fail",
      message: "Public access",
    },
  ],
  findingEvents: { created: 1 },
};

afterEach(() => {
  delete process.env.CLOUDRANGER_SLACK_WEBHOOK_URL;
  delete process.env.CLOUDRANGER_TEAMS_WEBHOOK_URL;
  delete process.env.CLOUDRANGER_SMTP_HOST;
});

describe("notifications", () => {
  it("renders a useful comparison message", () => {
    const text = notificationText(comparison);
    expect(text).toContain("AWS 123");
    expect(text).toContain("pass -> fail");
    expect(text).toContain("Coverage: 100% -> 90%");
  });

  it("delivers enabled channels and reports delivery failures", async () => {
    process.env.CLOUDRANGER_SLACK_WEBHOOK_URL = "https://slack.invalid/webhook";
    process.env.CLOUDRANGER_TEAMS_WEBHOOK_URL = "https://teams.invalid/webhook";
    process.env.CLOUDRANGER_SMTP_HOST = "smtp.invalid";
    const fetchImpl = vi.fn(async (url: string) => ({
      ok: url.includes("slack"),
      status: url.includes("slack") ? 200 : 500,
    })) as unknown as typeof fetch;
    const sendMail = vi.fn(async () => undefined);
    const result = await createNotificationSender({ fetchImpl, sendMail })(comparison);
    expect(result.enabled).toEqual(["slack", "teams", "email"]);
    expect(result.sent).toEqual(["slack", "email"]);
    expect(result.errors).toEqual([{ channel: "teams", error: "HTTP 500" }]);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(sendMail).toHaveBeenCalledOnce();
  });
});

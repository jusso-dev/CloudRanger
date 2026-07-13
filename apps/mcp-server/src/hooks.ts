import { createHmac } from "node:crypto";
import type { ScanRow, ScanSummary } from "@cloudranger/db";

/**
 * Agent-driven notification hooks. The agent chooses a destination by NAME
 * from an operator-configured allow-list — destination URLs never come from
 * the agent, so there is no SSRF surface by construction. Payloads are built
 * server-side from scan summaries and finding references only; raw evidence
 * never leaves the store through this path. Webhook deliveries are
 * HMAC-signed when a secret is configured.
 */

export interface NotifyDestination {
  name: string;
  kind: "slack" | "webhook";
  /** Never exposed to the agent. */
  url: string;
}

/**
 * Destinations come from the environment:
 *  - CLOUDRANGER_SLACK_WEBHOOK_URL → destination "slack" (Slack text payload)
 *  - CLOUDRANGER_NOTIFY_WEBHOOKS   → "name=https://…,other=https://…"
 */
export function listDestinations(env: NodeJS.ProcessEnv): NotifyDestination[] {
  const destinations: NotifyDestination[] = [];
  if (env.CLOUDRANGER_SLACK_WEBHOOK_URL) {
    destinations.push({ name: "slack", kind: "slack", url: env.CLOUDRANGER_SLACK_WEBHOOK_URL });
  }
  for (const entry of (env.CLOUDRANGER_NOTIFY_WEBHOOKS ?? "").split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const name = trimmed.slice(0, eq).trim();
    const url = trimmed.slice(eq + 1).trim();
    if (!/^[a-z0-9-]{1,64}$/.test(name) || !/^https:\/\//.test(url)) continue;
    destinations.push({ name, kind: "webhook", url });
  }
  return destinations;
}

export interface ScanDigest {
  event: "cloudranger.scan_digest";
  provider: string;
  scopeId: string;
  scanId: string;
  evaluatedAt?: string;
  summary?: ScanSummary;
  topFindings: Array<{
    controlId: string;
    severity: string;
    resourceId: string;
    state: string;
  }>;
  note: string;
}

/** Digest built from scan metadata + finding references. No evidence. */
export function buildScanDigest(
  scan: ScanRow,
  findings: Array<{ controlId: string; severity: string; resourceId: string; state: string }>,
): ScanDigest {
  return {
    event: "cloudranger.scan_digest",
    provider: scan.provider,
    scopeId: scan.scopeId,
    scanId: scan.id,
    evaluatedAt: scan.evaluatedAt,
    summary: scan.summary,
    topFindings: findings.slice(0, 20).map(({ controlId, severity, resourceId, state }) => ({
      controlId,
      severity,
      resourceId,
      state,
    })),
    note: "Summary and finding references only; evidence is never included in notifications.",
  };
}

export function digestText(digest: ScanDigest): string {
  const summary = digest.summary;
  const lines = [
    `CloudRanger scan digest: ${digest.provider.toUpperCase()} ${digest.scopeId}`,
    `Scan ${digest.scanId} (${digest.evaluatedAt ?? "not evaluated"})`,
    summary
      ? `pass=${summary.pass} fail=${summary.fail} error=${summary.error} coverage=${Math.round(summary.coverageRatio * 100)}%`
      : "no summary available",
    summary
      ? `findings: +${summary.findingsCreated} new, ${summary.findingsResolved} resolved, ${summary.findingsReopened} reopened`
      : "",
    ...digest.topFindings
      .slice(0, 10)
      .map((finding) => `- [${finding.severity}] ${finding.controlId} ${finding.resourceId}`),
  ];
  return lines.filter(Boolean).join("\n");
}

export interface SendResult {
  destination: string;
  kind: "slack" | "webhook";
  status: number;
  signed: boolean;
}

export async function sendToDestination(
  destination: NotifyDestination,
  digest: ScanDigest,
  options: { fetchImpl?: typeof fetch; hmacSecret?: string } = {},
): Promise<SendResult> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const body =
    destination.kind === "slack"
      ? JSON.stringify({ text: digestText(digest) })
      : JSON.stringify(digest);
  const headers: Record<string, string> = { "content-type": "application/json" };
  let signed = false;
  if (destination.kind === "webhook" && options.hmacSecret) {
    headers["x-cloudranger-signature"] =
      "sha256=" + createHmac("sha256", options.hmacSecret).update(body).digest("hex");
    signed = true;
  }
  const response = await fetchImpl(destination.url, { method: "POST", headers, body });
  if (!response.ok) {
    throw new Error(`delivery to ${destination.name} failed: HTTP ${response.status}`);
  }
  return { destination: destination.name, kind: destination.kind, status: response.status, signed };
}

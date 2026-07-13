import nodemailer from "nodemailer";
import type { ScanComparison } from "@cloudranger/db";

export interface NotificationResult {
  enabled: string[];
  sent: string[];
  errors: Array<{ channel: string; error: string }>;
}

export interface NotificationDeps {
  fetchImpl?: typeof fetch;
  sendMail?: (message: { subject: string; text: string }) => Promise<void>;
}

const transitionCount = (comparison: ScanComparison) =>
  Object.values(comparison.findingEvents).reduce((total, count) => total + count, 0);

export function notificationText(comparison: ScanComparison): string {
  const { baseline, current, coverage, controlChanges, findingEvents } = comparison;
  const lines = [
    `CloudRanger posture change: ${current.provider.toUpperCase()} ${current.scopeId}`,
    `Baseline: ${baseline.scanId} (${baseline.evaluatedAt ?? "unknown time"})`,
    `Current: ${current.scanId} (${current.evaluatedAt ?? "unknown time"})`,
    `Coverage: ${Math.round(coverage.baseline * 100)}% -> ${Math.round(coverage.current * 100)}% (${coverage.delta >= 0 ? "+" : ""}${Math.round(coverage.delta * 100)} points)`,
    `Control status changes: ${controlChanges.length}`,
    `Finding events: ${
      Object.entries(findingEvents)
        .map(([event, count]) => `${event}=${count}`)
        .join(", ") || "none"
    }`,
  ];
  for (const change of controlChanges.slice(0, 10)) {
    lines.push(
      `- ${change.controlId} ${change.resourceId}: ${change.baseline} -> ${change.current}`,
    );
  }
  if (controlChanges.length > 10) lines.push(`- ...and ${controlChanges.length - 10} more changes`);
  return lines.join("\n");
}

export function createNotificationSender(deps: NotificationDeps = {}) {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const sendMail =
    deps.sendMail ??
    (async (message: { subject: string; text: string }) => {
      const host = process.env.CLOUDRANGER_SMTP_HOST;
      if (!host) throw new Error("CLOUDRANGER_SMTP_HOST is not configured");
      const transporter = nodemailer.createTransport({
        host,
        port: Number(process.env.CLOUDRANGER_SMTP_PORT ?? "587"),
        secure: process.env.CLOUDRANGER_SMTP_SECURE === "true",
        auth: process.env.CLOUDRANGER_SMTP_USER
          ? { user: process.env.CLOUDRANGER_SMTP_USER, pass: process.env.CLOUDRANGER_SMTP_PASSWORD }
          : undefined,
      });
      const from = process.env.CLOUDRANGER_SMTP_FROM;
      const to = process.env.CLOUDRANGER_SMTP_TO;
      if (!from || !to)
        throw new Error("CLOUDRANGER_SMTP_FROM and CLOUDRANGER_SMTP_TO are required");
      await transporter.sendMail({ from, to, subject: message.subject, text: message.text });
    });

  return async (comparison: ScanComparison): Promise<NotificationResult> => {
    const result: NotificationResult = { enabled: [], sent: [], errors: [] };
    if (transitionCount(comparison) === 0 && comparison.controlChanges.length === 0) return result;
    const text = notificationText(comparison);
    const subject = `CloudRanger posture change: ${comparison.current.provider.toUpperCase()} ${comparison.current.scopeId}`;
    const channels: Array<{ name: string; url?: string }> = [
      { name: "slack", url: process.env.CLOUDRANGER_SLACK_WEBHOOK_URL },
      { name: "teams", url: process.env.CLOUDRANGER_TEAMS_WEBHOOK_URL },
    ];
    for (const channel of channels) {
      if (!channel.url) continue;
      result.enabled.push(channel.name);
      try {
        const response = await fetchImpl(channel.url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ text }),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        result.sent.push(channel.name);
      } catch (error) {
        result.errors.push({
          channel: channel.name,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
    if (process.env.CLOUDRANGER_SMTP_HOST) {
      result.enabled.push("email");
      try {
        await sendMail({ subject, text });
        result.sent.push("email");
      } catch (error) {
        result.errors.push({
          channel: "email",
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
    return result;
  };
}

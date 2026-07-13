import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

type ReportData = {
  generatedAt: string;
  windowDays: number;
  filters: { provider?: string; scopeId?: string };
  openFindingsBySeverity: Record<string, number>;
  openFindingsByService: Array<{ provider: string; service: string; count: number }>;
  topFailingControls: Array<{
    controlId: string;
    severity: string;
    count: number;
    title?: string;
    description?: string;
  }>;
  newFindingsInWindow: number;
  resolvedFindingsInWindow: number;
  currentlyReopened: number;
  riskAccepted: number;
  recentScans: Array<{
    provider: string;
    scopeId: string;
    status: string;
    createdAt: string;
    summary?: { coverageRatio?: number };
  }>;
  comparison?: {
    coverage: { baseline: number; current: number; delta: number };
    controlChanges: Array<{
      controlId: string;
      resourceId: string;
      baseline: string;
      current: string;
    }>;
    findingEvents: Record<string, number>;
  };
};

const severityOrder = ["critical", "high", "medium", "low", "informational"];
const escape = (value: unknown) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
const count = (report: ReportData, severity: string) =>
  report.openFindingsBySeverity[severity] ?? 0;

export function renderExecutiveReport(report: ReportData): string {
  const open = severityOrder.reduce((total, severity) => total + count(report, severity), 0);
  const latest = report.recentScans[0];
  const scope = report.filters.scopeId ?? "All scanned scopes";
  const provider = report.filters.provider?.toUpperCase() ?? "MULTI-CLOUD";
  const severityCards = severityOrder
    .map(
      (severity) =>
        `<div class="severity ${severity}"><span>${severity}</span><strong>${count(report, severity)}</strong></div>`,
    )
    .join("");
  const services =
    report.openFindingsByService
      .slice(0, 10)
      .map(
        (item) =>
          `<tr><td>${escape(item.provider.toUpperCase())}</td><td>${escape(item.service)}</td><td>${item.count}</td></tr>`,
      )
      .join("") || '<tr><td colspan="3">No open findings.</td></tr>';
  const controls =
    report.topFailingControls
      .slice(0, 10)
      .map(
        (item) =>
          `<tr><td><strong>${escape(item.title ?? item.controlId)}</strong><br><span class="control-id">${escape(item.controlId)}</span><br><span class="description">${escape(item.description ?? "Security control requires review.")}</span></td><td><span class="badge ${escape(item.severity)}">${escape(item.severity)}</span></td><td>${item.count}</td></tr>`,
      )
      .join("") || '<tr><td colspan="3">No open findings.</td></tr>';
  const coverage =
    latest?.summary?.coverageRatio === undefined
      ? "No completed scan available"
      : `${Math.round(latest.summary.coverageRatio * 100)}%`;
  const comparison = report.comparison
    ? `<h2>Change since previous scan</h2><div class="change"><strong>${report.comparison.controlChanges.length}</strong> control status changes &nbsp; <strong>${Math.round(report.comparison.coverage.delta * 100)} points</strong> coverage movement &nbsp; ${escape(
        Object.entries(report.comparison.findingEvents)
          .map(([key, value]) => `${key}: ${value}`)
          .join(" | ") || "No finding lifecycle changes",
      )}</div>`
    : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>CloudRanger Executive Security Report</title><style>
@page{size:A4;margin:15mm}*{box-sizing:border-box}body{font-family:Arial,sans-serif;color:#172033;margin:0;font-size:11px}h1,h2,p{margin:0}.hero{background:#102a43;color:#fff;padding:26px 28px;border-radius:10px}.eyebrow{color:#89c2d9;font-weight:700;letter-spacing:1px;font-size:10px}.hero h1{font-size:27px;margin:8px 0}.hero p{color:#d9e2ec}.meta{display:flex;gap:22px;margin-top:18px;font-size:10px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:18px 0}.card{border:1px solid #d9e2ec;border-radius:8px;padding:13px;background:#fff}.card .label{color:#627d98;text-transform:uppercase;font-size:9px;font-weight:700}.card strong{font-size:25px;display:block;margin-top:6px}.severity-row{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin:14px 0 20px}.severity{border-radius:7px;padding:10px;color:#fff;text-transform:uppercase;font-size:9px;font-weight:bold}.severity strong{display:block;font-size:21px;margin-top:4px}.critical{background:#9b1c1c}.high{background:#c05621}.medium{background:#b7791f}.low{background:#2b6cb0}.informational{background:#4a5568}h2{font-size:15px;margin:20px 0 8px;color:#102a43}table{width:100%;border-collapse:collapse;margin-bottom:14px}th{text-align:left;background:#f0f4f8;color:#486581;text-transform:uppercase;font-size:9px;padding:8px}td{padding:8px;border-bottom:1px solid #d9e2ec}.badge{border-radius:10px;color:#fff;font-size:9px;padding:3px 7px;text-transform:uppercase}.control-id{font-family:monospace;color:#627d98;font-size:9px}.description{color:#486581;font-size:10px}.note{padding:12px;border-left:4px solid #d69e2e;background:#fffaeb;color:#744210;line-height:1.45}.footer{margin-top:20px;color:#829ab1;font-size:9px;border-top:1px solid #d9e2ec;padding-top:8px}
</style></head><body><section class="hero"><div class="eyebrow">CLOUDRANGER | ${escape(provider)}</div><h1>Executive Security Posture Report</h1><p>${escape(scope)} - ${report.windowDays}-day reporting window</p><div class="meta"><span>Generated ${escape(new Date(report.generatedAt).toUTCString())}</span><span>Latest scan coverage: ${escape(coverage)}</span></div></section><section class="grid"><div class="card"><span class="label">Open findings</span><strong>${open}</strong></div><div class="card"><span class="label">New in window</span><strong>${report.newFindingsInWindow}</strong></div><div class="card"><span class="label">Resolved in window</span><strong>${report.resolvedFindingsInWindow}</strong></div><div class="card"><span class="label">Reopened / accepted</span><strong>${report.currentlyReopened} / ${report.riskAccepted}</strong></div></section>${comparison}<h2>Open findings by severity</h2><section class="severity-row">${severityCards}</section><div class="note"><strong>Coverage caveat:</strong> coverage is controls evaluated divided by controls requested. Missing or errored evidence is never treated as passing; the report must be read alongside the latest scan coverage figure.</div><h2>Services with open findings</h2><table><thead><tr><th>Provider</th><th>Service</th><th>Open findings</th></tr></thead><tbody>${services}</tbody></table><h2>Top failing controls</h2><table><thead><tr><th>Control</th><th>Severity</th><th>Open findings</th></tr></thead><tbody>${controls}</tbody></table><div class="footer">CloudRanger is a deterministic local-first CSPM. This report is a posture summary, not a compliance certification.</div></body></html>`;
}

export function writeHtmlReport(path: string, report: ReportData): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, renderExecutiveReport(report));
}

export function writePdfReport(htmlPath: string, pdfPath: string): void {
  mkdirSync(dirname(pdfPath), { recursive: true });
  execFileSync("weasyprint", [htmlPath, pdfPath], { stdio: "inherit" });
}

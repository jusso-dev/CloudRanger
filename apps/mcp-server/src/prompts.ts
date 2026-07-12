import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const user = (text: string) => ({
  messages: [{ role: "user" as const, content: { type: "text" as const, text } }],
});

export function registerPrompts(server: McpServer): void {
  server.registerPrompt(
    "run_full_scan",
    {
      title: "Run a full posture scan",
      description: "Guided end-to-end scan of one cloud scope",
      argsSchema: {
        provider: z.string().describe("aws | azure | gcp"),
        scopeId: z.string().describe("account / subscription / project ID"),
        regions: z.string().optional().describe("comma-separated AWS regions"),
      },
    },
    ({ provider, scopeId, regions }) =>
      user(`Run a full CloudRanger posture scan.

Provider: ${provider}
Scope: ${scopeId}
${regions ? `Regions: ${regions}` : ""}

Steps:
1. Read cloudranger://guides/workflow if you have not already.
2. Verify CLI authentication matches the scope (sts get-caller-identity / az account show / gcloud config get-value project). If it does not match, stop and tell the operator — do not scan the wrong scope.
3. Call scan_start and execute every plan step exactly as written. Run parent steps before per_resource steps. Never modify a command; never run anything mutating.
4. Submit ALL outputs via evidence_submit, including failed commands with their exact error text and exit codes.
5. Call scan_evaluate and review the summary and coverage.
6. Report: new/recurring/resolved/reopened findings, worst-severity items first, and an explicit list of coverage gaps (controls not assessed and why). Never present unassessed controls as passing.`),
  );

  server.registerPrompt(
    "daily_security_review",
    {
      title: "Daily cloud security review",
      description: "Review current posture, deltas and hygiene from persisted findings",
      argsSchema: {},
    },
    () =>
      user(`Perform a daily cloud security review using CloudRanger's persisted data (no new scan required unless stale).

1. scan_list — check when each scope was last scanned. Flag scopes with no scan in >24h as stale and offer to re-scan.
2. report_data (sinceDays: 1) — new, resolved and reopened findings in the last day.
3. findings_search { state: ["open","reopened"], severity: ["critical","high"] } — review each: is it new, recurring, or reopened? Reopened findings deserve special attention (regression).
4. findings_search { workflowState: ["risk_accepted"] } — flag any with expired or missing expiresAt.
5. Summarise: top actions (max 5, prioritised), posture deltas, coverage gaps and stale scopes. Cite finding fingerprints so items are traceable. Distinguish engine facts from your recommendations.`),
  );

  server.registerPrompt(
    "executive_brief",
    {
      title: "Executive posture brief",
      description: "Plain-language posture report for executives from repeatable metrics",
      argsSchema: {
        periodDays: z.string().optional().describe("reporting window in days, default 30"),
      },
    },
    ({ periodDays }) =>
      user(`Write an executive cloud security posture brief covering the last ${periodDays ?? "30"} days.

1. Pull numbers ONLY from report_data (sinceDays: ${periodDays ?? "30"}) so the report is repeatable — do not hand-count findings.
2. Structure:
   - Overall posture in one paragraph, plain language, no jargon.
   - What changed: new / resolved / reopened counts and what drove them.
   - Material risks: top failing controls translated into business impact (data exposure, service disruption, compliance exposure) — not tool output.
   - Risk acceptances currently in force and any expiring.
   - Coverage limitations: which scopes/controls were not assessed. Say so plainly; never imply full coverage.
   - Decisions needed from leadership, if any.
3. Keep it under a page. Numbers must match report_data exactly. Do not claim compliance certification from automated checks.`),
  );

  server.registerPrompt(
    "investigate_finding",
    {
      title: "Investigate a finding",
      description: "Deep-dive one finding with evidence, history and safe validation",
      argsSchema: { fingerprint: z.string().describe("finding fingerprint from findings_search") },
    },
    ({ fingerprint }) =>
      user(`Investigate CloudRanger finding ${fingerprint}.

1. findings_get — read the evidence, control rationale, lifecycle history (reopen count matters: regressions suggest process failure, not just misconfiguration).
2. catalog_get_control for the control — note the verifyCommand.
3. Optionally run the control's read-only verifyCommand to confirm current live state. Run nothing else, and nothing mutating.
4. Assess: is the finding still accurate? What is the realistic attack path? What nearby configuration should also be checked (use findings_search for the same resource/service)?
5. Produce: (a) a technical explanation with the exact evidence values, (b) a plain-language risk statement, (c) a remediation plan for the OPERATOR to execute — you must not execute changes — including validation and rollback steps, (d) a recommendation: fix / accept risk (with justification and expiry) / false positive (with reason).
6. Record your conclusion with findings_comment. If the operator makes a risk decision, record it with findings_set_status including their reason.
Clearly separate deterministic engine results from your inference throughout.`),
  );

  server.registerPrompt(
    "remediation_plan",
    {
      title: "Draft a remediation plan",
      description: "Group open findings into a safe, sequenced remediation plan (no execution)",
      argsSchema: {
        provider: z.string().optional().describe("aws | azure | gcp"),
        severity: z.string().optional().describe("minimum severity, default high"),
      },
    },
    ({ provider, severity }) =>
      user(`Draft a remediation plan for open CloudRanger findings${provider ? ` on ${provider}` : ""} (severity ${severity ?? "high"} and above). You must NOT execute any changes — this is a plan for the human operator.

1. findings_search { state: ["open","reopened"] } filtered accordingly; exclude risk_accepted and false_positive workflow states.
2. Group by root cause (e.g. one public-access misconfiguration pattern across many buckets is one work item), not by individual resource.
3. For each group: affected resources, the control's remediation steps (from catalog_get_control), change risk (availability / data loss), suggested order, pre-change validation, and the read-only verifyCommand to confirm success afterwards.
4. Sequence: quick low-risk wins first, then changes needing maintenance windows, then structural work.
5. End with: after operator changes are applied, re-run the affected controls via a targeted scan (scan_start with controlIds) so findings resolve through verified passing evaluations — never mark things resolved manually.`),
  );
}

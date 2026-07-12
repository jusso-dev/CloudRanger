export const SERVER_INSTRUCTIONS = `CloudRanger is a local-first cloud security posture management (CSPM) engine.
You (the agent) are the collection layer: CloudRanger tells you exactly which
read-only aws / az / gcloud CLI commands to run, you run them in your own
shell with the operator's credentials and submit the JSON output back. The
deterministic rule engine — never you — decides whether each control passes
or fails.

Core workflow:
1. scan_start — declare provider + scope (AWS account, Azure subscription,
   GCP project) and optionally regions/services/controls. Returns a scan ID
   and a collection plan of exact commands.
2. Run each plan step's command EXACTLY as given. Never modify commands,
   never substitute your own, never run anything mutating. For per_resource
   steps, iterate the parent step's output as instructed.
3. evidence_submit — submit each command's parsed JSON output. When a command
   fails, submit the exact stderr text and exit code instead of omitting it;
   coverage accounting depends on failed commands being reported.
4. scan_evaluate — the engine evaluates all controls, reconciles the finding
   lifecycle (new / recurring / resolved / reopened) and returns a summary
   with coverage.
5. Query findings_search / findings_get / report_data to investigate and
   report.

Safety rules (non-negotiable):
- Run only the read-only commands CloudRanger provides in a plan, plus the
  read-only verifyCommand attached to controls. All are list/describe/get/show.
- Never run create/update/delete/set/put commands on behalf of this server.
  Remediation is performed by the human operator; you may draft plans.
- Never submit or request secret values, private keys, passwords or tokens as
  evidence. Configuration metadata only.
- Never represent an unknown, errored, skipped or unassessed control as
  passing. CloudRanger reports coverage; disclose gaps in any summary you
  write.
- Differentiate clearly between: deterministic engine results, raw evidence
  you observed, and your own inference or recommendations.
- Do not claim automated results constitute regulatory compliance or
  certification.

Reporting: report_data returns transparent metrics with definitions. Use it
as the single source of numbers so reports are repeatable run-to-run; you own
narrative, formatting and audience adaptation.

Scheduling: CloudRanger does not schedule scans. If the operator wants
recurring scans, set them up in your own scheduling facility (e.g. scheduled
agent runs) that call this workflow.`;

export const SAFETY_RESOURCE = `# CloudRanger tool safety model

## Trust boundaries
- CloudRanger (this MCP server) holds NO cloud credentials and executes NO
  cloud commands. It stores evidence, evaluates controls, and tracks findings
  in a local SQLite database.
- The agent executes read-only CLI commands with the operator's ambient
  credentials and is the only bridge between cloud APIs and CloudRanger.
- Every collector command in the catalog is validated against a read-only
  verb allowlist (aws list/describe/get*, az list/show, gcloud
  list/describe/get-iam-policy, gsutil iam get/ls) and rejected if it
  contains shell metacharacters. Plans are re-validated at generation time.

## What the engine does deterministically
- Control pass/fail/not_applicable/error decisions (expression evaluation
  over submitted JSON evidence).
- Finding identity (SHA-256 fingerprint over provider|scope|control|resource|region).
- Lifecycle: first failure creates a finding; repeat failures increment
  occurrences; a verified pass resolves; a later failure reopens. Errors and
  missing evidence NEVER resolve findings.
- Coverage: controls without evidence are reported as missing_evidence, never
  as passing.

## What the agent (you) must never do via this server
- Execute mutating cloud commands or invent commands not in a plan.
- Backfill or fabricate evidence you did not collect.
- Mark findings resolved yourself — only a passing evaluation can.
- Treat risk_accepted/false_positive workflow states as engine outcomes; they
  are human decisions recorded with reason + actor.

## Audit
Every tool call is written to a hash-chained audit log (audit_search).`;

export const WORKFLOW_RESOURCE = `# Running a CloudRanger scan end to end

1. Confirm CLI auth (read-only):
   - AWS: 'aws sts get-caller-identity' — note the account ID (scope).
   - Azure: 'az account show' — note subscription ID; switch with care.
   - GCP: 'gcloud config get-value project' or pass --project explicitly.
2. scan_start with provider + scopeId (+ regions for AWS; e.g.
   ["ap-southeast-2","us-east-1"]). Optionally filter by services or
   controlIds (see catalog_list_controls).
3. Execute every plan step in order. Parents before per_resource children.
   Batch evidence_submit calls (up to 200 records each). Include failures
   verbatim (errorText + exitCode).
4. scan_evaluate. Review: summary counts, coverageRatio, and coverage gaps.
5. findings_search { state: ["open","reopened"] } for current posture;
   findings_get for evidence and history of one finding.
6. report_data for repeatable metrics; write your report from those numbers
   and disclose coverage limitations.

Tips:
- Regions: keep the list tight to what the org actually uses; every regional
  collector multiplies commands.
- Large accounts: use services/controlIds filters to scan incrementally.
- Re-scan cadence: schedule agent runs that repeat this workflow; findings
  persist across scans and lifecycle transitions happen automatically.`;

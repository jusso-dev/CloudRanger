# Threat model

## Assets

- **Cloud credentials** — held only by the operator's shell environment.
  CloudRanger never receives, stores or transmits them.
- **Evidence** — cloud configuration metadata in SQLite. Sensitive
  (reveals security posture and account structure) but by design contains no
  secret values: collectors gather configuration, never data-plane content
  or credential material.
- **Findings & history** — integrity matters: silently resolved or
  fabricated findings undermine the product's purpose.
- **Audit log** — must be tamper-evident.

## Trust boundaries

| Boundary           | Trust decision                                                                                                                                                       |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Operator ↔ agent   | Operator grants the agent read-only cloud CLI auth. Out of CloudRanger's control; onboarding docs prescribe read-only roles (SecurityAudit / Reader / roles/viewer). |
| Agent ↔ MCP server | Local stdio. The agent is semi-trusted: it can submit false evidence (see T3) but cannot make the server execute anything.                                           |
| MCP server ↔ cloud | **None.** The server makes no network calls.                                                                                                                         |

## Threats & mitigations

**T1 — Prompt injection makes the agent run a mutating command.**
Plans contain only commands validated against a read-only verb allowlist and
a shell-metacharacter reject list, enforced at catalog load _and_ plan
generation (`engine/src/safety.ts`, tested against injection payloads).
Scope/region parameters are charset-validated before substitution. Server
instructions and the safety resource direct the agent to refuse commands not
in a plan. Residual risk: the agent can always run arbitrary commands on its
own initiative — that boundary belongs to the agent harness (e.g. Claude
Code permission prompts), and CloudRanger never asks for anything mutating.

**T2 — Malicious/compromised catalog introduces a harmful command.**
Same allowlist rejects it at load; catalog tests assert every collector and
verifyCommand is read-only. Catalog changes ship via reviewed PRs.

**T3 — Agent submits fabricated or wrong-scope evidence.**
Deterministic evaluation makes results reproducible from stored evidence
(hashed at ingest); the workflow prompt requires the agent to verify CLI
identity matches the scan scope before collecting. Ultimately the operator
trusts their agent to relay CLI output faithfully — the audit log and stored
raw evidence make spot-checking cheap. Fabrication cannot _resolve_ findings
silently without leaving evidence rows behind.

**T4 — Findings silently disappear.**
Only a verified passing evaluation resolves a finding; errors, missing
evidence and not-applicable outcomes never do. Lifecycle transitions are
events in `finding_events`; resolved findings retain full history.

**T5 — Secret leakage into the database or logs.**
Collectors gather configuration metadata only (no secret-value APIs are in
the catalog). Audit-log argument payloads pass a key-based redactor
(`secret|token|password|credential|apikey|private`). Evidence payloads are
size-capped (2 MB/record) to prevent dump-style exfiltration through the DB.

**T6 — Audit tampering.**
Entries are hash-chained (each entry hashes its predecessor's hash);
`cloudranger audit verify` / `audit_search.chainIntact` detect edits.
Residual: an attacker with file access could rebuild the whole chain —
acceptable for a local-first, single-operator trust model.

**T7 — Oversized/hostile tool input.**
All inputs are zod-validated with bounded sizes (≤200 records/submit, ≤2 MB
output, ≤500 audit rows, regex patterns length-capped and screened for
catastrophic backtracking).

## Non-goals

- Multi-tenant isolation (single-operator local tool).
- Defending against a hostile operator or hostile local filesystem access.
- Runtime threat detection (this is posture management, not a SIEM).

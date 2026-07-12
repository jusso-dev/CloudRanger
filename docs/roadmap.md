# Roadmap

Phase 0/1 (done): engine, safety layer, seed catalog, SQLite lifecycle store,
MCP server (stdio), CLI, docs, threat model.

Phase 2 partial (done): 79 controls (34 AWS / 22 Azure / 23 GCP, 200+
fixtures), control packs, custom-control authoring (CLI + MCP tools + prompt),
operator custom catalog directory with override semantics, Prowler metadata
importer (`scripts/prowler-import.mjs`).

## Phase 2 — Catalog scale-out (porting pipeline), remaining

1. ~~Prowler metadata importer.~~ **Done** — `scripts/prowler-import.mjs`.
   Next: wire it to a real Prowler checkout and complete the highest-value
   stubs (collector + passWhen + fixtures) in bulk.
2. AWS depth: ELB/CloudFront TLS + logging, Lambda posture, EKS, ECR image
   scanning, IAM policy analysis (wildcards, admin, privilege escalation),
   organisations/SCP posture, Config rules coverage. Target 100+ AWS.
3. Azure depth: Entra ID via `az ad` (app credential expiry, ownerless SPs,
   privileged role assignments), Defender plan status, activity-log export,
   Postgres/MySQL flexible servers, Cosmos DB. Target 100+.
4. GCP depth: audit config + log sinks/metric filters, KMS rotation,
   BigQuery dataset IAM, Cloud Run ingress/auth, Essential Contacts,
   org policies. Target 100+.
5. Fixture recorder: `cloudranger fixtures capture` — sanitise real CLI
   output into fixture cases.
6. Credential-report support (CSV evidence type) for the full CIS 1.x IAM
   family.

## Phase 3 — Engine depth

7. Parameterised controls (org-tunable thresholds, e.g. key-age days).
8. `relationshipExists`/graph evidence for cross-resource controls
   (public LB → unencrypted backend).
9. ~~Control packs as named selections for `scan_start`.~~ **Done** — 7 packs.
   Next: framework-aligned packs (cis-aws-3.0, essential-eight-technical) once
   compliance rollup lands.
10. Coverage-aware compliance rollup tool (`compliance_status` per
    framework with direct/partial/manual flags).
11. Rule deprecation + version history retention on control updates.
12. Custom-control fixture authoring via MCP (agent submits fixtures alongside
    a custom control so it is regression-protected at install time).

## Phase 4 — Operations

12. Retention policies (evidence pruning with finding history preserved).
13. DB backup/restore commands; export findings as CSV/JSONL/SARIF.
14. Multi-scope digests (`report_data` across scopes with per-scope
    breakdown).
15. Optional streamable-HTTP MCP transport with token auth for remote
    agents.
16. Signed catalog releases; third-party control pack loading with the same
    safety validation.

## Phase 5 — Ecosystem

17. Import provider-native findings (Security Hub, Defender, SCC) as
    correlated—not duplicated—signals, clearly labelled as imported.
18. Notification hooks (agent-driven: webhook/Slack emitters the agent can
    call after `scan_evaluate`).
19. Community control contribution guide + CI porting checks.

Issues should follow: problem, scope, non-goals, security considerations,
acceptance criteria, tests, docs.

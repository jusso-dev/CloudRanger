# Roadmap

Phase 0/1 (this repo, done): engine, safety layer, seed catalog (49
controls, 118 fixtures), SQLite lifecycle store, MCP server (stdio), CLI,
docs, threat model.

## Phase 2 — Catalog scale-out (porting pipeline)

1. Prowler metadata importer: script that maps upstream `metadata.json`
   (severity, service, remediation, compliance) into control YAML stubs for
   human completion. **~top-priority issue.**
2. AWS depth: ELB/CloudFront TLS + logging, Lambda posture, EKS/ECR, SNS/SQS
   encryption, Secrets Manager rotation metadata, IAM policy analysis
   (wildcards, admin), organisations posture. Target 100+ AWS controls.
3. Azure depth: Entra ID via `az ad` (app credential expiry, ownerless SPs),
   Defender plan status, activity-log export, AKS/ACR, Postgres/MySQL
   flexible servers, per-app `az webapp config` collection. Target 100+.
4. GCP depth: audit config, log sinks/metric filters, GKE posture, KMS
   rotation, BigQuery dataset IAM, Essential Contacts. Target 100+.
5. Fixture recorder: `cloudranger fixtures capture` — sanitise real CLI
   output into fixture cases.
6. Credential-report support (CSV evidence type) for the full CIS 1.x IAM
   family.

## Phase 3 — Engine depth

7. Parameterised controls (org-tunable thresholds, e.g. key-age days).
8. `relationshipExists`/graph evidence for cross-resource controls
   (public LB → unencrypted backend).
9. Control packs (cis-baseline, public-exposure, essential-eight-technical)
   as named selections for `scan_start`.
10. Coverage-aware compliance rollup tool (`compliance_status` per
    framework with direct/partial/manual flags).
11. Rule deprecation + version history retention on control updates.

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

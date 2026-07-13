# Roadmap

Phase 0/1 (done): engine, safety layer, seed catalog, SQLite lifecycle store,
MCP server (stdio), CLI, docs, threat model.

Phase 2 partial (done): 553 controls (239 AWS / 181 Azure / 133 GCP), control
packs, custom-control authoring (CLI + MCP tools + prompt), operator custom
catalog directory with override semantics, and a Prowler metadata importer
(`scripts/prowler-import.mjs`).

## Phase 2 — Catalog scale-out (porting pipeline), remaining

1. ~~Prowler metadata importer.~~ **Done** — `scripts/prowler-import.mjs`.
   Next: continue the grounded port from a version-pinned Prowler checkout.
   Only ship a check after its exact read-only CLI evidence shape and pass/fail
   fixtures have been verified; checks that need graph joins, policy parsing,
   or unsupported API parameters require an engine/collector extension first.
2. AWS depth: ELB/CloudFront TLS + logging, Lambda posture, EKS, ECR image
   scanning, IAM policy analysis (wildcards, admin, privilege escalation),
   organisations/SCP posture, Config rules coverage. Target 100+ AWS.
3. Azure depth: Entra ID via `az ad` (app credential expiry, ownerless SPs,
   privileged role assignments), Defender plan status, activity-log export,
   Postgres/MySQL flexible servers, Cosmos DB. Target 100+.
4. GCP depth: audit config + log sinks/metric filters, KMS rotation,
   BigQuery dataset IAM, Cloud Run ingress/auth, Essential Contacts,
   org policies. Target 100+.
5. ~~Fixture recorder: `cloudranger fixtures capture` — sanitise real CLI
   output into fixture cases.~~ **Done** — deterministic sanitiser
   (engine `createSanitizer`), verdict validation before write, custom
   fixtures directory picked up by `catalog test`.
6. ~~Credential-report support (CSV evidence type) for the full CIS 1.x IAM
   family.~~ **Done** — engine-side `decode: base64Csv` on collectors, the
   exact-allowlisted `prepareCommand` mechanism, and controls
   CR-AWS-IAM-025…029 (root usage, unused keys/passwords, never-used keys,
   dual active keys) with fixtures.

## Phase 3 — Engine depth

7. ~~Parameterised controls (org-tunable thresholds, e.g. key-age days).~~
   **Done** — `parameters` declarations with `{ $param: name }` references,
   scope-level persistence (`parameters_set`/`parameters_list` + CLI), per-scan
   overrides on `scan_start`, and effective values recorded on findings.
8. ~~`relationshipExists`/graph evidence for cross-resource controls
   (public LB → unencrypted backend).~~ **Done** — declarative key-equality
   join over relatedCollectors evidence, shipped with internet-exposed
   SSH/RDP instance controls (CR-AWS-EC2-155/156).
9. ~~Control packs as named selections for `scan_start`.~~ **Done** — 7
   category packs plus framework-aligned packs (cis-aws-3.0,
   essential-eight-technical) resolved from compliance mappings.
10. ~~Coverage-aware compliance rollup tool (`compliance_status` per
    framework with direct/partial/manual flags).~~ **Done** —
    `compliance_status` MCP tool + `cloudranger compliance status`, honest
    coverage (ratios only for vendored requirement lists), documented in
    docs/rules/compliance-rollup.md.
11. ~~Rule deprecation + version history retention on control updates.~~
    **Done** — `deprecated` metadata (reason + supersededBy) excludes
    controls from default scans with an explicit notice, and every control
    revision (version + content hash + definition) is recorded at server
    startup and custom installs, queryable via `catalog_control_history`
    with a live tamper check.
12. ~~Custom-control fixture authoring via MCP (agent submits fixtures
    alongside a custom control so it is regression-protected at install
    time).~~ **Done** — `catalog_add_custom_control` accepts `fixtures`,
    rejects installs whose fixture verdicts disagree with the engine, and
    stores them in the custom fixtures directory run by `catalog test`.

## Phase 4 — Operations

12. ~~Retention policies (evidence pruning with finding history
    preserved).~~ **Done** — per-scope keepDays/keepScans policies,
    dry-run-by-default pruning (MCP `evidence_prune` admin-only with double
    confirmation; `cloudranger retention` CLI) that clears raw payloads only,
    preserving findings, evaluations and evidence digests.
13. ~~DB backup/restore commands; export findings as CSV/JSONL/SARIF.~~
    **Done** — consistent online SQLite backup/restore with integrity check
    and 0600 modes (pg_dump guidance for PostgreSQL), and
    `cloudranger findings export --format csv|jsonl|sarif`
    (docs/operations.md).
14. ~~Multi-scope digests (`report_data` across scopes with per-scope
    breakdown).~~ **Done** — `scopeIds`/`allScopes` inputs return an
    aggregate plus per-scope digests, listing scopes present-but-excluded
    and requested-but-scanless explicitly; single-scope shape unchanged.
15. ~~Optional streamable-HTTP MCP transport with token auth for remote
    agents.~~ **Done** — `--http` flag, mandatory constant-time bearer
    token, loopback-default bind with explicit non-loopback opt-in,
    DNS-rebinding protection, 4 MB body cap; threat model T6 +
    docs/operations.md.
16. ~~Signed catalog releases; third-party control pack loading with the
    same safety validation.~~ **Done** — Ed25519 manifest signing
    (scripts/catalog-sign.mjs, CI signing on tagged releases when the key
    secret is configured), `cloudranger catalog verify`, and
    `cloudranger packs add` with pinned publisher keys, explicit
    --trust-unsigned, and mandatory safety + fixture validation.

## Phase 5 — Ecosystem

17. ~~Import provider-native findings (Security Hub, Defender, SCC) as
    correlated—not duplicated—signals, clearly labelled as imported.~~
    **Done** — `signals_import`/`signals_list` MCP tools: sanitised,
    length-capped ingest, upsert on external id, resource-level correlation
    to open CloudRanger findings, never counted in pass/fail stats.
18. ~~Notification hooks (agent-driven: webhook/Slack emitters the agent
    can call after `scan_evaluate`).~~ **Done** — `notify_destinations` +
    `notify_scan_digest`: operator allow-list by name (URLs never exposed to
    or accepted from the agent), HMAC-signed webhook payloads, digests carry
    summaries and finding references only.
19. ~~Community control contribution guide + CI porting checks.~~ **Done**
    — docs/CONTRIBUTING-controls.md (grounded porting workflow, PR
    checklist, worked example) and the Catalog checks workflow enforcing
    pass+fail fixtures per control, read-only commands, and
    ledger/mapping integrity on every catalog-touching PR.

Issues should follow: problem, scope, non-goals, security considerations,
acceptance criteria, tests, docs.

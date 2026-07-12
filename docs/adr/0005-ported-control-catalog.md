# ADR-0005: Controls ported from established engines, never invented

**Status:** accepted · 2026-07-12

## Decision

Every control derives from an established open-source CSPM engine —
currently Prowler and Trivy (both Apache-2.0) — carrying a `source` block
(engine, upstream check ID, license). ScoutSuite (GPL) is reference-only;
no logic is ported from it. CIS/NIST mappings reference section identifiers
only; no benchmark text is redistributed.

## Rationale

Operator requirement ("don't just invent controls"). Upstream engines
encode years of triage on what constitutes a real misconfiguration and sane
severities; porting their logic against CLI JSON output preserves that
judgement while fitting the agent-collection model.

## Consequences

- Catalog tests enforce attribution and per-control pass/fail fixtures.
- Scaling the catalog is a porting pipeline (map upstream check → collector
  - expression + fixtures), roadmapped rather than hand-invented.
- Severity or logic disagreements with upstream are recorded in the control
  description, not silently changed.

# Compliance rollup

`compliance_status` (MCP) and `cloudranger compliance status` (CLI) roll the
latest evaluated scan of a scope up to framework requirements. The rollup is
coverage-aware by construction: it can only ever understate compliance, never
overstate it.

## How a requirement gets its status

Mappings come from two sources, merged:

- the curated registry `packages/catalog/catalog/mappings/frameworks.yaml`,
  where every entry carries an automation status
  (`automated | partial | manual | unsupported`) and a rationale;
- `compliance:` fields on control documents (CIS benchmarks etc.), treated as
  automated technical mappings.

Each requirement reports two independent axes:

| Axis         | Values                                                   | Meaning                                                                                                                                                                                            |
| ------------ | -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `automation` | `direct` / `partial` / `manual`                          | `direct` = at least one fully automated mapping; `partial` = automated evidence exists but the requirement needs manual assessment on top; `manual` = no automated evidence at all.                |
| `status`     | `non_compliant` / `error` / `compliant` / `not_assessed` | Derived from the mapped controls' results in the latest evaluated scan. Any failing control makes the requirement `non_compliant`; errors dominate passes; no evaluations at all = `not_assessed`. |

A requirement whose `automation` is `partial` or `manual` is **never** fully
evidenced by CloudRanger, even when `status` is `compliant` — the flags exist
precisely so a rollup consumer cannot conflate "our checks pass" with
"requirement satisfied". `fullyAssessed: false` marks requirements where some
mapped controls had no evidence in the scan.

## Coverage honesty

`totals.totalRequirements` and `totals.mappedRatio` are only emitted for
frameworks whose complete requirement list is vendored in this repository
(currently ISM, from the OSCAL upstream snapshot). Every other framework
reports `totalRequirements: null` with an explicit note that unmapped
requirements exist — no invented denominators.

## Framework-aligned packs

Two packs resolve controls by framework mapping instead of category:

- `cis-aws-3.0` — controls whose documents map to CIS AWS Foundations
  Benchmark v3.0 recommendations;
- `essential-eight-technical` — controls the registry maps to the
  cloud-technical slice of the ACSC Essential Eight (MFA, restricting admin
  privileges, patching, backups). All Essential Eight mappings are `partial`
  by design: E8 maturity covers fleets and processes far beyond cloud
  control-plane posture.

Start a scan with `scan_start { pack: "cis-aws-3.0" }`, then read
`compliance_status` for the per-requirement result.

A rollup is never a certification.

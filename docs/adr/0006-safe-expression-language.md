# ADR-0006: Declarative expression language, no eval

**Status:** accepted · 2026-07-12

## Decision

Controls express pass conditions in a closed JSON/YAML AST
(`equals`, `in`, `daysSinceGt`, `isPublicCidr`, `portIncludes`,
`anyItem`/`allItems`/`noneItem`, boolean composition, …) evaluated by a
recursive interpreter over dot-paths. No `eval`, no user JavaScript, regexes
length-capped and screened for catastrophic backtracking.

Semantics rule: **missing data never satisfies a positive predicate** — an
absent field can never make a control pass unless the control explicitly
tests for absence.

## Rationale

Deterministic, sandboxed-by-construction, serialisable (schema-validated
YAML), and expressive enough for the ported catalog (nested quantifiers
cover security-group/NSG/firewall shapes). Loose scalar coercion
("true"/true, "1"/1) absorbs CLI JSON stringiness.

## Consequences

Complex graph controls (privilege-escalation paths) will need a reviewed
programmatic-rule extension later; that stays out of scope until the
declarative catalog is broad.

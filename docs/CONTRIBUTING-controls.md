# Contributing controls

CloudRanger controls are deterministic: a read-only CLI command produces JSON
evidence, and a declarative rule decides pass/fail. Contributions are welcome
— this guide is the quality bar CI enforces on every catalog-touching PR.

## The one rule that matters

**Ground everything in real output.** Never write a `passWhen` against field
names you guessed or found in docs alone. Run the collector command against a
real account, look at the JSON, and write the rule against the exact paths
and value types you observed (`true` vs `"true"` matters).

## Porting workflow (from Prowler)

1. **Pick a check** from the coverage ledger:
   `node scripts/prowler-coverage.mjs report` shows what is `unmapped` per
   provider. Work from the version-pinned checkout recorded in
   `packages/catalog/catalog/upstream/prowler-v*.json` — not from whatever
   Prowler's main branch says today.
2. **Understand the upstream logic**, then decide whether the check is
   portable: it must be expressible as read-only CLI evidence plus the safe
   expression operators (see `docs/rules/custom-controls.md`). Checks that
   need policy parsing, graph joins beyond `relationshipExists`, or
   unsupported API parameters get ledger status `unsupported` with
   `requiredCapabilities` instead of a bad approximation.
3. **Find or add a collector.** Prefer existing collectors
   (`packages/catalog/catalog/collectors/`). New commands must pass the
   read-only safety validation — list/describe/get/show verbs only, no shell
   metacharacters. `prepareCommand` additions require a threat-model update.
4. **Write the control** in `packages/catalog/catalog/controls/` with source
   attribution (`source: { engine: prowler, id: <check_id>, license:
Apache-2.0 }`), honest severity, rationale, and operator remediation
   steps. Tunable thresholds should be declared `parameters` with defaults
   matching upstream behaviour.
5. **Capture fixtures** — at least one pass and one fail case per control.
   `cloudranger fixtures capture` sanitises real output and refuses to write
   a case whose verdict the engine disputes; point `--output` at
   `packages/catalog/fixtures/`. Fixture dates are evaluated against the
   fixed test clock 2026-01-01T00:00:00Z.
6. **Credit the ledger**: set the check's entry to `implemented` with your
   `controlIds` in `packages/catalog/catalog/upstream/prowler-v*.json`.
7. **Run the gate locally** (CI runs the same):

   ```
   pnpm build
   node apps/cli/dist/main.js catalog validate
   node apps/cli/dist/main.js catalog test
   node scripts/catalog-pr-checks.mjs
   pnpm prowler:coverage:validate
   pnpm compliance:mappings:validate
   ```

## PR checklist

- [ ] Rule grounded in observed CLI output (say so in the PR, with the
      command you ran — sanitised).
- [ ] ≥1 pass and ≥1 fail fixture case per control (CI rejects otherwise).
- [ ] Collector commands and `verifyCommand` are read-only.
- [ ] Coverage ledger updated; `source.id` matches the upstream check.
- [ ] Compliance mappings (CIS etc.) added where the mapping is defensible.
- [ ] Severity and remediation are honest — no alarm inflation.

## What CI enforces

The `Catalog checks` workflow runs on every PR touching the catalog: full
schema + read-only safety validation, every fixture case, the contribution
gate (pass+fail fixtures for **every** control, verify-command hygiene), and
ledger/mapping integrity. A control without fixtures, or a collector with a
mutating verb, cannot merge.

Maintainer review still matters: CI proves shape and safety, not that the
rule means what the upstream check means. Reviewers check the grounding
evidence and the rule's semantics against the upstream source.

## Worked example

CR-AWS-IAM-029 (`iam_user_two_active_access_key`) is a compact reference:
credential-report collector (engine-side CSV decode), per-user rule, pass +
fail fixtures generated from sanitised report content, ledger entry
crediting the upstream check. Start from
`packages/catalog/catalog/controls/aws-gen-iam-credential.yaml` and its
fixture file.

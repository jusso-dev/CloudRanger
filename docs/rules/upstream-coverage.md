# Prowler upstream coverage

CloudRanger distinguishes between accounting for upstream checks and being able
to execute them deterministically. A metadata entry alone never counts as an
implemented security check.

The pinned inventory is
`packages/catalog/catalog/upstream/prowler-v5.34.0.json`. It records every
AWS, Azure, and GCP check in Prowler 5.34.0 at commit
`dbdbd8a3798add4e33b3c3a81a02fbd271662738`.

## Statuses

| Status        | Meaning                                                                                                                              |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `implemented` | One or more CloudRanger controls use the exact Prowler `CheckID`, and every mapped control has deterministic pass and fail fixtures. |
| `superseded`  | A different grounded control covers the check; the record must explain why.                                                          |
| `unsupported` | The check cannot yet be evaluated by the current evidence model; it must state the required engine or collector capabilities.        |
| `deprecated`  | Prowler marks the check as deprecated; the record must state that reason.                                                            |
| `unmapped`    | The check is explicitly in the backlog and does not contribute to executable coverage.                                               |

Only `implemented` checks count as executable coverage. `superseded`,
`unsupported`, and `deprecated` provide an auditable disposition; they do not
silently inflate the implemented count.

## Commands

Use a local checkout of the target Prowler release to refresh the inventory:

```bash
pnpm prowler:coverage:sync -- --prowler /path/to/prowler
pnpm prowler:coverage:validate
pnpm prowler:coverage:report
```

`sync` preserves an existing check's manual status, reason, required
capabilities, and aliases. When a catalog control has an exact Prowler source
ID and both pass and fail fixtures, it is automatically recorded as
`implemented`.

An alias is only valid for a verified Prowler rename: the record must name the
older control source ID and document why the collector scope and pass/fail
condition are semantically equivalent. Similar titles alone are not enough.

`validate` runs as part of `pnpm test`. It rejects duplicate/missing inventory
records, invalid statuses, unreasoned dispositions, mappings to missing
controls, and `implemented` controls without both fixture outcomes.

## Porting a check

1. Add the least-privileged, read-only collector(s) needed for real CLI JSON.
2. Add deterministic control logic and sanitised pass/fail fixtures.
3. Set the control's `source.id` to the exact Prowler `CheckID`.
4. Re-run `pnpm prowler:coverage:sync -- --prowler /path/to/prowler`.
5. Run `pnpm test` and `pnpm prowler:coverage:report`.

If a check needs policy parsing, a cross-resource relationship, or a collector
parameter the engine cannot express, leave it `unmapped` until the capability
exists, then record it as `unsupported` with that capability in
`requiredCapabilities`. Do not add an unevaluable catalog stub.

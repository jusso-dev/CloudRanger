# Architecture overview

## System shape

CloudRanger is three packages and two apps around one inversion: **the LLM
agent is the collection layer**, and everything security-critical is
deterministic code.

```
             ┌────────────────────────────────────────────────────┐
             │                    operator                        │
             │  (authenticates aws / az / gcloud CLIs read-only)  │
             └───────────────────────┬────────────────────────────┘
                                     │ credentials stay here
             ┌───────────────────────▼────────────────────────────┐
             │              agent (Claude / Codex)                │
             │  executes plan commands · submits JSON evidence    │
             │  investigates · writes reports · schedules itself  │
             └───────────────────────┬────────────────────────────┘
                                     │ MCP (stdio)
┌────────────────────────────────────▼───────────────────────────────────────┐
│                        apps/mcp-server                                     │
│  tools · prompts · resources · per-call audit · input validation           │
├──────────────────┬──────────────────────────────┬──────────────────────────┤
│ packages/catalog │       packages/engine        │       packages/db        │
│ collectors YAML  │ expression evaluator         │ SQLite (better-sqlite3)  │
│ controls YAML    │ control evaluation           │ scans · evidence         │
│ fixtures         │ plan builder + cmd safety    │ evaluations · findings   │
│ (Prowler/Trivy-  │ finding fingerprints         │ finding_events           │
│  derived)        │ lifecycle reconciliation     │ hash-chained audit_log   │
└──────────────────┴──────────────────────────────┴──────────────────────────┘
```

`apps/cli` gives the operator direct access to the same catalog and database
(validate/test the catalog, query findings, print report JSON, verify the
audit chain, emit MCP client config).

## Scan data flow

1. **scan_start** — agent declares provider + scope (+ regions/services/
   controls). The plan builder resolves the collectors those controls need
   (including per-resource parents), validates every command against the
   read-only allowlist, expands regions, substitutes the scope into
   `{project}`-style placeholders, and returns ordered steps. A scan row is
   created in `collecting` state.
2. **collection** — the agent executes each step verbatim and calls
   **evidence_submit** with parsed JSON output. Failures are submitted too
   (errorText + exit code); the store hashes every payload.
3. **scan_evaluate** — the engine groups evidence by collector, extracts
   resources (`resourcesPath`, `[]` flattening, per-resource records),
   applies `applicableWhen` / `passWhen` expressions and `onError` mappings,
   and emits per-resource results: `pass · fail · not_applicable · error ·
not_assessed`. Controls with no evidence become coverage gaps.
4. **reconciliation** — inside one SQLite transaction, each result is matched
   to a finding by fingerprint (`sha256(provider|scope|control|resource|region)`):
   - first `fail` → create finding (`open`), record `created` event
   - repeat `fail` → bump `last_seen_at`/occurrences, `recurred` event
   - `pass` over open/reopened → `resolved` (+ `resolved_at`), evidence kept
   - `fail` over resolved → `reopened`, reopen counter incremented
   - `error`/`not_applicable`/missing → **no lifecycle change**
5. **reporting** — `report_data` aggregates open findings, deltas in a
   window, top failing controls, risk acceptances and scan health, each
   metric with an explicit definition so agent-written reports are
   reproducible run-to-run.

## Key decisions

See `docs/adr/`. In brief: agent-executed collection (ADR-0002), SQLite
zero-dependency storage (ADR-0003), MCP-only surface (ADR-0004),
Prowler/Trivy-derived catalog (ADR-0005), safe declarative expression
language with no eval (ADR-0006).

## Extending

- **New control**: add YAML to `packages/catalog/catalog/controls/`, add a
  collector if needed, add fixture cases in `packages/catalog/fixtures/`.
  `catalog.test.ts` enforces: schema validity, read-only commands, source
  attribution, ≥1 pass and ≥1 fail fixture per control.
- **New expression op**: extend `Expression` in `engine/src/types.ts`,
  implement in `expr.ts`, add to `schema.ts`, test in `expr.test.ts`.
- **New provider**: new collector namespace + safety regexes in
  `engine/src/safety.ts`.

# Custom controls and control packs

CloudRanger controls are deterministic: the engine decides pass/fail from CLI
JSON evidence. Custom controls are no exception — you (or an agent on your
behalf) author the same declarative YAML the bundled catalog uses. The LLM
never becomes the pass/fail judge.

## Control packs

Packs are named selections over the catalog, resolved dynamically so new
controls join matching packs automatically:

| Pack                 | Selects                                               |
| -------------------- | ----------------------------------------------------- |
| `essential-baseline` | every critical + high control                         |
| `public-exposure`    | internet-reachable storage/network/db/control-plane   |
| `identity`           | root/owner, MFA, stale & over-privileged credentials  |
| `encryption`         | at-rest / in-transit, keys, secrets                   |
| `logging-detection`  | audit trails, flow logs, recorder/detector enablement |
| `resilience`         | backup, versioning, deletion protection, patching     |
| `kubernetes`         | AKS + GKE control-plane and node posture              |

Scan by pack:

```
scan_start { provider: "gcp", scopeId: "my-project", pack: "kubernetes" }
```

or list them: MCP `catalog_list_packs`.

## Where custom controls live

Operator custom catalog directory (override with `CLOUDRANGER_CUSTOM_CATALOG`):

```
~/.cloudranger/catalog/
  controls/     # your control YAML documents
  collectors/   # optional: custom read-only collectors
```

It is merged over the bundled catalog. A custom control with a **matching id**
overrides the bundled one (tune severity or logic without forking); a new id
(`CUSTOM-...`) adds a control.

## Authoring

### Via CLI

```bash
cloudranger controls template --provider aws > my-control.yaml   # scaffold
$EDITOR my-control.yaml                                          # fill in
cloudranger controls add my-control.yaml                        # validate + install
cloudranger controls dir                                        # where it went
```

### Via an agent (MCP)

Agents submit fixtures in the same `catalog_add_custom_control` call
(`fixtures: [{ controlId, cases: [...] }]`). The install is rejected if any
case's engine verdict disagrees with its declared expectation, so a custom
control ships regression-protected or not at all; accepted fixtures land in
`<custom-catalog>/fixtures/` and run on every `cloudranger catalog test`.

- `catalog_generate_control_template` — returns the scaffold, the full
  expression-operator reference, and the available read-only collectors.
- `catalog_add_custom_control` — validates and installs a YAML document.
- Prompt `author_custom_control` walks an agent through grounding the
  expression in real CLI output before installing.

## Rules the validator enforces

- Schema-valid control (id pattern `(CR|CUSTOM)-(AWS|AZURE|GCP)-<SERVICE>-<NNN>`).
- `collector` must exist (bundled, or defined in the same document).
- Any custom collector `command` must pass read-only safety validation
  (list/describe/get/show; no shell metacharacters) — a mutating command is
  rejected outright.
- `passWhen` must use only the safe expression operators (no code, no eval).
- Parameter declarations must be coherent: every `{ $param: name }` reference
  declared, every declaration referenced, defaults within their own
  bounds/enum.

## Parameters (org-tunable thresholds)

A control can declare tunable thresholds instead of hard-coding them:

```yaml
parameters:
  maxKeyAgeDays:
    type: number
    description: Maximum age in days for an active access key.
    default: 90
    min: 1
    max: 365
passWhen:
  op: daysSinceGt
  path: CreateDate
  value: { $param: maxKeyAgeDays }
```

Defaults must reproduce the control's documented behaviour. Operators tune
values per scope with `parameters_set` (MCP) or
`cloudranger parameters set --provider aws --scope <account> --control <id>
--param maxKeyAgeDays=60`, and per scan via `scan_start`'s `parameters` input
(scan wins over persisted scope values, per key). Overrides are validated
against the declared type, bounds, and enum — they can tune a control within
its declared range, never disable it — and the effective values used are
recorded on every finding and evaluation for audit. Fixture cases may set
`"parameters": { ... }` to pin a case to specific values.

## Grounding (important)

Write `passWhen` against **actual** CLI output you have run and observed — not
guessed field names. Note whether values come back as `true` vs `"true"`
(the engine coerces common CLI stringiness, but paths must be exact). Then add
fixture cases:

```
packages/catalog/fixtures/<file>.json   # one entry per control, ≥1 pass + ≥1 fail
cloudranger catalog test                # runs every fixture deterministically
```

### Capturing fixtures from real output

`cloudranger fixtures capture` turns real CLI output into a fixture case in
one step — sanitised, verdict-checked, and appended to a fixture file:

```
aws iam get-account-password-policy --output json \
  | cloudranger fixtures capture --control CR-AWS-IAM-016 --expected pass

# or let the recorder run the control's own collector command:
cloudranger fixtures capture --control CR-AWS-IAM-016 --expected pass --run
```

Before anything is written the recorder (a) sanitises account IDs, UUIDs,
emails and public IPs to stable placeholders (rule-bearing values like
`0.0.0.0/0` and private addresses are preserved so verdicts don't change),
and (b) evaluates the case — if the engine's verdict disagrees with
`--expected`, nothing is written. Raw output never touches disk. `--run` only
executes commands that pass the read-only safety validation. Output defaults
to `<custom-catalog>/fixtures/<control>.json`, which `cloudranger catalog
test` picks up automatically; repo contributors point `--output` at
`packages/catalog/fixtures/`.

## Bulk porting from Prowler

`scripts/prowler-import.mjs` turns a local Prowler checkout's `metadata.json`
files into control **stubs** (severity, service, remediation, compliance
pre-filled; collector + `passWhen` + fixtures left as TODO). Stubs deliberately
fail `catalog validate` until completed — the deterministic logic is the part a
human must finish. See the roadmap for the porting pipeline.

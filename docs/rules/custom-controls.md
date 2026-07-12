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

## Grounding (important)

Write `passWhen` against **actual** CLI output you have run and observed — not
guessed field names. Note whether values come back as `true` vs `"true"`
(the engine coerces common CLI stringiness, but paths must be exact). Then add
fixture cases:

```
packages/catalog/fixtures/<file>.json   # one entry per control, ≥1 pass + ≥1 fail
cloudranger catalog test                # runs every fixture deterministically
```

## Bulk porting from Prowler

`scripts/prowler-import.mjs` turns a local Prowler checkout's `metadata.json`
files into control **stubs** (severity, service, remediation, compliance
pre-filled; collector + `passWhen` + fixtures left as TODO). Stubs deliberately
fail `catalog validate` until completed — the deterministic logic is the part a
human must finish. See the roadmap for the porting pipeline.

<p align="center">
  <img src="docs/assets/cloudranger-logo.png" alt="CloudRanger" width="640" />
</p>

<h1 align="center">CloudRanger</h1>

<p align="center">
  <b>Local-first, agent-driven Cloud Security Posture Management for AWS, Azure and GCP.</b><br/>
  An MCP server + deterministic control engine that turns Claude or Codex into your CSPM operator.
</p>

---

## What it is

CloudRanger inverts the usual CSPM architecture. Instead of a heavyweight platform that holds your cloud credentials and runs its own collectors, CloudRanger is a **local MCP server** that:

1. **Plans** — tells your agent (Claude Code, Claude Desktop, Codex, any MCP client) the exact **read-only** `aws` / `az` / `gcloud` commands to run for the controls you want assessed.
2. **Evaluates** — your agent runs the commands with _your_ credentials in _your_ shell and submits the JSON output back. A deterministic rule engine — never the LLM — decides pass/fail for every control.
3. **Remembers** — findings persist in a local SQLite database with a full lifecycle: first seen, recurring, resolved on verified pass, reopened on regression. Nothing silently disappears.
4. **Reports** — `report_data` returns transparent metrics (every number has a definition) so the agent can write repeatable executive or technical reports in any format you ask for.

The server holds **no cloud credentials**, executes **no cloud commands**, and works entirely offline apart from what your agent collects.

```
┌─────────────────────┐   scan_start    ┌──────────────────────────┐
│  Claude / Codex     │ ──────────────► │  CloudRanger MCP server  │
│  (MCP client)       │ ◄────────────── │                          │
│                     │  plan: exact    │  • control catalog       │
│  runs read-only     │  read-only CLI  │    (Prowler/Trivy-       │
│  aws / az / gcloud  │  commands       │     derived, attributed) │
│  commands locally   │                 │  • deterministic engine  │
│                     │ evidence_submit │  • finding lifecycle     │
│  your credentials   │ ──────────────► │  • SQLite history        │
│  never leave your   │  scan_evaluate  │  • hash-chained audit    │
│  machine            │ ──────────────► │    log                   │
└─────────────────────┘                 └──────────────────────────┘
```

## Design principles

- **Deterministic by default** — control outcomes are computed by the engine from collected evidence. The LLM investigates, explains, prioritises and reports; it never decides pass/fail.
- **Read-only by construction** — every collector command is validated against a read-only verb allowlist (`list`/`describe`/`get`/`show`) and rejected if it contains shell metacharacters. Remediation is guidance for the human operator, never executed by the platform.
- **No invented controls** — every control is ported from established open-source engines (currently [Prowler](https://github.com/prowler-cloud/prowler) and [Trivy](https://github.com/aquasecurity/trivy), both Apache-2.0) with per-control attribution, and ships with pass/fail/error fixtures.
- **Missing evidence is never a pass** — controls without evidence are reported as coverage gaps; errors never resolve findings.
- **Local-first** — one SQLite file, no Docker, no SaaS, no telemetry.

## Quickstart

Requires Node.js ≥ 22 and pnpm.

```bash
git clone <repo> cloudranger && cd cloudranger
pnpm install
pnpm build

# register with Claude Code
claude mcp add cloudranger -- node $(pwd)/apps/mcp-server/dist/main.js

# or print config for other clients
node apps/cli/dist/main.js mcp-config --client claude-desktop
node apps/cli/dist/main.js mcp-config --client codex
```

Then, in your agent, with read-only cloud CLI auth configured (see [onboarding guides](docs/onboarding/)):

> "Run a full CloudRanger scan of AWS account 123456789012 in ap-southeast-2 and us-east-1, then give me an executive summary."

The agent will call `scan_start`, execute the returned read-only commands, submit evidence, evaluate, and report. Findings persist across scans — re-run tomorrow and resolved/reopened deltas are tracked automatically.

### Scheduling

CloudRanger deliberately has no scheduler. Use your agent's scheduling facility (e.g. Claude Code scheduled agents / cron-invoked `claude -p`) to run the `run_full_scan` or `daily_security_review` prompt on whatever cadence you want. History and lifecycle live in the database, so every run builds on the last.

## MCP surface

| Tool                                            | Purpose                                                                       |
| ----------------------------------------------- | ----------------------------------------------------------------------------- |
| `catalog_list_controls` / `catalog_get_control` | Browse the control catalog                                                    |
| `scan_start` / `scan_get_plan`                  | Create a scan, get exact read-only commands                                   |
| `evidence_submit`                               | Submit command output (including failures)                                    |
| `scan_evaluate`                                 | Deterministic evaluation + finding reconciliation                             |
| `scan_status` / `scan_list` / `scan_cancel`     | Scan management                                                               |
| `findings_search` / `findings_get`              | Query findings with evidence + history                                        |
| `findings_set_status` / `findings_comment`      | Workflow: acknowledge, risk-accept (reason + expiry required), false positive |
| `report_data`                                   | Repeatable metrics JSON with definitions                                      |
| `audit_search`                                  | Hash-chained audit log of every tool call                                     |

Custom controls: `catalog_generate_control_template`, `catalog_add_custom_control`, `catalog_list_packs`.

Prompts: `run_full_scan`, `daily_security_review`, `executive_brief`, `investigate_finding`, `remediation_plan`, `author_custom_control`.
Resources: `cloudranger://guides/safety`, `cloudranger://guides/workflow`, `cloudranger://catalog/summary`.

## Control catalog

553 deterministic controls (239 AWS, 181 Azure, 133 GCP) across identity, storage, network exposure, databases, encryption, logging/detection, containers/Kubernetes and resilience — each with severity, rationale, remediation steps, compliance mappings (CIS section references, NIST CSF), upstream attribution and deterministic fixtures. The porting pipeline (`scripts/prowler-import.mjs`) scaffolds stubs from a local Prowler checkout; the full upstream catalog remains an explicitly tracked, ongoing porting effort (not every upstream check can be grounded in a single read-only CLI response). See [docs/roadmap.md](docs/roadmap.md).

The exhaustive upstream inventory is pinned to Prowler 5.34.0 (919 AWS/Azure/GCP checks). `pnpm prowler:coverage:report` shows which checks are implemented versus explicitly unmapped, unsupported, superseded, or deprecated; `pnpm test` validates that every inventory entry has a disposition. See [the upstream coverage guide](docs/rules/upstream-coverage.md).

**Control packs** group controls by theme for targeted scans: `essential-baseline`, `public-exposure`, `identity`, `encryption`, `logging-detection`, `resilience`, `kubernetes`. Pass `pack: "public-exposure"` to `scan_start`.

**Custom controls** live in `~/.cloudranger/catalog/` and merge over the bundled catalog (matching IDs override). Author them with the CLI or have an agent generate one — the engine still decides pass/fail deterministically. See [docs/rules/custom-controls.md](docs/rules/custom-controls.md).

```bash
node apps/cli/dist/main.js catalog list
node apps/cli/dist/main.js catalog validate
node apps/cli/dist/main.js catalog test
```

## CLI

```bash
cloudranger findings --state open,reopened --severity critical,high
cloudranger report --since-days 30
cloudranger scans
cloudranger controls template --provider aws       # scaffold a custom control
cloudranger controls add my-control.yaml           # validate + install it
cloudranger audit verify        # verify the audit hash chain
cloudranger db-path
```

## Development

### Database backends

CloudRanger uses SQLite by default for a zero-configuration local deployment (`CLOUDRANGER_DB`, defaulting to `~/.cloudranger/cloudranger.db`). For shared deployments, the database package includes a Drizzle PostgreSQL schema and pooled connection factory. Set `CLOUDRANGER_DATABASE_URL` to a PostgreSQL connection string and run the Drizzle migration workflow:

```sh
CLOUDRANGER_DATABASE_URL=postgresql://user:password@host:5432/cloudranger pnpm --filter @cloudranger/db db:generate
CLOUDRANGER_DATABASE_URL=postgresql://user:password@host:5432/cloudranger pnpm --filter @cloudranger/db db:migrate
```

The PostgreSQL repository adapter is being introduced behind this schema so existing synchronous SQLite callers remain compatible during migration. Applications embedding CloudRanger can use `createPostgresDatabase()` from `@cloudranger/db` to build Drizzle queries and tooling against the shared schema.

```bash
pnpm build      # build all packages
pnpm test       # engine, catalog, db, mcp e2e tests
pnpm lint
pnpm typecheck
```

Repository layout:

```
packages/engine      pure deterministic core: expressions, evaluation, plans,
                     fingerprints, lifecycle reconciliation, command safety
packages/catalog     collectors + controls (YAML) + fixtures
packages/db          SQLite store: scans, evidence, findings, audit chain
apps/mcp-server      the MCP server (stdio)
apps/cli             operator CLI
docs/                architecture, threat model, ADRs, onboarding, roadmap
```

## Security model

See [docs/architecture/threat-model.md](docs/architecture/threat-model.md). Highlights: the server never touches cloud credentials; all catalog commands are read-only-validated at load time _and_ plan time; evidence is size-capped and hashed; secrets are redacted from the audit log; the audit log is hash-chained and verifiable.

## Attribution & license

CloudRanger is Apache-2.0. Control logic is derived from [Prowler](https://github.com/prowler-cloud/prowler) and [Trivy](https://github.com/aquasecurity/trivy) (both Apache-2.0); each control carries its upstream source ID. CIS/NIST references are section identifiers only — no benchmark text is redistributed. Passing automated checks does not constitute compliance certification.

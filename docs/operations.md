# Operations: backup, restore, export, retention

## Backup and restore (SQLite)

```
cloudranger db backup --output backups/cloudranger-2026-07-13.db
cloudranger db restore backups/cloudranger-2026-07-13.db [--force]
```

Backups use SQLite's online backup API, so they are consistent even while
scans are running. **A backup contains raw evidence and findings — protect it
exactly like the live database.** Backup files are written mode `0600`;
restore refuses to overwrite an existing database without `--force`, and
integrity-checks the backup (`PRAGMA quick_check`) before touching anything.

PostgreSQL deployments back up with the standard tooling instead:

```
pg_dump "$CLOUDRANGER_DATABASE_URL" --format=custom --file cloudranger.dump
pg_restore --dbname "$CLOUDRANGER_DATABASE_URL" cloudranger.dump
```

## Findings export

```
cloudranger findings export --format csv   [filters] [--output findings.csv]
cloudranger findings export --format jsonl [filters] [--output findings.jsonl]
cloudranger findings export --format sarif [filters] [--output findings.sarif]
```

Filters: `--state open,reopened` `--severity critical,high` `--provider aws`
`--scope <id>`. Without `--output` the export streams to stdout.

- **CSV** — column set is stable (append-only contract) for spreadsheets and
  BI ingestion.
- **JSONL** — one finding object per line, for SIEM/log pipelines.
- **SARIF 2.1.0** — controls become rules (severity → error/warning/note),
  resources become logical locations, and finding fingerprints ride in
  `partialFingerprints`, so the file loads in GitHub code scanning and other
  SARIF viewers.

## Evidence retention

See `cloudranger retention` (and the `retention_policy_set` /
`evidence_prune` MCP tools): per-scope `keepDays`/`keepScans` policies,
dry-run by default, and pruning that clears raw payloads only — findings,
evaluations, and evidence digests (hash, size, captured-at) always survive,
so audit trails remain verifiable after space is reclaimed.

## Remote agents: streamable-HTTP transport

```
CLOUDRANGER_HTTP_TOKEN=$(openssl rand -hex 32) node apps/mcp-server/dist/main.js --http
```

Stdio remains the default; `--http` (or `CLOUDRANGER_HTTP=true`) starts the
MCP streamable-HTTP listener instead. Configuration:

| Env                                | Default       | Notes                                                                                           |
| ---------------------------------- | ------------- | ----------------------------------------------------------------------------------------------- |
| `CLOUDRANGER_HTTP_TOKEN` / `_FILE` | — (required)  | Bearer token, ≥16 chars; checked in constant time before anything else.                         |
| `CLOUDRANGER_HTTP_PORT`            | `8484`        |                                                                                                 |
| `CLOUDRANGER_HTTP_BIND`            | `127.0.0.1`   | Non-loopback binds require `CLOUDRANGER_HTTP_ALLOW_NONLOOPBACK=true`; a loud warning is logged. |
| `CLOUDRANGER_HTTP_ALLOWED_ORIGINS` | loopback only | Comma-separated extra `Origin` values for browser-based clients.                                |

The listener never terminates TLS — put a TLS-terminating reverse proxy
(Caddy, nginx, a tunnel) in front of any non-loopback deployment, and treat
the token like a database credential. Threat model: T6 in
docs/architecture/threat-model.md.

## Catalog signing and third-party packs

Signatures prove **provenance, never safety** — every loaded document passes
the same schema and read-only safety validation regardless of signature
status.

Release signing (repository owner):

```
node scripts/catalog-sign.mjs keygen cloudranger-catalog   # once; commit only the .pub.pem
# Add the private key as the CLOUDRANGER_CATALOG_SIGNING_KEY repo secret.
# Tagged releases then ship catalog.manifest.json + catalog.manifest.sig.
node scripts/catalog-sign.mjs verify packages/catalog/catalog --pub cloudranger-catalog.pub.pem
```

Key rotation: generate a new pair, publish the new public key alongside the
old one for one release cycle, then retire the old key. Verifiers accept any
pinned key, so overlap is safe.

Third-party packs (operators):

```
mkdir -p ~/.cloudranger/trusted-keys           # pin publisher public keys here
cloudranger packs add ./vendor-pack            # verify → safety-validate → fixture-check → install
cloudranger packs add ./local-pack --trust-unsigned   # explicit opt-in for unsigned packs
```

`packs add` refuses unverified packs by default, runs full catalog safety
validation (read-only collector allowlist, schema, parameter coherence) and
rejects packs whose fixtures disagree with the engine — a valid signature on
a mutating collector still fails. Installed files land in the custom catalog
prefixed with the pack name.

## Agent-driven notification hooks

```
CLOUDRANGER_SLACK_WEBHOOK_URL=https://hooks.slack.com/…      # destination "slack"
CLOUDRANGER_NOTIFY_WEBHOOKS="soc=https://soc.example/hook"   # named generic webhooks (https only)
CLOUDRANGER_NOTIFY_HMAC_SECRET=…                             # sign webhook bodies (x-cloudranger-signature)
```

After `scan_evaluate`, an agent may call `notify_scan_digest { scanId,
destination }`. The agent only ever selects a destination **name** from the
operator allow-list — URLs are never exposed to or accepted from the agent,
so there is no SSRF surface. Digest payloads contain scan summaries and
finding references only; raw evidence never leaves the store through
notifications. Nothing is ever sent automatically.

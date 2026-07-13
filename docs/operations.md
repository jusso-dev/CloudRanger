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

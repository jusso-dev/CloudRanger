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

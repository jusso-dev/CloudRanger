# ADR-0003: SQLite (better-sqlite3), no Docker dependency

**Status:** accepted · 2026-07-12

## Decision

Single SQLite file (default `~/.cloudranger/cloudranger.db`), WAL mode,
migrations via `PRAGMA user_version`. Synchronous `better-sqlite3` driver.
Plain SQL, no ORM.

## Rationale

- Product is a local, single-operator stdio MCP server: zero-dependency
  startup beats Postgres+Docker for this shape (original Postgres plan was
  descoped with the no-web-UI pivot).
- Synchronous driver makes finding reconciliation a straightforward
  transaction; JSON columns hold evidence.

## Consequences

- Single-writer; fine for one MCP server instance. Revisit (Postgres behind
  the same store interface) if a multi-user deployment ever materialises.
- Backup = copy one file.

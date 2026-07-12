# ADR-0001: TypeScript pnpm monorepo

**Status:** accepted · 2026-07-12

## Decision

pnpm workspaces + Turborepo, strict TypeScript (ESM, NodeNext), vitest,
eslint flat config. Packages: `engine` (pure), `catalog` (data), `db`
(storage); apps: `mcp-server`, `cli`.

## Rationale

- The MCP TypeScript SDK is first-class; one language across engine, server
  and CLI.
- Strict separation keeps the deterministic core (`engine`) free of I/O so
  it is trivially testable and reusable (CLI, tests, future runners).
- pnpm/turbo are low-ceremony for a repo this size while allowing growth.

## Consequences

Node ≥ 22 required. `better-sqlite3` is the only native dependency.

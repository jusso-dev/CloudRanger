# ADR-0002: Agent-executed evidence collection

**Status:** accepted · 2026-07-12

## Context

Classic CSPMs hold cloud credentials and run SDK collectors. The operator
explicitly wants the LLM agent (Claude/Codex) to drive scanning using the
cloud CLIs it already has authenticated.

## Decision

CloudRanger never touches cloud credentials or APIs. `scan_start` returns a
**collection plan**: exact read-only `aws`/`az`/`gcloud` commands (validated
against a verb allowlist + shell-metacharacter screen). The agent executes
them and submits JSON via `evidence_submit`. The engine evaluates only what
was submitted.

## Rationale

- Smallest possible credential surface: the server can't leak what it never
  has.
- Reuses the operator's existing CLI auth (SSO, profiles, MFA) — zero
  onboarding infrastructure.
- Agent harnesses (Claude Code) already gate command execution with
  permission prompts, adding a human checkpoint.

## Consequences / trade-offs

- Scan fidelity depends on the agent faithfully relaying CLI output
  (threat T3): mitigated by evidence hashing, identity verification in the
  workflow, and deterministic re-evaluation.
- Collection is slower than parallel SDK calls; acceptable for
  daily-cadence posture scanning.
- CLI JSON shapes are the evidence contract; controls are written (and
  fixture-tested) against them.

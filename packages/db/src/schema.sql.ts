/**
 * SQLite schema, applied via PRAGMA user_version migrations. Append new
 * migrations to the end of MIGRATIONS — never edit an applied entry.
 */
export const MIGRATIONS: string[] = [
  `
  CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL CHECK (provider IN ('aws','azure','gcp')),
    scope_id TEXT NOT NULL,
    regions TEXT NOT NULL DEFAULT '[]',
    control_ids TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'collecting'
      CHECK (status IN ('collecting','evaluated','cancelled')),
    created_at TEXT NOT NULL,
    evaluated_at TEXT,
    coverage TEXT,
    summary TEXT
  );

  CREATE TABLE evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    collector_id TEXT NOT NULL,
    region TEXT,
    resource_key TEXT,
    output TEXT,
    error_text TEXT,
    exit_code INTEGER NOT NULL,
    evidence_hash TEXT NOT NULL,
    collected_at TEXT NOT NULL
  );
  CREATE INDEX idx_evidence_scan ON evidence(scan_id, collector_id);

  CREATE TABLE evaluations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL,
    control_version TEXT NOT NULL,
    status TEXT NOT NULL
      CHECK (status IN ('pass','fail','not_applicable','error','not_assessed')),
    severity TEXT NOT NULL,
    service TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_name TEXT,
    region TEXT,
    message TEXT NOT NULL,
    evidence TEXT,
    evaluated_at TEXT NOT NULL
  );
  CREATE INDEX idx_evaluations_scan ON evaluations(scan_id);
  CREATE INDEX idx_evaluations_control ON evaluations(control_id, status);

  CREATE TABLE findings (
    fingerprint TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    control_version TEXT NOT NULL,
    severity TEXT NOT NULL,
    service TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_name TEXT,
    region TEXT,
    state TEXT NOT NULL DEFAULT 'open'
      CHECK (state IN ('open','resolved','reopened')),
    workflow_state TEXT NOT NULL DEFAULT 'new'
      CHECK (workflow_state IN ('new','acknowledged','in_progress','risk_accepted','false_positive','closed')),
    workflow_reason TEXT,
    workflow_actor TEXT,
    workflow_expires_at TEXT,
    message TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    resolved_at TEXT,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    reopen_count INTEGER NOT NULL DEFAULT 0,
    last_scan_id TEXT NOT NULL,
    latest_evidence TEXT
  );
  CREATE INDEX idx_findings_state ON findings(state, severity);
  CREATE INDEX idx_findings_scope ON findings(provider, scope_id);
  CREATE INDEX idx_findings_control ON findings(control_id);

  CREATE TABLE finding_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL REFERENCES findings(fingerprint) ON DELETE CASCADE,
    scan_id TEXT,
    event_type TEXT NOT NULL
      CHECK (event_type IN ('created','recurred','resolved','reopened','workflow_change','comment')),
    from_state TEXT,
    to_state TEXT,
    message TEXT,
    evidence TEXT,
    actor TEXT,
    created_at TEXT NOT NULL
  );
  CREATE INDEX idx_finding_events_fp ON finding_events(fingerprint, created_at);

  CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    tool TEXT NOT NULL,
    args TEXT,
    success INTEGER NOT NULL,
    detail TEXT,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
  );
  `,
  `
  ALTER TABLE findings ADD COLUMN owner TEXT;
  ALTER TABLE findings ADD COLUMN due_at TEXT;
  CREATE INDEX idx_findings_owner_due ON findings(owner, due_at);
  `,
  `
  CREATE TABLE workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE identities (
    subject TEXT PRIMARY KEY,
    display_name TEXT,
    created_at TEXT NOT NULL
  );
  CREATE TABLE workspace_memberships (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    subject TEXT NOT NULL REFERENCES identities(subject) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('admin','operator','auditor','reader')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, subject)
  );
  CREATE INDEX idx_workspace_memberships_subject ON workspace_memberships(subject);
  `,
  `
  ALTER TABLE scans ADD COLUMN parameters TEXT;
  ALTER TABLE evaluations ADD COLUMN effective_parameters TEXT;
  ALTER TABLE findings ADD COLUMN effective_parameters TEXT;
  CREATE TABLE scope_parameters (
    provider TEXT NOT NULL CHECK (provider IN ('aws','azure','gcp')),
    scope_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    parameters TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (provider, scope_id, control_id)
  );
  `,
];

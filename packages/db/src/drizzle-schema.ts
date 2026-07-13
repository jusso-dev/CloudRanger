import {
  boolean,
  index,
  integer,
  jsonb,
  primaryKey,
  pgTable,
  text,
  timestamp,
  varchar,
} from "drizzle-orm/pg-core";

/**
 * PostgreSQL schema used by Drizzle for shared/team deployments. SQLite keeps
 * its existing migration path for backwards compatibility; the column names
 * intentionally match so exports and future repository adapters are portable.
 */
export const scans = pgTable("scans", {
  id: varchar("id", { length: 36 }).primaryKey(),
  provider: varchar("provider", { length: 16 }).notNull(),
  scopeId: text("scope_id").notNull(),
  regions: jsonb("regions").$type<string[]>().notNull().default([]),
  controlIds: jsonb("control_ids").$type<string[]>().notNull().default([]),
  status: varchar("status", { length: 16 }).notNull().default("collecting"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  evaluatedAt: timestamp("evaluated_at", { withTimezone: true }),
  coverage: jsonb("coverage"),
  summary: jsonb("summary"),
  parameters: jsonb("parameters").$type<Record<string, Record<string, unknown>>>(),
});

export const evidence = pgTable(
  "evidence",
  {
    id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
    scanId: varchar("scan_id", { length: 36 }).notNull(),
    collectorId: text("collector_id").notNull(),
    region: text("region"),
    resourceKey: text("resource_key"),
    output: jsonb("output"),
    errorText: text("error_text"),
    exitCode: integer("exit_code").notNull(),
    evidenceHash: text("evidence_hash").notNull(),
    collectedAt: timestamp("collected_at", { withTimezone: true }).notNull(),
  },
  (table) => [index("idx_evidence_scan").on(table.scanId, table.collectorId)],
);

export const evaluations = pgTable("evaluations", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  scanId: varchar("scan_id", { length: 36 }).notNull(),
  controlId: text("control_id").notNull(),
  controlVersion: text("control_version").notNull(),
  status: text("status").notNull(),
  severity: text("severity").notNull(),
  service: text("service").notNull(),
  resourceId: text("resource_id").notNull(),
  resourceName: text("resource_name"),
  region: text("region"),
  message: text("message").notNull(),
  evidence: jsonb("evidence"),
  effectiveParameters: jsonb("effective_parameters"),
  evaluatedAt: timestamp("evaluated_at", { withTimezone: true }).notNull(),
});

export const findings = pgTable(
  "findings",
  {
    fingerprint: text("fingerprint").primaryKey(),
    provider: text("provider").notNull(),
    scopeId: text("scope_id").notNull(),
    controlId: text("control_id").notNull(),
    controlVersion: text("control_version").notNull(),
    severity: text("severity").notNull(),
    service: text("service").notNull(),
    resourceId: text("resource_id").notNull(),
    resourceName: text("resource_name"),
    region: text("region"),
    state: text("state").notNull().default("open"),
    workflowState: text("workflow_state").notNull().default("new"),
    workflowReason: text("workflow_reason"),
    workflowActor: text("workflow_actor"),
    workflowExpiresAt: timestamp("workflow_expires_at", { withTimezone: true }),
    owner: text("owner"),
    dueAt: timestamp("due_at", { withTimezone: true }),
    message: text("message").notNull(),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull(),
    resolvedAt: timestamp("resolved_at", { withTimezone: true }),
    occurrenceCount: integer("occurrence_count").notNull().default(1),
    reopenCount: integer("reopen_count").notNull().default(0),
    lastScanId: varchar("last_scan_id", { length: 36 }).notNull(),
    latestEvidence: jsonb("latest_evidence"),
    effectiveParameters: jsonb("effective_parameters"),
  },
  (table) => [
    index("idx_findings_state").on(table.state, table.severity),
    index("idx_findings_scope").on(table.provider, table.scopeId),
    index("idx_findings_control").on(table.controlId),
    index("idx_findings_owner_due").on(table.owner, table.dueAt),
  ],
);

export const findingEvents = pgTable("finding_events", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  fingerprint: text("fingerprint").notNull(),
  scanId: varchar("scan_id", { length: 36 }),
  eventType: text("event_type").notNull(),
  fromState: text("from_state"),
  toState: text("to_state"),
  message: text("message"),
  evidence: jsonb("evidence"),
  actor: text("actor"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
});

export const auditLog = pgTable("audit_log", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  actor: text("actor").notNull(),
  tool: text("tool").notNull(),
  args: jsonb("args"),
  success: boolean("success").notNull(),
  detail: text("detail"),
  prevHash: text("prev_hash").notNull(),
  entryHash: text("entry_hash").notNull(),
});

export const workspaces = pgTable("workspaces", {
  id: varchar("id", { length: 63 }).primaryKey(),
  name: text("name").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
});

export const identities = pgTable("identities", {
  subject: text("subject").primaryKey(),
  displayName: text("display_name"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
});

export const workspaceMemberships = pgTable(
  "workspace_memberships",
  {
    workspaceId: varchar("workspace_id", { length: 63 })
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    subject: text("subject")
      .notNull()
      .references(() => identities.subject, { onDelete: "cascade" }),
    role: varchar("role", {
      length: 16,
      enum: ["admin", "operator", "auditor", "reader"],
    }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.workspaceId, table.subject] }),
    index("idx_workspace_memberships_subject").on(table.subject),
  ],
);

export const scopeParameters = pgTable(
  "scope_parameters",
  {
    provider: varchar("provider", { length: 16 }).notNull(),
    scopeId: text("scope_id").notNull(),
    controlId: text("control_id").notNull(),
    parameters: jsonb("parameters").$type<Record<string, unknown>>().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
  },
  (table) => [primaryKey({ columns: [table.provider, table.scopeId, table.controlId] })],
);

export const controlRevisions = pgTable(
  "control_revisions",
  {
    controlId: text("control_id").notNull(),
    version: text("version").notNull(),
    contentHash: text("content_hash").notNull(),
    definition: jsonb("definition").notNull(),
    deprecated: boolean("deprecated").notNull().default(false),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.controlId, table.version, table.contentHash] }),
    index("idx_control_revisions_control").on(table.controlId, table.firstSeenAt),
  ],
);

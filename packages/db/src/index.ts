import Database from "better-sqlite3";
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import {
  evidenceHash,
  findingFingerprint,
  reconcileOne,
  type ControlCoverage,
  type EvaluationResult,
  type EvidenceRecord,
  type FindingState,
  type PriorFinding,
  type Provider,
  type WorkflowState,
} from "@cloudranger/engine";
import { MIGRATIONS } from "./schema.sql.js";

export { createPostgresDatabase } from "./postgres.js";
export type { PostgresDatabase } from "./postgres.js";
export { createRepository, type RepositoryConfig } from "./factory.js";
export { PostgresCloudRangerStore } from "./postgres-store.js";
export type { CloudRangerRepository, WorkspaceMember, WorkspaceRole } from "./repository.js";

export interface ScanRow {
  id: string;
  provider: Provider;
  scopeId: string;
  regions: string[];
  controlIds: string[];
  status: "collecting" | "evaluated" | "cancelled";
  /** Per-control parameter overrides captured at scan start. */
  parameters?: Record<string, Record<string, unknown>>;
  createdAt: string;
  evaluatedAt?: string;
  coverage?: ControlCoverage[];
  summary?: ScanSummary;
}

export interface ScanSummary {
  pass: number;
  fail: number;
  error: number;
  notApplicable: number;
  coverageRatio: number;
  findingsCreated: number;
  findingsRecurred: number;
  findingsResolved: number;
  findingsReopened: number;
  evidenceRecords?: number;
  evidenceErrors?: number;
}

export interface ScanHealth {
  scanId: string;
  status: ScanRow["status"] | "stale";
  healthy: boolean;
  stale: boolean;
  ageMinutes: number;
  requestedControls: number;
  evaluatedControls: number;
  missingEvidenceControls: number;
  coverageRatio: number;
  evidenceRecords: number;
  evidenceErrors: number;
  expectedCollectors: number;
  observedCollectors: number;
  missingCollectors: string[];
  reasons: string[];
}

export interface FindingRow {
  fingerprint: string;
  provider: Provider;
  scopeId: string;
  controlId: string;
  controlVersion: string;
  severity: string;
  service: string;
  resourceId: string;
  resourceName?: string;
  region?: string;
  state: FindingState;
  workflowState: WorkflowState;
  workflowReason?: string;
  workflowActor?: string;
  workflowExpiresAt?: string;
  owner?: string;
  dueAt?: string;
  message: string;
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt?: string;
  occurrenceCount: number;
  reopenCount: number;
  lastScanId: string;
  latestEvidence?: unknown;
  /** Effective parameter values in force when the finding was last evaluated. */
  effectiveParameters?: Record<string, unknown>;
}

export interface FindingEventRow {
  id: number;
  fingerprint: string;
  scanId?: string;
  eventType: string;
  fromState?: string;
  toState?: string;
  message?: string;
  evidence?: unknown;
  actor?: string;
  createdAt: string;
}

export interface FindingSearchFilters {
  provider?: Provider;
  scopeId?: string;
  controlId?: string;
  service?: string;
  severity?: string[];
  state?: FindingState[];
  workflowState?: WorkflowState[];
  resourceId?: string;
  limit?: number;
  offset?: number;
  owner?: string;
  overdue?: boolean;
}

export interface ScanComparison {
  baseline: {
    scanId: string;
    provider: Provider;
    scopeId: string;
    evaluatedAt?: string;
    summary?: ScanSummary;
  };
  current: {
    scanId: string;
    provider: Provider;
    scopeId: string;
    evaluatedAt?: string;
    summary?: ScanSummary;
  };
  coverage: {
    baseline: number;
    current: number;
    delta: number;
    baselineEvaluated: number;
    currentEvaluated: number;
    baselineRequested: number;
    currentRequested: number;
  };
  controlChanges: Array<{
    controlId: string;
    resourceId: string;
    region?: string;
    baseline: string;
    current: string;
    message?: string;
    severity?: string;
  }>;
  findingEvents: Record<string, number>;
}

const j = (v: unknown) => JSON.stringify(v);
const pj = <T>(v: unknown, fallback: T): T => {
  if (typeof v !== "string" || v.length === 0) return fallback;
  try {
    return JSON.parse(v) as T;
  } catch {
    return fallback;
  }
};

export class CloudRangerStore {
  readonly db: Database.Database;

  constructor(path: string) {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.migrate();
  }

  private migrate(): void {
    const current = this.db.pragma("user_version", { simple: true }) as number;
    for (let v = current; v < MIGRATIONS.length; v++) {
      this.db.transaction(() => {
        this.db.exec(MIGRATIONS[v]!);
        this.db.pragma(`user_version = ${v + 1}`);
      })();
    }
  }

  close(): void {
    this.db.close();
  }

  initializeWorkspace(input: {
    workspaceId: string;
    workspaceName: string;
    subject: string;
    displayName?: string;
    bootstrapAdmin?: boolean;
  }): import("./repository.js").WorkspaceRole {
    const existing = this.db.prepare("SELECT id FROM workspaces LIMIT 1").get() as
      { id: string } | undefined;
    if (!existing) {
      if (!input.bootstrapAdmin) {
        throw new Error("workspace is not initialized; set CLOUDRANGER_BOOTSTRAP_ADMIN=true once");
      }
      const now = new Date().toISOString();
      this.db.transaction(() => {
        this.db
          .prepare("INSERT INTO workspaces (id, name, created_at) VALUES (?, ?, ?)")
          .run(input.workspaceId, input.workspaceName, now);
        this.db
          .prepare("INSERT INTO identities (subject, display_name, created_at) VALUES (?, ?, ?)")
          .run(input.subject, input.displayName ?? null, now);
        this.db
          .prepare(
            "INSERT INTO workspace_memberships (workspace_id, subject, role, created_at, updated_at) VALUES (?, ?, 'admin', ?, ?)",
          )
          .run(input.workspaceId, input.subject, now, now);
      })();
      return "admin";
    }
    if (existing.id !== input.workspaceId) {
      throw new Error(`database is bound to workspace ${existing.id}, not ${input.workspaceId}`);
    }
    const membership = this.db
      .prepare("SELECT role FROM workspace_memberships WHERE workspace_id = ? AND subject = ?")
      .get(input.workspaceId, input.subject) as
      { role: import("./repository.js").WorkspaceRole } | undefined;
    if (!membership) throw new Error(`identity ${input.subject} is not a workspace member`);
    return membership.role;
  }

  listWorkspaceMembers(workspaceId: string): import("./repository.js").WorkspaceMember[] {
    return this.db
      .prepare(
        `SELECT m.subject, i.display_name, m.role, m.created_at, m.updated_at
         FROM workspace_memberships m JOIN identities i ON i.subject = m.subject
         WHERE m.workspace_id = ? ORDER BY m.subject`,
      )
      .all(workspaceId)
      .map((row: any) => ({
        subject: row.subject,
        displayName: row.display_name ?? undefined,
        role: row.role,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      }));
  }

  setWorkspaceMember(input: {
    workspaceId: string;
    subject: string;
    displayName?: string;
    role: import("./repository.js").WorkspaceRole;
  }): void {
    const now = new Date().toISOString();
    this.db.transaction(() => {
      const workspace = this.db
        .prepare("SELECT id FROM workspaces WHERE id = ?")
        .get(input.workspaceId);
      if (!workspace) throw new Error(`unknown workspace: ${input.workspaceId}`);
      const existing = this.db
        .prepare("SELECT role FROM workspace_memberships WHERE workspace_id = ? AND subject = ?")
        .get(input.workspaceId, input.subject) as { role: string } | undefined;
      if (existing?.role === "admin" && input.role !== "admin") {
        const admins = (
          this.db
            .prepare(
              "SELECT COUNT(*) AS count FROM workspace_memberships WHERE workspace_id = ? AND role = 'admin'",
            )
            .get(input.workspaceId) as { count: number }
        ).count;
        if (admins <= 1) throw new Error("cannot demote the last workspace admin");
      }
      this.db
        .prepare(
          `INSERT INTO identities (subject, display_name, created_at) VALUES (?, ?, ?)
           ON CONFLICT(subject) DO UPDATE SET display_name = COALESCE(excluded.display_name, identities.display_name)`,
        )
        .run(input.subject, input.displayName ?? null, now);
      this.db
        .prepare(
          `INSERT INTO workspace_memberships (workspace_id, subject, role, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(workspace_id, subject) DO UPDATE SET role = excluded.role, updated_at = excluded.updated_at`,
        )
        .run(input.workspaceId, input.subject, input.role, now, now);
    })();
  }

  removeWorkspaceMember(workspaceId: string, subject: string): void {
    this.db.transaction(() => {
      const member = this.db
        .prepare("SELECT role FROM workspace_memberships WHERE workspace_id = ? AND subject = ?")
        .get(workspaceId, subject) as { role: string } | undefined;
      if (!member) throw new Error(`identity ${subject} is not a workspace member`);
      if (member.role === "admin") {
        const admins = (
          this.db
            .prepare(
              "SELECT COUNT(*) AS count FROM workspace_memberships WHERE workspace_id = ? AND role = 'admin'",
            )
            .get(workspaceId) as { count: number }
        ).count;
        if (admins <= 1) throw new Error("cannot remove the last workspace admin");
      }
      this.db
        .prepare("DELETE FROM workspace_memberships WHERE workspace_id = ? AND subject = ?")
        .run(workspaceId, subject);
    })();
  }

  // ---- scans ----

  createScan(input: {
    provider: Provider;
    scopeId: string;
    regions: string[];
    controlIds: string[];
    parameters?: Record<string, Record<string, unknown>>;
  }): ScanRow {
    const id = randomUUID();
    const createdAt = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO scans (id, provider, scope_id, regions, control_ids, status, created_at, parameters)
         VALUES (?, ?, ?, ?, ?, 'collecting', ?, ?)`,
      )
      .run(
        id,
        input.provider,
        input.scopeId,
        j(input.regions),
        j(input.controlIds),
        createdAt,
        input.parameters && Object.keys(input.parameters).length > 0 ? j(input.parameters) : null,
      );
    return this.getScan(id)!;
  }

  // ---- retention ----

  setRetentionPolicy(
    provider: Provider,
    scopeId: string,
    policy: { keepDays?: number; keepScans?: number } | null,
  ): void {
    if (policy === null || (policy.keepDays === undefined && policy.keepScans === undefined)) {
      this.db
        .prepare("DELETE FROM retention_policies WHERE provider = ? AND scope_id = ?")
        .run(provider, scopeId);
      return;
    }
    this.db
      .prepare(
        `INSERT INTO retention_policies (provider, scope_id, keep_days, keep_scans, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (provider, scope_id)
         DO UPDATE SET keep_days = excluded.keep_days, keep_scans = excluded.keep_scans, updated_at = excluded.updated_at`,
      )
      .run(
        provider,
        scopeId,
        policy.keepDays ?? null,
        policy.keepScans ?? null,
        new Date().toISOString(),
      );
  }

  listRetentionPolicies(): Array<{
    provider: Provider;
    scopeId: string;
    keepDays?: number;
    keepScans?: number;
    updatedAt: string;
  }> {
    const rows = this.db
      .prepare("SELECT * FROM retention_policies ORDER BY provider, scope_id")
      .all() as any[];
    return rows.map((row) => ({
      provider: row.provider,
      scopeId: row.scope_id,
      keepDays: row.keep_days ?? undefined,
      keepScans: row.keep_scans ?? undefined,
      updatedAt: row.updated_at,
    }));
  }

  /**
   * Prune raw evidence payloads for one scope according to its retention
   * policy. Findings, evaluations, scan metadata and evidence digests
   * (hash, size, captured-at) are always preserved — only `output` is
   * cleared, with pruned_at/output_bytes recording what was removed. Dry
   * run by default; execute performs the update inside a transaction and
   * VACUUMs afterwards.
   */
  pruneEvidence(input: { provider: Provider; scopeId: string; execute?: boolean }): {
    policy: { keepDays?: number; keepScans?: number };
    protectedScans: number;
    prunableScans: string[];
    prunableRecords: number;
    prunableBytes: number;
    executed: boolean;
  } {
    const policy = this.listRetentionPolicies().find(
      (p) => p.provider === input.provider && p.scopeId === input.scopeId,
    );
    if (!policy) {
      throw new Error(`no retention policy for ${input.provider}/${input.scopeId} — set one first`);
    }
    const scans = this.db
      .prepare(
        "SELECT id, created_at FROM scans WHERE provider = ? AND scope_id = ? ORDER BY created_at DESC, rowid DESC",
      )
      .all(input.provider, input.scopeId) as Array<{ id: string; created_at: string }>;
    const cutoff =
      policy.keepDays !== undefined
        ? new Date(Date.now() - policy.keepDays * 86_400_000).toISOString()
        : undefined;
    const protectedIds = new Set<string>();
    for (const [index, scan] of scans.entries()) {
      const byCount = policy.keepScans !== undefined && index < policy.keepScans;
      const byAge = cutoff !== undefined && scan.created_at >= cutoff;
      if (byCount || byAge) protectedIds.add(scan.id);
    }
    const prunable = scans.filter((scan) => !protectedIds.has(scan.id)).map((scan) => scan.id);
    let prunableRecords = 0;
    let prunableBytes = 0;
    if (prunable.length > 0) {
      const placeholders = prunable.map(() => "?").join(",");
      const row = this.db
        .prepare(
          `SELECT COUNT(*) AS records, COALESCE(SUM(LENGTH(output)), 0) AS bytes
           FROM evidence WHERE scan_id IN (${placeholders}) AND output IS NOT NULL`,
        )
        .get(...prunable) as { records: number; bytes: number };
      prunableRecords = row.records;
      prunableBytes = row.bytes;
      if (input.execute && prunableRecords > 0) {
        const now = new Date().toISOString();
        this.db.transaction(() => {
          this.db
            .prepare(
              `UPDATE evidence SET output_bytes = LENGTH(output), output = NULL, pruned_at = ?
               WHERE scan_id IN (${placeholders}) AND output IS NOT NULL`,
            )
            .run(now, ...prunable);
        })();
        this.db.exec("VACUUM");
      }
    }
    return {
      policy: { keepDays: policy.keepDays, keepScans: policy.keepScans },
      protectedScans: protectedIds.size,
      prunableScans: prunable,
      prunableRecords,
      prunableBytes,
      executed: Boolean(input.execute && prunableRecords > 0),
    };
  }

  // ---- control revisions ----

  /**
   * Record the current revision of each control (id + version + content
   * hash). Idempotent: an existing (id, version, hash) row is untouched, so
   * first_seen_at marks when that exact revision first reached this store.
   */
  recordControlRevisions(
    revisions: Array<{
      controlId: string;
      version: string;
      contentHash: string;
      definition: unknown;
      deprecated: boolean;
    }>,
  ): number {
    const insert = this.db.prepare(
      `INSERT OR IGNORE INTO control_revisions (control_id, version, content_hash, definition, deprecated, first_seen_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    );
    const now = new Date().toISOString();
    let added = 0;
    const tx = this.db.transaction(() => {
      for (const r of revisions) {
        const result = insert.run(
          r.controlId,
          r.version,
          r.contentHash,
          j(r.definition),
          r.deprecated ? 1 : 0,
          now,
        );
        added += result.changes;
      }
    });
    tx();
    return added;
  }

  listControlRevisions(controlId: string): Array<{
    controlId: string;
    version: string;
    contentHash: string;
    definition: unknown;
    deprecated: boolean;
    firstSeenAt: string;
  }> {
    const rows = this.db
      .prepare(
        "SELECT * FROM control_revisions WHERE control_id = ? ORDER BY first_seen_at, version",
      )
      .all(controlId) as any[];
    return rows.map((row) => ({
      controlId: row.control_id,
      version: row.version,
      contentHash: row.content_hash,
      definition: pj(row.definition, undefined),
      deprecated: row.deprecated === 1,
      firstSeenAt: row.first_seen_at,
    }));
  }

  // ---- scope parameter overrides ----

  /** Set (or clear, with null) persisted parameter overrides for one control in a scope. */
  setScopeParameters(
    provider: Provider,
    scopeId: string,
    controlId: string,
    parameters: Record<string, unknown> | null,
  ): void {
    if (parameters === null || Object.keys(parameters).length === 0) {
      this.db
        .prepare(
          "DELETE FROM scope_parameters WHERE provider = ? AND scope_id = ? AND control_id = ?",
        )
        .run(provider, scopeId, controlId);
      return;
    }
    this.db
      .prepare(
        `INSERT INTO scope_parameters (provider, scope_id, control_id, parameters, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (provider, scope_id, control_id)
         DO UPDATE SET parameters = excluded.parameters, updated_at = excluded.updated_at`,
      )
      .run(provider, scopeId, controlId, j(parameters), new Date().toISOString());
  }

  listScopeParameters(
    provider: Provider,
    scopeId: string,
  ): Array<{ controlId: string; parameters: Record<string, unknown>; updatedAt: string }> {
    const rows = this.db
      .prepare(
        "SELECT control_id, parameters, updated_at FROM scope_parameters WHERE provider = ? AND scope_id = ? ORDER BY control_id",
      )
      .all(provider, scopeId) as any[];
    return rows.map((row) => ({
      controlId: row.control_id,
      parameters: pj(row.parameters, {}),
      updatedAt: row.updated_at,
    }));
  }

  getScan(id: string): ScanRow | undefined {
    const row = this.db.prepare("SELECT * FROM scans WHERE id = ?").get(id) as any;
    return row ? mapScan(row) : undefined;
  }

  listScans(limit = 20): ScanRow[] {
    const rows = this.db
      .prepare("SELECT * FROM scans ORDER BY created_at DESC, rowid DESC LIMIT ?")
      .all(limit) as any[];
    return rows.map(mapScan);
  }

  compareScans(baselineScanId: string, currentScanId: string): ScanComparison {
    const baseline = this.getScan(baselineScanId);
    const current = this.getScan(currentScanId);
    if (!baseline || !current) throw new Error("both scans must exist");
    if (baseline.status !== "evaluated" || current.status !== "evaluated") {
      throw new Error("both scans must be evaluated before comparison");
    }
    if (baseline.provider !== current.provider || baseline.scopeId !== current.scopeId) {
      throw new Error("scans must use the same provider and scope");
    }
    const rows = (scanId: string) =>
      this.db
        .prepare(
          `SELECT control_id, resource_id, region, status, message, severity
           FROM evaluations WHERE scan_id = ?
           ORDER BY control_id, resource_id, region`,
        )
        .all(scanId) as Array<{
        control_id: string;
        resource_id: string;
        region: string | null;
        status: string;
        message: string;
      }>;
    const key = (row: { control_id: string; resource_id: string; region: string | null }) =>
      `${row.control_id}\u0000${row.resource_id}\u0000${row.region ?? ""}`;
    const before = new Map(rows(baselineScanId).map((row) => [key(row), row]));
    const after = new Map(rows(currentScanId).map((row) => [key(row), row]));
    const controlChanges: ScanComparison["controlChanges"] = [];
    for (const [entryKey, currentRow] of after) {
      const baselineRow = before.get(entryKey);
      if (baselineRow && baselineRow.status === currentRow.status) continue;
      controlChanges.push({
        controlId: currentRow.control_id,
        resourceId: currentRow.resource_id,
        region: currentRow.region ?? undefined,
        baseline: baselineRow?.status ?? "not_assessed",
        current: currentRow.status,
        message: currentRow.message,
        severity: (currentRow as any).severity,
      });
    }
    for (const [entryKey, baselineRow] of before) {
      if (after.has(entryKey)) continue;
      controlChanges.push({
        controlId: baselineRow.control_id,
        resourceId: baselineRow.resource_id,
        region: baselineRow.region ?? undefined,
        baseline: baselineRow.status,
        current: "not_assessed",
        message: "Resource or evaluation was not present in the current scan.",
        severity: (baselineRow as any).severity,
      });
    }
    const eventRows = this.db
      .prepare(
        `SELECT event_type, COUNT(*) AS n FROM finding_events
         WHERE scan_id IN (?, ?) GROUP BY event_type`,
      )
      .all(baselineScanId, currentScanId) as Array<{ event_type: string; n: number }>;
    const eventCounts = Object.fromEntries(eventRows.map((row) => [row.event_type, row.n]));
    const coverage = (scan: ScanRow) => ({
      ratio: scan.summary?.coverageRatio ?? 0,
      evaluated: scan.coverage?.filter((item) => item.status === "evaluated").length ?? 0,
      requested: scan.coverage?.length ?? scan.controlIds.length,
    });
    const beforeCoverage = coverage(baseline);
    const afterCoverage = coverage(current);
    return {
      baseline: {
        scanId: baseline.id,
        provider: baseline.provider,
        scopeId: baseline.scopeId,
        evaluatedAt: baseline.evaluatedAt,
        summary: baseline.summary,
      },
      current: {
        scanId: current.id,
        provider: current.provider,
        scopeId: current.scopeId,
        evaluatedAt: current.evaluatedAt,
        summary: current.summary,
      },
      coverage: {
        baseline: beforeCoverage.ratio,
        current: afterCoverage.ratio,
        delta: afterCoverage.ratio - beforeCoverage.ratio,
        baselineEvaluated: beforeCoverage.evaluated,
        currentEvaluated: afterCoverage.evaluated,
        baselineRequested: beforeCoverage.requested,
        currentRequested: afterCoverage.requested,
      },
      controlChanges,
      findingEvents: eventCounts,
    };
  }

  /** Evaluation rows for one scan, aggregated per control by the caller. */
  getEvaluations(scanId: string): Array<{
    controlId: string;
    status: string;
    resourceId: string;
    region?: string;
    severity: string;
  }> {
    const rows = this.db
      .prepare(
        "SELECT control_id, status, resource_id, region, severity FROM evaluations WHERE scan_id = ?",
      )
      .all(scanId) as any[];
    return rows.map((row) => ({
      controlId: row.control_id,
      status: row.status,
      resourceId: row.resource_id,
      region: row.region ?? undefined,
      severity: row.severity,
    }));
  }

  cancelScan(id: string): void {
    this.db
      .prepare("UPDATE scans SET status = 'cancelled' WHERE id = ? AND status = 'collecting'")
      .run(id);
  }

  // ---- evidence ----

  addEvidence(scanId: string, records: Omit<EvidenceRecord, "collectedAt">[]): number {
    const scan = this.getScan(scanId);
    if (!scan) throw new Error(`unknown scan: ${scanId}`);
    if (scan.status !== "collecting")
      throw new Error(`scan ${scanId} is ${scan.status}; evidence not accepted`);
    const collectedAt = new Date().toISOString();
    const insert = this.db.prepare(
      `INSERT INTO evidence (scan_id, collector_id, region, resource_key, output, error_text, exit_code, evidence_hash, collected_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const tx = this.db.transaction(() => {
      for (const r of records) {
        insert.run(
          scanId,
          r.collectorId,
          r.region ?? null,
          r.resourceKey ?? null,
          r.output === null || r.output === undefined ? null : j(r.output),
          r.errorText ?? null,
          r.exitCode,
          evidenceHash(r.output ?? null),
          collectedAt,
        );
      }
    });
    tx();
    return records.length;
  }

  getEvidence(scanId: string): EvidenceRecord[] {
    const rows = this.db.prepare("SELECT * FROM evidence WHERE scan_id = ?").all(scanId) as any[];
    return rows.map((r) => ({
      collectorId: r.collector_id,
      region: r.region ?? undefined,
      resourceKey: r.resource_key ?? undefined,
      output: r.output === null ? null : pj(r.output, null),
      errorText: r.error_text ?? undefined,
      exitCode: r.exit_code,
      collectedAt: r.collected_at,
    }));
  }

  evidenceStats(
    scanId: string,
  ): { collectorId: string; region?: string; records: number; errors: number }[] {
    const rows = this.db
      .prepare(
        `SELECT collector_id, region, COUNT(*) AS records,
                SUM(CASE WHEN exit_code != 0 THEN 1 ELSE 0 END) AS errors
         FROM evidence WHERE scan_id = ? GROUP BY collector_id, region`,
      )
      .all(scanId) as any[];
    return rows.map((r) => ({
      collectorId: r.collector_id,
      region: r.region ?? undefined,
      records: r.records,
      errors: r.errors,
    }));
  }

  scanHealth(
    scanId: string,
    staleAfterMinutes = 60,
    expectedCollectorIds: string[] = [],
  ): ScanHealth {
    const scan = this.getScan(scanId);
    if (!scan) throw new Error(`unknown scan: ${scanId}`);
    const evidence = this.db
      .prepare(
        `SELECT COUNT(*) AS records,
                SUM(CASE WHEN exit_code != 0 THEN 1 ELSE 0 END) AS errors
         FROM evidence WHERE scan_id = ?`,
      )
      .get(scanId) as { records: number; errors: number | null };
    const requestedControls = scan.coverage?.length ?? scan.controlIds.length;
    const evaluatedControls =
      scan.coverage?.filter((item) => item.status === "evaluated").length ?? 0;
    const missingEvidence = scan.coverage?.filter((item) => item.status !== "evaluated") ?? [];
    const evidenceRecords = evidence.records ?? 0;
    const evidenceErrors = evidence.errors ?? 0;
    const observedCollectorIds = new Set(
      this.evidenceStats(scanId).map((item) => item.collectorId),
    );
    const missingCollectorIds = expectedCollectorIds.filter(
      (collectorId) => !observedCollectorIds.has(collectorId),
    );
    const ageMinutes = Math.max(0, (Date.now() - Date.parse(scan.createdAt)) / 60_000);
    const stale = scan.status === "collecting" && ageMinutes > staleAfterMinutes;
    const reasons: string[] = [];
    if (scan.status === "collecting") reasons.push("scan has not been evaluated");
    if (scan.status === "cancelled") reasons.push("scan was cancelled");
    if (stale) reasons.push(`scan is older than ${staleAfterMinutes} minutes`);
    if (missingEvidence.length > 0)
      reasons.push(`${missingEvidence.length} controls have missing or errored evidence`);
    if (evidenceErrors > 0) reasons.push(`${evidenceErrors} evidence records failed`);
    if (missingCollectorIds.length > 0)
      reasons.push(`${missingCollectorIds.length} required collectors have no submitted evidence`);
    return {
      scanId,
      status: stale ? "stale" : scan.status,
      healthy:
        scan.status === "evaluated" &&
        !stale &&
        missingEvidence.length === 0 &&
        missingCollectorIds.length === 0 &&
        evidenceErrors === 0,
      stale,
      ageMinutes: Math.round(ageMinutes * 10) / 10,
      requestedControls,
      evaluatedControls,
      missingEvidenceControls: missingEvidence.length,
      coverageRatio:
        scan.summary?.coverageRatio ??
        (requestedControls ? evaluatedControls / requestedControls : 0),
      evidenceRecords,
      evidenceErrors,
      expectedCollectors: expectedCollectorIds.length,
      observedCollectors: observedCollectorIds.size,
      missingCollectors: [
        ...new Set([
          ...missingEvidence.flatMap((item) => item.missingCollectors),
          ...missingCollectorIds,
        ]),
      ],
      reasons,
    };
  }

  // ---- evaluation + reconciliation ----

  /**
   * Persist evaluation results for a scan, reconcile the finding lifecycle,
   * and mark the scan evaluated. One transaction: a scan either fully
   * reconciles or not at all.
   */
  finalizeScan(
    scanId: string,
    results: EvaluationResult[],
    coverage: ControlCoverage[],
  ): ScanSummary {
    const scan = this.getScan(scanId);
    if (!scan) throw new Error(`unknown scan: ${scanId}`);
    if (scan.status === "cancelled") throw new Error(`scan ${scanId} is cancelled`);

    const now = new Date().toISOString();
    const summary: ScanSummary = {
      pass: 0,
      fail: 0,
      error: 0,
      notApplicable: 0,
      coverageRatio:
        coverage.length === 0
          ? 0
          : coverage.filter((c) => c.status === "evaluated").length / coverage.length,
      findingsCreated: 0,
      findingsRecurred: 0,
      findingsResolved: 0,
      findingsReopened: 0,
      evidenceRecords: this.getEvidence(scanId).length,
      evidenceErrors: this.getEvidence(scanId).filter((record) => record.exitCode !== 0).length,
    };

    const insertEvaluation = this.db.prepare(
      `INSERT INTO evaluations (scan_id, control_id, control_version, status, severity, service, resource_id, resource_name, region, message, evidence, effective_parameters, evaluated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const getFinding = this.db.prepare("SELECT * FROM findings WHERE fingerprint = ?");
    const insertFinding = this.db.prepare(
      `INSERT INTO findings (fingerprint, provider, scope_id, control_id, control_version, severity, service, resource_id, resource_name, region, state, message, first_seen_at, last_seen_at, last_scan_id, latest_evidence, effective_parameters)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)`,
    );
    const insertEvent = this.db.prepare(
      `INSERT INTO finding_events (fingerprint, scan_id, event_type, from_state, to_state, message, evidence, actor, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'engine', ?)`,
    );

    const tx = this.db.transaction(() => {
      for (const r of results) {
        insertEvaluation.run(
          scanId,
          r.controlId,
          r.controlVersion,
          r.status,
          r.severity,
          r.service,
          r.resourceId,
          r.resourceName ?? null,
          r.region ?? null,
          r.message,
          j(r.evidence ?? null),
          r.effectiveParameters ? j(r.effectiveParameters) : null,
          r.evaluatedAt,
        );
        if (r.status === "pass") summary.pass++;
        else if (r.status === "fail") summary.fail++;
        else if (r.status === "error") summary.error++;
        else if (r.status === "not_applicable") summary.notApplicable++;

        const existing = getFinding.get(fingerprintFor(scan.scopeId, r)) as any;
        const prior: PriorFinding | undefined = existing
          ? {
              fingerprint: existing.fingerprint,
              state: existing.state,
              occurrenceCount: existing.occurrence_count,
              reopenCount: existing.reopen_count,
            }
          : undefined;
        const action = reconcileOne(scan.scopeId, r, prior);

        switch (action.type) {
          case "create":
            insertFinding.run(
              action.fingerprint,
              r.provider,
              scan.scopeId,
              r.controlId,
              r.controlVersion,
              r.severity,
              r.service,
              r.resourceId,
              r.resourceName ?? null,
              r.region ?? null,
              r.message,
              now,
              now,
              scanId,
              j(r.evidence ?? null),
              r.effectiveParameters ? j(r.effectiveParameters) : null,
            );
            insertEvent.run(
              action.fingerprint,
              scanId,
              "created",
              null,
              "open",
              r.message,
              j(r.evidence ?? null),
              now,
            );
            summary.findingsCreated++;
            break;
          case "recur":
            this.db
              .prepare(
                `UPDATE findings SET last_seen_at = ?, occurrence_count = occurrence_count + 1,
                 message = ?, severity = ?, control_version = ?, last_scan_id = ?, latest_evidence = ?,
                 effective_parameters = ?
                 WHERE fingerprint = ?`,
              )
              .run(
                now,
                r.message,
                r.severity,
                r.controlVersion,
                scanId,
                j(r.evidence ?? null),
                r.effectiveParameters ? j(r.effectiveParameters) : null,
                action.fingerprint,
              );
            insertEvent.run(
              action.fingerprint,
              scanId,
              "recurred",
              existing.state,
              existing.state,
              r.message,
              null,
              now,
            );
            summary.findingsRecurred++;
            break;
          case "resolve":
            this.db
              .prepare(
                `UPDATE findings SET state = 'resolved', resolved_at = ?, last_seen_at = ?, last_scan_id = ?
                 WHERE fingerprint = ?`,
              )
              .run(now, now, scanId, action.fingerprint);
            insertEvent.run(
              action.fingerprint,
              scanId,
              "resolved",
              existing.state,
              "resolved",
              r.message,
              j(r.evidence ?? null),
              now,
            );
            summary.findingsResolved++;
            break;
          case "reopen":
            this.db
              .prepare(
                `UPDATE findings SET state = 'reopened', resolved_at = NULL, last_seen_at = ?,
                 occurrence_count = occurrence_count + 1, reopen_count = reopen_count + 1,
                 message = ?, severity = ?, control_version = ?, last_scan_id = ?, latest_evidence = ?,
                 effective_parameters = ?
                 WHERE fingerprint = ?`,
              )
              .run(
                now,
                r.message,
                r.severity,
                r.controlVersion,
                scanId,
                j(r.evidence ?? null),
                r.effectiveParameters ? j(r.effectiveParameters) : null,
                action.fingerprint,
              );
            insertEvent.run(
              action.fingerprint,
              scanId,
              "reopened",
              "resolved",
              "reopened",
              r.message,
              j(r.evidence ?? null),
              now,
            );
            summary.findingsReopened++;
            break;
          case "none":
            break;
        }
      }
      this.db
        .prepare(
          "UPDATE scans SET status = 'evaluated', evaluated_at = ?, coverage = ?, summary = ? WHERE id = ?",
        )
        .run(now, j(coverage), j(summary), scanId);
    });
    tx();
    return summary;
  }

  // ---- findings ----

  searchFindings(filters: FindingSearchFilters = {}): { total: number; findings: FindingRow[] } {
    this.expireWorkflowStates();
    const where: string[] = [];
    const params: unknown[] = [];
    if (filters.provider) {
      where.push("provider = ?");
      params.push(filters.provider);
    }
    if (filters.scopeId) {
      where.push("scope_id = ?");
      params.push(filters.scopeId);
    }
    if (filters.controlId) {
      where.push("control_id = ?");
      params.push(filters.controlId);
    }
    if (filters.service) {
      where.push("service = ?");
      params.push(filters.service);
    }
    if (filters.resourceId) {
      where.push("resource_id = ?");
      params.push(filters.resourceId);
    }
    if (filters.owner) {
      where.push("owner = ?");
      params.push(filters.owner);
    }
    if (filters.overdue) {
      where.push("due_at IS NOT NULL AND due_at < ? AND state IN ('open','reopened')");
      params.push(new Date().toISOString());
    }
    if (filters.severity?.length) {
      where.push(`severity IN (${filters.severity.map(() => "?").join(",")})`);
      params.push(...filters.severity);
    }
    if (filters.state?.length) {
      where.push(`state IN (${filters.state.map(() => "?").join(",")})`);
      params.push(...filters.state);
    }
    if (filters.workflowState?.length) {
      where.push(`workflow_state IN (${filters.workflowState.map(() => "?").join(",")})`);
      params.push(...filters.workflowState);
    }
    const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const total = (
      this.db.prepare(`SELECT COUNT(*) AS n FROM findings ${clause}`).get(...params) as any
    ).n as number;
    const limit = Math.min(filters.limit ?? 50, 200);
    const offset = filters.offset ?? 0;
    const rows = this.db
      .prepare(
        `SELECT * FROM findings ${clause}
         ORDER BY CASE severity
             WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
             WHEN 'low' THEN 3 ELSE 4 END,
           last_seen_at DESC
         LIMIT ? OFFSET ?`,
      )
      .all(...params, limit, offset) as any[];
    return { total, findings: rows.map(mapFinding) };
  }

  getFinding(fingerprint: string): FindingRow | undefined {
    this.expireWorkflowStates();
    const row = this.db
      .prepare("SELECT * FROM findings WHERE fingerprint = ?")
      .get(fingerprint) as any;
    return row ? mapFinding(row) : undefined;
  }

  getFindingEvents(fingerprint: string): FindingEventRow[] {
    const rows = this.db
      .prepare("SELECT * FROM finding_events WHERE fingerprint = ? ORDER BY created_at, id")
      .all(fingerprint) as any[];
    return rows.map((r) => ({
      id: r.id,
      fingerprint: r.fingerprint,
      scanId: r.scan_id ?? undefined,
      eventType: r.event_type,
      fromState: r.from_state ?? undefined,
      toState: r.to_state ?? undefined,
      message: r.message ?? undefined,
      evidence: r.evidence ? pj(r.evidence, undefined) : undefined,
      actor: r.actor ?? undefined,
      createdAt: r.created_at,
    }));
  }

  setWorkflowState(
    fingerprint: string,
    workflowState: WorkflowState,
    opts: { reason?: string; actor: string; expiresAt?: string },
  ): FindingRow {
    const existing = this.getFinding(fingerprint);
    if (!existing) throw new Error(`unknown finding: ${fingerprint}`);
    if ((workflowState === "risk_accepted" || workflowState === "false_positive") && !opts.reason) {
      throw new Error(`${workflowState} requires a reason`);
    }
    const now = new Date().toISOString();
    this.db.transaction(() => {
      this.db
        .prepare(
          `UPDATE findings SET workflow_state = ?, workflow_reason = ?, workflow_actor = ?, workflow_expires_at = ?
           WHERE fingerprint = ?`,
        )
        .run(workflowState, opts.reason ?? null, opts.actor, opts.expiresAt ?? null, fingerprint);
      this.db
        .prepare(
          `INSERT INTO finding_events (fingerprint, scan_id, event_type, from_state, to_state, message, evidence, actor, created_at)
           VALUES (?, NULL, 'workflow_change', ?, ?, ?, NULL, ?, ?)`,
        )
        .run(
          fingerprint,
          existing.workflowState,
          workflowState,
          opts.reason ?? null,
          opts.actor,
          now,
        );
    })();
    return this.getFinding(fingerprint)!;
  }

  assignFinding(
    fingerprint: string,
    opts: { owner: string; dueAt?: string; actor: string },
  ): FindingRow {
    const existing = this.getFinding(fingerprint);
    if (!existing) throw new Error(`unknown finding: ${fingerprint}`);
    if (!opts.owner.trim()) throw new Error("owner is required");
    if (opts.dueAt && Number.isNaN(Date.parse(opts.dueAt)))
      throw new Error("dueAt must be an ISO timestamp");
    const now = new Date().toISOString();
    this.db.transaction(() => {
      this.db
        .prepare("UPDATE findings SET owner = ?, due_at = ? WHERE fingerprint = ?")
        .run(opts.owner.trim(), opts.dueAt ?? null, fingerprint);
      this.db
        .prepare(
          `INSERT INTO finding_events (fingerprint, scan_id, event_type, from_state, to_state, message, evidence, actor, created_at)
           VALUES (?, NULL, 'workflow_change', ?, ?, ?, NULL, ?, ?)`,
        )
        .run(
          fingerprint,
          existing.workflowState,
          existing.workflowState,
          `Assigned to ${opts.owner.trim()}${opts.dueAt ? `; due ${opts.dueAt}` : ""}`,
          opts.actor,
          now,
        );
    })();
    return this.getFinding(fingerprint)!;
  }

  expireWorkflowStates(now = new Date().toISOString()): number {
    const rows = this.db
      .prepare(
        `SELECT fingerprint, workflow_state FROM findings
         WHERE workflow_state IN ('risk_accepted','false_positive')
           AND workflow_expires_at IS NOT NULL AND workflow_expires_at <= ?`,
      )
      .all(now) as Array<{ fingerprint: string; workflow_state: string }>;
    if (rows.length === 0) return 0;
    const update = this.db.prepare(
      "UPDATE findings SET workflow_state = 'new', workflow_reason = NULL, workflow_actor = 'engine', workflow_expires_at = NULL WHERE fingerprint = ?",
    );
    const event = this.db.prepare(
      `INSERT INTO finding_events (fingerprint, scan_id, event_type, from_state, to_state, message, evidence, actor, created_at)
       VALUES (?, NULL, 'workflow_change', ?, 'new', ?, NULL, 'engine', ?)`,
    );
    this.db.transaction(() => {
      for (const row of rows) {
        update.run(row.fingerprint);
        event.run(
          row.fingerprint,
          row.workflow_state,
          "Workflow exception expired; review required.",
          now,
        );
      }
    })();
    return rows.length;
  }

  addFindingComment(fingerprint: string, comment: string, actor: string): void {
    if (!this.getFinding(fingerprint)) throw new Error(`unknown finding: ${fingerprint}`);
    this.db
      .prepare(
        `INSERT INTO finding_events (fingerprint, scan_id, event_type, from_state, to_state, message, evidence, actor, created_at)
         VALUES (?, NULL, 'comment', NULL, NULL, ?, NULL, ?, ?)`,
      )
      .run(fingerprint, comment, actor, new Date().toISOString());
  }

  // ---- reporting ----

  reportData(filters: { provider?: Provider; scopeId?: string; sinceDays?: number } = {}): unknown {
    this.expireWorkflowStates();
    const since = new Date(Date.now() - (filters.sinceDays ?? 30) * 86_400_000).toISOString();
    const where: string[] = [];
    const params: unknown[] = [];
    if (filters.provider) {
      where.push("provider = ?");
      params.push(filters.provider);
    }
    if (filters.scopeId) {
      where.push("scope_id = ?");
      params.push(filters.scopeId);
    }
    const clause = where.length ? `AND ${where.join(" AND ")}` : "";
    const openWhere = `WHERE state IN ('open','reopened') ${clause}`;

    const bySeverity = this.db
      .prepare(`SELECT severity, COUNT(*) AS n FROM findings ${openWhere} GROUP BY severity`)
      .all(...params) as any[];
    const byService = this.db
      .prepare(
        `SELECT provider, service, COUNT(*) AS n FROM findings ${openWhere} GROUP BY provider, service ORDER BY n DESC`,
      )
      .all(...params) as any[];
    const byControl = this.db
      .prepare(
        `SELECT control_id, severity, COUNT(*) AS n FROM findings ${openWhere} GROUP BY control_id ORDER BY n DESC LIMIT 15`,
      )
      .all(...params) as any[];
    const newSince = (
      this.db
        .prepare(
          `SELECT COUNT(*) AS n FROM findings WHERE first_seen_at >= ? ${clause} AND state IN ('open','reopened')`,
        )
        .get(since, ...params) as any
    ).n;
    const resolvedSince = (
      this.db
        .prepare(`SELECT COUNT(*) AS n FROM findings WHERE resolved_at >= ? ${clause}`)
        .get(since, ...params) as any
    ).n;
    const reopened = (
      this.db
        .prepare(`SELECT COUNT(*) AS n FROM findings WHERE state = 'reopened' ${clause}`)
        .get(...params) as any
    ).n;
    const riskAccepted = (
      this.db
        .prepare(
          `SELECT COUNT(*) AS n FROM findings WHERE workflow_state = 'risk_accepted' ${clause}`,
        )
        .get(...params) as any
    ).n;
    const overdue = (
      this.db
        .prepare(
          `SELECT COUNT(*) AS n FROM findings WHERE due_at IS NOT NULL AND due_at < ? AND state IN ('open','reopened') ${clause}`,
        )
        .get(new Date().toISOString(), ...params) as any
    ).n;
    const unassignedOpen = (
      this.db
        .prepare(
          `SELECT COUNT(*) AS n FROM findings WHERE owner IS NULL AND state IN ('open','reopened') ${clause}`,
        )
        .get(...params) as any
    ).n;
    const scanFilters: string[] = [];
    const scanParams: unknown[] = [];
    if (filters.provider) {
      scanFilters.push("provider = ?");
      scanParams.push(filters.provider);
    }
    if (filters.scopeId) {
      scanFilters.push("scope_id = ?");
      scanParams.push(filters.scopeId);
    }
    const scans = this.db
      .prepare(
        `SELECT id, provider, scope_id, status, created_at, evaluated_at, summary FROM scans
         ${scanFilters.length ? `WHERE ${scanFilters.join(" AND ")}` : ""}
         ORDER BY created_at DESC, rowid DESC LIMIT 10`,
      )
      .all(...scanParams) as any[];
    const recentScans = scans.map((s) => ({
      id: s.id,
      provider: s.provider,
      scopeId: s.scope_id,
      status: s.status,
      createdAt: s.created_at,
      evaluatedAt: s.evaluated_at ?? undefined,
      summary: pj<ScanSummary | undefined>(s.summary, undefined),
    }));
    const evaluatedScans = recentScans.filter((scan) => scan.status === "evaluated");
    const comparison =
      evaluatedScans.length >= 2
        ? this.compareScans(evaluatedScans[1]!.id, evaluatedScans[0]!.id)
        : undefined;
    const chronologicalScans = recentScans
      .filter((scan) => scan.status === "evaluated" && scan.summary)
      .slice()
      .reverse();
    const scanTrends = chronologicalScans.map((scan, index) => {
      const lowerBound = chronologicalScans[index - 1]?.evaluatedAt ?? scan.createdAt;
      const upperBound = scan.evaluatedAt ?? scan.createdAt;
      const accepted = (
        this.db
          .prepare(
            `SELECT COUNT(*) AS n FROM finding_events fe
             JOIN findings f ON f.fingerprint = fe.fingerprint
             WHERE fe.event_type = 'workflow_change' AND fe.to_state = 'risk_accepted'
               AND fe.created_at > ? AND fe.created_at <= ?
               AND f.provider = ? AND f.scope_id = ?`,
          )
          .get(lowerBound, upperBound, scan.provider, scan.scopeId) as { n: number }
      ).n;
      return {
        scanId: scan.id,
        evaluatedAt: scan.evaluatedAt,
        coverageRatio: scan.summary!.coverageRatio,
        pass: scan.summary!.pass,
        fail: scan.summary!.fail,
        error: scan.summary!.error,
        findingsCreated: scan.summary!.findingsCreated,
        findingsRecurred: scan.summary!.findingsRecurred,
        findingsResolved: scan.summary!.findingsResolved,
        findingsReopened: scan.summary!.findingsReopened,
        findingsAccepted: accepted,
      };
    });

    return {
      generatedAt: new Date().toISOString(),
      windowDays: filters.sinceDays ?? 30,
      filters,
      openFindingsBySeverity: Object.fromEntries(bySeverity.map((r) => [r.severity, r.n])),
      openFindingsByService: byService.map((r) => ({
        provider: r.provider,
        service: r.service,
        count: r.n,
      })),
      topFailingControls: byControl.map((r) => ({
        controlId: r.control_id,
        severity: r.severity,
        count: r.n,
      })),
      newFindingsInWindow: newSince,
      resolvedFindingsInWindow: resolvedSince,
      currentlyReopened: reopened,
      riskAccepted,
      overdueFindings: overdue,
      unassignedOpenFindings: unassignedOpen,
      recentScans: recentScans,
      scanTrends,
      comparison,
      metricDefinitions: {
        openFindingsBySeverity:
          "Findings with lifecycle state open or reopened, grouped by severity. Excludes resolved; includes risk-accepted (workflow state is reported separately).",
        newFindingsInWindow: "Findings first seen within the window and still open or reopened.",
        resolvedFindingsInWindow:
          "Findings whose resolved_at falls within the window (verified passing evaluation).",
        currentlyReopened: "Findings that previously resolved and are failing again now.",
        overdueFindings: "Open or reopened findings whose assigned due_at timestamp has passed.",
        unassignedOpenFindings: "Open or reopened findings without an owner assignment.",
        coverage:
          "Per-scan coverageRatio = controls evaluated / controls requested. Controls without evidence are never counted as passing.",
      },
    };
  }

  // ---- audit ----

  audit(entry: {
    actor: string;
    tool: string;
    args?: unknown;
    success: boolean;
    detail?: string;
  }): void {
    const last = this.db
      .prepare("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
      .get() as any;
    const prevHash = last?.entry_hash ?? "genesis";
    const createdAt = new Date().toISOString();
    const argsJson = entry.args === undefined ? null : j(redactSecrets(entry.args));
    const entryHash = createHash("sha256")
      .update(
        [
          prevHash,
          createdAt,
          entry.actor,
          entry.tool,
          argsJson ?? "",
          String(entry.success),
          entry.detail ?? "",
        ].join("|"),
      )
      .digest("hex");
    this.db
      .prepare(
        `INSERT INTO audit_log (created_at, actor, tool, args, success, detail, prev_hash, entry_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        createdAt,
        entry.actor,
        entry.tool,
        argsJson,
        entry.success ? 1 : 0,
        entry.detail ?? null,
        prevHash,
        entryHash,
      );
  }

  searchAudit(limit = 50): unknown[] {
    const rows = this.db
      .prepare(
        "SELECT id, created_at, actor, tool, args, success, detail FROM audit_log ORDER BY id DESC LIMIT ?",
      )
      .all(Math.min(limit, 500)) as any[];
    return rows.map((r) => ({
      id: r.id,
      createdAt: r.created_at,
      actor: r.actor,
      tool: r.tool,
      args: pj(r.args, undefined),
      success: r.success === 1,
      detail: r.detail ?? undefined,
    }));
  }

  /** Verify the audit hash chain; returns first broken entry id or null. */
  verifyAuditChain(): number | null {
    const rows = this.db.prepare("SELECT * FROM audit_log ORDER BY id").all() as any[];
    let prev = "genesis";
    for (const r of rows) {
      const expected = createHash("sha256")
        .update(
          [
            prev,
            r.created_at,
            r.actor,
            r.tool,
            r.args ?? "",
            r.success === 1 ? "true" : "false",
            r.detail ?? "",
          ].join("|"),
        )
        .digest("hex");
      if (r.prev_hash !== prev || r.entry_hash !== expected) return r.id;
      prev = r.entry_hash;
    }
    return null;
  }
}

const SECRET_KEY_PATTERN = /secret|token|password|credential|apikey|api_key|private/i;

function redactSecrets(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) =>
        SECRET_KEY_PATTERN.test(k) ? [k, "[REDACTED]"] : [k, redactSecrets(v)],
      ),
    );
  }
  return value;
}

function fingerprintFor(scopeId: string, r: EvaluationResult): string {
  return findingFingerprint({
    provider: r.provider,
    scopeId,
    controlId: r.controlId,
    resourceId: r.resourceId,
    region: r.region,
  });
}

function mapScan(row: any): ScanRow {
  return {
    id: row.id,
    provider: row.provider,
    scopeId: row.scope_id,
    regions: pj(row.regions, []),
    controlIds: pj(row.control_ids, []),
    status: row.status,
    parameters: row.parameters ? pj(row.parameters, undefined) : undefined,
    createdAt: row.created_at,
    evaluatedAt: row.evaluated_at ?? undefined,
    coverage: row.coverage ? pj(row.coverage, undefined) : undefined,
    summary: row.summary ? pj(row.summary, undefined) : undefined,
  };
}

function mapFinding(row: any): FindingRow {
  return {
    fingerprint: row.fingerprint,
    provider: row.provider,
    scopeId: row.scope_id,
    controlId: row.control_id,
    controlVersion: row.control_version,
    severity: row.severity,
    service: row.service,
    resourceId: row.resource_id,
    resourceName: row.resource_name ?? undefined,
    region: row.region ?? undefined,
    state: row.state,
    workflowState: row.workflow_state,
    workflowReason: row.workflow_reason ?? undefined,
    workflowActor: row.workflow_actor ?? undefined,
    workflowExpiresAt: row.workflow_expires_at ?? undefined,
    owner: row.owner ?? undefined,
    dueAt: row.due_at ?? undefined,
    message: row.message,
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
    resolvedAt: row.resolved_at ?? undefined,
    occurrenceCount: row.occurrence_count,
    reopenCount: row.reopen_count,
    lastScanId: row.last_scan_id,
    latestEvidence: row.latest_evidence ? pj(row.latest_evidence, undefined) : undefined,
    effectiveParameters: row.effective_parameters
      ? pj(row.effective_parameters, undefined)
      : undefined,
  };
}

import { createHash, randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { and, desc, eq } from "drizzle-orm";
import {
  evidenceHash,
  findingFingerprint,
  reconcileOne,
  type ControlCoverage,
  type EvaluationResult,
  type EvidenceRecord,
  type PriorFinding,
  type Provider,
  type WorkflowState,
} from "@cloudranger/engine";
import { scans } from "./drizzle-schema.js";
import { createPostgresDatabase, type PostgresDatabase } from "./postgres.js";
import type { CloudRangerRepository } from "./repository.js";
import type { WorkspaceMember, WorkspaceRole } from "./repository.js";
import type {
  FindingEventRow,
  FindingRow,
  FindingSearchFilters,
  ScanComparison,
  ScanHealth,
  ScanRow,
  ScanSummary,
} from "./index.js";

type Queryable = Pick<Pool, "query"> | Pick<PoolClient, "query">;
const iso = (value: unknown): string | undefined =>
  value instanceof Date ? value.toISOString() : typeof value === "string" ? value : undefined;

function scanRow(row: any): ScanRow {
  return {
    id: row.id,
    provider: row.provider,
    scopeId: row.scope_id,
    regions: row.regions ?? [],
    controlIds: row.control_ids ?? [],
    status: row.status,
    createdAt: iso(row.created_at)!,
    evaluatedAt: iso(row.evaluated_at),
    coverage: row.coverage ?? undefined,
    summary: row.summary ?? undefined,
    parameters: row.parameters ?? undefined,
  };
}

function typedScanRow(row: typeof scans.$inferSelect): ScanRow {
  return {
    id: row.id,
    provider: row.provider as Provider,
    scopeId: row.scopeId,
    regions: row.regions,
    controlIds: row.controlIds,
    status: row.status as ScanRow["status"],
    createdAt: row.createdAt.toISOString(),
    evaluatedAt: row.evaluatedAt?.toISOString(),
    coverage: row.coverage as ControlCoverage[] | undefined,
    summary: row.summary as ScanSummary | undefined,
    parameters: row.parameters ?? undefined,
  };
}

function findingRow(row: any): FindingRow {
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
    workflowExpiresAt: iso(row.workflow_expires_at),
    owner: row.owner ?? undefined,
    dueAt: iso(row.due_at),
    message: row.message,
    firstSeenAt: iso(row.first_seen_at)!,
    lastSeenAt: iso(row.last_seen_at)!,
    resolvedAt: iso(row.resolved_at),
    occurrenceCount: row.occurrence_count,
    reopenCount: row.reopen_count,
    lastScanId: row.last_scan_id,
    latestEvidence: row.latest_evidence ?? undefined,
    effectiveParameters: row.effective_parameters ?? undefined,
  };
}

export class PostgresCloudRangerStore implements CloudRangerRepository {
  readonly pool: Pool;
  readonly db: PostgresDatabase;

  constructor(connectionString?: string) {
    const connection = createPostgresDatabase(connectionString);
    this.pool = connection.pool;
    this.db = connection.db;
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  async initializeWorkspace(input: {
    workspaceId: string;
    workspaceName: string;
    subject: string;
    displayName?: string;
    bootstrapAdmin?: boolean;
  }): Promise<WorkspaceRole> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtext('cloudranger-workspace-bootstrap'))",
      );
      const existing = await client.query<{ id: string }>("SELECT id FROM workspaces LIMIT 1");
      if (existing.rowCount === 0) {
        if (!input.bootstrapAdmin) {
          throw new Error(
            "workspace is not initialized; set CLOUDRANGER_BOOTSTRAP_ADMIN=true once",
          );
        }
        await client.query("INSERT INTO workspaces (id, name, created_at) VALUES ($1, $2, NOW())", [
          input.workspaceId,
          input.workspaceName,
        ]);
        await client.query(
          "INSERT INTO identities (subject, display_name, created_at) VALUES ($1, $2, NOW())",
          [input.subject, input.displayName ?? null],
        );
        await client.query(
          `INSERT INTO workspace_memberships
             (workspace_id, subject, role, created_at, updated_at)
           VALUES ($1, $2, 'admin', NOW(), NOW())`,
          [input.workspaceId, input.subject],
        );
        await client.query("COMMIT");
        return "admin";
      }
      const boundWorkspace = existing.rows[0]!.id;
      if (boundWorkspace !== input.workspaceId) {
        throw new Error(
          `database is bound to workspace ${boundWorkspace}, not ${input.workspaceId}`,
        );
      }
      const membership = await client.query<{ role: WorkspaceRole }>(
        "SELECT role FROM workspace_memberships WHERE workspace_id = $1 AND subject = $2",
        [input.workspaceId, input.subject],
      );
      if (membership.rowCount === 0) {
        throw new Error(`identity ${input.subject} is not a workspace member`);
      }
      await client.query("COMMIT");
      return membership.rows[0]!.role;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async listWorkspaceMembers(workspaceId: string): Promise<WorkspaceMember[]> {
    const result = await this.pool.query(
      `SELECT m.subject, i.display_name, m.role, m.created_at, m.updated_at
       FROM workspace_memberships m JOIN identities i ON i.subject = m.subject
       WHERE m.workspace_id = $1 ORDER BY m.subject`,
      [workspaceId],
    );
    return result.rows.map((row) => ({
      subject: row.subject,
      displayName: row.display_name ?? undefined,
      role: row.role,
      createdAt: iso(row.created_at)!,
      updatedAt: iso(row.updated_at)!,
    }));
  }

  async setWorkspaceMember(input: {
    workspaceId: string;
    subject: string;
    displayName?: string;
    role: WorkspaceRole;
  }): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const workspace = await client.query("SELECT id FROM workspaces WHERE id = $1 FOR UPDATE", [
        input.workspaceId,
      ]);
      if (workspace.rowCount === 0) throw new Error(`unknown workspace: ${input.workspaceId}`);
      const existing = await client.query<{ role: WorkspaceRole }>(
        "SELECT role FROM workspace_memberships WHERE workspace_id = $1 AND subject = $2",
        [input.workspaceId, input.subject],
      );
      if (existing.rows[0]?.role === "admin" && input.role !== "admin") {
        const admins = await client.query<{ count: string }>(
          "SELECT COUNT(*) AS count FROM workspace_memberships WHERE workspace_id = $1 AND role = 'admin'",
          [input.workspaceId],
        );
        if (Number(admins.rows[0]!.count) <= 1) {
          throw new Error("cannot demote the last workspace admin");
        }
      }
      await client.query(
        `INSERT INTO identities (subject, display_name, created_at) VALUES ($1, $2, NOW())
         ON CONFLICT(subject) DO UPDATE
         SET display_name = COALESCE(EXCLUDED.display_name, identities.display_name)`,
        [input.subject, input.displayName ?? null],
      );
      await client.query(
        `INSERT INTO workspace_memberships
           (workspace_id, subject, role, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         ON CONFLICT(workspace_id, subject) DO UPDATE
         SET role = EXCLUDED.role, updated_at = NOW()`,
        [input.workspaceId, input.subject, input.role],
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async removeWorkspaceMember(workspaceId: string, subject: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT id FROM workspaces WHERE id = $1 FOR UPDATE", [workspaceId]);
      const member = await client.query<{ role: WorkspaceRole }>(
        "SELECT role FROM workspace_memberships WHERE workspace_id = $1 AND subject = $2",
        [workspaceId, subject],
      );
      if (member.rowCount === 0) throw new Error(`identity ${subject} is not a workspace member`);
      if (member.rows[0]!.role === "admin") {
        const admins = await client.query<{ count: string }>(
          "SELECT COUNT(*) AS count FROM workspace_memberships WHERE workspace_id = $1 AND role = 'admin'",
          [workspaceId],
        );
        if (Number(admins.rows[0]!.count) <= 1) {
          throw new Error("cannot remove the last workspace admin");
        }
      }
      await client.query(
        "DELETE FROM workspace_memberships WHERE workspace_id = $1 AND subject = $2",
        [workspaceId, subject],
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async createScan(input: {
    provider: Provider;
    scopeId: string;
    regions: string[];
    controlIds: string[];
    parameters?: Record<string, Record<string, unknown>>;
  }): Promise<ScanRow> {
    const id = randomUUID();
    const createdAt = new Date().toISOString();
    await this.db.insert(scans).values({
      id,
      provider: input.provider,
      scopeId: input.scopeId,
      regions: input.regions,
      controlIds: input.controlIds,
      status: "collecting",
      createdAt: new Date(createdAt),
      parameters:
        input.parameters && Object.keys(input.parameters).length > 0 ? input.parameters : null,
    });
    return (await this.getScan(id))!;
  }

  async recordControlRevisions(
    revisions: Array<{
      controlId: string;
      version: string;
      contentHash: string;
      definition: unknown;
      deprecated: boolean;
    }>,
  ): Promise<number> {
    let added = 0;
    for (const r of revisions) {
      const result = await this.pool.query(
        `INSERT INTO control_revisions (control_id, version, content_hash, definition, deprecated, first_seen_at)
         VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
        [
          r.controlId,
          r.version,
          r.contentHash,
          JSON.stringify(r.definition),
          r.deprecated,
          new Date().toISOString(),
        ],
      );
      added += result.rowCount ?? 0;
    }
    return added;
  }

  async listControlRevisions(controlId: string): Promise<
    Array<{
      controlId: string;
      version: string;
      contentHash: string;
      definition: unknown;
      deprecated: boolean;
      firstSeenAt: string;
    }>
  > {
    const result = await this.pool.query(
      "SELECT * FROM control_revisions WHERE control_id=$1 ORDER BY first_seen_at, version",
      [controlId],
    );
    return result.rows.map((row) => ({
      controlId: row.control_id,
      version: row.version,
      contentHash: row.content_hash,
      definition: row.definition,
      deprecated: row.deprecated,
      firstSeenAt: iso(row.first_seen_at)!,
    }));
  }

  async setScopeParameters(
    provider: Provider,
    scopeId: string,
    controlId: string,
    parameters: Record<string, unknown> | null,
  ): Promise<void> {
    if (parameters === null || Object.keys(parameters).length === 0) {
      await this.pool.query(
        "DELETE FROM scope_parameters WHERE provider=$1 AND scope_id=$2 AND control_id=$3",
        [provider, scopeId, controlId],
      );
      return;
    }
    await this.pool.query(
      `INSERT INTO scope_parameters (provider, scope_id, control_id, parameters, updated_at)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (provider, scope_id, control_id)
       DO UPDATE SET parameters = EXCLUDED.parameters, updated_at = EXCLUDED.updated_at`,
      [provider, scopeId, controlId, JSON.stringify(parameters), new Date().toISOString()],
    );
  }

  async listScopeParameters(
    provider: Provider,
    scopeId: string,
  ): Promise<Array<{ controlId: string; parameters: Record<string, unknown>; updatedAt: string }>> {
    const result = await this.pool.query(
      "SELECT control_id, parameters, updated_at FROM scope_parameters WHERE provider=$1 AND scope_id=$2 ORDER BY control_id",
      [provider, scopeId],
    );
    return result.rows.map((row) => ({
      controlId: row.control_id,
      parameters: row.parameters ?? {},
      updatedAt: iso(row.updated_at)!,
    }));
  }

  async getEvaluations(scanId: string): Promise<
    Array<{
      controlId: string;
      status: string;
      resourceId: string;
      region?: string;
      severity: string;
    }>
  > {
    const result = await this.pool.query(
      "SELECT control_id, status, resource_id, region, severity FROM evaluations WHERE scan_id=$1",
      [scanId],
    );
    return result.rows.map((row) => ({
      controlId: row.control_id,
      status: row.status,
      resourceId: row.resource_id,
      region: row.region ?? undefined,
      severity: row.severity,
    }));
  }

  async getScan(id: string): Promise<ScanRow | undefined> {
    const row = await this.db.query.scans.findFirst({ where: eq(scans.id, id) });
    return row ? typedScanRow(row) : undefined;
  }

  async listScans(limit = 20): Promise<ScanRow[]> {
    const rows = await this.db
      .select()
      .from(scans)
      .orderBy(desc(scans.createdAt))
      .limit(Math.min(limit, 200));
    return rows.map(typedScanRow);
  }

  async compareScans(baselineScanId: string, currentScanId: string): Promise<ScanComparison> {
    const baseline = await this.getScan(baselineScanId);
    const current = await this.getScan(currentScanId);
    if (!baseline || !current) throw new Error("both scans must exist");
    if (baseline.status !== "evaluated" || current.status !== "evaluated")
      throw new Error("both scans must be evaluated before comparison");
    if (baseline.provider !== current.provider || baseline.scopeId !== current.scopeId)
      throw new Error("scans must use the same provider and scope");
    const result = await this.pool.query(
      `SELECT scan_id, control_id, resource_id, region, status, message, severity FROM evaluations
       WHERE scan_id IN ($1,$2) ORDER BY control_id, resource_id, region`,
      [baselineScanId, currentScanId],
    );
    const key = (row: any) => `${row.control_id}\u0000${row.resource_id}\u0000${row.region ?? ""}`;
    const before = new Map(
      result.rows.filter((r) => r.scan_id === baselineScanId).map((r) => [key(r), r]),
    );
    const after = new Map(
      result.rows.filter((r) => r.scan_id === currentScanId).map((r) => [key(r), r]),
    );
    const controlChanges: ScanComparison["controlChanges"] = [];
    for (const [entryKey, value] of after) {
      const row = value as any;
      const prior = before.get(entryKey) as any;
      if (prior?.status === row.status) continue;
      controlChanges.push({
        controlId: row.control_id,
        resourceId: row.resource_id,
        region: row.region ?? undefined,
        baseline: prior?.status ?? "not_assessed",
        current: row.status,
        message: row.message,
        severity: row.severity,
      });
    }
    for (const [entryKey, value] of before) {
      if (after.has(entryKey)) continue;
      const row = value as any;
      controlChanges.push({
        controlId: row.control_id,
        resourceId: row.resource_id,
        region: row.region ?? undefined,
        baseline: row.status,
        current: "not_assessed",
        message: "Resource or evaluation was not present in the current scan.",
        severity: row.severity,
      });
    }
    const events = await this.pool.query(
      "SELECT event_type, COUNT(*)::int AS n FROM finding_events WHERE scan_id IN ($1,$2) GROUP BY event_type",
      [baselineScanId, currentScanId],
    );
    const coverage = (scan: ScanRow) => ({
      ratio: scan.summary?.coverageRatio ?? 0,
      evaluated: scan.coverage?.filter((c) => c.status === "evaluated").length ?? 0,
      requested: scan.coverage?.length ?? scan.controlIds.length,
    });
    const b = coverage(baseline);
    const c = coverage(current);
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
        baseline: b.ratio,
        current: c.ratio,
        delta: c.ratio - b.ratio,
        baselineEvaluated: b.evaluated,
        currentEvaluated: c.evaluated,
        baselineRequested: b.requested,
        currentRequested: c.requested,
      },
      controlChanges,
      findingEvents: Object.fromEntries(events.rows.map((r) => [r.event_type, r.n])),
    };
  }

  async cancelScan(id: string): Promise<void> {
    await this.db
      .update(scans)
      .set({ status: "cancelled" })
      .where(and(eq(scans.id, id), eq(scans.status, "collecting")));
  }

  async addEvidence(
    scanId: string,
    records: Omit<EvidenceRecord, "collectedAt">[],
  ): Promise<number> {
    const scan = await this.getScan(scanId);
    if (!scan) throw new Error(`unknown scan: ${scanId}`);
    if (scan.status !== "collecting")
      throw new Error(`scan ${scanId} is ${scan.status}; evidence not accepted`);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const collectedAt = new Date().toISOString();
      for (const record of records) {
        await client.query(
          `INSERT INTO evidence (scan_id,collector_id,region,resource_key,output,error_text,exit_code,evidence_hash,collected_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [
            scanId,
            record.collectorId,
            record.region ?? null,
            record.resourceKey ?? null,
            record.output == null ? null : JSON.stringify(record.output),
            record.errorText ?? null,
            record.exitCode,
            evidenceHash(record.output ?? null),
            collectedAt,
          ],
        );
      }
      await client.query("COMMIT");
      return records.length;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async getEvidence(scanId: string): Promise<EvidenceRecord[]> {
    const result = await this.pool.query("SELECT * FROM evidence WHERE scan_id=$1 ORDER BY id", [
      scanId,
    ]);
    return result.rows.map((r) => ({
      collectorId: r.collector_id,
      region: r.region ?? undefined,
      resourceKey: r.resource_key ?? undefined,
      output: r.output,
      errorText: r.error_text ?? undefined,
      exitCode: r.exit_code,
      collectedAt: iso(r.collected_at)!,
    }));
  }

  async evidenceStats(
    scanId: string,
  ): Promise<Array<{ collectorId: string; region?: string; records: number; errors: number }>> {
    const result = await this.pool.query(
      `SELECT collector_id, region, COUNT(*)::int AS records,
       COUNT(*) FILTER (WHERE exit_code != 0)::int AS errors FROM evidence
       WHERE scan_id=$1 GROUP BY collector_id, region`,
      [scanId],
    );
    return result.rows.map((r) => ({
      collectorId: r.collector_id,
      region: r.region ?? undefined,
      records: r.records,
      errors: r.errors,
    }));
  }

  async scanHealth(
    scanId: string,
    staleAfterMinutes = 60,
    expectedCollectorIds: string[] = [],
  ): Promise<ScanHealth> {
    const scan = await this.getScan(scanId);
    if (!scan) throw new Error(`unknown scan: ${scanId}`);
    const aggregate = (
      await this.pool.query(
        `SELECT COUNT(*)::int AS records, COUNT(*) FILTER (WHERE exit_code != 0)::int AS errors FROM evidence WHERE scan_id=$1`,
        [scanId],
      )
    ).rows[0];
    const requestedControls = scan.coverage?.length ?? scan.controlIds.length;
    const evaluatedControls = scan.coverage?.filter((c) => c.status === "evaluated").length ?? 0;
    const missingEvidence = scan.coverage?.filter((c) => c.status !== "evaluated") ?? [];
    const stats = await this.evidenceStats(scanId);
    const observed = new Set(stats.map((s) => s.collectorId));
    const missingCollectorIds = expectedCollectorIds.filter((id) => !observed.has(id));
    const ageMinutes = Math.max(0, (Date.now() - Date.parse(scan.createdAt)) / 60_000);
    const stale = scan.status === "collecting" && ageMinutes > staleAfterMinutes;
    const reasons: string[] = [];
    if (scan.status === "collecting") reasons.push("scan has not been evaluated");
    if (scan.status === "cancelled") reasons.push("scan was cancelled");
    if (stale) reasons.push(`scan is older than ${staleAfterMinutes} minutes`);
    if (missingEvidence.length)
      reasons.push(`${missingEvidence.length} controls have missing or errored evidence`);
    if (aggregate.errors) reasons.push(`${aggregate.errors} evidence records failed`);
    if (missingCollectorIds.length)
      reasons.push(`${missingCollectorIds.length} required collectors have no submitted evidence`);
    return {
      scanId,
      status: stale ? "stale" : scan.status,
      healthy:
        scan.status === "evaluated" &&
        !stale &&
        !missingEvidence.length &&
        !missingCollectorIds.length &&
        !aggregate.errors,
      stale,
      ageMinutes: Math.round(ageMinutes * 10) / 10,
      requestedControls,
      evaluatedControls,
      missingEvidenceControls: missingEvidence.length,
      coverageRatio:
        scan.summary?.coverageRatio ??
        (requestedControls ? evaluatedControls / requestedControls : 0),
      evidenceRecords: aggregate.records,
      evidenceErrors: aggregate.errors,
      expectedCollectors: expectedCollectorIds.length,
      observedCollectors: observed.size,
      missingCollectors: [
        ...new Set([
          ...missingEvidence.flatMap((c) => c.missingCollectors),
          ...missingCollectorIds,
        ]),
      ],
      reasons,
    };
  }

  async finalizeScan(
    scanId: string,
    results: EvaluationResult[],
    coverage: ControlCoverage[],
  ): Promise<ScanSummary> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const scanResult = await client.query("SELECT * FROM scans WHERE id=$1 FOR UPDATE", [scanId]);
      const scan = scanResult.rows[0] ? scanRow(scanResult.rows[0]) : undefined;
      if (!scan) throw new Error(`unknown scan: ${scanId}`);
      if (scan.status === "cancelled") throw new Error(`scan ${scanId} is cancelled`);
      const evidence = await client.query("SELECT exit_code FROM evidence WHERE scan_id=$1", [
        scanId,
      ]);
      const now = new Date().toISOString();
      const summary: ScanSummary = {
        pass: 0,
        fail: 0,
        error: 0,
        notApplicable: 0,
        coverageRatio: coverage.length
          ? coverage.filter((c) => c.status === "evaluated").length / coverage.length
          : 0,
        findingsCreated: 0,
        findingsRecurred: 0,
        findingsResolved: 0,
        findingsReopened: 0,
        evidenceRecords: evidence.rowCount ?? 0,
        evidenceErrors: evidence.rows.filter((r) => r.exit_code !== 0).length,
      };
      for (const result of results) {
        await client.query(
          `INSERT INTO evaluations (scan_id,control_id,control_version,status,severity,service,resource_id,resource_name,region,message,evidence,effective_parameters,evaluated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
          [
            scanId,
            result.controlId,
            result.controlVersion,
            result.status,
            result.severity,
            result.service,
            result.resourceId,
            result.resourceName ?? null,
            result.region ?? null,
            result.message,
            JSON.stringify(result.evidence ?? null),
            result.effectiveParameters ? JSON.stringify(result.effectiveParameters) : null,
            result.evaluatedAt,
          ],
        );
        if (result.status === "pass") summary.pass += 1;
        else if (result.status === "fail") summary.fail += 1;
        else if (result.status === "error") summary.error += 1;
        else if (result.status === "not_applicable") summary.notApplicable += 1;
        const fingerprint = findingFingerprint({
          provider: result.provider,
          scopeId: scan.scopeId,
          controlId: result.controlId,
          resourceId: result.resourceId,
          region: result.region,
        });
        const existingResult = await client.query(
          "SELECT * FROM findings WHERE fingerprint=$1 FOR UPDATE",
          [fingerprint],
        );
        const existing = existingResult.rows[0];
        const prior: PriorFinding | undefined = existing
          ? {
              fingerprint,
              state: existing.state,
              occurrenceCount: existing.occurrence_count,
              reopenCount: existing.reopen_count,
            }
          : undefined;
        const action = reconcileOne(scan.scopeId, result, prior);
        if (action.type === "create") {
          await client.query(
            `INSERT INTO findings (fingerprint,provider,scope_id,control_id,control_version,severity,service,resource_id,resource_name,region,state,message,first_seen_at,last_seen_at,last_scan_id,latest_evidence,effective_parameters)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'open',$11,$12,$12,$13,$14,$15)`,
            [
              fingerprint,
              result.provider,
              scan.scopeId,
              result.controlId,
              result.controlVersion,
              result.severity,
              result.service,
              result.resourceId,
              result.resourceName ?? null,
              result.region ?? null,
              result.message,
              now,
              scanId,
              JSON.stringify(result.evidence ?? null),
              result.effectiveParameters ? JSON.stringify(result.effectiveParameters) : null,
            ],
          );
          await this.insertEvent(
            client,
            fingerprint,
            scanId,
            "created",
            null,
            "open",
            result.message,
            result.evidence,
            "engine",
            now,
          );
          summary.findingsCreated += 1;
        } else if (action.type === "recur") {
          await client.query(
            `UPDATE findings SET last_seen_at=$1,occurrence_count=occurrence_count+1,message=$2,severity=$3,control_version=$4,last_scan_id=$5,latest_evidence=$6,effective_parameters=$7 WHERE fingerprint=$8`,
            [
              now,
              result.message,
              result.severity,
              result.controlVersion,
              scanId,
              JSON.stringify(result.evidence ?? null),
              result.effectiveParameters ? JSON.stringify(result.effectiveParameters) : null,
              fingerprint,
            ],
          );
          await this.insertEvent(
            client,
            fingerprint,
            scanId,
            "recurred",
            existing.state,
            existing.state,
            result.message,
            undefined,
            "engine",
            now,
          );
          summary.findingsRecurred += 1;
        } else if (action.type === "resolve") {
          await client.query(
            "UPDATE findings SET state='resolved',resolved_at=$1,last_seen_at=$1,last_scan_id=$2 WHERE fingerprint=$3",
            [now, scanId, fingerprint],
          );
          await this.insertEvent(
            client,
            fingerprint,
            scanId,
            "resolved",
            existing.state,
            "resolved",
            result.message,
            result.evidence,
            "engine",
            now,
          );
          summary.findingsResolved += 1;
        } else if (action.type === "reopen") {
          await client.query(
            `UPDATE findings SET state='reopened',resolved_at=NULL,last_seen_at=$1,occurrence_count=occurrence_count+1,reopen_count=reopen_count+1,message=$2,severity=$3,control_version=$4,last_scan_id=$5,latest_evidence=$6,effective_parameters=$7 WHERE fingerprint=$8`,
            [
              now,
              result.message,
              result.severity,
              result.controlVersion,
              scanId,
              JSON.stringify(result.evidence ?? null),
              result.effectiveParameters ? JSON.stringify(result.effectiveParameters) : null,
              fingerprint,
            ],
          );
          await this.insertEvent(
            client,
            fingerprint,
            scanId,
            "reopened",
            "resolved",
            "reopened",
            result.message,
            result.evidence,
            "engine",
            now,
          );
          summary.findingsReopened += 1;
        }
      }
      await client.query(
        "UPDATE scans SET status='evaluated',evaluated_at=$1,coverage=$2,summary=$3 WHERE id=$4",
        [now, JSON.stringify(coverage), JSON.stringify(summary), scanId],
      );
      await client.query("COMMIT");
      return summary;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async searchFindings(
    filters: FindingSearchFilters = {},
  ): Promise<{ total: number; findings: FindingRow[] }> {
    await this.expireWorkflowStates();
    const where: string[] = [];
    const values: unknown[] = [];
    const add = (condition: string, value: unknown) => {
      values.push(value);
      where.push(condition.replace("?", `$${values.length}`));
    };
    if (filters.provider) add("provider=?", filters.provider);
    if (filters.scopeId) add("scope_id=?", filters.scopeId);
    if (filters.controlId) add("control_id=?", filters.controlId);
    if (filters.service) add("service=?", filters.service);
    if (filters.resourceId) add("resource_id=?", filters.resourceId);
    if (filters.owner) add("owner=?", filters.owner);
    if (filters.overdue)
      add(
        "due_at IS NOT NULL AND due_at < ? AND state IN ('open','reopened')",
        new Date().toISOString(),
      );
    const addAny = (column: string, items?: string[]) => {
      if (items?.length) {
        values.push(items);
        where.push(`${column} = ANY($${values.length})`);
      }
    };
    addAny("severity", filters.severity);
    addAny("state", filters.state);
    addAny("workflow_state", filters.workflowState);
    const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const count = await this.pool.query(
      `SELECT COUNT(*)::int AS n FROM findings ${clause}`,
      values,
    );
    values.push(Math.min(filters.limit ?? 50, 200), filters.offset ?? 0);
    const rows = await this.pool.query(
      `SELECT * FROM findings ${clause} ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,last_seen_at DESC LIMIT $${values.length - 1} OFFSET $${values.length}`,
      values,
    );
    return { total: count.rows[0].n, findings: rows.rows.map(findingRow) };
  }

  async getFinding(fingerprint: string): Promise<FindingRow | undefined> {
    await this.expireWorkflowStates();
    const result = await this.pool.query("SELECT * FROM findings WHERE fingerprint=$1", [
      fingerprint,
    ]);
    return result.rows[0] ? findingRow(result.rows[0]) : undefined;
  }

  async getFindingEvents(fingerprint: string): Promise<FindingEventRow[]> {
    const result = await this.pool.query(
      "SELECT * FROM finding_events WHERE fingerprint=$1 ORDER BY created_at,id",
      [fingerprint],
    );
    return result.rows.map((r) => ({
      id: r.id,
      fingerprint: r.fingerprint,
      scanId: r.scan_id ?? undefined,
      eventType: r.event_type,
      fromState: r.from_state ?? undefined,
      toState: r.to_state ?? undefined,
      message: r.message ?? undefined,
      evidence: r.evidence ?? undefined,
      actor: r.actor ?? undefined,
      createdAt: iso(r.created_at)!,
    }));
  }

  async setWorkflowState(
    fingerprint: string,
    workflowState: WorkflowState,
    opts: { reason?: string; actor: string; expiresAt?: string },
  ): Promise<FindingRow> {
    const existing = await this.getFinding(fingerprint);
    if (!existing) throw new Error(`unknown finding: ${fingerprint}`);
    if ((workflowState === "risk_accepted" || workflowState === "false_positive") && !opts.reason)
      throw new Error(`${workflowState} requires a reason`);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        "UPDATE findings SET workflow_state=$1,workflow_reason=$2,workflow_actor=$3,workflow_expires_at=$4 WHERE fingerprint=$5",
        [workflowState, opts.reason ?? null, opts.actor, opts.expiresAt ?? null, fingerprint],
      );
      await this.insertEvent(
        client,
        fingerprint,
        null,
        "workflow_change",
        existing.workflowState,
        workflowState,
        opts.reason,
        undefined,
        opts.actor,
        new Date().toISOString(),
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    return (await this.getFinding(fingerprint))!;
  }

  async assignFinding(
    fingerprint: string,
    opts: { owner: string; dueAt?: string; actor: string },
  ): Promise<FindingRow> {
    const existing = await this.getFinding(fingerprint);
    if (!existing) throw new Error(`unknown finding: ${fingerprint}`);
    if (!opts.owner.trim()) throw new Error("owner is required");
    if (opts.dueAt && Number.isNaN(Date.parse(opts.dueAt)))
      throw new Error("dueAt must be an ISO timestamp");
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("UPDATE findings SET owner=$1,due_at=$2 WHERE fingerprint=$3", [
        opts.owner.trim(),
        opts.dueAt ?? null,
        fingerprint,
      ]);
      await this.insertEvent(
        client,
        fingerprint,
        null,
        "workflow_change",
        existing.workflowState,
        existing.workflowState,
        `Assigned to ${opts.owner.trim()}${opts.dueAt ? `; due ${opts.dueAt}` : ""}`,
        undefined,
        opts.actor,
        new Date().toISOString(),
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    return (await this.getFinding(fingerprint))!;
  }

  async expireWorkflowStates(now = new Date().toISOString()): Promise<number> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `SELECT fingerprint,workflow_state FROM findings WHERE workflow_state IN ('risk_accepted','false_positive') AND workflow_expires_at IS NOT NULL AND workflow_expires_at <= $1 FOR UPDATE`,
        [now],
      );
      for (const row of result.rows) {
        await client.query(
          "UPDATE findings SET workflow_state='new',workflow_reason=NULL,workflow_actor='engine',workflow_expires_at=NULL WHERE fingerprint=$1",
          [row.fingerprint],
        );
        await this.insertEvent(
          client,
          row.fingerprint,
          null,
          "workflow_change",
          row.workflow_state,
          "new",
          "Workflow exception expired; review required.",
          undefined,
          "engine",
          now,
        );
      }
      await client.query("COMMIT");
      return result.rowCount ?? 0;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async addFindingComment(fingerprint: string, comment: string, actor: string): Promise<void> {
    if (!(await this.getFinding(fingerprint))) throw new Error(`unknown finding: ${fingerprint}`);
    await this.insertEvent(
      this.pool,
      fingerprint,
      null,
      "comment",
      null,
      null,
      comment,
      undefined,
      actor,
      new Date().toISOString(),
    );
  }

  async reportData(
    filters: { provider?: Provider; scopeId?: string; sinceDays?: number } = {},
  ): Promise<unknown> {
    await this.expireWorkflowStates();
    const conditions: string[] = [];
    const params: unknown[] = [];
    if (filters.provider) {
      params.push(filters.provider);
      conditions.push(`provider=$${params.length}`);
    }
    if (filters.scopeId) {
      params.push(filters.scopeId);
      conditions.push(`scope_id=$${params.length}`);
    }
    const suffix = conditions.length ? ` AND ${conditions.join(" AND ")}` : "";
    const openWhere = `WHERE state IN ('open','reopened')${suffix}`;
    const [severity, service, control] = await Promise.all([
      this.pool.query(
        `SELECT severity,COUNT(*)::int AS n FROM findings ${openWhere} GROUP BY severity`,
        params,
      ),
      this.pool.query(
        `SELECT provider,service,COUNT(*)::int AS n FROM findings ${openWhere} GROUP BY provider,service ORDER BY n DESC`,
        params,
      ),
      this.pool.query(
        `SELECT control_id,severity,COUNT(*)::int AS n FROM findings ${openWhere} GROUP BY control_id,severity ORDER BY n DESC LIMIT 15`,
        params,
      ),
    ]);
    const since = new Date(Date.now() - (filters.sinceDays ?? 30) * 86_400_000).toISOString();
    const scalar = async (sqlText: string, leading: unknown[] = []) =>
      (await this.pool.query(sqlText, [...leading, ...params])).rows[0].n as number;
    const sinceIndex = 1;
    const shiftedSuffix = conditions.length
      ? ` AND ${conditions.map((condition) => condition.replace(/\$(\d+)/g, (_m, n) => `$${Number(n) + 1}`)).join(" AND ")}`
      : "";
    const [newSince, resolvedSince, reopened, riskAccepted, overdue, unassignedOpen] =
      await Promise.all([
        scalar(
          `SELECT COUNT(*)::int AS n FROM findings WHERE first_seen_at >= $${sinceIndex}${shiftedSuffix} AND state IN ('open','reopened')`,
          [since],
        ),
        scalar(
          `SELECT COUNT(*)::int AS n FROM findings WHERE resolved_at >= $${sinceIndex}${shiftedSuffix}`,
          [since],
        ),
        scalar(`SELECT COUNT(*)::int AS n FROM findings WHERE state='reopened'${suffix}`),
        scalar(
          `SELECT COUNT(*)::int AS n FROM findings WHERE workflow_state='risk_accepted'${suffix}`,
        ),
        scalar(
          `SELECT COUNT(*)::int AS n FROM findings WHERE due_at IS NOT NULL AND due_at < $1 AND state IN ('open','reopened')${shiftedSuffix}`,
          [new Date().toISOString()],
        ),
        scalar(
          `SELECT COUNT(*)::int AS n FROM findings WHERE owner IS NULL AND state IN ('open','reopened')${suffix}`,
        ),
      ]);
    const scanConditions: string[] = [];
    const scanParams: unknown[] = [];
    if (filters.provider) {
      scanParams.push(filters.provider);
      scanConditions.push(`provider=$${scanParams.length}`);
    }
    if (filters.scopeId) {
      scanParams.push(filters.scopeId);
      scanConditions.push(`scope_id=$${scanParams.length}`);
    }
    const scans = await this.pool.query(
      `SELECT * FROM scans ${scanConditions.length ? `WHERE ${scanConditions.join(" AND ")}` : ""} ORDER BY created_at DESC LIMIT 10`,
      scanParams,
    );
    const recentScans = scans.rows.map(scanRow);
    const evaluated = recentScans.filter((s) => s.status === "evaluated");
    const comparison =
      evaluated.length >= 2
        ? await this.compareScans(evaluated[1]!.id, evaluated[0]!.id)
        : undefined;
    const chronologicalScans = recentScans
      .filter((scan) => scan.status === "evaluated" && scan.summary)
      .slice()
      .reverse();
    const scanTrends = await Promise.all(
      chronologicalScans.map(async (scan, index) => {
        const lowerBound = chronologicalScans[index - 1]?.evaluatedAt ?? scan.createdAt;
        const upperBound = scan.evaluatedAt ?? scan.createdAt;
        const accepted = await this.pool.query<{ n: number }>(
          `SELECT COUNT(*)::int AS n FROM finding_events fe
           JOIN findings f ON f.fingerprint = fe.fingerprint
           WHERE fe.event_type = 'workflow_change' AND fe.to_state = 'risk_accepted'
             AND fe.created_at > $1 AND fe.created_at <= $2
             AND f.provider = $3 AND f.scope_id = $4`,
          [lowerBound, upperBound, scan.provider, scan.scopeId],
        );
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
          findingsAccepted: accepted.rows[0]!.n,
        };
      }),
    );
    return {
      generatedAt: new Date().toISOString(),
      windowDays: filters.sinceDays ?? 30,
      filters,
      openFindingsBySeverity: Object.fromEntries(severity.rows.map((r) => [r.severity, r.n])),
      openFindingsByService: service.rows.map((r) => ({
        provider: r.provider,
        service: r.service,
        count: r.n,
      })),
      topFailingControls: control.rows.map((r) => ({
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
      recentScans,
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

  async audit(entry: {
    actor: string;
    tool: string;
    args?: unknown;
    success: boolean;
    detail?: string;
  }): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(hashtext('cloudranger:audit'))");
      const last = await client.query("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1");
      const prevHash = last.rows[0]?.entry_hash ?? "genesis";
      const createdAt = new Date().toISOString();
      const args = entry.args === undefined ? null : redactSecrets(entry.args);
      const argsJson = args === null ? "" : JSON.stringify(args);
      const entryHash = createHash("sha256")
        .update(
          [
            prevHash,
            createdAt,
            entry.actor,
            entry.tool,
            argsJson,
            String(entry.success),
            entry.detail ?? "",
          ].join("|"),
        )
        .digest("hex");
      await client.query(
        `INSERT INTO audit_log (created_at,actor,tool,args,success,detail,prev_hash,entry_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
          createdAt,
          entry.actor,
          entry.tool,
          args === null ? null : JSON.stringify(args),
          entry.success,
          entry.detail ?? null,
          prevHash,
          entryHash,
        ],
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async searchAudit(limit = 50): Promise<unknown[]> {
    const result = await this.pool.query(
      "SELECT id,created_at,actor,tool,args,success,detail FROM audit_log ORDER BY id DESC LIMIT $1",
      [Math.min(limit, 500)],
    );
    return result.rows.map((r) => ({
      id: r.id,
      createdAt: iso(r.created_at),
      actor: r.actor,
      tool: r.tool,
      args: r.args ?? undefined,
      success: r.success,
      detail: r.detail ?? undefined,
    }));
  }

  async verifyAuditChain(): Promise<number | null> {
    const result = await this.pool.query("SELECT * FROM audit_log ORDER BY id");
    let prev = "genesis";
    for (const row of result.rows) {
      const argsJson = row.args == null ? "" : JSON.stringify(row.args);
      const expected = createHash("sha256")
        .update(
          [
            prev,
            iso(row.created_at),
            row.actor,
            row.tool,
            argsJson,
            String(row.success),
            row.detail ?? "",
          ].join("|"),
        )
        .digest("hex");
      if (row.prev_hash !== prev || row.entry_hash !== expected) return row.id;
      prev = row.entry_hash;
    }
    return null;
  }

  private async insertEvent(
    db: Queryable,
    fingerprint: string,
    scanId: string | null,
    eventType: string,
    fromState: string | null,
    toState: string | null,
    message: string | undefined,
    evidence: unknown,
    actor: string,
    createdAt: string,
  ): Promise<void> {
    await db.query(
      `INSERT INTO finding_events (fingerprint,scan_id,event_type,from_state,to_state,message,evidence,actor,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        fingerprint,
        scanId,
        eventType,
        fromState,
        toState,
        message ?? null,
        evidence === undefined ? null : JSON.stringify(evidence),
        actor,
        createdAt,
      ],
    );
  }
}

const SECRET_KEY_PATTERN = /secret|token|password|credential|apikey|api_key|private/i;
function redactSecrets(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) =>
        SECRET_KEY_PATTERN.test(key) ? [key, "[REDACTED]"] : [key, redactSecrets(item)],
      ),
    );
  return value;
}

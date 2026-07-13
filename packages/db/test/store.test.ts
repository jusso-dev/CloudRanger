import { beforeEach, describe, expect, it } from "vitest";
import { CloudRangerStore } from "../src/index.js";
import type { EvaluationResult } from "@cloudranger/engine";

let store: CloudRangerStore;

beforeEach(() => {
  store = new CloudRangerStore(":memory:");
});

const failResult = (overrides: Partial<EvaluationResult> = {}): EvaluationResult => ({
  controlId: "CR-AWS-S3-001",
  controlVersion: "1.0.0",
  provider: "aws",
  service: "s3",
  severity: "high",
  status: "fail",
  resourceId: "my-bucket",
  message: "Bucket does not block public access.",
  evidence: { "PublicAccessBlockConfiguration.BlockPublicAcls": false },
  evaluatedAt: new Date().toISOString(),
  ...overrides,
});

function runScan(results: EvaluationResult[]) {
  const scan = store.createScan({
    provider: "aws",
    scopeId: "123456789012",
    regions: ["ap-southeast-2"],
    controlIds: ["CR-AWS-S3-001"],
  });
  const summary = store.finalizeScan(scan.id, results, [
    { controlId: "CR-AWS-S3-001", status: "evaluated", missingCollectors: [] },
  ]);
  return { scan, summary };
}

describe("workspace access isolation", () => {
  it("persists memberships and protects the final administrator", () => {
    expect(() =>
      store.initializeWorkspace({
        workspaceId: "security-team",
        workspaceName: "Security Team",
        subject: "admin@example.com",
      }),
    ).toThrow(/not initialized/);
    expect(
      store.initializeWorkspace({
        workspaceId: "security-team",
        workspaceName: "Security Team",
        subject: "admin@example.com",
        bootstrapAdmin: true,
      }),
    ).toBe("admin");
    store.setWorkspaceMember({
      workspaceId: "security-team",
      subject: "operator@example.com",
      displayName: "Operator",
      role: "operator",
    });
    expect(store.listWorkspaceMembers("security-team")).toEqual([
      expect.objectContaining({ subject: "admin@example.com", role: "admin" }),
      expect.objectContaining({ subject: "operator@example.com", role: "operator" }),
    ]);
    expect(
      store.initializeWorkspace({
        workspaceId: "security-team",
        workspaceName: "Security Team",
        subject: "operator@example.com",
      }),
    ).toBe("operator");
    expect(() =>
      store.initializeWorkspace({
        workspaceId: "another-team",
        workspaceName: "Another Team",
        subject: "admin@example.com",
      }),
    ).toThrow(/bound to workspace security-team/);
    expect(() => store.removeWorkspaceMember("security-team", "admin@example.com")).toThrow(
      /last workspace admin/,
    );
  });
});

describe("finding lifecycle across scans", () => {
  it("includes the latest posture comparison in report data", () => {
    runScan([failResult()]);
    runScan([failResult({ status: "pass", message: "Bucket blocks all public access." })]);
    const report = store.reportData({}) as any;
    expect(report.comparison).toEqual(
      expect.objectContaining({
        coverage: expect.objectContaining({ baseline: 1, current: 1, delta: 0 }),
        controlChanges: [
          expect.objectContaining({
            controlId: "CR-AWS-S3-001",
            baseline: "fail",
            current: "pass",
          }),
        ],
      }),
    );
  });

  it("compares control status, finding events, and coverage across scans", () => {
    const baseline = runScan([failResult()]).scan;
    const current = runScan([
      failResult({ status: "pass", message: "Bucket blocks all public access." }),
    ]).scan;
    const comparison = store.compareScans(baseline.id, current.id);
    expect(comparison.coverage.baseline).toBe(1);
    expect(comparison.coverage.current).toBe(1);
    expect(comparison.coverage.delta).toBe(0);
    expect(comparison.controlChanges).toEqual([
      expect.objectContaining({
        controlId: "CR-AWS-S3-001",
        baseline: "fail",
        current: "pass",
      }),
    ]);
    expect(comparison.findingEvents).toEqual({ created: 1, resolved: 1 });
  });

  it("create -> recur -> resolve -> reopen preserves identity and history", () => {
    const { summary: s1 } = runScan([failResult()]);
    expect(s1.findingsCreated).toBe(1);
    const findings = store.searchFindings({ state: ["open"] }).findings;
    expect(findings).toHaveLength(1);
    const fp = findings[0]!.fingerprint;
    expect(findings[0]!.occurrenceCount).toBe(1);

    const { summary: s2 } = runScan([failResult()]);
    expect(s2.findingsRecurred).toBe(1);
    expect(store.getFinding(fp)!.occurrenceCount).toBe(2);
    expect(store.getFinding(fp)!.state).toBe("open");

    const { summary: s3 } = runScan([
      failResult({ status: "pass", message: "Bucket blocks all public access." }),
    ]);
    expect(s3.findingsResolved).toBe(1);
    const resolved = store.getFinding(fp)!;
    expect(resolved.state).toBe("resolved");
    expect(resolved.resolvedAt).toBeTruthy();

    const { summary: s4 } = runScan([failResult()]);
    expect(s4.findingsReopened).toBe(1);
    const reopened = store.getFinding(fp)!;
    expect(reopened.state).toBe("reopened");
    expect(reopened.reopenCount).toBe(1);
    expect(reopened.occurrenceCount).toBe(3);

    const events = store.getFindingEvents(fp).map((e) => e.eventType);
    expect(events).toEqual(["created", "recurred", "resolved", "reopened"]);
  });

  it("error results never resolve an open finding", () => {
    runScan([failResult()]);
    const fp = store.searchFindings({}).findings[0]!.fingerprint;
    runScan([failResult({ status: "error", message: "AccessDenied" })]);
    expect(store.getFinding(fp)!.state).toBe("open");
  });

  it("different regions produce distinct findings", () => {
    runScan([
      failResult({ resourceId: "sg-1", region: "ap-southeast-2" }),
      failResult({ resourceId: "sg-1", region: "us-east-1" }),
    ]);
    expect(store.searchFindings({}).total).toBe(2);
  });
});

describe("workflow state", () => {
  it("assigns ownership, finds overdue work, and expires exceptions", () => {
    runScan([failResult()]);
    const fp = store.searchFindings({}).findings[0]!.fingerprint;
    const assigned = store.assignFinding(fp, {
      owner: "platform-security",
      dueAt: "2020-01-01T00:00:00Z",
      actor: "manager",
    });
    expect(assigned.owner).toBe("platform-security");
    expect(store.searchFindings({ overdue: true }).total).toBe(1);
    store.setWorkflowState(fp, "risk_accepted", {
      actor: "manager",
      reason: "Temporary approved exception",
      expiresAt: "2020-01-01T00:00:00Z",
    });
    expect(store.getFinding(fp)!.workflowState).toBe("new");
    expect(store.getFindingEvents(fp).at(-1)!.message).toContain("expired");
  });

  it("risk acceptance requires a reason and records an event", () => {
    runScan([failResult()]);
    const fp = store.searchFindings({}).findings[0]!.fingerprint;
    expect(() => store.setWorkflowState(fp, "risk_accepted", { actor: "justin" })).toThrow(
      /reason/,
    );
    const updated = store.setWorkflowState(fp, "risk_accepted", {
      actor: "justin",
      reason: "Public bucket hosts the static marketing site",
      expiresAt: "2026-12-31T00:00:00Z",
    });
    expect(updated.workflowState).toBe("risk_accepted");
    expect(store.getFindingEvents(fp).at(-1)!.eventType).toBe("workflow_change");
  });
});

describe("evidence handling", () => {
  it("reports scan health gaps and failed evidence explicitly", () => {
    const scan = store.createScan({
      provider: "aws",
      scopeId: "1",
      regions: [],
      controlIds: ["CR-AWS-S3-001"],
    });
    store.addEvidence(scan.id, [
      {
        collectorId: "aws.s3.list_buckets",
        output: null,
        errorText: "AccessDenied",
        exitCode: 255,
      },
    ]);
    store.finalizeScan(
      scan.id,
      [failResult({ status: "error", message: "AccessDenied" })],
      [
        {
          controlId: "CR-AWS-S3-001",
          status: "missing_evidence",
          missingCollectors: ["aws.s3.list_buckets"],
        },
      ],
    );
    const health = store.scanHealth(scan.id);
    expect(health.healthy).toBe(false);
    expect(health.coverageRatio).toBe(0);
    expect(health.evidenceErrors).toBe(1);
    expect(health.missingCollectors).toEqual(["aws.s3.list_buckets"]);
    expect(health.reasons).toEqual(expect.arrayContaining(["1 evidence records failed"]));
  });

  it("detects required collectors that have not submitted evidence yet", () => {
    const scan = store.createScan({
      provider: "aws",
      scopeId: "1",
      regions: [],
      controlIds: ["CR-AWS-S3-001"],
    });
    const health = store.scanHealth(scan.id, 60, ["aws.s3.list_buckets"]);
    expect(health.status).toBe("collecting");
    expect(health.healthy).toBe(false);
    expect(health.expectedCollectors).toBe(1);
    expect(health.missingCollectors).toEqual(["aws.s3.list_buckets"]);
  });

  it("rejects evidence for evaluated scans", () => {
    const { scan } = runScan([failResult()]);
    expect(() =>
      store.addEvidence(scan.id, [{ collectorId: "aws.s3.list_buckets", output: {}, exitCode: 0 }]),
    ).toThrow(/not accepted/);
  });

  it("stores and returns evidence with stats", () => {
    const scan = store.createScan({ provider: "aws", scopeId: "1", regions: [], controlIds: [] });
    store.addEvidence(scan.id, [
      { collectorId: "aws.s3.list_buckets", output: { Buckets: [] }, exitCode: 0 },
      {
        collectorId: "aws.iam.get_account_summary",
        output: null,
        errorText: "denied",
        exitCode: 255,
      },
    ]);
    expect(store.getEvidence(scan.id)).toHaveLength(2);
    const stats = store.evidenceStats(scan.id);
    expect(stats.find((s) => s.collectorId === "aws.iam.get_account_summary")!.errors).toBe(1);
  });
});

describe("report data", () => {
  it("aggregates open findings and defines its metrics", () => {
    runScan([failResult(), failResult({ resourceId: "other-bucket", severity: "critical" })]);
    const report = store.reportData({}) as any;
    expect(report.openFindingsBySeverity).toEqual({ high: 1, critical: 1 });
    expect(report.metricDefinitions.openFindingsBySeverity).toContain("open or reopened");
    expect(report.recentScans).toHaveLength(1);
    expect(report.scanTrends).toEqual([
      expect.objectContaining({ coverageRatio: 1, fail: 2, findingsCreated: 2 }),
    ]);
  });
});

describe("audit log", () => {
  it("chains hashes, redacts secrets, and detects tampering", () => {
    store.audit({
      actor: "agent",
      tool: "scan_start",
      args: { provider: "aws", apiKey: "supersecret" },
      success: true,
    });
    store.audit({ actor: "agent", tool: "findings_search", success: true });
    const entries = store.searchAudit() as any[];
    expect(entries[1].args.apiKey).toBe("[REDACTED]");
    expect(store.verifyAuditChain()).toBeNull();
    store.db.prepare("UPDATE audit_log SET args = '{}' WHERE id = 1").run();
    expect(store.verifyAuditChain()).toBe(1);
  });
});

describe("scope parameter overrides", () => {
  it("round-trips, upserts, and clears per-control overrides", () => {
    store.setScopeParameters("aws", "123456789012", "CR-AWS-IAM-005", { maxKeyAgeDays: 30 });
    store.setScopeParameters("aws", "123456789012", "CR-AWS-IAM-003", {
      minimumPasswordLength: 16,
    });
    let rows = store.listScopeParameters("aws", "123456789012");
    expect(rows.map((r) => r.controlId)).toEqual(["CR-AWS-IAM-003", "CR-AWS-IAM-005"]);
    expect(rows[1]!.parameters).toEqual({ maxKeyAgeDays: 30 });

    store.setScopeParameters("aws", "123456789012", "CR-AWS-IAM-005", { maxKeyAgeDays: 60 });
    rows = store.listScopeParameters("aws", "123456789012");
    expect(rows[1]!.parameters).toEqual({ maxKeyAgeDays: 60 });

    store.setScopeParameters("aws", "123456789012", "CR-AWS-IAM-005", null);
    rows = store.listScopeParameters("aws", "123456789012");
    expect(rows.map((r) => r.controlId)).toEqual(["CR-AWS-IAM-003"]);

    expect(store.listScopeParameters("aws", "999999999999")).toEqual([]);
  });

  it("persists scan parameters and effective values on findings", () => {
    const scan = store.createScan({
      provider: "aws",
      scopeId: "123456789012",
      regions: ["ap-southeast-2"],
      controlIds: ["CR-AWS-S3-001"],
      parameters: { "CR-AWS-S3-001": { threshold: 5 } },
    });
    expect(store.getScan(scan.id)!.parameters).toEqual({ "CR-AWS-S3-001": { threshold: 5 } });

    store.finalizeScan(
      scan.id,
      [failResult({ effectiveParameters: { threshold: 5 } })],
      [{ controlId: "CR-AWS-S3-001", status: "evaluated", missingCollectors: [] }],
    );
    const { findings } = store.searchFindings({ state: ["open"] });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.effectiveParameters).toEqual({ threshold: 5 });
  });
});

describe("control revisions", () => {
  it("records revisions idempotently and preserves history across updates", () => {
    const rev = (version: string, hash: string) => ({
      controlId: "CR-AWS-S3-001",
      version,
      contentHash: hash,
      definition: { id: "CR-AWS-S3-001", version },
      deprecated: false,
    });
    expect(store.recordControlRevisions([rev("1.0.0", "aaa")])).toBe(1);
    expect(store.recordControlRevisions([rev("1.0.0", "aaa")])).toBe(0);
    expect(store.recordControlRevisions([rev("1.1.0", "bbb")])).toBe(1);
    const history = store.listControlRevisions("CR-AWS-S3-001");
    expect(history).toHaveLength(2);
    expect(history[0]!.firstSeenAt).toBeTruthy();
    expect(store.listControlRevisions("CR-NOPE-X-001")).toEqual([]);
  });
});

describe("evidence retention", () => {
  it("prunes only unprotected scans' payloads, preserving digests and findings", () => {
    store.setRetentionPolicy("aws", "123456789012", { keepScans: 1 });
    const record = {
      collectorId: "aws.s3.list_buckets",
      output: { Buckets: [{ Name: "b1" }] },
      exitCode: 0,
    };
    const older = store.createScan({
      provider: "aws",
      scopeId: "123456789012",
      regions: [],
      controlIds: ["CR-AWS-S3-001"],
    });
    store.addEvidence(older.id, [record]);
    store.finalizeScan(
      older.id,
      [failResult()],
      [{ controlId: "CR-AWS-S3-001", status: "evaluated", missingCollectors: [] }],
    );
    const newer = store.createScan({
      provider: "aws",
      scopeId: "123456789012",
      regions: [],
      controlIds: ["CR-AWS-S3-001"],
    });
    store.addEvidence(newer.id, [record]);

    const dry = store.pruneEvidence({ provider: "aws", scopeId: "123456789012" });
    expect(dry.executed).toBe(false);
    expect(dry.prunableScans).toEqual([older.id]);
    expect(dry.prunableRecords).toBe(1);
    expect(dry.prunableBytes).toBeGreaterThan(0);
    // Dry run really deleted nothing.
    expect(store.getEvidence(older.id)[0]!.output).toBeTruthy();

    const done = store.pruneEvidence({ provider: "aws", scopeId: "123456789012", execute: true });
    expect(done.executed).toBe(true);
    const pruned = store.getEvidence(older.id)[0]!;
    expect(pruned.output).toBeNull();
    // Digest metadata survives; newer scan untouched; findings intact.
    expect(store.getEvidence(newer.id)[0]!.output).toBeTruthy();
    expect(store.searchFindings({ state: ["open"] }).findings).toHaveLength(1);
    // Idempotent: nothing left to prune.
    expect(store.pruneEvidence({ provider: "aws", scopeId: "123456789012" }).prunableRecords).toBe(
      0,
    );
  });

  it("refuses to prune without a policy and supports clearing policies", () => {
    expect(() => store.pruneEvidence({ provider: "aws", scopeId: "555555555555" })).toThrow(
      /no retention policy/,
    );
    store.setRetentionPolicy("aws", "555555555555", { keepDays: 30 });
    expect(store.listRetentionPolicies()).toHaveLength(1);
    store.setRetentionPolicy("aws", "555555555555", null);
    expect(store.listRetentionPolicies()).toHaveLength(0);
  });
});

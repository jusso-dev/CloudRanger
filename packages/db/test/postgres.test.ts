import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { EvaluationResult } from "@cloudranger/engine";
import { PostgresCloudRangerStore } from "../src/postgres-store.js";

const databaseUrl = process.env.CLOUDRANGER_TEST_DATABASE_URL;
const suite = databaseUrl ? describe : describe.skip;
let store: PostgresCloudRangerStore;

suite("PostgreSQL repository", () => {
  beforeAll(async () => {
    store = new PostgresCloudRangerStore(databaseUrl!);
    await store.pool.query(
      "TRUNCATE audit_log,finding_events,findings,evaluations,evidence,scans,workspace_memberships,identities,workspaces RESTART IDENTITY CASCADE",
    );
  });
  afterAll(async () => store.close());

  it("binds the database to one workspace and persists roles", async () => {
    await expect(
      store.initializeWorkspace({
        workspaceId: "security-team",
        workspaceName: "Security Team",
        subject: "admin@example.com",
      }),
    ).rejects.toThrow(/not initialized/);
    await expect(
      store.initializeWorkspace({
        workspaceId: "security-team",
        workspaceName: "Security Team",
        subject: "admin@example.com",
        bootstrapAdmin: true,
      }),
    ).resolves.toBe("admin");
    await store.setWorkspaceMember({
      workspaceId: "security-team",
      subject: "auditor@example.com",
      role: "auditor",
    });
    await expect(
      store.initializeWorkspace({
        workspaceId: "security-team",
        workspaceName: "Security Team",
        subject: "auditor@example.com",
      }),
    ).resolves.toBe("auditor");
    expect(await store.listWorkspaceMembers("security-team")).toHaveLength(2);
    await expect(
      store.initializeWorkspace({
        workspaceId: "other-team",
        workspaceName: "Other Team",
        subject: "admin@example.com",
      }),
    ).rejects.toThrow(/bound to workspace security-team/);
  });

  it("persists the complete scan and finding lifecycle", async () => {
    const scan = await store.createScan({
      provider: "aws",
      scopeId: "123456789012",
      regions: ["ap-southeast-2"],
      controlIds: ["CR-AWS-S3-001"],
    });
    await store.addEvidence(scan.id, [
      {
        collectorId: "aws.s3.list_buckets",
        output: { Buckets: [{ Name: "public" }] },
        exitCode: 0,
      },
    ]);
    const result: EvaluationResult = {
      controlId: "CR-AWS-S3-001",
      controlVersion: "1.0.0",
      provider: "aws",
      service: "s3",
      severity: "critical",
      status: "fail",
      resourceId: "public",
      message: "Bucket is public.",
      evidence: { public: true },
      evaluatedAt: new Date().toISOString(),
    };
    const summary = await store.finalizeScan(
      scan.id,
      [result],
      [{ controlId: result.controlId, status: "evaluated", missingCollectors: [] }],
    );
    expect(summary.findingsCreated).toBe(1);
    expect((await store.getScan(scan.id))?.status).toBe("evaluated");
    const findings = await store.searchFindings({ state: ["open"] });
    expect(findings.total).toBe(1);
    const finding = findings.findings[0]!;
    expect(
      (await store.assignFinding(finding.fingerprint, { owner: "platform", actor: "test" })).owner,
    ).toBe("platform");
    expect(
      (await store.getFindingEvents(finding.fingerprint)).map((event) => event.eventType),
    ).toEqual(["created", "workflow_change"]);
    const report = (await store.reportData({ provider: "aws" })) as any;
    expect(report.openFindingsBySeverity.critical).toBe(1);
  });

  it("serializes concurrent audit writes into a valid hash chain", async () => {
    await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        store.audit({
          actor: `actor-${index}`,
          tool: "integration_test",
          args: { token: "secret" },
          success: true,
        }),
      ),
    );
    expect(await store.verifyAuditChain()).toBeNull();
    expect((await store.searchAudit(20))[0]).toMatchObject({ success: true });
  });
});

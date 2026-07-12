import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CloudRangerStore } from "@cloudranger/db";
import { createServer } from "../src/server.js";

// Point the operator custom catalog dir at an isolated temp dir so the
// catalog_add_custom_control test does not pollute the real ~/.cloudranger,
// and bundled-control counts stay deterministic.
const customDir = mkdtempSync(join(tmpdir(), "cr-mcp-catalog-"));
process.env.CLOUDRANGER_CUSTOM_CATALOG = customDir;

let client: Client;
let store: CloudRangerStore;
let loadDefaultCatalog: typeof import("@cloudranger/catalog").loadDefaultCatalog;

async function call(name: string, args: Record<string, unknown> = {}): Promise<any> {
  const result = (await client.callTool({ name, arguments: args })) as any;
  const text = result.content?.[0]?.text as string;
  const parsed = JSON.parse(text);
  if (result.isError) throw new Error(parsed.error);
  return parsed;
}

beforeAll(async () => {
  ({ loadDefaultCatalog } = await import("@cloudranger/catalog"));
  store = new CloudRangerStore(":memory:");
  const server = createServer({ store, catalog: loadDefaultCatalog(), actor: "test-agent" });
  client = new Client({ name: "cloudranger-test", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
});

afterAll(() => rmSync(customDir, { recursive: true, force: true }));

describe("MCP scan loop", () => {
  let scanId: string;
  let fingerprint: string;

  // Scan is scoped to an explicit control set so assertions stay stable as the
  // catalog grows (services: filters would pull in every ported control).
  const SCAN_CONTROLS = [
    "CR-AWS-IAM-001",
    "CR-AWS-IAM-002",
    "CR-AWS-IAM-003",
    "CR-AWS-S3-001",
    "CR-AWS-S3-003",
  ];

  it("lists catalog controls", async () => {
    const result = await call("catalog_list_controls", { provider: "aws", service: "s3" });
    expect(result.total).toBeGreaterThanOrEqual(4);
    expect(result.controls[0].source).toContain("prowler:");
  });

  it("starts a scan and returns a safe plan", async () => {
    const result = await call("scan_start", {
      provider: "aws",
      scopeId: "123456789012",
      regions: ["ap-southeast-2"],
      controlIds: SCAN_CONTROLS,
    });
    scanId = result.scanId;
    expect(result.controlCount).toBe(5);
    expect(result.plan.steps.length).toBeGreaterThan(0);
    for (const step of result.plan.steps) {
      expect(step.command).toMatch(/^aws /);
      expect(step.command).not.toMatch(/[;&|>`$]/);
    }
    const perResource = result.plan.steps.filter((s: any) => s.kind === "per_resource");
    expect(perResource.length).toBeGreaterThan(0);
    expect(perResource[0].iterate.instruction).toContain("{resource}");
  });

  it("rejects invalid scope values", async () => {
    await expect(
      call("scan_start", { provider: "aws", scopeId: "123; rm -rf /", regions: ["us-east-1"] }),
    ).rejects.toThrow(/invalid scopeId/);
  });

  it("accepts evidence and evaluates deterministically", async () => {
    await call("evidence_submit", {
      scanId,
      records: [
        {
          collectorId: "aws.iam.get_account_summary",
          exitCode: 0,
          output: { SummaryMap: { AccountMFAEnabled: 0, AccountAccessKeysPresent: 0 } },
        },
        {
          collectorId: "aws.s3.list_buckets",
          exitCode: 0,
          output: { Buckets: [{ Name: "exposed-bucket" }] },
        },
        {
          collectorId: "aws.s3.get_public_access_block",
          resourceKey: "exposed-bucket",
          exitCode: 254,
          output: null,
          errorText: "An error occurred (NoSuchPublicAccessBlockConfiguration)",
        },
        {
          collectorId: "aws.s3.get_bucket_versioning",
          resourceKey: "exposed-bucket",
          exitCode: 0,
          output: { Status: "Enabled" },
        },
      ],
    });
    const result = await call("scan_evaluate", { scanId });
    expect(result.summary.fail).toBe(2); // root MFA + public access block
    expect(result.summary.pass).toBe(2); // root keys + versioning
    expect(result.summary.findingsCreated).toBe(2);
    expect(result.coverage.gaps.length).toBeGreaterThan(0); // password policy etc. not collected
    expect(result.note).toContain("NOT assessed");
  });

  it("rejects evidence for unknown collectors", async () => {
    const scan = await call("scan_start", {
      provider: "aws",
      scopeId: "123456789012",
      regions: ["ap-southeast-2"],
      services: ["s3"],
    });
    await expect(
      call("evidence_submit", {
        scanId: scan.scanId,
        records: [{ collectorId: "aws.evil.exec", exitCode: 0, output: {} }],
      }),
    ).rejects.toThrow(/unknown collector/);
  });

  it("searches findings and returns detail with control context", async () => {
    const search = await call("findings_search", { state: ["open"] });
    expect(search.total).toBe(2);
    const s3Finding = search.findings.find((f: any) => f.controlId === "CR-AWS-S3-001");
    fingerprint = s3Finding.fingerprint;
    const detail = await call("findings_get", { fingerprint });
    expect(detail.control.remediation.steps.length).toBeGreaterThan(0);
    expect(detail.history[0].eventType).toBe("created");
  });

  it("enforces reason on risk acceptance", async () => {
    await expect(
      call("findings_set_status", { fingerprint, workflowState: "risk_accepted" }),
    ).rejects.toThrow(/reason/);
    const updated = await call("findings_set_status", {
      fingerprint,
      workflowState: "risk_accepted",
      reason: "Bucket intentionally public pending CDN migration",
      expiresAt: "2026-09-30T00:00:00Z",
    });
    expect(updated.workflowState).toBe("risk_accepted");
  });

  it("resolves and reopens findings across subsequent scans", async () => {
    // Second scan: bucket fixed.
    const scan2 = await call("scan_start", {
      provider: "aws",
      scopeId: "123456789012",
      regions: ["ap-southeast-2"],
      controlIds: ["CR-AWS-S3-001"],
    });
    await call("evidence_submit", {
      scanId: scan2.scanId,
      records: [
        {
          collectorId: "aws.s3.list_buckets",
          exitCode: 0,
          output: { Buckets: [{ Name: "exposed-bucket" }] },
        },
        {
          collectorId: "aws.s3.get_public_access_block",
          resourceKey: "exposed-bucket",
          exitCode: 0,
          output: {
            PublicAccessBlockConfiguration: {
              BlockPublicAcls: true,
              IgnorePublicAcls: true,
              BlockPublicPolicy: true,
              RestrictPublicBuckets: true,
            },
          },
        },
      ],
    });
    const eval2 = await call("scan_evaluate", { scanId: scan2.scanId });
    expect(eval2.summary.findingsResolved).toBe(1);
    let detail = await call("findings_get", { fingerprint });
    expect(detail.finding.state).toBe("resolved");

    // Third scan: regression.
    const scan3 = await call("scan_start", {
      provider: "aws",
      scopeId: "123456789012",
      regions: ["ap-southeast-2"],
      controlIds: ["CR-AWS-S3-001"],
    });
    await call("evidence_submit", {
      scanId: scan3.scanId,
      records: [
        {
          collectorId: "aws.s3.list_buckets",
          exitCode: 0,
          output: { Buckets: [{ Name: "exposed-bucket" }] },
        },
        {
          collectorId: "aws.s3.get_public_access_block",
          resourceKey: "exposed-bucket",
          exitCode: 254,
          output: null,
          errorText: "An error occurred (NoSuchPublicAccessBlockConfiguration)",
        },
      ],
    });
    const eval3 = await call("scan_evaluate", { scanId: scan3.scanId });
    expect(eval3.summary.findingsReopened).toBe(1);
    detail = await call("findings_get", { fingerprint });
    expect(detail.finding.state).toBe("reopened");
    expect(detail.finding.reopenCount).toBe(1);
    expect(detail.history.map((e: any) => e.eventType)).toContain("resolved");
  });

  it("lists packs and scans by pack", async () => {
    const packs = await call("catalog_list_packs");
    const ids = packs.packs.map((p: any) => p.id);
    expect(ids).toContain("essential-baseline");
    expect(packs.packs.every((p: any) => p.controlCount > 0)).toBe(true);

    const scan = await call("scan_start", {
      provider: "gcp",
      scopeId: "my-project",
      pack: "kubernetes",
    });
    expect(scan.controlCount).toBe(13);
    expect(scan.plan.steps.map((s: any) => s.collectorId)).toEqual(["gcp.container.clusters_list"]);

    await expect(
      call("scan_start", { provider: "gcp", scopeId: "my-project", pack: "bogus" }),
    ).rejects.toThrow(/unknown pack/);
  });

  it("produces repeatable report data with metric definitions", async () => {
    const report = await call("report_data", { sinceDays: 7 });
    expect(report.metricDefinitions).toBeTruthy();
    expect(report.openFindingsBySeverity.critical).toBe(1); // root MFA
    expect(report.currentlyReopened).toBe(1);
  });

  it("audits every tool call in a verifiable chain", async () => {
    const audit = await call("audit_search", { limit: 100 });
    expect(audit.chainIntact).toBe(true);
    const tools = audit.entries.map((e: any) => e.tool);
    expect(tools).toContain("scan_start");
    expect(tools).toContain("evidence_submit");
    expect(tools).toContain("findings_set_status");
    const failed = audit.entries.find((e: any) => e.tool === "findings_set_status" && !e.success);
    expect(failed).toBeTruthy();
    expect(audit.entries.every((e: any) => e.actor === "test-agent")).toBe(true);
  });

  it("generates a control template and adds a validated custom control", async () => {
    const template = await call("catalog_generate_control_template", {
      provider: "aws",
      collectorId: "aws.s3.get_bucket_versioning",
    });
    expect(template.template).toContain("CUSTOM-AWS-MYSERVICE-001");
    expect(
      template.availableCollectors.some((c: any) => c.id === "aws.s3.get_bucket_versioning"),
    ).toBe(true);

    const before = (await call("catalog_list_controls", { provider: "aws" })).total;
    const added = await call("catalog_add_custom_control", {
      filename: "custom-s3-mfa-delete",
      yaml: `controls:
  - id: CUSTOM-AWS-S3-001
    version: 1.0.0
    provider: aws
    service: s3
    title: S3 bucket has MFA Delete enabled
    description: Verifies MFA Delete on bucket versioning.
    rationale: MFA Delete requires a second factor to destroy versions.
    severity: low
    categories: [custom, resilience]
    source: { engine: custom, id: org-s3-17, license: Apache-2.0 }
    collector: aws.s3.get_bucket_versioning
    resourceIdField: $resourceKey
    passWhen: { op: equals, path: MFADelete, value: Enabled }
    failMessage: Bucket does not have MFA Delete enabled.
    passMessage: Bucket has MFA Delete enabled.
    remediation:
      summary: Enable MFA Delete via the root user with an MFA device.
      steps: [Enable MFA Delete on bucket versioning.]
    compliance: []
    references: [https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html]`,
    });
    expect(added.controls).toEqual(["CUSTOM-AWS-S3-001"]);
    expect(added.overridden).toEqual([]);
    const after = (await call("catalog_list_controls", { provider: "aws" })).total;
    expect(after).toBe(before + 1);

    // Custom control is immediately usable in a scan and evaluates deterministically.
    const scan = await call("scan_start", {
      provider: "aws",
      scopeId: "123456789012",
      controlIds: ["CUSTOM-AWS-S3-001"],
      regions: ["ap-southeast-2"],
    });
    await call("evidence_submit", {
      scanId: scan.scanId,
      records: [
        { collectorId: "aws.s3.list_buckets", exitCode: 0, output: { Buckets: [{ Name: "b" }] } },
        {
          collectorId: "aws.s3.get_bucket_versioning",
          resourceKey: "b",
          exitCode: 0,
          output: { Status: "Enabled", MFADelete: "Disabled" },
        },
      ],
    });
    const evaluated = await call("scan_evaluate", { scanId: scan.scanId });
    expect(evaluated.summary.fail).toBe(1);
  });

  it("rejects an unsafe custom collector", async () => {
    await expect(
      call("catalog_add_custom_control", {
        filename: "evil",
        yaml: `collectors:
  - id: aws.evil.wipe
    provider: aws
    service: evil
    description: nope
    kind: single
    command: aws ec2 terminate-instances --instance-ids i-1
    regional: false
    outputFormat: json`,
      }),
    ).rejects.toThrow(/unsafe command|validation failed/);
  });

  it("lists custom-control tools", async () => {
    const tools = await client.listTools();
    const names = tools.tools.map((t) => t.name);
    expect(names).toContain("catalog_generate_control_template");
    expect(names).toContain("catalog_add_custom_control");
    expect(names).toContain("catalog_list_packs");
  });

  it("exposes resources and prompts", async () => {
    const resources = await client.listResources();
    const uris = resources.resources.map((r) => r.uri);
    expect(uris).toContain("cloudranger://guides/safety");
    const safety = await client.readResource({ uri: "cloudranger://guides/safety" });
    expect((safety.contents[0] as any).text).toContain("read-only");

    const prompts = await client.listPrompts();
    const names = prompts.prompts.map((p) => p.name);
    for (const expected of [
      "run_full_scan",
      "daily_security_review",
      "executive_brief",
      "investigate_finding",
      "remediation_plan",
    ]) {
      expect(names).toContain(expected);
    }
    const brief = await client.getPrompt({
      name: "executive_brief",
      arguments: { periodDays: "14" },
    });
    expect((brief.messages[0]!.content as any).text).toContain("report_data");
  });
});

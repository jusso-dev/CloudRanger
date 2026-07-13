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

  it("resumes a scan from persisted evidence without repeating completed steps", async () => {
    const started = await call("scan_start", {
      provider: "aws",
      scopeId: "123456789012",
      regions: ["ap-southeast-2"],
      controlIds: ["CR-AWS-S3-001"],
    });
    await call("evidence_submit", {
      scanId: started.scanId,
      records: [
        {
          collectorId: "aws.s3.list_buckets",
          exitCode: 0,
          output: { Buckets: [{ Name: "resume-bucket" }] },
        },
      ],
    });
    const resumed = await call("scan_resume", { scanId: started.scanId });
    expect(resumed.persistedEvidenceRecords).toBe(1);
    expect(resumed.pendingSteps.map((step: any) => step.collectorId)).not.toContain(
      "aws.s3.list_buckets",
    );
    expect(resumed.pendingSteps.map((step: any) => step.collectorId)).toContain(
      "aws.s3.get_public_access_block",
    );
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

describe("parameterised controls over MCP", () => {
  const SCOPE = "222233334444";

  it("persists, lists, and validates scope parameter overrides", async () => {
    const set = await call("parameters_set", {
      provider: "aws",
      scopeId: SCOPE,
      controlId: "CR-AWS-IAM-003",
      parameters: { minimumPasswordLength: 20 },
    });
    expect(set.parameters).toEqual({ minimumPasswordLength: 20 });
    expect(set.declared.minimumPasswordLength.default).toBe(14);

    const listed = await call("parameters_list", { provider: "aws", scopeId: SCOPE });
    expect(listed.overrides).toHaveLength(1);
    expect(listed.overrides[0].controlId).toBe("CR-AWS-IAM-003");
    expect(listed.parameterisedControls.some((c: any) => c.controlId === "CR-AWS-IAM-005")).toBe(
      true,
    );

    await expect(
      call("parameters_set", {
        provider: "aws",
        scopeId: SCOPE,
        controlId: "CR-AWS-IAM-003",
        parameters: { minimumPasswordLength: 2 },
      }),
    ).rejects.toThrow(/below the minimum/);

    await expect(
      call("parameters_set", {
        provider: "aws",
        scopeId: SCOPE,
        controlId: "CR-AWS-IAM-001",
        parameters: { nope: 1 },
      }),
    ).rejects.toThrow(/does not declare/);
  });

  it("applies persisted + scan overrides and records effective values on findings", async () => {
    const started = await call("scan_start", {
      provider: "aws",
      scopeId: SCOPE,
      regions: ["ap-southeast-2"],
      controlIds: ["CR-AWS-IAM-003"],
    });
    expect(started.parameters).toEqual({
      "CR-AWS-IAM-003": { minimumPasswordLength: 20 },
    });

    await call("evidence_submit", {
      scanId: started.scanId,
      records: [
        {
          collectorId: "aws.iam.get_account_password_policy",
          output: { PasswordPolicy: { MinimumPasswordLength: 16 } },
          exitCode: 0,
        },
      ],
    });
    const evaluated = await call("scan_evaluate", { scanId: started.scanId });
    // 16 >= 14 default would pass, but the persisted override of 20 fails it.
    expect(evaluated.summary.fail).toBe(1);

    const findings = await call("findings_search", {
      scopeId: SCOPE,
      controlId: "CR-AWS-IAM-003",
    });
    expect(findings.findings[0].effectiveParameters).toEqual({ minimumPasswordLength: 20 });

    // A per-scan override wins over the persisted one.
    const rerun = await call("scan_start", {
      provider: "aws",
      scopeId: SCOPE,
      regions: ["ap-southeast-2"],
      controlIds: ["CR-AWS-IAM-003"],
      parameters: { "CR-AWS-IAM-003": { minimumPasswordLength: 12 } },
    });
    expect(rerun.parameters).toEqual({ "CR-AWS-IAM-003": { minimumPasswordLength: 12 } });
    await call("evidence_submit", {
      scanId: rerun.scanId,
      records: [
        {
          collectorId: "aws.iam.get_account_password_policy",
          output: { PasswordPolicy: { MinimumPasswordLength: 16 } },
          exitCode: 0,
        },
      ],
    });
    const reEvaluated = await call("scan_evaluate", { scanId: rerun.scanId });
    expect(reEvaluated.summary.pass).toBe(1);

    await expect(
      call("scan_start", {
        provider: "aws",
        scopeId: SCOPE,
        regions: ["ap-southeast-2"],
        controlIds: ["CR-AWS-IAM-003"],
        parameters: { "CR-AWS-IAM-999": { anything: 1 } },
      }),
    ).rejects.toThrow(/not in this scan/);
  });
});

describe("compliance_status over MCP", () => {
  const SCOPE = "555566667777";

  it("reports everything not assessed when no scan exists", async () => {
    const result = await call("compliance_status", {
      provider: "aws",
      scopeId: SCOPE,
      framework: "cis-aws-foundations",
    });
    expect(result.scanId).toBeUndefined();
    expect(result.note).toMatch(/No evaluated scan/);
    expect(result.frameworks[0].requirements.every((r: any) => r.status === "not_assessed")).toBe(
      true,
    );
  });

  it("rolls the latest evaluated scan up to framework requirements", async () => {
    const started = await call("scan_start", {
      provider: "aws",
      scopeId: SCOPE,
      regions: ["ap-southeast-2"],
      controlIds: ["CR-AWS-IAM-001"],
    });
    await call("evidence_submit", {
      scanId: started.scanId,
      records: [
        {
          collectorId: "aws.iam.get_account_summary",
          output: { SummaryMap: { AccountMFAEnabled: 0, AccountAccessKeysPresent: 0 } },
          exitCode: 0,
        },
      ],
    });
    await call("scan_evaluate", { scanId: started.scanId });

    const result = await call("compliance_status", { provider: "aws", scopeId: SCOPE });
    expect(result.scanId).toBe(started.scanId);
    const e8 = result.frameworks.find((f: any) => f.framework === "essential-eight");
    expect(e8).toBeDefined();
    const mfa = e8.requirements.find((r: any) => r.requirement === "multi-factor-authentication");
    // Root MFA disabled → CR-AWS-IAM-001 fails → requirement non_compliant,
    // and E8 mappings are all partial automation.
    expect(mfa.status).toBe("non_compliant");
    expect(mfa.automation).toBe("partial");
    expect(mfa.fullyAssessed).toBe(false); // IAM-004/018 not in the scan
    const ism = result.frameworks.find((f: any) => f.framework === "ism");
    expect(ism.totals.totalRequirements).toBeGreaterThan(1000);
    expect(ism.totals.mappedRatio).toBeLessThan(0.05);
  });

  it("scan_start accepts the framework-aligned packs", async () => {
    const cis = await call("scan_start", {
      provider: "aws",
      scopeId: SCOPE,
      regions: ["ap-southeast-2"],
      pack: "cis-aws-3.0",
    });
    expect(cis.controlCount).toBeGreaterThan(10);
    const e8 = await call("scan_start", {
      provider: "aws",
      scopeId: SCOPE,
      regions: ["ap-southeast-2"],
      pack: "essential-eight-technical",
    });
    expect(e8.controlCount).toBeGreaterThanOrEqual(8);
  });
});

describe("custom-control fixture authoring via MCP", () => {
  const yaml = `controls:
  - id: CUSTOM-AWS-S3-901
    version: 1.0.0
    provider: aws
    service: s3
    title: Bucket versioning enabled (custom)
    description: d
    rationale: r
    severity: medium
    categories: [resilience]
    source: { engine: custom, id: custom_bucket_versioning, license: Apache-2.0 }
    collector: aws.s3.get_bucket_versioning
    resourceIdField: $resourceKey
    passWhen: { op: equals, path: Status, value: Enabled }
    failMessage: Versioning off.
    passMessage: Versioning on.
    remediation: { summary: s, steps: [s] }
    compliance: []
    references: []
`;
  const fixtures = (expected: string) => [
    {
      controlId: "CUSTOM-AWS-S3-901",
      cases: [
        {
          name: "enabled passes",
          expected: "pass",
          records: [
            {
              collectorId: "aws.s3.get_bucket_versioning",
              resourceKey: "bucket-a",
              output: { Status: "Enabled" },
              exitCode: 0,
            },
          ],
        },
        {
          name: "suspended verdict",
          expected,
          records: [
            {
              collectorId: "aws.s3.get_bucket_versioning",
              resourceKey: "bucket-b",
              output: { Status: "Suspended" },
              exitCode: 0,
            },
          ],
        },
      ],
    },
  ];

  it("rejects the install when a fixture disagrees with the engine", async () => {
    await expect(
      call("catalog_add_custom_control", {
        yaml,
        filename: "custom-versioning-bad",
        fixtures: fixtures("pass"), // Suspended cannot pass
      }),
    ).rejects.toThrow(/expected pass, engine says fail — install rejected/);
  });

  it("rejects fixtures referencing controls outside the document", async () => {
    await expect(
      call("catalog_add_custom_control", {
        yaml,
        filename: "custom-versioning-foreign",
        fixtures: [{ controlId: "CR-AWS-IAM-001", cases: fixtures("fail")[0].cases }],
      }),
    ).rejects.toThrow(/not in this document/);
  });

  it("installs control + fixtures together when verdicts agree", async () => {
    const result = await call("catalog_add_custom_control", {
      yaml,
      filename: "custom-versioning",
      fixtures: fixtures("fail"),
    });
    expect(result.controls).toEqual(["CUSTOM-AWS-S3-901"]);
    expect(result.fixtureCases).toBe(2);
    expect(result.savedFixtures).toMatch(/fixtures\/custom-versioning\.json$/);
    expect(result.note).toMatch(/fixtures run/);
  });
});

describe("deprecation and revision history", () => {
  const deprecatedYaml = `controls:
  - id: CUSTOM-AWS-S3-902
    version: 1.0.0
    provider: aws
    service: s3
    title: Old bucket check (deprecated)
    description: d
    rationale: r
    severity: low
    categories: [resilience]
    source: { engine: custom, id: old_check, license: Apache-2.0 }
    collector: aws.s3.get_bucket_versioning
    resourceIdField: $resourceKey
    passWhen: { op: equals, path: Status, value: Enabled }
    failMessage: f
    passMessage: p
    remediation: { summary: s, steps: [s] }
    compliance: []
    references: []
    deprecated:
      reason: Superseded by CUSTOM-AWS-S3-901.
      supersededBy: CUSTOM-AWS-S3-901
`;

  it("records revisions at install and startup, queryable with a tamper check", async () => {
    await call("catalog_add_custom_control", {
      yaml: deprecatedYaml,
      filename: "custom-deprecated",
    });
    const history = await call("catalog_control_history", { controlId: "CUSTOM-AWS-S3-902" });
    expect(history.revisions).toHaveLength(1);
    expect(history.revisions[0].deprecated).toBe(true);
    expect(history.live.matchesRecordedRevision).toBe(true);
    expect(history.live.deprecated.supersededBy).toBe("CUSTOM-AWS-S3-901");
  });

  it("excludes deprecated controls from scans unless explicitly requested", async () => {
    const scoped = await call("scan_start", {
      provider: "aws",
      scopeId: "888899990000",
      regions: ["ap-southeast-2"],
      services: ["s3"],
    });
    expect(scoped.plan.controlIds ?? []).not.toContain("CUSTOM-AWS-S3-902");
    expect(scoped.deprecatedExcluded).toContain("CUSTOM-AWS-S3-902");
    expect(scoped.deprecationNote).toMatch(/excluded/);

    const explicit = await call("scan_start", {
      provider: "aws",
      scopeId: "888899990000",
      regions: ["ap-southeast-2"],
      controlIds: ["CUSTOM-AWS-S3-902"],
    });
    expect(explicit.controlCount).toBe(1);
    expect(explicit.deprecatedExcluded).toBeUndefined();

    const included = await call("scan_start", {
      provider: "aws",
      scopeId: "888899990000",
      regions: ["ap-southeast-2"],
      services: ["s3"],
      includeDeprecated: true,
    });
    expect(included.deprecatedExcluded).toBeUndefined();
  });

  it("keeps prior revisions when a control is updated", async () => {
    const bumped = deprecatedYaml.replace("version: 1.0.0", "version: 1.1.0");
    await call("catalog_add_custom_control", { yaml: bumped, filename: "custom-deprecated" });
    const history = await call("catalog_control_history", { controlId: "CUSTOM-AWS-S3-902" });
    expect(history.revisions).toHaveLength(2);
    expect(history.revisions.map((r: any) => r.version).sort()).toEqual(["1.0.0", "1.1.0"]);
    expect(history.live.version).toBe("1.1.0");
    expect(history.live.matchesRecordedRevision).toBe(true);
  });
});

describe("retention over MCP", () => {
  it("sets policy, dry-runs by default, and demands double confirmation", async () => {
    await call("retention_policy_set", {
      provider: "aws",
      scopeId: "121212121212",
      keepScans: 1,
    });
    const listed = await call("retention_policy_list", {});
    expect(listed.policies.some((p: any) => p.scopeId === "121212121212")).toBe(true);

    const dry = await call("evidence_prune", { provider: "aws", scopeId: "121212121212" });
    expect(dry.executed).toBe(false);
    expect(dry.note).toMatch(/Dry run/);

    await expect(
      call("evidence_prune", { provider: "aws", scopeId: "121212121212", execute: true }),
    ).rejects.toThrow(/confirm/);
  });
});

describe("multi-scope report_data", () => {
  it("aggregates across scopes with per-scope breakdown and explicit exclusions", async () => {
    // Two scopes already have evaluated scans from earlier tests
    // (222233334444 and 555566667777); ask for one explicitly.
    const result = await call("report_data", {
      provider: "aws",
      scopeIds: ["555566667777"],
    });
    expect(result.multiScope).toBe(true);
    expect(result.scopes).toHaveLength(1);
    expect(result.scopes[0].scopeId).toBe("555566667777");
    expect(result.scopes[0].latestEvaluatedScan).toBeDefined();
    expect(result.scopesPresentButNotIncluded.length).toBeGreaterThan(0);
    expect(result.note).toMatch(/never deduplicated/);

    const everything = await call("report_data", { provider: "aws", allScopes: true });
    expect(everything.scopes.length).toBeGreaterThanOrEqual(2);
    const sum = everything.scopes.reduce(
      (n: number, scope: any) =>
        n +
        Object.values(scope.openFindingsBySeverity as Record<string, number>).reduce(
          (a: number, b: number) => a + b,
          0,
        ),
      0,
    );
    const aggregate = Object.values(
      everything.aggregate.openFindingsBySeverity as Record<string, number>,
    ).reduce((a: number, b: number) => a + b, 0);
    expect(aggregate).toBe(sum);

    await expect(call("report_data", { scopeId: "x", scopeIds: ["y"] })).rejects.toThrow(
      /cannot be combined/,
    );

    const missing = await call("report_data", {
      provider: "aws",
      scopeIds: ["000000000000"],
    });
    expect(missing.requestedButNoScans).toEqual(["000000000000"]);
    expect(missing.scopes).toHaveLength(0);
  });
});

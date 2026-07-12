import { describe, expect, it } from "vitest";
import { evaluateControls } from "../src/evaluate.js";
import type { CollectorDefinition, ControlDefinition, EvidenceBundle } from "../src/types.js";

const NOW = new Date("2026-07-12T00:00:00Z");

const listBucketsCollector: CollectorDefinition = {
  id: "aws.s3.list_buckets",
  provider: "aws",
  service: "s3",
  description: "List S3 buckets",
  kind: "single",
  command: "aws s3api list-buckets --output json",
  regional: false,
  outputFormat: "json",
};

const pabCollector: CollectorDefinition = {
  id: "aws.s3.get_public_access_block",
  provider: "aws",
  service: "s3",
  description: "Get bucket public access block",
  kind: "per_resource",
  command: "aws s3api get-public-access-block --bucket {resource} --output json",
  regional: false,
  parent: { collector: "aws.s3.list_buckets", itemsPath: "Buckets", resourceField: "Name" },
  outputFormat: "json",
};

const pabControl: ControlDefinition = {
  id: "CR-AWS-S3-001",
  version: "1.0.0",
  provider: "aws",
  service: "s3",
  title: "S3 bucket blocks public access",
  description: "d",
  rationale: "r",
  severity: "high",
  categories: ["public-exposure"],
  source: { engine: "prowler", id: "s3_bucket_public_access_block", license: "Apache-2.0" },
  collector: "aws.s3.get_public_access_block",
  resourceIdField: "Name",
  passWhen: {
    op: "and",
    exprs: [
      { op: "equals", path: "PublicAccessBlockConfiguration.BlockPublicAcls", value: true },
      { op: "equals", path: "PublicAccessBlockConfiguration.IgnorePublicAcls", value: true },
      { op: "equals", path: "PublicAccessBlockConfiguration.BlockPublicPolicy", value: true },
      { op: "equals", path: "PublicAccessBlockConfiguration.RestrictPublicBuckets", value: true },
    ],
  },
  onError: [
    {
      contains: "NoSuchPublicAccessBlockConfiguration",
      status: "fail",
      message: "No public access block configured.",
    },
    { contains: "AccessDenied", status: "error" },
  ],
  failMessage: "Bucket does not block all public access.",
  passMessage: "Bucket blocks all public access.",
  remediation: { summary: "Enable public access block.", steps: ["Enable all four settings."] },
  compliance: [],
  references: [],
};

const sgControl: ControlDefinition = {
  id: "CR-AWS-EC2-001",
  version: "1.0.0",
  provider: "aws",
  service: "ec2",
  title: "No SSH open to the world",
  description: "d",
  rationale: "r",
  severity: "high",
  categories: ["network"],
  source: {
    engine: "prowler",
    id: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
    license: "Apache-2.0",
  },
  collector: "aws.ec2.describe_security_groups",
  resourcesPath: "SecurityGroups",
  resourceIdField: "GroupId",
  resourceNameField: "GroupName",
  passWhen: {
    op: "noneItem",
    path: "IpPermissions",
    condition: {
      op: "and",
      exprs: [
        { op: "portIncludes", fromPath: "FromPort", toPath: "ToPort", value: 22 },
        {
          op: "or",
          exprs: [
            { op: "anyItem", path: "IpRanges", condition: { op: "isPublicCidr", path: "CidrIp" } },
            {
              op: "anyItem",
              path: "Ipv6Ranges",
              condition: { op: "isPublicCidr", path: "CidrIpv6" },
            },
          ],
        },
      ],
    },
  },
  failMessage: "Security group allows SSH from the internet.",
  passMessage: "No world-open SSH.",
  remediation: { summary: "Restrict port 22.", steps: ["Restrict source ranges."] },
  compliance: [],
  references: [],
};

const sgCollector: CollectorDefinition = {
  id: "aws.ec2.describe_security_groups",
  provider: "aws",
  service: "ec2",
  description: "Describe security groups",
  kind: "single",
  command: "aws ec2 describe-security-groups --region {region} --output json",
  regional: true,
  outputFormat: "json",
};

const collectors = new Map<string, CollectorDefinition>([
  [listBucketsCollector.id, listBucketsCollector],
  [pabCollector.id, pabCollector],
  [sgCollector.id, sgCollector],
]);

describe("evaluateControls", () => {
  it("evaluates per_resource evidence including error mapping", () => {
    const bundle: EvidenceBundle = {
      provider: "aws",
      scopeId: "123456789012",
      records: [
        {
          collectorId: "aws.s3.get_public_access_block",
          resourceKey: "good-bucket",
          output: {
            PublicAccessBlockConfiguration: {
              BlockPublicAcls: true,
              IgnorePublicAcls: true,
              BlockPublicPolicy: true,
              RestrictPublicBuckets: true,
            },
          },
          exitCode: 0,
          collectedAt: NOW.toISOString(),
        },
        {
          collectorId: "aws.s3.get_public_access_block",
          resourceKey: "bad-bucket",
          output: null,
          errorText:
            "An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation",
          exitCode: 254,
          collectedAt: NOW.toISOString(),
        },
        {
          collectorId: "aws.s3.get_public_access_block",
          resourceKey: "denied-bucket",
          output: null,
          errorText: "An error occurred (AccessDenied)",
          exitCode: 254,
          collectedAt: NOW.toISOString(),
        },
      ],
    };
    const { results } = evaluateControls([pabControl], collectors, bundle, { now: NOW });
    const byResource = Object.fromEntries(results.map((r) => [r.resourceId, r.status]));
    expect(byResource).toEqual({
      "good-bucket": "pass",
      "bad-bucket": "fail",
      "denied-bucket": "error",
    });
  });

  it("evaluates array resources from single collectors across regions", () => {
    const bundle: EvidenceBundle = {
      provider: "aws",
      scopeId: "123456789012",
      records: [
        {
          collectorId: "aws.ec2.describe_security_groups",
          region: "ap-southeast-2",
          output: {
            SecurityGroups: [
              {
                GroupId: "sg-open",
                GroupName: "open",
                IpPermissions: [{ FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "0.0.0.0/0" }] }],
              },
              {
                GroupId: "sg-closed",
                GroupName: "closed",
                IpPermissions: [{ FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "10.0.0.0/8" }] }],
              },
            ],
          },
          exitCode: 0,
          collectedAt: NOW.toISOString(),
        },
        {
          collectorId: "aws.ec2.describe_security_groups",
          region: "us-east-1",
          output: { SecurityGroups: [] },
          exitCode: 0,
          collectedAt: NOW.toISOString(),
        },
      ],
    };
    const { results, coverage } = evaluateControls([sgControl], collectors, bundle, { now: NOW });
    expect(results).toHaveLength(2);
    expect(results.find((r) => r.resourceId === "sg-open")?.status).toBe("fail");
    expect(results.find((r) => r.resourceId === "sg-open")?.region).toBe("ap-southeast-2");
    expect(results.find((r) => r.resourceId === "sg-closed")?.status).toBe("pass");
    expect(coverage[0]).toEqual({
      controlId: "CR-AWS-EC2-001",
      status: "evaluated",
      missingCollectors: [],
    });
  });

  it("reports missing evidence as coverage gap, not pass", () => {
    const bundle: EvidenceBundle = { provider: "aws", scopeId: "123456789012", records: [] };
    const { results, coverage } = evaluateControls([sgControl, pabControl], collectors, bundle, {
      now: NOW,
    });
    expect(results).toHaveLength(0);
    expect(coverage.every((c) => c.status === "missing_evidence")).toBe(true);
  });

  it("collector-level failure produces error result, never pass", () => {
    const bundle: EvidenceBundle = {
      provider: "aws",
      scopeId: "123456789012",
      records: [
        {
          collectorId: "aws.ec2.describe_security_groups",
          region: "ap-southeast-2",
          output: null,
          errorText: "Unable to locate credentials",
          exitCode: 255,
          collectedAt: NOW.toISOString(),
        },
      ],
    };
    const { results } = evaluateControls([sgControl], collectors, bundle, { now: NOW });
    expect(results).toHaveLength(1);
    expect(results[0]!.status).toBe("error");
  });

  it("aggregate mode treats a top-level array as one scope resource for anyItem", () => {
    // Account-level check: "does ANY analyzer exist" over a top-level array.
    const listCollector: CollectorDefinition = {
      id: "aws.accessanalyzer.list_analyzers",
      provider: "aws",
      service: "accessanalyzer",
      description: "List IAM Access Analyzers",
      kind: "single",
      command: "aws accessanalyzer list-analyzers --region {region} --output json",
      regional: true,
      outputFormat: "json",
    };
    const aggControl: ControlDefinition = {
      id: "CR-AWS-ACCESSANALYZER-001",
      version: "1.0.0",
      provider: "aws",
      service: "accessanalyzer",
      title: "At least one active IAM Access Analyzer exists",
      description: "The account has an active analyzer.",
      rationale: "Access Analyzer surfaces resources shared externally.",
      severity: "medium",
      categories: ["identity"],
      source: { engine: "prowler", id: "accessanalyzer_enabled", license: "Apache-2.0" },
      collector: "aws.accessanalyzer.list_analyzers",
      aggregate: true,
      resourceIdField: "$scope",
      passWhen: {
        op: "anyItem",
        path: "$",
        condition: { op: "equals", path: "status", value: "ACTIVE" },
      },
      onError: [],
      failMessage: "No active Access Analyzer.",
      passMessage: "An active Access Analyzer exists.",
      remediation: { summary: "Create an analyzer.", steps: ["Create an account analyzer."] },
      compliance: [],
      references: [],
    };
    const aggCollectors = new Map<string, CollectorDefinition>([[listCollector.id, listCollector]]);
    const mk = (output: unknown): EvidenceBundle => ({
      provider: "aws",
      scopeId: "123456789012",
      records: [
        {
          collectorId: listCollector.id,
          region: "us-east-1",
          output,
          exitCode: 0,
          collectedAt: NOW.toISOString(),
        },
      ],
    });

    // One record, whole array = one unit → exactly one result (not split per item).
    const pass = evaluateControls([aggControl], aggCollectors, mk([{ status: "ACTIVE" }]), {
      now: NOW,
    });
    expect(pass.results).toHaveLength(1);
    expect(pass.results[0]!.status).toBe("pass");
    expect(pass.results[0]!.resourceId).toBe("123456789012");

    // Empty inventory → the aggregate unit exists but no item matches → fail (not no_results).
    const fail = evaluateControls([aggControl], aggCollectors, mk([]), { now: NOW });
    expect(fail.results).toHaveLength(1);
    expect(fail.results[0]!.status).toBe("fail");
  });
});

import { describe, expect, it } from "vitest";
import { buildPlan } from "../src/plan.js";
import type { CollectorDefinition, ControlDefinition } from "../src/types.js";

const collectors = new Map<string, CollectorDefinition>([
  [
    "aws.s3.list_buckets",
    {
      id: "aws.s3.list_buckets",
      provider: "aws",
      service: "s3",
      description: "List buckets",
      kind: "single",
      command: "aws s3api list-buckets --output json",
      regional: false,
      outputFormat: "json",
    },
  ],
  [
    "aws.s3.get_bucket_versioning",
    {
      id: "aws.s3.get_bucket_versioning",
      provider: "aws",
      service: "s3",
      description: "Bucket versioning",
      kind: "per_resource",
      command: "aws s3api get-bucket-versioning --bucket {resource} --output json",
      regional: false,
      parent: { collector: "aws.s3.list_buckets", itemsPath: "Buckets", resourceField: "Name" },
      outputFormat: "json",
    },
  ],
  [
    "aws.ec2.describe_security_groups",
    {
      id: "aws.ec2.describe_security_groups",
      provider: "aws",
      service: "ec2",
      description: "Security groups",
      kind: "single",
      command: "aws ec2 describe-security-groups --region {region} --output json",
      regional: true,
      outputFormat: "json",
    },
  ],
]);

const control = (id: string, collector: string): ControlDefinition => ({
  id,
  version: "1.0.0",
  provider: "aws",
  service: "s3",
  title: "t",
  description: "d",
  rationale: "r",
  severity: "high",
  categories: ["x"],
  source: { engine: "prowler", id: "src", license: "Apache-2.0" },
  collector,
  resourceIdField: "Name",
  passWhen: { op: "exists", path: "$" },
  failMessage: "f",
  passMessage: "p",
  remediation: { summary: "s", steps: ["s"] },
  compliance: [],
  references: [],
});

describe("buildPlan", () => {
  it("expands regional collectors per region and includes parents of per_resource collectors", () => {
    const plan = buildPlan(
      [
        control("CR-AWS-S3-010", "aws.s3.get_bucket_versioning"),
        control("CR-AWS-EC2-001", "aws.ec2.describe_security_groups"),
      ],
      collectors,
      { provider: "aws", regions: ["ap-southeast-2", "us-east-1"] },
    );
    const ids = plan.steps.map((s) => s.collectorId);
    expect(ids.filter((id) => id === "aws.ec2.describe_security_groups")).toHaveLength(2);
    expect(ids).toContain("aws.s3.list_buckets");
    expect(ids).toContain("aws.s3.get_bucket_versioning");
    // parent listed before dependent
    expect(ids.indexOf("aws.s3.list_buckets")).toBeLessThan(
      ids.indexOf("aws.s3.get_bucket_versioning"),
    );
    const regional = plan.steps.find((s) => s.collectorId === "aws.ec2.describe_security_groups");
    expect(regional?.command).toContain("--region ap-southeast-2");
    const perResource = plan.steps.find((s) => s.collectorId === "aws.s3.get_bucket_versioning");
    expect(perResource?.iterate?.fromStepCollector).toBe("aws.s3.list_buckets");
  });

  it("rejects malicious region values", () => {
    expect(() =>
      buildPlan([control("CR-AWS-EC2-001", "aws.ec2.describe_security_groups")], collectors, {
        provider: "aws",
        regions: ["us-east-1; rm -rf /"],
      }),
    ).toThrow(/invalid region/);
  });

  it("filters by requested control ids", () => {
    const plan = buildPlan(
      [
        control("CR-AWS-S3-010", "aws.s3.get_bucket_versioning"),
        control("CR-AWS-EC2-001", "aws.ec2.describe_security_groups"),
      ],
      collectors,
      { provider: "aws", regions: ["ap-southeast-2"], controlIds: ["CR-AWS-EC2-001"] },
    );
    expect(plan.controlIds).toEqual(["CR-AWS-EC2-001"]);
    expect(plan.steps.map((s) => s.collectorId)).toEqual(["aws.ec2.describe_security_groups"]);
  });
});

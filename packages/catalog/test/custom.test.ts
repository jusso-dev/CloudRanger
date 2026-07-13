import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { loadCatalog, validateCatalogDocument } from "@cloudranger/engine";
import { catalogDir, loadBundledCatalog } from "../src/index.js";

const tmp = mkdtempSync(join(tmpdir(), "cr-custom-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const CUSTOM_DOC = `
controls:
  - id: CUSTOM-AWS-TAGS-001
    version: 1.0.0
    provider: aws
    service: resourcegroupstagging
    title: Every EC2 instance carries an owner tag
    description: Custom org policy - instances must be attributable.
    rationale: Untagged resources cannot be attributed or costed.
    severity: low
    categories: [custom, governance]
    source: { engine: custom, id: org-tagging-policy, license: Apache-2.0 }
    collector: aws.ec2.describe_instances
    resourcesPath: Reservations[].Instances
    resourceIdField: InstanceId
    passWhen:
      op: anyItem
      path: Tags
      condition: { op: equals, path: Key, value: Owner }
    failMessage: Instance has no Owner tag.
    passMessage: Instance has an Owner tag.
    remediation:
      summary: Tag the instance.
      steps: [Add an Owner tag.]
    compliance: []
    references: [https://example.com/policy]
`;

const OVERRIDE_DOC = `
controls:
  - id: CR-AWS-RDS-006
    version: 1.0.1
    provider: aws
    service: rds
    title: RDS instance is Multi-AZ (org severity high)
    description: Org override - Multi-AZ is mandatory here.
    rationale: Org uptime requirements.
    severity: high
    categories: [database, resilience]
    source: { engine: prowler, id: rds_instance_multi_az, license: Apache-2.0 }
    collector: aws.rds.describe_db_instances
    resourcesPath: DBInstances
    resourceIdField: DBInstanceIdentifier
    passWhen: { op: equals, path: MultiAZ, value: true }
    failMessage: RDS instance is not Multi-AZ.
    passMessage: RDS instance is Multi-AZ.
    remediation:
      summary: Convert to Multi-AZ.
      steps: [Modify the instance.]
    compliance: []
    references: [https://example.com/override]
`;

describe("custom catalog directory", () => {
  it("merges custom controls and applies overrides over the bundled catalog", () => {
    mkdirSync(join(tmp, "controls"), { recursive: true });
    writeFileSync(join(tmp, "controls", "custom.yaml"), CUSTOM_DOC);
    writeFileSync(join(tmp, "controls", "override.yaml"), OVERRIDE_DOC);

    const bundled = loadBundledCatalog();
    const merged = loadCatalog([catalogDir(), tmp]);
    expect(merged.issues).toEqual([]);
    expect(merged.controls.length).toBe(bundled.controls.length + 1);
    expect(merged.controls.find((c) => c.id === "CUSTOM-AWS-TAGS-001")).toBeTruthy();
    const overridden = merged.controls.find((c) => c.id === "CR-AWS-RDS-006")!;
    expect(overridden.severity).toBe("high");
    expect(overridden.version).toBe("1.0.1");
    expect(bundled.controls.find((c) => c.id === "CR-AWS-RDS-006")!.severity).toBe("low");
  }, 60_000);

  it("a missing custom directory is not an error", () => {
    const merged = loadCatalog([catalogDir(), join(tmp, "does-not-exist")]);
    expect(merged.issues).toEqual([]);
  });

  it("validateCatalogDocument rejects unsafe collectors and unknown references", () => {
    const bundled = loadBundledCatalog();
    const bad = validateCatalogDocument(
      `collectors:
  - id: aws.evil.delete_everything
    provider: aws
    service: evil
    description: nope
    kind: single
    command: aws ec2 terminate-instances --instance-ids i-123
    regional: false
    outputFormat: json
controls: []`,
      bundled.collectors,
    );
    expect(bad.errors[0]).toContain("unsafe command");

    const unknown = validateCatalogDocument(
      CUSTOM_DOC.replace("aws.ec2.describe_instances", "aws.nonexistent.thing"),
      bundled.collectors,
    );
    expect(unknown.errors[0]).toContain("unknown collector");
  });
});

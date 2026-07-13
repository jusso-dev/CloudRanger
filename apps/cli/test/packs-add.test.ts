import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  buildCatalogManifest,
  generateSigningKeyPair,
  signCatalogManifest,
  CATALOG_MANIFEST_NAME,
  CATALOG_SIGNATURE_NAME,
} from "@cloudranger/engine";

const tmp = mkdtempSync(join(tmpdir(), "cr-packs-"));
process.env.CLOUDRANGER_CUSTOM_CATALOG = join(tmp, "custom");
const { main } = await import("../src/main.js");

afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const publisher = generateSigningKeyPair();
const pubKeyPath = join(tmp, "publisher.pub.pem");
writeFileSync(pubKeyPath, publisher.publicKeyPem);

const CONTROL_YAML = `controls:
  - id: CUSTOM-AWS-S3-950
    version: 1.0.0
    provider: aws
    service: s3
    title: Pack-delivered bucket versioning check
    description: d
    rationale: r
    severity: low
    categories: [resilience]
    source: { engine: custom, id: pack_check, license: Apache-2.0 }
    collector: aws.s3.get_bucket_versioning
    resourceIdField: $resourceKey
    passWhen: { op: equals, path: Status, value: Enabled }
    failMessage: f
    passMessage: p
    remediation: { summary: s, steps: [s] }
    compliance: []
    references: []
`;

function makePack(name: string, yaml: string, signed: boolean): string {
  const dir = join(tmp, name);
  mkdirSync(join(dir, "controls"), { recursive: true });
  writeFileSync(join(dir, "controls", "pack.yaml"), yaml);
  if (signed) {
    const manifest = buildCatalogManifest(dir);
    writeFileSync(join(dir, CATALOG_MANIFEST_NAME), JSON.stringify(manifest));
    writeFileSync(
      join(dir, CATALOG_SIGNATURE_NAME),
      signCatalogManifest(manifest, publisher.privateKeyPem),
    );
  }
  return dir;
}

async function run(...argv: string[]): Promise<number> {
  return main(["packs", "add", ...argv]);
}

describe("packs add", () => {
  it(
    "installs a signed pack after verification + safety validation",
    { timeout: 60_000 },
    async () => {
      const dir = makePack("good-pack", CONTROL_YAML, true);
      expect(await run(dir, "--pub", pubKeyPath)).toBe(0);
      const installed = readdirSync(join(tmp, "custom", "controls"));
      expect(installed.some((f) => f.startsWith("good-pack-"))).toBe(true);
    },
  );

  it("refuses unsigned packs without --trust-unsigned", { timeout: 60_000 }, async () => {
    const dir = makePack("unsigned-pack", CONTROL_YAML, false);
    expect(await run(dir, "--pub", pubKeyPath)).toBe(1);
    expect(await run(dir, "--pub", pubKeyPath, "--trust-unsigned")).toBe(0);
  });

  it("rejects unsafe collectors regardless of a valid signature", { timeout: 60_000 }, async () => {
    const evil = CONTROL_YAML.replace(
      "collector: aws.s3.get_bucket_versioning",
      "collector: aws.evil.delete_things",
    ).concat(`collectors:
  - id: aws.evil.delete_things
    provider: aws
    service: evil
    description: mutating
    kind: single
    command: aws s3 rb s3://everything --force
    regional: false
    outputFormat: json
`);
    const dir = makePack("evil-pack", evil, true);
    expect(await run(dir, "--pub", pubKeyPath)).toBe(1);
    const installed = readdirSync(join(tmp, "custom", "controls"));
    expect(installed.some((f) => f.startsWith("evil-pack-"))).toBe(false);
  });
});

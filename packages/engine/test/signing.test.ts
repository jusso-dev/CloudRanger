import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  buildCatalogManifest,
  generateSigningKeyPair,
  signCatalogManifest,
  verifyCatalogDirectory,
  CATALOG_MANIFEST_NAME,
  CATALOG_SIGNATURE_NAME,
} from "../src/signing.js";

const dir = mkdtempSync(join(tmpdir(), "cr-signing-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const publisher = generateSigningKeyPair();
const stranger = generateSigningKeyPair();

function signDir(target: string, privateKeyPem: string): void {
  const manifest = buildCatalogManifest(target);
  writeFileSync(join(target, CATALOG_MANIFEST_NAME), JSON.stringify(manifest));
  writeFileSync(join(target, CATALOG_SIGNATURE_NAME), signCatalogManifest(manifest, privateKeyPem));
}

describe("catalog signing", () => {
  it("round-trips: signed directory verifies against the publisher key", () => {
    writeFileSync(join(dir, "controls.yaml"), "controls: []\n");
    signDir(dir, publisher.privateKeyPem);
    const result = verifyCatalogDirectory(dir, [stranger.publicKeyPem, publisher.publicKeyPem]);
    expect(result).toEqual({ ok: true, keyIndex: 1 });
  });

  it("rejects tampered, added, and removed files", () => {
    writeFileSync(join(dir, "controls.yaml"), "controls: [tampered]\n");
    expect(verifyCatalogDirectory(dir, [publisher.publicKeyPem]).reason).toMatch(/differs/);

    writeFileSync(join(dir, "controls.yaml"), "controls: []\n"); // restore
    writeFileSync(join(dir, "sneaky.yaml"), "collectors: []\n"); // add
    expect(verifyCatalogDirectory(dir, [publisher.publicKeyPem]).reason).toMatch(/file set/);
    rmSync(join(dir, "sneaky.yaml"));
  });

  it("rejects signatures from untrusted keys and missing material", () => {
    signDir(dir, stranger.privateKeyPem);
    expect(verifyCatalogDirectory(dir, [publisher.publicKeyPem]).reason).toMatch(
      /not from any trusted/,
    );
    rmSync(join(dir, CATALOG_SIGNATURE_NAME));
    expect(verifyCatalogDirectory(dir, [publisher.publicKeyPem]).reason).toMatch(/missing/);
  });
});

import { createHash, generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

/**
 * Catalog signing: Ed25519 over a canonical file manifest.
 *
 * A signature proves provenance (who published this catalog/pack), never
 * safety — every loaded document still passes the same schema and read-only
 * safety validation regardless of signature status. Pure Node crypto: no
 * external signing tooling required, and third-party publishers can generate
 * keys with `catalog-sign keygen` or openssl.
 */

export interface CatalogManifest {
  schemaVersion: 1;
  algorithm: "ed25519";
  /** repo-relative POSIX paths → sha256 hex of file bytes. */
  files: Record<string, string>;
  /** sha256 over the canonical files map — the signed subject. */
  rootHash: string;
}

const MANIFEST_NAME = "catalog.manifest.json";
const SIGNATURE_NAME = "catalog.manifest.sig";

function walkFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const entry of readdirSync(d).sort()) {
      const full = join(d, entry);
      if (statSync(full).isDirectory()) walk(full);
      else out.push(full);
    }
  };
  walk(dir);
  return out;
}

function canonicalFilesHash(files: Record<string, string>): string {
  const canonical = Object.keys(files)
    .sort()
    .map((path) => `${path}\n${files[path]}\n`)
    .join("");
  return createHash("sha256").update(canonical).digest("hex");
}

/** Build the manifest for a catalog/pack directory (manifest files excluded). */
export function buildCatalogManifest(dir: string): CatalogManifest {
  const files: Record<string, string> = {};
  for (const full of walkFiles(dir)) {
    const rel = relative(dir, full).split(sep).join("/");
    if (rel === MANIFEST_NAME || rel === SIGNATURE_NAME) continue;
    files[rel] = createHash("sha256").update(readFileSync(full)).digest("hex");
  }
  return {
    schemaVersion: 1,
    algorithm: "ed25519",
    files,
    rootHash: canonicalFilesHash(files),
  };
}

export function generateSigningKeyPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

/** Sign a manifest's root hash. Returns base64. */
export function signCatalogManifest(manifest: CatalogManifest, privateKeyPem: string): string {
  return edSign(null, Buffer.from(manifest.rootHash, "utf8"), privateKeyPem).toString("base64");
}

export interface CatalogVerification {
  ok: boolean;
  reason?: string;
  /** Which trusted key verified the signature, when ok. */
  keyIndex?: number;
}

/**
 * Verify a directory against its manifest + signature and a set of pinned
 * publisher public keys. Fails on: missing manifest/signature, any file
 * changed/added/removed since signing, or a signature no trusted key made.
 */
export function verifyCatalogDirectory(dir: string, publicKeysPem: string[]): CatalogVerification {
  let manifest: CatalogManifest;
  let signature: Buffer;
  try {
    manifest = JSON.parse(readFileSync(join(dir, MANIFEST_NAME), "utf8"));
    signature = Buffer.from(readFileSync(join(dir, SIGNATURE_NAME), "utf8").trim(), "base64");
  } catch {
    return { ok: false, reason: "missing or unreadable catalog.manifest.json / .sig" };
  }
  if (manifest.schemaVersion !== 1 || manifest.algorithm !== "ed25519") {
    return { ok: false, reason: "unsupported manifest schema or algorithm" };
  }
  const current = buildCatalogManifest(dir);
  const currentPaths = Object.keys(current.files).sort();
  const manifestPaths = Object.keys(manifest.files ?? {}).sort();
  if (JSON.stringify(currentPaths) !== JSON.stringify(manifestPaths)) {
    return { ok: false, reason: "file set differs from the signed manifest" };
  }
  for (const path of currentPaths) {
    if (current.files[path] !== manifest.files[path]) {
      return { ok: false, reason: `content of ${path} differs from the signed manifest` };
    }
  }
  if (canonicalFilesHash(manifest.files) !== manifest.rootHash) {
    return { ok: false, reason: "manifest root hash is inconsistent with its file list" };
  }
  for (const [index, keyPem] of publicKeysPem.entries()) {
    try {
      if (edVerify(null, Buffer.from(manifest.rootHash, "utf8"), keyPem, signature)) {
        return { ok: true, keyIndex: index };
      }
    } catch {
      // Malformed key: try the next one.
    }
  }
  return { ok: false, reason: "signature is not from any trusted publisher key" };
}

export const CATALOG_MANIFEST_NAME = MANIFEST_NAME;
export const CATALOG_SIGNATURE_NAME = SIGNATURE_NAME;

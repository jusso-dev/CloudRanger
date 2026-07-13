#!/usr/bin/env node
/**
 * Catalog signing utility (release engineering).
 *
 *   node scripts/catalog-sign.mjs keygen <out-prefix>
 *     Writes <out-prefix>.key.pem (KEEP SECRET) and <out-prefix>.pub.pem.
 *
 *   node scripts/catalog-sign.mjs sign <dir> --key <private.pem|env:VAR>
 *     Writes catalog.manifest.json + catalog.manifest.sig into <dir>.
 *
 *   node scripts/catalog-sign.mjs verify <dir> --pub <public.pem>[,more.pem]
 *     Exits non-zero if verification fails.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  buildCatalogManifest,
  generateSigningKeyPair,
  signCatalogManifest,
  verifyCatalogDirectory,
  CATALOG_MANIFEST_NAME,
  CATALOG_SIGNATURE_NAME,
} from "../packages/engine/dist/index.js";

const [mode, target, ...rest] = process.argv.slice(2);
const flag = (name) => {
  const index = rest.indexOf(name);
  return index >= 0 ? rest[index + 1] : undefined;
};

if (mode === "keygen") {
  if (!target) throw new Error("usage: catalog-sign keygen <out-prefix>");
  const { privateKeyPem, publicKeyPem } = generateSigningKeyPair();
  writeFileSync(`${target}.key.pem`, privateKeyPem, { mode: 0o600 });
  writeFileSync(`${target}.pub.pem`, publicKeyPem);
  console.log(`wrote ${target}.key.pem (KEEP SECRET) and ${target}.pub.pem`);
} else if (mode === "sign") {
  const keyRef = flag("--key");
  if (!target || !keyRef)
    throw new Error("usage: catalog-sign sign <dir> --key <private.pem|env:VAR>");
  const privateKeyPem = keyRef.startsWith("env:")
    ? process.env[keyRef.slice(4)]
    : readFileSync(keyRef, "utf8");
  if (!privateKeyPem) throw new Error(`signing key not found via ${keyRef}`);
  const manifest = buildCatalogManifest(target);
  writeFileSync(join(target, CATALOG_MANIFEST_NAME), JSON.stringify(manifest, null, 2) + "\n");
  writeFileSync(
    join(target, CATALOG_SIGNATURE_NAME),
    signCatalogManifest(manifest, privateKeyPem) + "\n",
  );
  console.log(
    `signed ${Object.keys(manifest.files).length} files in ${target} (root ${manifest.rootHash.slice(0, 16)}…)`,
  );
} else if (mode === "verify") {
  const pub = flag("--pub");
  if (!target || !pub)
    throw new Error("usage: catalog-sign verify <dir> --pub <public.pem>[,more]");
  const keys = pub.split(",").map((path) => readFileSync(path, "utf8"));
  const result = verifyCatalogDirectory(target, keys);
  if (!result.ok) {
    console.error(`verification FAILED: ${result.reason}`);
    process.exit(1);
  }
  console.log(`verification OK (trusted key #${result.keyIndex})`);
} else {
  console.error("usage: catalog-sign keygen|sign|verify …");
  process.exit(1);
}

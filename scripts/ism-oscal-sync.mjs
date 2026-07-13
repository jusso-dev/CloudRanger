#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { parseArgs } from "node:util";

const DEFAULT_REPOSITORY = "https://github.com/AustralianCyberSecurityCentre/ism-oscal.git";
const DEFAULT_TAG = "v2026.06.18";
const DEFAULT_OUTPUT = "packages/catalog/catalog/mappings/upstream/ism-oscal-v2026.06.18.json";

const { values } = parseArgs({
  args: process.argv.slice(2).filter((argument) => argument !== "--"),
  options: {
    source: { type: "string" },
    output: { type: "string" },
    tag: { type: "string" },
  },
});
const tag = values.tag ?? DEFAULT_TAG;
const output = resolve(values.output ?? DEFAULT_OUTPUT);
let checkout = values.source ? resolve(values.source) : undefined;
let temporaryCheckout;

try {
  if (!checkout) {
    temporaryCheckout = mkdtempSync(`${tmpdir()}/cloudranger-ism-oscal-`);
    execFileSync(
      "git",
      ["clone", "--depth", "1", "--branch", tag, DEFAULT_REPOSITORY, temporaryCheckout],
      {
        stdio: "inherit",
      },
    );
    checkout = temporaryCheckout;
  }
  const catalogPath = resolve(checkout, "ISM_catalog.json");
  if (!existsSync(catalogPath)) throw new Error(`ISM OSCAL catalog not found: ${catalogPath}`);
  const catalog = JSON.parse(readFileSync(catalogPath, "utf8"));
  const controls = [];
  const visit = (node) => {
    if (node && typeof node === "object") {
      if (typeof node.id === "string" && /^ism-\d{4}$/.test(node.id)) {
        controls.push({
          id: node.id,
          statement: (node.parts ?? [])
            .filter((part) => part.name === "statement")
            .map((part) => part.prose)
            .join(" "),
          applicability: (node.props ?? [])
            .filter((prop) => prop.name === "applicability")
            .map((prop) => prop.value),
        });
      }
      for (const value of Object.values(node)) {
        if (value && typeof value === "object") visit(value);
      }
    }
  };
  visit(catalog.catalog);
  controls.sort((a, b) => a.id.localeCompare(b.id));
  const revision = execFileSync("git", ["-C", checkout, "rev-parse", "HEAD"], {
    encoding: "utf8",
  }).trim();
  const outputDocument = {
    generatedFrom: {
      authority: "Australian Signals Directorate",
      repository: "https://github.com/AustralianCyberSecurityCentre/ism-oscal",
      tag,
      revision,
      catalogVersion: catalog.catalog?.metadata?.version,
      source:
        "https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/ism/ism-oscal-releases",
    },
    controls,
  };
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(outputDocument, null, 2)}\n`);
  console.log(`Wrote ${controls.length} ISM controls to ${output}`);
} finally {
  if (temporaryCheckout) rmSync(temporaryCheckout, { recursive: true, force: true });
}

#!/usr/bin/env node
/**
 * Prowler metadata importer.
 *
 * Prowler (Apache-2.0) ships one metadata.json per check describing severity,
 * service, risk, remediation and framework mappings. This script maps that
 * metadata into CloudRanger control YAML STUBS — the deterministic passWhen
 * expression and the collector are left as TODO markers for a human to
 * complete against real CLI output, because the pass/fail logic is the part
 * that must never be guessed.
 *
 * It never emits a ready-to-ship control: every stub is marked draft: true in
 * a comment and uses a placeholder collector so `cloudranger catalog validate`
 * flags it until completed. This keeps the "no invented controls, deterministic
 * only" guarantees intact while removing the boilerplate of porting.
 *
 * Usage:
 *   node scripts/prowler-import.mjs \
 *     --prowler /path/to/prowler/prowler/providers/aws/services \
 *     --provider aws \
 *     --service s3 \
 *     --out /tmp/aws-s3-stubs.yaml
 *
 * Requires a local Prowler checkout (not vendored — respect upstream repo).
 */
import { readFileSync, readdirSync, writeFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: {
    prowler: { type: "string" },
    provider: { type: "string" },
    service: { type: "string" },
    out: { type: "string" },
  },
});

if (!values.prowler || !values.provider) {
  console.error(
    "usage: prowler-import.mjs --prowler <prowler services dir> --provider aws|azure|gcp [--service <name>] [--out <file.yaml>]",
  );
  process.exit(1);
}

const PROVIDER = values.provider;
const PROVIDER_UPPER = PROVIDER.toUpperCase();

const SEVERITY_MAP = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  informational: "informational",
};

/** Recursively find every *.metadata.json under the Prowler services dir. */
function findMetadataFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...findMetadataFiles(full));
    else if (entry.endsWith(".metadata.json")) out.push(full);
  }
  return out;
}

/** Convert a Prowler CheckID to a CloudRanger control id stub. */
function toControlId(meta, index) {
  const service = (meta.ServiceName || meta.CheckID?.split("_")[0] || "svc")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "");
  return `CR-${PROVIDER_UPPER}-${service}-${String(index).padStart(3, "0")}`;
}

function yamlEscape(text) {
  if (text == null) return '""';
  const clean = String(text).replace(/\s+/g, " ").trim();
  return JSON.stringify(clean);
}

function mapCompliance(meta) {
  const out = [];
  const compliance = meta.Compliance || meta.compliance || [];
  for (const entry of Array.isArray(compliance) ? compliance : []) {
    const framework = (entry.Framework || "").toLowerCase().replace(/[^a-z0-9]+/g, "-");
    const controls = (entry.Requirements || entry.Controls || [])
      .map((r) => r.Id || r)
      .filter(Boolean);
    if (framework && controls.length) out.push({ framework, controls });
  }
  return out;
}

function toStub(meta, index) {
  const id = toControlId(meta, index);
  const severity = SEVERITY_MAP[(meta.Severity || "medium").toLowerCase()] || "medium";
  const service = (meta.ServiceName || "unknown").toLowerCase();
  const compliance = mapCompliance(meta);
  const complianceYaml =
    compliance.length === 0
      ? "compliance: []"
      : "compliance:\n" +
        compliance
          .map(
            (c) =>
              `      - { framework: ${c.framework}, controls: [${c.controls.map((x) => yamlEscape(x)).join(", ")}] }`,
          )
          .join("\n");

  return `  # DRAFT — port ${meta.CheckID}. Set collector + passWhen against real CLI output, add fixtures, then remove this comment.
  - id: ${id}
    version: 0.1.0
    provider: ${PROVIDER}
    service: ${service}
    title: ${yamlEscape(meta.CheckTitle || meta.CheckID)}
    description: ${yamlEscape(meta.Description)}
    rationale: ${yamlEscape(meta.Risk || meta.Description)}
    severity: ${severity}
    categories: [${(meta.Categories || ["ported"]).map((c) => JSON.stringify(c)).join(", ") || '"ported"'}]
    source: { engine: prowler, id: ${yamlEscape(meta.CheckID)}, license: Apache-2.0 }
    collector: ${PROVIDER}.${service}.TODO_COLLECTOR   # TODO: existing or new read-only collector
    resourcesPath: $                                  # TODO: path to the resource array, or omit for per_resource
    resourceIdField: TODO_ID_FIELD
    passWhen:                                          # TODO: deterministic condition grounded in real CLI JSON
      op: exists
      path: TODO_FIELD
    failMessage: ${yamlEscape(meta.CheckTitle || "Resource does not meet the control.")}
    passMessage: ${yamlEscape((meta.CheckTitle || "Resource meets the control.") + " (satisfied)")}
    remediation:
      summary: ${yamlEscape(meta.Remediation?.Recommendation?.Text || "See references.")}
      steps:
        - ${yamlEscape(meta.Remediation?.Recommendation?.Text || "TODO remediation step (operator action).")}
    ${complianceYaml}
    references:
      - ${yamlEscape(meta.Remediation?.Recommendation?.Url || meta.RelatedUrl || "https://github.com/prowler-cloud/prowler")}`;
}

const files = findMetadataFiles(values.prowler).filter((f) => {
  if (!values.service) return true;
  return f.includes(`/${values.service}/`) || f.includes(`${values.service}_`);
});

const metas = [];
for (const file of files) {
  try {
    const meta = JSON.parse(readFileSync(file, "utf8"));
    if ((meta.Provider || PROVIDER).toLowerCase() === PROVIDER) metas.push(meta);
  } catch (error) {
    console.error(`skip ${file}: ${error.message}`);
  }
}
metas.sort((a, b) => (a.CheckID || "").localeCompare(b.CheckID || ""));

const stubs = metas.map((meta, i) => toStub(meta, i + 1));
const header = `# Auto-generated Prowler control STUBS (${PROVIDER}${values.service ? `/${values.service}` : ""}).
# ${metas.length} checks. Each is a DRAFT: collector, passWhen, resourceIdField
# and fixtures must be completed by hand against real CLI output before the
# control will pass \`cloudranger catalog validate\`. Logic ported from Prowler
# (Apache-2.0). Do NOT ship these unedited.
controls:
`;
const output = header + stubs.join("\n\n") + "\n";

if (values.out) {
  writeFileSync(values.out, output);
  console.error(`wrote ${metas.length} stubs to ${values.out}`);
} else {
  process.stdout.write(output);
  console.error(`\n# ${metas.length} stubs generated`);
}

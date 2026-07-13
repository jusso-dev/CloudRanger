import type { FindingRow } from "@cloudranger/db";

/**
 * Findings export formats. CSV columns are stable (append-only contract);
 * JSONL is one finding per line; SARIF 2.1.0 maps controls to rules so the
 * file loads in GitHub code scanning and similar viewers.
 */

const CSV_COLUMNS = [
  "fingerprint",
  "provider",
  "scopeId",
  "controlId",
  "controlVersion",
  "severity",
  "service",
  "resourceId",
  "resourceName",
  "region",
  "state",
  "workflowState",
  "owner",
  "dueAt",
  "message",
  "firstSeenAt",
  "lastSeenAt",
  "resolvedAt",
  "occurrenceCount",
  "reopenCount",
  "lastScanId",
] as const;

function csvCell(value: unknown): string {
  if (value === undefined || value === null) return "";
  const text = String(value);
  return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export function findingsToCsv(findings: FindingRow[]): string {
  const rows = findings.map((finding) =>
    CSV_COLUMNS.map((column) => csvCell(finding[column as keyof FindingRow])).join(","),
  );
  return [CSV_COLUMNS.join(","), ...rows].join("\n") + "\n";
}

export function findingsToJsonl(findings: FindingRow[]): string {
  return findings.map((finding) => JSON.stringify(finding)).join("\n") + "\n";
}

const SARIF_LEVEL: Record<string, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  informational: "note",
};

export function findingsToSarif(
  findings: FindingRow[],
  controls: Map<string, { title: string; description: string; references: string[] }>,
): string {
  const ruleIds = [...new Set(findings.map((finding) => finding.controlId))].sort();
  const rules = ruleIds.map((id) => {
    const control = controls.get(id);
    return {
      id,
      name: id,
      shortDescription: { text: control?.title ?? id },
      fullDescription: { text: control?.description ?? id },
      ...(control?.references?.[0] ? { helpUri: control.references[0] } : {}),
    };
  });
  const ruleIndex = new Map(ruleIds.map((id, index) => [id, index]));
  const results = findings.map((finding) => ({
    ruleId: finding.controlId,
    ruleIndex: ruleIndex.get(finding.controlId)!,
    level: SARIF_LEVEL[finding.severity] ?? "warning",
    message: { text: finding.message },
    locations: [
      {
        logicalLocations: [
          {
            fullyQualifiedName: `${finding.provider}/${finding.scopeId}/${finding.service}/${finding.resourceId}`,
            kind: "resource",
          },
        ],
      },
    ],
    partialFingerprints: { cloudRangerFinding: finding.fingerprint },
    properties: {
      provider: finding.provider,
      scopeId: finding.scopeId,
      region: finding.region,
      state: finding.state,
      workflowState: finding.workflowState,
      firstSeenAt: finding.firstSeenAt,
      lastSeenAt: finding.lastSeenAt,
    },
  }));
  const sarif = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0" as const,
    runs: [
      {
        tool: {
          driver: {
            name: "CloudRanger",
            informationUri: "https://github.com/jusso-dev/CloudRanger",
            rules,
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2) + "\n";
}

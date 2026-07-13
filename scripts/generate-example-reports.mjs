#!/usr/bin/env node
import { copyFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { writeHtmlReport, writePdfReport } from "../apps/cli/dist/report.js";

const output = process.argv[2] ?? "output/pdf";
mkdirSync(output, { recursive: true });
const repositoryOutput = "docs/examples/reports";
mkdirSync(repositoryOutput, { recursive: true });

const examples = [
  {
    file: "aws-example-executive-report",
    provider: "aws",
    scopeId: "Example AWS account 000000000000 (dummy data)",
    services: [
      { provider: "aws", service: "IAM", count: 3 },
      { provider: "aws", service: "S3", count: 2 },
      { provider: "aws", service: "CloudTrail", count: 1 },
    ],
    findings: [
      {
        controlId: "CR-AWS-IAM-001",
        severity: "high",
        count: 2,
        title: "Protect the root account with multi-factor authentication",
        description:
          "The AWS root account must have MFA enabled to reduce the risk of account takeover.",
      },
      {
        controlId: "CR-AWS-S3-001",
        severity: "critical",
        count: 2,
        title: "Block public access to storage buckets",
        description: "S3 buckets should not allow anonymous internet access to data.",
      },
      {
        controlId: "CR-AWS-CLOUDTRAIL-001",
        severity: "medium",
        count: 1,
        title: "Record activity across all regions",
        description: "CloudTrail should record management activity in every AWS region.",
      },
    ],
    severity: { critical: 2, high: 2, medium: 1, low: 0, informational: 0 },
  },
  {
    file: "azure-example-executive-report",
    provider: "azure",
    scopeId: "Example Azure subscription 00000000-0000-0000-0000-000000000000 (dummy data)",
    services: [
      { provider: "azure", service: "Storage", count: 2 },
      { provider: "azure", service: "App Service", count: 2 },
      { provider: "azure", service: "Network", count: 1 },
    ],
    findings: [
      {
        controlId: "CR-AZURE-STORAGE-002",
        severity: "critical",
        count: 2,
        title: "Prevent anonymous access to storage",
        description:
          "Storage accounts should prevent public blob access unless explicitly approved.",
      },
      {
        controlId: "CR-AZURE-APP-001",
        severity: "high",
        count: 2,
        title: "Require HTTPS for web applications",
        description:
          "App Service applications should redirect users to encrypted HTTPS connections.",
      },
      {
        controlId: "CR-AZURE-NETWORK-001",
        severity: "high",
        count: 1,
        title: "Do not expose SSH to the internet",
        description:
          "Network security groups should not permit inbound SSH from any internet address.",
      },
    ],
    severity: { critical: 2, high: 3, medium: 0, low: 0, informational: 0 },
  },
  {
    file: "gcp-example-executive-report",
    provider: "gcp",
    scopeId: "Example GCP project cloudranger-demo (dummy data)",
    services: [
      { provider: "gcp", service: "Storage", count: 2 },
      { provider: "gcp", service: "Logging", count: 2 },
      { provider: "gcp", service: "Compute", count: 1 },
    ],
    findings: [
      {
        controlId: "CR-GCP-STORAGE-001",
        severity: "critical",
        count: 2,
        title: "Prevent public access to storage buckets",
        description:
          "Cloud Storage IAM should not grant access to all internet users or all authenticated users.",
      },
      {
        controlId: "CR-GCP-LOGGING-119",
        severity: "high",
        count: 1,
        title: "Alert on firewall rule changes",
        description: "A log-based metric and alert should detect changes to VPC firewall rules.",
      },
      {
        controlId: "CR-GCP-FIREWALL-001",
        severity: "high",
        count: 1,
        title: "Do not expose SSH to the internet",
        description: "VPC firewall rules should not allow SSH from the public internet.",
      },
    ],
    severity: { critical: 2, high: 2, medium: 0, low: 0, informational: 0 },
  },
];

for (const example of examples) {
  const report = {
    generatedAt: "2026-07-13T00:00:00.000Z",
    windowDays: 30,
    filters: { provider: example.provider, scopeId: example.scopeId },
    openFindingsBySeverity: example.severity,
    openFindingsByService: example.services,
    topFailingControls: example.findings,
    newFindingsInWindow: 5,
    resolvedFindingsInWindow: 2,
    currentlyReopened: 1,
    riskAccepted: 0,
    recentScans: [
      {
        provider: example.provider,
        scopeId: example.scopeId,
        status: "evaluated",
        createdAt: "2026-07-13T00:00:00.000Z",
        summary: { coverageRatio: 0.92 },
      },
    ],
  };
  const html = join(output, `${example.file}.html`);
  const pdf = join(output, `${example.file}.pdf`);
  writeHtmlReport(html, report);
  writePdfReport(html, pdf);
  copyFileSync(pdf, join(repositoryOutput, `${example.file}.pdf`));
  console.log(pdf);
}

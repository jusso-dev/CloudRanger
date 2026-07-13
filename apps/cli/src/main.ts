#!/usr/bin/env node
import { copyFileSync, mkdirSync, readFileSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { basename } from "node:path";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { resolve } from "node:path";
import { writeHtmlReport, writePdfReport } from "./report.js";
import { complianceCoverage } from "./compliance.js";
import {
  catalogDir,
  customCatalogDir,
  fixturesDir,
  loadDefaultCatalog,
} from "@cloudranger/catalog";
import { CloudRangerStore } from "@cloudranger/db";
import {
  controlTemplate,
  fixtureFileSchema,
  runFixtureFile,
  validateCatalogDocument,
} from "@cloudranger/engine";

const dbPath = () =>
  process.env.CLOUDRANGER_DB ?? join(homedir(), ".cloudranger", "cloudranger.db");

const HELP = `cloudranger — local-first, agent-driven multi-cloud CSPM

Usage:
  cloudranger catalog validate          Validate bundled controls + collectors
  cloudranger catalog test              Run all control fixture tests
  cloudranger catalog list [--provider aws|azure|gcp]
  cloudranger findings [--state open,reopened] [--severity critical,high] [--json]
  cloudranger report [--since-days 30] [--provider aws|azure|gcp]
  cloudranger report html [--output output/html/cloudranger-report.html] [--since-days 30] [--provider aws|azure|gcp]
  cloudranger report pdf [--output output/pdf/cloudranger-report.pdf] [--since-days 30] [--provider aws|azure|gcp]
  cloudranger compliance coverage [--framework <id>] [--provider aws|azure|gcp] [--json]
  cloudranger scans                     List recent scans
  cloudranger audit [--limit 50]        Show recent audit entries
  cloudranger audit verify              Verify the audit hash chain
  cloudranger controls template [--provider aws|azure|gcp] [--collector <id>]
                                        Print a custom-control YAML template
  cloudranger controls add <file.yaml>  Validate + install a custom control
  cloudranger controls dir              Print the custom catalog directory
  cloudranger mcp-config [--client claude-code|claude-desktop|codex]
  cloudranger db-path                   Print the database location

Environment:
  CLOUDRANGER_DB     Database file (default ~/.cloudranger/cloudranger.db)
`;

function main(): number {
  const [command, subcommand, ...rest] = process.argv.slice(2);

  if (!command || command === "help" || command === "--help") {
    console.log(HELP);
    return 0;
  }

  if (command === "db-path") {
    console.log(dbPath());
    return 0;
  }

  if (command === "catalog" && subcommand === "validate") {
    const catalog = loadDefaultCatalog();
    console.log(`catalog: ${catalogDir()}`);
    console.log(`controls: ${catalog.controls.length}, collectors: ${catalog.collectors.size}`);
    if (catalog.issues.length > 0) {
      for (const issue of catalog.issues) console.error(`ISSUE ${issue.file}: ${issue.message}`);
      return 1;
    }
    console.log("OK — no validation issues");
    return 0;
  }

  if (command === "catalog" && subcommand === "test") {
    const catalog = loadDefaultCatalog();
    let failures = 0;
    let cases = 0;
    for (const file of readdirSync(fixturesDir()).filter((f) => f.endsWith(".json"))) {
      const fixtures = JSON.parse(readFileSync(join(fixturesDir(), file), "utf8")) as unknown[];
      for (const raw of fixtures) {
        const fixture = fixtureFileSchema.parse(raw);
        for (const result of runFixtureFile(fixture, catalog.controls, catalog.collectors)) {
          cases++;
          if (!result.ok) {
            failures++;
            console.error(
              `FAIL ${result.controlId} / ${result.caseName}: expected ${result.expected}, got ${result.actual}`,
            );
          }
        }
      }
    }
    console.log(`${cases - failures}/${cases} fixture cases passed`);
    return failures === 0 ? 0 : 1;
  }

  if (command === "catalog" && subcommand === "list") {
    const { values } = parseArgs({ args: rest, options: { provider: { type: "string" } } });
    const catalog = loadDefaultCatalog();
    for (const control of catalog.controls.filter(
      (c) => !values.provider || c.provider === values.provider,
    )) {
      console.log(
        `${control.id}  ${control.severity.padEnd(13)} ${control.service.padEnd(12)} ${control.title}`,
      );
    }
    return 0;
  }

  if (command === "controls" && subcommand === "template") {
    const { values } = parseArgs({
      args: rest,
      options: { provider: { type: "string" }, collector: { type: "string" } },
    });
    const provider = (values.provider ?? "aws") as "aws" | "azure" | "gcp";
    if (!["aws", "azure", "gcp"].includes(provider)) {
      console.error("--provider must be aws, azure or gcp");
      return 1;
    }
    console.log(controlTemplate({ provider, collectorId: values.collector }));
    return 0;
  }

  if (command === "controls" && subcommand === "add") {
    const file = rest[0];
    if (!file) {
      console.error("usage: cloudranger controls add <file.yaml>");
      return 1;
    }
    const catalog = loadDefaultCatalog();
    const result = validateCatalogDocument(readFileSync(file, "utf8"), catalog.collectors);
    if (result.errors.length > 0) {
      for (const error of result.errors) console.error(`ERROR ${error}`);
      return 1;
    }
    const dir = join(customCatalogDir(), "controls");
    mkdirSync(dir, { recursive: true });
    const dest = join(dir, basename(file));
    copyFileSync(file, dest);
    const merged = loadDefaultCatalog();
    if (merged.issues.length > 0) {
      for (const issue of merged.issues) console.error(`ISSUE ${issue.file}: ${issue.message}`);
      return 1;
    }
    console.log(`installed: ${dest}`);
    console.log(`controls: ${result.controls.map((c) => c.id).join(", ") || "(none)"}`);
    console.log(`collectors: ${result.collectors.map((c) => c.id).join(", ") || "(none)"}`);
    console.log(`catalog now has ${merged.controls.length} controls`);
    return 0;
  }

  if (command === "controls" && subcommand === "dir") {
    console.log(customCatalogDir());
    return 0;
  }

  if (command === "findings") {
    const { values } = parseArgs({
      args: [subcommand, ...rest].filter((a): a is string => a !== undefined),
      options: {
        state: { type: "string" },
        severity: { type: "string" },
        provider: { type: "string" },
        json: { type: "boolean" },
      },
    });
    const store = new CloudRangerStore(dbPath());
    const { total, findings } = store.searchFindings({
      state: values.state?.split(",") as any,
      severity: values.severity?.split(","),
      provider: values.provider as any,
      limit: 200,
    });
    if (values.json) {
      console.log(JSON.stringify({ total, findings }, null, 2));
    } else {
      for (const f of findings) {
        console.log(
          `${f.severity.padEnd(9)} ${f.state.padEnd(9)} ${f.controlId.padEnd(24)} ${f.resourceId}${f.region ? ` (${f.region})` : ""}  seen x${f.occurrenceCount}`,
        );
      }
      console.log(`\n${total} finding(s)`);
    }
    store.close();
    return 0;
  }

  if (command === "report") {
    const { values } = parseArgs({
      args: (subcommand === "html" || subcommand === "pdf" ? rest : [subcommand, ...rest]).filter(
        (a): a is string => a !== undefined,
      ),
      options: {
        "since-days": { type: "string" },
        provider: { type: "string" },
        output: { type: "string" },
      },
    });
    const store = new CloudRangerStore(dbPath());
    const report = store.reportData({
      sinceDays: values["since-days"] ? Number(values["since-days"]) : undefined,
      provider: values.provider as any,
    }) as any;
    const controlsById = new Map(
      loadDefaultCatalog().controls.map((control) => [control.id, control]),
    );
    report.topFailingControls = report.topFailingControls.map((item: any) => {
      const control = controlsById.get(item.controlId);
      return { ...item, title: control?.title, description: control?.description };
    });
    if (subcommand === "html" || subcommand === "pdf") {
      const defaultPath =
        subcommand === "html"
          ? "output/html/cloudranger-report.html"
          : "output/pdf/cloudranger-report.pdf";
      const output = resolve(values.output ?? defaultPath);
      const htmlPath = subcommand === "html" ? output : output.replace(/\.pdf$/i, ".html");
      writeHtmlReport(htmlPath, report);
      if (subcommand === "pdf") writePdfReport(htmlPath, output);
      console.log(output);
    } else console.log(JSON.stringify(report, null, 2));
    store.close();
    return 0;
  }

  if (command === "compliance" && subcommand === "coverage") {
    const { values } = parseArgs({
      args: rest,
      options: {
        framework: { type: "string" },
        provider: { type: "string" },
        json: { type: "boolean" },
      },
    });
    const coverage = complianceCoverage({
      framework: values.framework,
      provider: values.provider,
    });
    if (values.framework && coverage.length === 0) {
      console.error(`unknown framework: ${values.framework}`);
      return 1;
    }
    if (values.json) console.log(JSON.stringify(coverage, null, 2));
    else {
      for (const item of coverage) {
        const statuses = Object.entries(item.statuses)
          .filter(([, count]) => count > 0)
          .map(([status, count]) => `${status}=${count}`)
          .join(" ");
        console.log(
          `${item.framework.padEnd(28)} ${String(item.mappedControls).padStart(3)}/${String(item.totalControls).padEnd(3)} controls  ${String(Math.round(item.coverageRatio * 100)).padStart(3)}%  ${statuses || "no mappings"}`,
        );
      }
      console.log(
        "\nMapping coverage describes CloudRanger technical evidence only; it is not a compliance certification.",
      );
    }
    return 0;
  }

  if (command === "scans") {
    const store = new CloudRangerStore(dbPath());
    for (const scan of store.listScans(20)) {
      console.log(
        `${scan.createdAt}  ${scan.provider.padEnd(6)} ${scan.scopeId.padEnd(20)} ${scan.status.padEnd(10)} ${scan.summary ? `fail=${scan.summary.fail} pass=${scan.summary.pass} coverage=${Math.round(scan.summary.coverageRatio * 100)}%` : ""}`,
      );
    }
    store.close();
    return 0;
  }

  if (command === "audit" && subcommand === "verify") {
    const store = new CloudRangerStore(dbPath());
    const broken = store.verifyAuditChain();
    store.close();
    if (broken === null) {
      console.log("audit chain intact");
      return 0;
    }
    console.error(`audit chain BROKEN at entry ${broken}`);
    return 1;
  }

  if (command === "audit") {
    const { values } = parseArgs({
      args: [subcommand, ...rest].filter((a): a is string => a !== undefined),
      options: { limit: { type: "string" } },
    });
    const store = new CloudRangerStore(dbPath());
    for (const entry of store.searchAudit(values.limit ? Number(values.limit) : 50) as any[]) {
      console.log(
        `${entry.createdAt}  ${entry.success ? "ok " : "ERR"}  ${entry.actor.padEnd(20)} ${entry.tool}`,
      );
    }
    store.close();
    return 0;
  }

  if (command === "mcp-config") {
    const { values } = parseArgs({
      args: [subcommand, ...rest].filter((a): a is string => a !== undefined),
      options: { client: { type: "string" } },
    });
    const client = values.client ?? "claude-code";
    const serverPath = join(import.meta.dirname, "..", "..", "mcp-server", "dist", "main.js");
    if (client === "codex") {
      console.log(
        `# ~/.codex/config.toml\n[mcp_servers.cloudranger]\ncommand = "node"\nargs = ["${serverPath}"]`,
      );
    } else if (client === "claude-desktop") {
      console.log(
        JSON.stringify(
          { mcpServers: { cloudranger: { command: "node", args: [serverPath] } } },
          null,
          2,
        ),
      );
    } else {
      console.log(`claude mcp add cloudranger -- node ${serverPath}`);
    }
    return 0;
  }

  console.error(`unknown command: ${command} ${subcommand ?? ""}\n`);
  console.log(HELP);
  return 1;
}

process.exit(main());

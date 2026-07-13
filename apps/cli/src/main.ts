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
  complianceStatus,
  customCatalogDir,
  fixturesDir,
  loadDefaultCatalog,
  loadFrameworkRegistry,
  type ControlEvaluationCounts,
} from "@cloudranger/catalog";
import { createRepository } from "@cloudranger/db";
import {
  controlTemplate,
  fixtureFileSchema,
  runFixtureFile,
  validateCatalogDocument,
  validateParameterOverrides,
} from "@cloudranger/engine";

const dbPath = () =>
  process.env.CLOUDRANGER_DB ?? join(homedir(), ".cloudranger", "cloudranger.db");

const HELP = `cloudranger — local-first, agent-driven multi-cloud CSPM

Usage:
  cloudranger catalog validate          Validate bundled controls + collectors
  cloudranger catalog test              Run all control fixture tests
  cloudranger catalog list [--provider aws|azure|gcp]
  cloudranger findings [--state open,reopened] [--severity critical,high] [--owner team] [--overdue] [--json]
  cloudranger parameters list --provider aws|azure|gcp --scope <scopeId> [--json]
  cloudranger parameters set --provider aws|azure|gcp --scope <scopeId> --control <id> [--param name=value ...]
                                        Persist parameter overrides (no --param clears)
  cloudranger report [--since-days 30] [--provider aws|azure|gcp]
  cloudranger report html [--output output/html/cloudranger-report.html] [--since-days 30] [--provider aws|azure|gcp]
  cloudranger report pdf [--output output/pdf/cloudranger-report.pdf] [--since-days 30] [--provider aws|azure|gcp]
  cloudranger compliance coverage [--framework <id>] [--provider aws|azure|gcp] [--json]
  cloudranger compliance status --provider aws|azure|gcp --scope <scopeId> [--framework <id>] [--json]
                                        Per-requirement rollup of the latest evaluated scan
  cloudranger scans                     List recent scans
  cloudranger scans compare <baselineScanId> <currentScanId>
  cloudranger audit [--limit 50]        Show recent audit entries
  cloudranger audit verify              Verify the audit hash chain
  cloudranger controls template [--provider aws|azure|gcp] [--collector <id>]
                                        Print a custom-control YAML template
  cloudranger controls add <file.yaml>  Validate + install a custom control
  cloudranger controls dir              Print the custom catalog directory
  cloudranger mcp-config [--client claude-code|claude-desktop|codex]
  cloudranger db-path                   Print the database location

Environment:
  CLOUDRANGER_DB             SQLite file (default ~/.cloudranger/cloudranger.db)
  CLOUDRANGER_DATABASE_URL   PostgreSQL URL for shared deployments (takes precedence)
`;

async function main(): Promise<number> {
  const [command, subcommand, ...rest] = process.argv.slice(2);

  if (!command || command === "help" || command === "--help") {
    console.log(HELP);
    return 0;
  }

  if (command === "db-path") {
    console.log(
      process.env.CLOUDRANGER_DATABASE_URL ? "postgresql (CLOUDRANGER_DATABASE_URL)" : dbPath(),
    );
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
        owner: { type: "string" },
        overdue: { type: "boolean" },
        json: { type: "boolean" },
      },
    });
    const store = createRepository({ sqlitePath: dbPath() });
    const { total, findings } = await store.searchFindings({
      state: values.state?.split(",") as any,
      severity: values.severity?.split(","),
      provider: values.provider as any,
      owner: values.owner,
      overdue: values.overdue,
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
    await store.close();
    return 0;
  }

  if (command === "parameters") {
    const { values } = parseArgs({
      args: rest.filter((a): a is string => a !== undefined),
      options: {
        provider: { type: "string" },
        scope: { type: "string" },
        control: { type: "string" },
        param: { type: "string", multiple: true },
        json: { type: "boolean" },
      },
    });
    if (!values.provider || !["aws", "azure", "gcp"].includes(values.provider) || !values.scope) {
      console.error("parameters requires --provider aws|azure|gcp and --scope <scopeId>");
      return 1;
    }
    const provider = values.provider as "aws" | "azure" | "gcp";
    const store = createRepository({ sqlitePath: dbPath() });
    try {
      if (subcommand === "list") {
        const rows = await store.listScopeParameters(provider, values.scope);
        if (values.json) {
          console.log(JSON.stringify(rows, null, 2));
        } else if (rows.length === 0) {
          console.log("no persisted parameter overrides for this scope");
        } else {
          for (const row of rows) {
            console.log(
              `${row.controlId}  ${JSON.stringify(row.parameters)}  (updated ${row.updatedAt})`,
            );
          }
        }
        return 0;
      }
      if (subcommand === "set") {
        if (!values.control) {
          console.error("parameters set requires --control <controlId>");
          return 1;
        }
        const catalog = loadDefaultCatalog();
        const control = catalog.controls.find((c) => c.id === values.control);
        if (!control) {
          console.error(`unknown control: ${values.control}`);
          return 1;
        }
        const overrides: Record<string, number | string | boolean> = {};
        for (const pair of values.param ?? []) {
          const eq = pair.indexOf("=");
          if (eq <= 0) {
            console.error(`invalid --param ${pair}; expected name=value`);
            return 1;
          }
          const name = pair.slice(0, eq);
          const raw = pair.slice(eq + 1);
          const decl = control.parameters?.[name];
          overrides[name] =
            decl?.type === "number" ? Number(raw) : decl?.type === "boolean" ? raw === "true" : raw;
        }
        if (Object.keys(overrides).length === 0) {
          await store.setScopeParameters(provider, values.scope, values.control, null);
          console.log(`cleared overrides for ${values.control}`);
          return 0;
        }
        const issues = validateParameterOverrides(control, overrides);
        if (issues.length > 0) {
          console.error(`invalid parameters: ${issues.join("; ")}`);
          return 1;
        }
        await store.setScopeParameters(provider, values.scope, values.control, overrides);
        console.log(`saved ${JSON.stringify(overrides)} for ${values.control} in ${values.scope}`);
        return 0;
      }
      console.error("usage: cloudranger parameters list|set ...");
      return 1;
    } finally {
      await store.close();
    }
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
    const store = createRepository({ sqlitePath: dbPath() });
    const report = (await store.reportData({
      sinceDays: values["since-days"] ? Number(values["since-days"]) : undefined,
      provider: values.provider as any,
    })) as any;
    const controlsById = new Map(
      loadDefaultCatalog().controls.map((control) => [control.id, control]),
    );
    report.topFailingControls = report.topFailingControls.map((item: any) => {
      const control = controlsById.get(item.controlId);
      return { ...item, title: control?.title, description: control?.description };
    });
    const openFindings = await store.searchFindings({
      provider: values.provider as any,
      state: ["open", "reopened"],
      limit: 200,
    });
    const frameworks = new Map<string, { findings: number; controls: Set<string> }>();
    for (const finding of openFindings.findings) {
      for (const mapping of controlsById.get(finding.controlId)?.compliance ?? []) {
        const key = `${mapping.framework}${mapping.version ? ` ${mapping.version}` : ""}`;
        const entry = frameworks.get(key) ?? { findings: 0, controls: new Set<string>() };
        entry.findings += 1;
        entry.controls.add(finding.controlId);
        frameworks.set(key, entry);
      }
    }
    report.complianceSummary = [...frameworks.entries()]
      .map(([framework, entry]) => ({
        framework,
        openFindings: entry.findings,
        failingControls: entry.controls.size,
      }))
      .sort((a, b) => b.openFindings - a.openFindings || a.framework.localeCompare(b.framework));
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
    await store.close();
    return 0;
  }

  if (command === "compliance" && subcommand === "status") {
    const { values } = parseArgs({
      args: rest,
      options: {
        provider: { type: "string" },
        scope: { type: "string" },
        framework: { type: "string" },
        json: { type: "boolean" },
      },
    });
    if (!values.provider || !["aws", "azure", "gcp"].includes(values.provider) || !values.scope) {
      console.error("compliance status requires --provider aws|azure|gcp and --scope <scopeId>");
      return 1;
    }
    const provider = values.provider as "aws" | "azure" | "gcp";
    const store = createRepository({ sqlitePath: dbPath() });
    try {
      const latest = (await store.listScans(200)).find(
        (scan) =>
          scan.status === "evaluated" &&
          scan.provider === provider &&
          scan.scopeId === values.scope,
      );
      const evaluations = new Map<string, ControlEvaluationCounts>();
      if (latest) {
        for (const row of await store.getEvaluations(latest.id)) {
          const counts = evaluations.get(row.controlId) ?? {
            pass: 0,
            fail: 0,
            error: 0,
            notApplicable: 0,
          };
          if (row.status === "pass") counts.pass += 1;
          else if (row.status === "fail") counts.fail += 1;
          else if (row.status === "error") counts.error += 1;
          else if (row.status === "not_applicable") counts.notApplicable += 1;
          evaluations.set(row.controlId, counts);
        }
      }
      const frameworks = complianceStatus({
        controls: loadDefaultCatalog().controls,
        registry: loadFrameworkRegistry(),
        evaluations,
        framework: values.framework,
        provider,
      });
      if (values.json) {
        console.log(
          JSON.stringify(
            { scanId: latest?.id, evaluatedAt: latest?.evaluatedAt, frameworks },
            null,
            2,
          ),
        );
        return 0;
      }
      if (!latest) {
        console.log("no evaluated scan for this scope — every requirement is not assessed\n");
      }
      for (const fw of frameworks) {
        const t = fw.totals;
        const coverage =
          t.totalRequirements === null
            ? `${t.mappedRequirements} mapped (total unknown)`
            : `${t.mappedRequirements}/${t.totalRequirements} mapped (${Math.round((t.mappedRatio ?? 0) * 100)}%)`;
        console.log(`${fw.framework} ${fw.version} — ${coverage}`);
        for (const req of fw.requirements) {
          console.log(
            `  ${req.status.padEnd(14)} [${req.automation.padEnd(7)}] ${req.requirement}  (${req.controls.map((c) => c.controlId).join(", ")})`,
          );
        }
      }
      console.log(
        "\nStatuses reflect CloudRanger technical evidence only; partial/manual requirements need assessment beyond these checks.",
      );
      return 0;
    } finally {
      await store.close();
    }
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
    const store = createRepository({ sqlitePath: dbPath() });
    if (subcommand === "compare") {
      const [baselineScanId, currentScanId] = rest;
      if (!baselineScanId || !currentScanId) {
        console.error("usage: cloudranger scans compare <baselineScanId> <currentScanId>");
        await store.close();
        return 1;
      }
      console.log(JSON.stringify(await store.compareScans(baselineScanId, currentScanId), null, 2));
      await store.close();
      return 0;
    }
    for (const scan of await store.listScans(20)) {
      console.log(
        `${scan.createdAt}  ${scan.provider.padEnd(6)} ${scan.scopeId.padEnd(20)} ${scan.status.padEnd(10)} ${scan.summary ? `fail=${scan.summary.fail} pass=${scan.summary.pass} coverage=${Math.round(scan.summary.coverageRatio * 100)}%` : ""}`,
      );
    }
    await store.close();
    return 0;
  }

  if (command === "audit" && subcommand === "verify") {
    const store = createRepository({ sqlitePath: dbPath() });
    const broken = await store.verifyAuditChain();
    await store.close();
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
    const store = createRepository({ sqlitePath: dbPath() });
    for (const entry of (await store.searchAudit(
      values.limit ? Number(values.limit) : 50,
    )) as any[]) {
      console.log(
        `${entry.createdAt}  ${entry.success ? "ok " : "ERR"}  ${entry.actor.padEnd(20)} ${entry.tool}`,
      );
    }
    await store.close();
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

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });

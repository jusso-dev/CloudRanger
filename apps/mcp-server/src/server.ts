import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  buildPlan,
  controlTemplate,
  evaluateControls,
  validateCatalogDocument,
  validateParamValue,
  type LoadedCatalog,
  type Provider,
} from "@cloudranger/engine";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PACKS, customCatalogDir, resolvePack } from "@cloudranger/catalog";
import { CloudRangerStore } from "@cloudranger/db";
import { SAFETY_RESOURCE, SERVER_INSTRUCTIONS, WORKFLOW_RESOURCE } from "./instructions.js";
import { registerPrompts } from "./prompts.js";

const MAX_RECORDS_PER_SUBMIT = 200;
const MAX_OUTPUT_BYTES = 2_000_000;

const providerParam = z.enum(["aws", "azure", "gcp"]);
const severityParam = z.enum(["informational", "low", "medium", "high", "critical"]);

export interface ServerDeps {
  store: CloudRangerStore;
  catalog: LoadedCatalog;
  actor?: string;
}

export function createServer(deps: ServerDeps): McpServer {
  const { store, catalog } = deps;
  const server = new McpServer(
    { name: "cloudranger", version: "0.1.0" },
    { instructions: SERVER_INSTRUCTIONS },
  );

  const actor = () => {
    const client = server.server.getClientVersion();
    return deps.actor ?? (client ? `mcp:${client.name}` : "mcp:unknown");
  };

  const json = (value: unknown) => ({
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
  });

  const fail = (message: string) => ({
    content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }],
    isError: true as const,
  });

  /** Wrap a handler with audit logging; errors become structured tool errors. */
  const audited = <A>(tool: string, handler: (args: A) => unknown) => {
    return async (args: A) => {
      try {
        const result = handler(args);
        store.audit({ actor: actor(), tool, args, success: true });
        return json(result);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        store.audit({ actor: actor(), tool, args, success: false, detail: message });
        return fail(message);
      }
    };
  };

  const readOnly = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };

  // ---------- catalog ----------

  server.registerTool(
    "catalog_list_controls",
    {
      title: "List security controls",
      description:
        "List the deterministic posture controls in the catalog. Filter by provider, service or severity. Returns summaries; use catalog_get_control for full detail.",
      inputSchema: {
        provider: providerParam.optional(),
        service: z.string().optional(),
        severity: severityParam.optional(),
      },
      annotations: readOnly,
    },
    audited(
      "catalog_list_controls",
      (args: { provider?: Provider; service?: string; severity?: string }) => {
        const controls = catalog.controls
          .filter((c) => !args.provider || c.provider === args.provider)
          .filter((c) => !args.service || c.service === args.service)
          .filter((c) => !args.severity || c.severity === args.severity)
          .map((c) => ({
            id: c.id,
            provider: c.provider,
            service: c.service,
            title: c.title,
            severity: c.severity,
            categories: c.categories,
            source: `${c.source.engine}:${c.source.id}`,
          }));
        return { total: controls.length, controls };
      },
    ),
  );

  server.registerTool(
    "catalog_get_control",
    {
      title: "Get control detail",
      description:
        "Full definition of one control: rationale, evaluation logic, evidence collector, remediation guidance, compliance mappings and upstream attribution.",
      inputSchema: { controlId: z.string() },
      annotations: readOnly,
    },
    audited("catalog_get_control", (args: { controlId: string }) => {
      const control = catalog.controls.find((c) => c.id === args.controlId);
      if (!control) throw new Error(`unknown control: ${args.controlId}`);
      const collector = catalog.collectors.get(control.collector);
      return { control, collector };
    }),
  );

  server.registerTool(
    "catalog_list_packs",
    {
      title: "List control packs",
      description:
        "Named control selections (baseline, public-exposure, identity, encryption, logging-detection, resilience, kubernetes) usable as the pack argument to scan_start.",
      inputSchema: {},
      annotations: readOnly,
    },
    audited("catalog_list_packs", () => ({
      packs: PACKS.map((pack) => ({
        ...pack,
        controlCount: resolvePack(catalog.controls, pack.id).length,
      })),
    })),
  );

  server.registerTool(
    "catalog_generate_control_template",
    {
      title: "Generate a custom control template",
      description:
        "YAML template for authoring a custom control (plus optional custom collector), with the full expression-operator reference inline. Fill it in — grounding passWhen in real CLI JSON output you have observed — then submit via catalog_add_custom_control or save with the CLI (cloudranger controls add).",
      inputSchema: {
        provider: providerParam,
        collectorId: z
          .string()
          .optional()
          .describe("Existing collector to evaluate (see catalog_get_control for examples)"),
      },
      annotations: readOnly,
    },
    audited(
      "catalog_generate_control_template",
      (args: { provider: Provider; collectorId?: string }) => {
        if (args.collectorId && !catalog.collectors.has(args.collectorId)) {
          throw new Error(`unknown collector: ${args.collectorId}`);
        }
        return {
          template: controlTemplate(args),
          availableCollectors: [...catalog.collectors.values()]
            .filter((c) => c.provider === args.provider)
            .map((c) => ({ id: c.id, kind: c.kind, description: c.description })),
          guidance:
            "Base passWhen on actual CLI JSON output you have run and observed — do not guess field names. Custom collectors must be read-only (list/describe/get/show) or they will be rejected. Use id prefix CUSTOM- for your own controls; reusing an existing CR- id intentionally overrides the bundled control.",
        };
      },
    ),
  );

  server.registerTool(
    "catalog_add_custom_control",
    {
      title: "Add or override a control (custom catalog)",
      description:
        "Validate a custom control YAML document (controls: and optional collectors: lists) and persist it to the operator's custom catalog directory. Matching IDs override bundled definitions. The document is schema-validated and every command must pass read-only safety validation. Takes effect immediately for new scans.",
      inputSchema: {
        yaml: z.string().max(50_000).describe("The full YAML document"),
        filename: z
          .string()
          .regex(/^[a-z0-9-]+$/)
          .describe("File name (kebab-case, no extension) to store it under"),
      },
      annotations: { ...readOnly, readOnlyHint: false },
    },
    audited("catalog_add_custom_control", (args: { yaml: string; filename: string }) => {
      const result = validateCatalogDocument(args.yaml, catalog.collectors);
      if (result.errors.length > 0) {
        throw new Error(`validation failed: ${result.errors.join(" | ")}`);
      }
      const dir = join(customCatalogDir(), "controls");
      mkdirSync(dir, { recursive: true });
      const path = join(dir, `${args.filename}.yaml`);
      writeFileSync(path, args.yaml, "utf8");
      // Apply to the live catalog: overrides replace, new entries append.
      for (const collector of result.collectors) {
        catalog.collectors.set(collector.id, collector);
      }
      const overridden: string[] = [];
      for (const control of result.controls) {
        const index = catalog.controls.findIndex((c) => c.id === control.id);
        if (index >= 0) {
          catalog.controls[index] = control;
          overridden.push(control.id);
        } else {
          catalog.controls.push(control);
        }
      }
      return {
        saved: path,
        controls: result.controls.map((c) => c.id),
        collectors: result.collectors.map((c) => c.id),
        overridden,
        note: "Custom control is active now and will load automatically on future server starts. Add fixture cases and test with: cloudranger catalog test",
      };
    }),
  );

  // ---------- scans ----------

  server.registerTool(
    "scan_start",
    {
      title: "Start a scan (returns collection plan)",
      description:
        "Create a scan for one provider scope (AWS account / Azure subscription / GCP project) and return the exact read-only CLI commands to run. Filter with services or controlIds to scan incrementally. AWS scans require regions.",
      inputSchema: {
        provider: providerParam,
        scopeId: z
          .string()
          .describe(
            "AWS account ID, Azure subscription ID, or GCP project ID the agent's CLI is authenticated against",
          ),
        regions: z
          .array(z.string())
          .max(30)
          .optional()
          .describe("AWS regions to scan (required for aws)"),
        services: z
          .array(z.string())
          .optional()
          .describe("Restrict to these services (e.g. s3, iam)"),
        controlIds: z.array(z.string()).optional().describe("Restrict to these control IDs"),
        pack: z
          .string()
          .optional()
          .describe("Restrict to a named control pack (see catalog_list_packs)"),
      },
      annotations: { ...readOnly, readOnlyHint: false },
    },
    audited(
      "scan_start",
      (args: {
        provider: Provider;
        scopeId: string;
        regions?: string[];
        services?: string[];
        controlIds?: string[];
        pack?: string;
      }) => {
        if (!validateParamValue(args.scopeId)) throw new Error("invalid scopeId");
        const regions = args.regions ?? [];
        if (args.provider === "aws" && regions.length === 0) {
          throw new Error("AWS scans require at least one region");
        }
        let controls = args.pack
          ? resolvePack(catalog.controls, args.pack, args.provider)
          : catalog.controls.filter((c) => c.provider === args.provider);
        if (args.services?.length)
          controls = controls.filter((c) => args.services!.includes(c.service));
        if (args.controlIds?.length)
          controls = controls.filter((c) => args.controlIds!.includes(c.id));
        if (controls.length === 0) throw new Error("no controls match the requested filters");
        const plan = buildPlan(controls, catalog.collectors, {
          provider: args.provider,
          regions,
          scopeId: args.scopeId,
        });
        const scan = store.createScan({
          provider: args.provider,
          scopeId: args.scopeId,
          regions,
          controlIds: plan.controlIds,
        });
        return { scanId: scan.id, controlCount: plan.controlIds.length, plan };
      },
    ),
  );

  server.registerTool(
    "scan_get_plan",
    {
      title: "Re-fetch a scan's collection plan",
      description:
        "Re-render the collection plan for an existing scan (e.g. after a context reset).",
      inputSchema: { scanId: z.string() },
      annotations: readOnly,
    },
    audited("scan_get_plan", (args: { scanId: string }) => {
      const scan = store.getScan(args.scanId);
      if (!scan) throw new Error(`unknown scan: ${args.scanId}`);
      const controls = catalog.controls.filter((c) => scan.controlIds.includes(c.id));
      const plan = buildPlan(controls, catalog.collectors, {
        provider: scan.provider,
        regions: scan.regions,
        scopeId: scan.scopeId,
      });
      return { scanId: scan.id, status: scan.status, plan };
    }),
  );

  server.registerTool(
    "evidence_submit",
    {
      title: "Submit collected evidence",
      description:
        "Submit the JSON output (or error) of executed plan commands. Submit failed commands too — errorText and exitCode — never omit them. Batch up to 200 records per call.",
      inputSchema: {
        scanId: z.string(),
        records: z
          .array(
            z.object({
              collectorId: z.string(),
              region: z.string().optional(),
              resourceKey: z
                .string()
                .optional()
                .describe(
                  "For per_resource collectors: the {resource} value this record belongs to",
                ),
              output: z.unknown().optional().describe("Parsed JSON output of the command"),
              errorText: z.string().max(10_000).optional(),
              exitCode: z.number().int(),
            }),
          )
          .min(1)
          .max(MAX_RECORDS_PER_SUBMIT),
      },
      annotations: { ...readOnly, readOnlyHint: false },
    },
    audited(
      "evidence_submit",
      (args: {
        scanId: string;
        records: {
          collectorId: string;
          region?: string;
          resourceKey?: string;
          output?: unknown;
          errorText?: string;
          exitCode: number;
        }[];
      }) => {
        for (const record of args.records) {
          if (!catalog.collectors.has(record.collectorId)) {
            throw new Error(`unknown collector: ${record.collectorId}`);
          }
          if (
            record.output !== undefined &&
            JSON.stringify(record.output).length > MAX_OUTPUT_BYTES
          ) {
            throw new Error(
              `output for ${record.collectorId} exceeds ${MAX_OUTPUT_BYTES} bytes; split the collection or reduce scope`,
            );
          }
          if (record.exitCode !== 0 && record.output === undefined && !record.errorText) {
            throw new Error(`failed record for ${record.collectorId} must include errorText`);
          }
        }
        const accepted = store.addEvidence(
          args.scanId,
          args.records.map((r) => ({ ...r, output: r.output ?? null })),
        );
        return { accepted, stats: store.evidenceStats(args.scanId) };
      },
    ),
  );

  server.registerTool(
    "scan_evaluate",
    {
      title: "Evaluate scan and reconcile findings",
      description:
        "Run the deterministic engine over all submitted evidence: evaluates every requested control, reconciles the finding lifecycle (create/recur/resolve/reopen) and returns summary + coverage. Controls without evidence are reported as coverage gaps, never as passing.",
      inputSchema: { scanId: z.string() },
      annotations: { ...readOnly, readOnlyHint: false, idempotentHint: true },
    },
    audited("scan_evaluate", (args: { scanId: string }) => {
      const scan = store.getScan(args.scanId);
      if (!scan) throw new Error(`unknown scan: ${args.scanId}`);
      if (scan.status === "evaluated") {
        return {
          scanId: scan.id,
          alreadyEvaluated: true,
          summary: scan.summary,
          coverage: scan.coverage,
        };
      }
      if (scan.status === "cancelled") throw new Error("scan is cancelled");
      const evidence = store.getEvidence(args.scanId);
      const { results, coverage } = evaluateControls(
        catalog.controls,
        catalog.collectors,
        { provider: scan.provider, scopeId: scan.scopeId, records: evidence },
        { controlIds: scan.controlIds },
      );
      const summary = store.finalizeScan(args.scanId, results, coverage);
      const gaps = coverage.filter((c) => c.status !== "evaluated");
      return {
        scanId: scan.id,
        summary,
        coverage: {
          requestedControls: coverage.length,
          evaluated: coverage.length - gaps.length,
          gaps,
        },
        note:
          gaps.length > 0
            ? "Some controls had no evidence and were NOT assessed. Disclose this in any report."
            : "All requested controls were evaluated.",
      };
    }),
  );

  server.registerTool(
    "scan_status",
    {
      title: "Get scan status",
      description: "Status, evidence statistics, summary and coverage for one scan.",
      inputSchema: { scanId: z.string() },
      annotations: readOnly,
    },
    audited("scan_status", (args: { scanId: string }) => {
      const scan = store.getScan(args.scanId);
      if (!scan) throw new Error(`unknown scan: ${args.scanId}`);
      return { scan, evidenceStats: store.evidenceStats(args.scanId) };
    }),
  );

  server.registerTool(
    "scan_list",
    {
      title: "List recent scans",
      description: "Most recent scans with status and summaries.",
      inputSchema: { limit: z.number().int().min(1).max(100).optional() },
      annotations: readOnly,
    },
    audited("scan_list", (args: { limit?: number }) => ({
      scans: store.listScans(args.limit ?? 20),
    })),
  );

  server.registerTool(
    "scan_compare",
    {
      title: "Compare two evaluated scans",
      description:
        "Compare a baseline scan with a later scan for the same provider scope. Returns control status changes, finding lifecycle events, and coverage movement.",
      inputSchema: {
        baselineScanId: z.string(),
        currentScanId: z.string(),
      },
      annotations: readOnly,
    },
    audited("scan_compare", (args: { baselineScanId: string; currentScanId: string }) =>
      store.compareScans(args.baselineScanId, args.currentScanId),
    ),
  );

  server.registerTool(
    "scan_cancel",
    {
      title: "Cancel a collecting scan",
      description: "Mark a scan cancelled; it will no longer accept evidence or evaluate.",
      inputSchema: { scanId: z.string() },
      annotations: { ...readOnly, readOnlyHint: false },
    },
    audited("scan_cancel", (args: { scanId: string }) => {
      store.cancelScan(args.scanId);
      return { scanId: args.scanId, status: store.getScan(args.scanId)?.status };
    }),
  );

  // ---------- findings ----------

  server.registerTool(
    "findings_search",
    {
      title: "Search findings",
      description:
        "Search persisted findings across all scans. Findings have a technical lifecycle state (open/resolved/reopened) and a separate human workflow state. Default sort: severity, then most recently seen.",
      inputSchema: {
        provider: providerParam.optional(),
        scopeId: z.string().optional(),
        controlId: z.string().optional(),
        service: z.string().optional(),
        resourceId: z.string().optional(),
        severity: z.array(severityParam).optional(),
        state: z.array(z.enum(["open", "resolved", "reopened"])).optional(),
        workflowState: z
          .array(
            z.enum([
              "new",
              "acknowledged",
              "in_progress",
              "risk_accepted",
              "false_positive",
              "closed",
            ]),
          )
          .optional(),
        limit: z.number().int().min(1).max(200).optional(),
        offset: z.number().int().min(0).optional(),
      },
      annotations: readOnly,
    },
    audited("findings_search", (args: any) => store.searchFindings(args)),
  );

  server.registerTool(
    "findings_get",
    {
      title: "Get finding detail with history",
      description:
        "One finding with its latest evidence and complete lifecycle history (created/recurred/resolved/reopened/workflow events).",
      inputSchema: { fingerprint: z.string() },
      annotations: readOnly,
    },
    audited("findings_get", (args: { fingerprint: string }) => {
      const finding = store.getFinding(args.fingerprint);
      if (!finding) throw new Error(`unknown finding: ${args.fingerprint}`);
      const control = catalog.controls.find((c) => c.id === finding.controlId);
      return {
        finding,
        history: store.getFindingEvents(args.fingerprint),
        control: control
          ? {
              id: control.id,
              title: control.title,
              rationale: control.rationale,
              remediation: control.remediation,
              compliance: control.compliance,
              references: control.references,
              source: control.source,
            }
          : undefined,
      };
    }),
  );

  server.registerTool(
    "findings_set_status",
    {
      title: "Set finding workflow status",
      description:
        "Human workflow decision on a finding (acknowledge, in_progress, risk_accepted, false_positive, closed). risk_accepted and false_positive require a reason; risk acceptance should include expiresAt. This never changes the technical lifecycle state — only passing evaluations resolve findings.",
      inputSchema: {
        fingerprint: z.string(),
        workflowState: z.enum([
          "new",
          "acknowledged",
          "in_progress",
          "risk_accepted",
          "false_positive",
          "closed",
        ]),
        reason: z.string().max(2000).optional(),
        expiresAt: z.string().optional().describe("ISO timestamp when a risk acceptance expires"),
      },
      annotations: { ...readOnly, readOnlyHint: false },
    },
    audited(
      "findings_set_status",
      (args: { fingerprint: string; workflowState: any; reason?: string; expiresAt?: string }) =>
        store.setWorkflowState(args.fingerprint, args.workflowState, {
          reason: args.reason,
          expiresAt: args.expiresAt,
          actor: actor(),
        }),
    ),
  );

  server.registerTool(
    "findings_comment",
    {
      title: "Comment on a finding",
      description: "Append an investigation note to a finding's history.",
      inputSchema: { fingerprint: z.string(), comment: z.string().max(5000) },
      annotations: { ...readOnly, readOnlyHint: false },
    },
    audited("findings_comment", (args: { fingerprint: string; comment: string }) => {
      store.addFindingComment(args.fingerprint, args.comment, actor());
      return { ok: true };
    }),
  );

  // ---------- reporting / audit ----------

  server.registerTool(
    "report_data",
    {
      title: "Get repeatable report metrics (JSON)",
      description:
        "Aggregated posture metrics with explicit definitions: open findings by severity/service, top failing controls, new/resolved/reopened counts in a window, risk acceptances and recent scan health. Use these numbers as the single source of truth when writing executive or technical reports.",
      inputSchema: {
        provider: providerParam.optional(),
        scopeId: z.string().optional(),
        sinceDays: z.number().int().min(1).max(365).optional(),
      },
      annotations: readOnly,
    },
    audited("report_data", (args: { provider?: Provider; scopeId?: string; sinceDays?: number }) =>
      store.reportData(args),
    ),
  );

  server.registerTool(
    "audit_search",
    {
      title: "Search the audit log",
      description: "Recent audit entries (hash-chained). Every MCP tool call is recorded here.",
      inputSchema: { limit: z.number().int().min(1).max(500).optional() },
      annotations: readOnly,
    },
    audited("audit_search", (args: { limit?: number }) => ({
      entries: store.searchAudit(args.limit ?? 50),
      chainIntact: store.verifyAuditChain() === null,
    })),
  );

  // ---------- resources ----------

  server.registerResource(
    "safety-model",
    "cloudranger://guides/safety",
    {
      title: "CloudRanger safety model",
      description: "Trust boundaries and agent obligations",
      mimeType: "text/markdown",
    },
    async (uri) => ({ contents: [{ uri: uri.href, text: SAFETY_RESOURCE }] }),
  );
  server.registerResource(
    "scan-workflow",
    "cloudranger://guides/workflow",
    {
      title: "Scan workflow guide",
      description: "How to run a scan end to end",
      mimeType: "text/markdown",
    },
    async (uri) => ({ contents: [{ uri: uri.href, text: WORKFLOW_RESOURCE }] }),
  );
  server.registerResource(
    "catalog-summary",
    "cloudranger://catalog/summary",
    {
      title: "Control catalog summary",
      description: "All controls by provider and service",
      mimeType: "application/json",
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          text: JSON.stringify(
            catalog.controls.map((c) => ({
              id: c.id,
              provider: c.provider,
              service: c.service,
              severity: c.severity,
              title: c.title,
            })),
            null,
            2,
          ),
        },
      ],
    }),
  );

  registerPrompts(server);

  return server;
}

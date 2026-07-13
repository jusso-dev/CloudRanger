import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  buildPlan,
  controlContentHash,
  controlTemplate,
  evaluateControls,
  fixtureFileSchema,
  runFixtureFile,
  validateCatalogDocument,
  validateParamValue,
  validateParameterOverrides,
  type LoadedCatalog,
  type Provider,
} from "@cloudranger/engine";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  PACKS,
  complianceStatus,
  customCatalogDir,
  loadFrameworkRegistry,
  resolvePack,
  type ControlEvaluationCounts,
} from "@cloudranger/catalog";
import type { CloudRangerRepository, ScanRow } from "@cloudranger/db";
import { SAFETY_RESOURCE, SERVER_INSTRUCTIONS, WORKFLOW_RESOURCE } from "./instructions.js";
import { registerPrompts } from "./prompts.js";
import { createNotificationSender } from "./notifications.js";
import { authorizeTool, type CloudRangerRole } from "./authorization.js";

const MAX_RECORDS_PER_SUBMIT = 200;
const MAX_OUTPUT_BYTES = 2_000_000;

const providerParam = z.enum(["aws", "azure", "gcp"]);
const severityParam = z.enum(["informational", "low", "medium", "high", "critical"]);

export interface ServerDeps {
  store: CloudRangerRepository;
  catalog: LoadedCatalog;
  actor?: string;
  role?: CloudRangerRole;
  workspaceId?: string;
}

/**
 * Record the current revision of every catalog control in the lifecycle
 * store. Called at server startup so control updates leave an auditable
 * version history behind (findings reference controlId + controlVersion).
 */
export async function recordCatalogRevisions(
  store: CloudRangerRepository,
  catalog: LoadedCatalog,
): Promise<number> {
  return store.recordControlRevisions(
    catalog.controls.map((control) => ({
      controlId: control.id,
      version: control.version,
      contentHash: controlContentHash(control),
      definition: control,
      deprecated: Boolean(control.deprecated),
    })),
  );
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

  const expectedCollectorsForScan = (scan: ScanRow | undefined) => {
    if (!scan) return [];
    const controls = catalog.controls.filter((control) => scan.controlIds.includes(control.id));
    return [
      ...new Set(
        buildPlan(controls, catalog.collectors, {
          provider: scan.provider,
          regions: scan.regions,
          scopeId: scan.scopeId,
        }).steps.map((step) => step.collectorId),
      ),
    ];
  };

  const json = (value: unknown) => ({
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
  });

  const fail = (message: string) => ({
    content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }],
    isError: true as const,
  });

  /** Wrap a handler with audit logging; errors become structured tool errors. */
  const audited = <A>(tool: string, handler: (args: A) => unknown | Promise<unknown>) => {
    return async (args: A) => {
      try {
        authorizeTool(deps.role ?? "admin", tool);
        const result = await handler(args);
        await store.audit({ actor: actor(), tool, args, success: true });
        return json(result);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        await store.audit({ actor: actor(), tool, args, success: false, detail: message });
        return fail(message);
      }
    };
  };

  const readOnly = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };

  if (deps.workspaceId) {
    server.registerTool(
      "workspace_list_members",
      {
        title: "List workspace members",
        description: "List authenticated identities and roles for this isolated workspace.",
        inputSchema: {},
        annotations: readOnly,
      },
      audited("workspace_list_members", () => store.listWorkspaceMembers(deps.workspaceId!)),
    );
    server.registerTool(
      "workspace_set_member",
      {
        title: "Add or update workspace member",
        description: "Grant an identity access to this workspace or update its persisted role.",
        inputSchema: {
          subject: z.string().min(1).max(300),
          displayName: z.string().min(1).max(300).optional(),
          role: z.enum(["admin", "operator", "auditor", "reader"]),
        },
        annotations: { ...readOnly, readOnlyHint: false },
      },
      audited(
        "workspace_set_member",
        async (args: { subject: string; displayName?: string; role: CloudRangerRole }) => {
          await store.setWorkspaceMember({ workspaceId: deps.workspaceId!, ...args });
          return { workspaceId: deps.workspaceId, subject: args.subject, role: args.role };
        },
      ),
    );
    server.registerTool(
      "workspace_remove_member",
      {
        title: "Remove workspace member",
        description:
          "Revoke an identity's workspace access. The final administrator cannot be removed.",
        inputSchema: { subject: z.string().min(1).max(300) },
        annotations: { ...readOnly, readOnlyHint: false },
      },
      audited("workspace_remove_member", async (args: { subject: string }) => {
        await store.removeWorkspaceMember(deps.workspaceId!, args.subject);
        return { workspaceId: deps.workspaceId, subject: args.subject, removed: true };
      }),
    );
  }

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
            ...(c.deprecated ? { deprecated: c.deprecated } : {}),
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
    "catalog_control_history",
    {
      title: "Control revision history",
      description:
        "Version history of one control as recorded by this store: every (version, content hash) revision seen, when it first appeared, and whether the live catalog definition matches a recorded revision (tamper check). Findings reference controlId + controlVersion, so this links historical findings to the exact rule content they were evaluated against.",
      inputSchema: { controlId: z.string() },
      annotations: readOnly,
    },
    audited("catalog_control_history", async (args: { controlId: string }) => {
      const revisions = await store.listControlRevisions(args.controlId);
      const live = catalog.controls.find((c) => c.id === args.controlId);
      const liveHash = live ? controlContentHash(live) : undefined;
      return {
        controlId: args.controlId,
        revisions: revisions.map(({ definition: _definition, ...meta }) => meta),
        live: live
          ? {
              version: live.version,
              contentHash: liveHash,
              deprecated: live.deprecated,
              matchesRecordedRevision: revisions.some(
                (r) => r.version === live.version && r.contentHash === liveHash,
              ),
            }
          : undefined,
        note:
          revisions.length === 0
            ? "No revisions recorded yet — the server records revisions at startup."
            : undefined,
      };
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
        fixtures: z
          .array(
            z.object({
              controlId: z.string(),
              cases: z.array(z.unknown()).min(1),
            }),
          )
          .max(20)
          .optional()
          .describe(
            "Fixture entries ({ controlId, cases: [...] }) validated against the submitted controls before install — the install is rejected if any case's engine verdict disagrees with its declared expectation. Submit at least one pass and one fail case per control so it is regression-protected.",
          ),
      },
      annotations: { ...readOnly, readOnlyHint: false },
    },
    audited(
      "catalog_add_custom_control",
      async (args: { yaml: string; filename: string; fixtures?: unknown[] }) => {
        const result = validateCatalogDocument(args.yaml, catalog.collectors);
        if (result.errors.length > 0) {
          throw new Error(`validation failed: ${result.errors.join(" | ")}`);
        }

        // Validate submitted fixtures BEFORE installing anything: a custom
        // control ships regression-protected or not at all.
        const submittedIds = new Set(result.controls.map((c) => c.id));
        const fixtureFiles = (args.fixtures ?? []).map((raw) => {
          const parsed = fixtureFileSchema.safeParse(raw);
          if (!parsed.success) {
            throw new Error(
              `invalid fixture entry: ${parsed.error.issues.map((i) => `${i.path.join(".")} ${i.message}`).join("; ")}`,
            );
          }
          if (JSON.stringify(parsed.data).length > MAX_OUTPUT_BYTES) {
            throw new Error(`fixture for ${parsed.data.controlId} exceeds the evidence size limit`);
          }
          if (!submittedIds.has(parsed.data.controlId)) {
            throw new Error(
              `fixture references ${parsed.data.controlId}, which is not in this document`,
            );
          }
          return parsed.data;
        });
        if (fixtureFiles.length > 0) {
          const mergedCollectors = new Map(catalog.collectors);
          for (const collector of result.collectors) mergedCollectors.set(collector.id, collector);
          for (const fixture of fixtureFiles) {
            for (const verdict of runFixtureFile(fixture, result.controls, mergedCollectors)) {
              if (!verdict.ok) {
                throw new Error(
                  `fixture "${verdict.caseName}" for ${verdict.controlId}: expected ${verdict.expected}, engine says ${verdict.actual}${verdict.detail ? ` (${verdict.detail})` : ""} — install rejected`,
                );
              }
            }
          }
        }

        const dir = join(customCatalogDir(), "controls");
        mkdirSync(dir, { recursive: true });
        const path = join(dir, `${args.filename}.yaml`);
        writeFileSync(path, args.yaml, "utf8");
        let fixturesPath: string | undefined;
        if (fixtureFiles.length > 0) {
          const fixturesDirPath = join(customCatalogDir(), "fixtures");
          mkdirSync(fixturesDirPath, { recursive: true });
          fixturesPath = join(fixturesDirPath, `${args.filename}.json`);
          writeFileSync(fixturesPath, JSON.stringify(fixtureFiles, null, 2) + "\n", "utf8");
        }
        // Apply to the live catalog: overrides replace, new entries append.
        for (const collector of result.collectors) {
          catalog.collectors.set(collector.id, collector);
        }
        // Installed/overriding definitions become recorded revisions
        // immediately, so history captures custom updates too.
        await store.recordControlRevisions(
          result.controls.map((control) => ({
            controlId: control.id,
            version: control.version,
            contentHash: controlContentHash(control),
            definition: control,
            deprecated: Boolean(control.deprecated),
          })),
        );
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
          savedFixtures: fixturesPath,
          fixtureCases: fixtureFiles.reduce((n, f) => n + f.cases.length, 0),
          controls: result.controls.map((c) => c.id),
          collectors: result.collectors.map((c) => c.id),
          overridden,
          note: fixturesPath
            ? "Custom control is active now, and its fixtures run with: cloudranger catalog test"
            : "Custom control is active now. It has NO fixtures — resubmit with the fixtures argument (one pass + one fail case) so it is regression-protected.",
        };
      },
    ),
  );

  // ---------- compliance ----------

  server.registerTool(
    "compliance_status",
    {
      title: "Coverage-aware compliance rollup for a scope",
      description:
        "Roll the latest evaluated scan of a scope up to framework requirements. Each requirement carries an automation flag (direct = fully automated evidence, partial = needs manual assessment on top, manual = no automated evidence) and a status derived from mapped control results. Coverage ratios are only reported for frameworks whose full requirement list is vendored — this never overstates coverage and is never a certification.",
      inputSchema: {
        provider: providerParam,
        scopeId: z.string(),
        framework: z
          .string()
          .optional()
          .describe("Restrict to one framework id (see compliance registry)"),
      },
      annotations: readOnly,
    },
    audited(
      "compliance_status",
      async (args: { provider: Provider; scopeId: string; framework?: string }) => {
        if (!validateParamValue(args.scopeId)) throw new Error("invalid scopeId");
        const latest = (await store.listScans(200)).find(
          (scan) =>
            scan.status === "evaluated" &&
            scan.provider === args.provider &&
            scan.scopeId === args.scopeId,
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
          controls: catalog.controls,
          registry: loadFrameworkRegistry(),
          evaluations,
          framework: args.framework,
          provider: args.provider,
        });
        return {
          provider: args.provider,
          scopeId: args.scopeId,
          scanId: latest?.id,
          evaluatedAt: latest?.evaluatedAt,
          note: latest
            ? "Rollup reflects the latest evaluated scan only. Requirements marked partial or manual need assessment beyond CloudRanger evidence."
            : "No evaluated scan exists for this scope — every requirement is reported as not assessed. Run a scan first.",
          frameworks,
        };
      },
    ),
  );

  // ---------- retention ----------

  server.registerTool(
    "retention_policy_set",
    {
      title: "Set an evidence retention policy for a scope",
      description:
        "Persist how long raw evidence payloads are kept for one scope: keepDays (age-based) and/or keepScans (most recent N scans). Pruning never touches findings, evaluations, scan metadata, or evidence digests — only raw payloads. Omit both values to clear the policy.",
      inputSchema: {
        provider: providerParam,
        scopeId: z.string(),
        keepDays: z.number().int().min(1).max(3650).optional(),
        keepScans: z.number().int().min(1).max(1000).optional(),
      },
      annotations: { ...readOnly, readOnlyHint: false, idempotentHint: true },
    },
    audited(
      "retention_policy_set",
      async (args: {
        provider: Provider;
        scopeId: string;
        keepDays?: number;
        keepScans?: number;
      }) => {
        if (!validateParamValue(args.scopeId)) throw new Error("invalid scopeId");
        if (args.keepDays === undefined && args.keepScans === undefined) {
          await store.setRetentionPolicy(args.provider, args.scopeId, null);
          return { cleared: true };
        }
        await store.setRetentionPolicy(args.provider, args.scopeId, {
          keepDays: args.keepDays,
          keepScans: args.keepScans,
        });
        return {
          provider: args.provider,
          scopeId: args.scopeId,
          keepDays: args.keepDays,
          keepScans: args.keepScans,
        };
      },
    ),
  );

  server.registerTool(
    "retention_policy_list",
    {
      title: "List evidence retention policies",
      description: "Every persisted per-scope evidence retention policy.",
      inputSchema: {},
      annotations: readOnly,
    },
    audited("retention_policy_list", async () => ({
      policies: await store.listRetentionPolicies(),
    })),
  );

  server.registerTool(
    "evidence_prune",
    {
      title: "Prune raw evidence per the scope's retention policy",
      description:
        "Apply the scope's retention policy to raw evidence payloads. Dry run by default: reports which scans and how many records/bytes would be pruned. Destructive execution requires BOTH execute: true and confirm: true, preserves findings/evaluations/digests (hash, size, captured-at), and reclaims space afterwards.",
      inputSchema: {
        provider: providerParam,
        scopeId: z.string(),
        execute: z.boolean().optional().describe("Actually prune (default: dry run)"),
        confirm: z
          .boolean()
          .optional()
          .describe("Required alongside execute — pruned payloads cannot be recovered"),
      },
      annotations: { ...readOnly, readOnlyHint: false, destructiveHint: true },
    },
    audited(
      "evidence_prune",
      async (args: {
        provider: Provider;
        scopeId: string;
        execute?: boolean;
        confirm?: boolean;
      }) => {
        if (!validateParamValue(args.scopeId)) throw new Error("invalid scopeId");
        if (args.execute && !args.confirm) {
          throw new Error(
            "execute: true requires confirm: true — pruned payloads cannot be recovered",
          );
        }
        const result = await store.pruneEvidence({
          provider: args.provider,
          scopeId: args.scopeId,
          execute: Boolean(args.execute && args.confirm),
        });
        return {
          ...result,
          note: result.executed
            ? "Raw payloads pruned. Findings, evaluations, and evidence digests are preserved."
            : "Dry run — nothing was deleted. Re-run with execute: true and confirm: true to prune.",
        };
      },
    ),
  );

  // ---------- scope parameters ----------

  server.registerTool(
    "parameters_set",
    {
      title: "Set persisted parameter overrides for a control in a scope",
      description:
        "Persist org-tunable parameter overrides (e.g. key-age days) for one control in one scope. Values are validated against the control's declared type, bounds, and enum — overrides tune a control within its declared range, never disable it. Omit parameters (or pass {}) to clear the override. Future scans of the scope pick these up automatically.",
      inputSchema: {
        provider: providerParam,
        scopeId: z.string().describe("AWS account, Azure subscription, or GCP project ID"),
        controlId: z.string().describe("Control declaring the parameters"),
        parameters: z
          .record(z.string(), z.union([z.number(), z.string(), z.boolean()]))
          .optional()
          .describe("Parameter values to persist; omit to clear"),
      },
      annotations: { ...readOnly, readOnlyHint: false, idempotentHint: true },
    },
    audited(
      "parameters_set",
      async (args: {
        provider: Provider;
        scopeId: string;
        controlId: string;
        parameters?: Record<string, number | string | boolean>;
      }) => {
        if (!validateParamValue(args.scopeId)) throw new Error("invalid scopeId");
        const control = catalog.controls.find((c) => c.id === args.controlId);
        if (!control) throw new Error(`unknown control: ${args.controlId}`);
        if (!args.parameters || Object.keys(args.parameters).length === 0) {
          await store.setScopeParameters(args.provider, args.scopeId, args.controlId, null);
          return { cleared: true, controlId: args.controlId };
        }
        if (!control.parameters || Object.keys(control.parameters).length === 0) {
          throw new Error(`${args.controlId} does not declare any parameters`);
        }
        const issues = validateParameterOverrides(control, args.parameters);
        if (issues.length > 0) throw new Error(`invalid parameters: ${issues.join("; ")}`);
        await store.setScopeParameters(
          args.provider,
          args.scopeId,
          args.controlId,
          args.parameters,
        );
        return {
          controlId: args.controlId,
          parameters: args.parameters,
          declared: control.parameters,
        };
      },
    ),
  );

  server.registerTool(
    "parameters_list",
    {
      title: "List persisted parameter overrides for a scope",
      description:
        "Show every persisted parameter override in a scope alongside each control's declared parameters and defaults, so effective values are auditable before a scan.",
      inputSchema: {
        provider: providerParam,
        scopeId: z.string(),
      },
      annotations: readOnly,
    },
    audited("parameters_list", async (args: { provider: Provider; scopeId: string }) => {
      const overrides = await store.listScopeParameters(args.provider, args.scopeId);
      return {
        overrides: overrides.map((row) => ({
          ...row,
          declared: catalog.controls.find((c) => c.id === row.controlId)?.parameters,
        })),
        parameterisedControls: catalog.controls
          .filter(
            (c) =>
              c.provider === args.provider && c.parameters && Object.keys(c.parameters).length > 0,
          )
          .map((c) => ({ controlId: c.id, parameters: c.parameters })),
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
        includeDeprecated: z
          .boolean()
          .optional()
          .describe(
            "Include deprecated controls (excluded by default unless listed in controlIds)",
          ),
        parameters: z
          .record(z.string(), z.record(z.string(), z.union([z.number(), z.string(), z.boolean()])))
          .optional()
          .describe(
            "Per-control parameter overrides for this scan (controlId → name → value); merged over persisted scope parameters and validated against each control's declarations",
          ),
      },
      annotations: { ...readOnly, readOnlyHint: false },
    },
    audited(
      "scan_start",
      async (args: {
        provider: Provider;
        scopeId: string;
        regions?: string[];
        services?: string[];
        controlIds?: string[];
        pack?: string;
        includeDeprecated?: boolean;
        parameters?: Record<string, Record<string, unknown>>;
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
        // Deprecated controls are excluded unless explicitly requested —
        // either via includeDeprecated or by naming them in controlIds.
        const explicit = new Set(args.controlIds ?? []);
        const deprecatedExcluded = args.includeDeprecated
          ? []
          : controls.filter((c) => c.deprecated && !explicit.has(c.id)).map((c) => c.id);
        if (deprecatedExcluded.length > 0) {
          controls = controls.filter((c) => !deprecatedExcluded.includes(c.id));
        }
        if (controls.length === 0) throw new Error("no controls match the requested filters");

        // Effective parameters: persisted scope overrides ⊕ per-scan overrides
        // (scan wins per key), validated against each control's declarations.
        const persisted = await store.listScopeParameters(args.provider, args.scopeId);
        const merged: Record<string, Record<string, unknown>> = {};
        for (const row of persisted) merged[row.controlId] = { ...row.parameters };
        for (const [controlId, overrides] of Object.entries(args.parameters ?? {})) {
          merged[controlId] = { ...merged[controlId], ...overrides };
        }
        const inScan = new Set(controls.map((c) => c.id));
        const parameters: Record<string, Record<string, unknown>> = {};
        for (const [controlId, overrides] of Object.entries(merged)) {
          if (!inScan.has(controlId)) {
            // Persisted overrides for controls outside this scan are ignored;
            // explicit per-scan overrides for unknown controls are an error.
            if (args.parameters?.[controlId]) {
              throw new Error(
                `parameter overrides reference a control not in this scan: ${controlId}`,
              );
            }
            continue;
          }
          const control = controls.find((c) => c.id === controlId)!;
          const issues = validateParameterOverrides(control, overrides);
          if (issues.length > 0) {
            throw new Error(`invalid parameters for ${controlId}: ${issues.join("; ")}`);
          }
          parameters[controlId] = overrides;
        }

        const plan = buildPlan(controls, catalog.collectors, {
          provider: args.provider,
          regions,
          scopeId: args.scopeId,
        });
        const scan = await store.createScan({
          provider: args.provider,
          scopeId: args.scopeId,
          regions,
          controlIds: plan.controlIds,
          parameters,
        });
        return {
          scanId: scan.id,
          controlCount: plan.controlIds.length,
          parameters: Object.keys(parameters).length > 0 ? parameters : undefined,
          ...(deprecatedExcluded.length > 0
            ? {
                deprecatedExcluded,
                deprecationNote:
                  "Deprecated controls were excluded. Pass includeDeprecated: true or list them in controlIds to scan them anyway.",
              }
            : {}),
          plan,
        };
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
    audited("scan_get_plan", async (args: { scanId: string }) => {
      const scan = await store.getScan(args.scanId);
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
    "scan_resume",
    {
      title: "Resume an incomplete scan",
      description:
        "Rebuild a collecting scan plan from persisted evidence and return only collector steps that are missing or have no successful result.",
      inputSchema: { scanId: z.string() },
      annotations: readOnly,
    },
    audited("scan_resume", async (args: { scanId: string }) => {
      const scan = await store.getScan(args.scanId);
      if (!scan) throw new Error(`unknown scan: ${args.scanId}`);
      if (scan.status !== "collecting") {
        throw new Error(`scan ${scan.id} is ${scan.status}; only collecting scans can resume`);
      }
      const controls = catalog.controls.filter((control) => scan.controlIds.includes(control.id));
      const plan = buildPlan(controls, catalog.collectors, {
        provider: scan.provider,
        regions: scan.regions,
        scopeId: scan.scopeId,
      });
      const evidence = await store.getEvidence(scan.id);
      const pendingSteps = plan.steps
        .filter(
          (step) =>
            !evidence.some(
              (record) =>
                record.collectorId === step.collectorId &&
                record.region === step.region &&
                record.exitCode === 0,
            ),
        )
        .map((step) => ({
          ...step,
          failedResourceKeys: evidence
            .filter(
              (record) =>
                record.collectorId === step.collectorId &&
                record.region === step.region &&
                record.exitCode !== 0 &&
                record.resourceKey,
            )
            .map((record) => record.resourceKey),
        }));
      return {
        scanId: scan.id,
        persistedEvidenceRecords: evidence.length,
        completedSteps: plan.steps.length - pendingSteps.length,
        pendingSteps,
        instructions: plan.instructions,
      };
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
      async (args: {
        scanId: string;
        records: Array<{
          collectorId: string;
          region?: string;
          resourceKey?: string;
          output?: unknown;
          errorText?: string;
          exitCode: number;
        }>;
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
        const accepted = await store.addEvidence(
          args.scanId,
          args.records.map((r) => ({ ...r, output: r.output ?? null })),
        );
        return { accepted, stats: await store.evidenceStats(args.scanId) };
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
    audited("scan_evaluate", async (args: { scanId: string }) => {
      const scan = await store.getScan(args.scanId);
      if (!scan) throw new Error(`unknown scan: ${args.scanId}`);
      if (scan.status === "evaluated") {
        return {
          scanId: scan.id,
          alreadyEvaluated: true,
          summary: scan.summary,
          coverage: scan.coverage,
          health: await store.scanHealth(scan.id, 60, expectedCollectorsForScan(scan)),
        };
      }
      if (scan.status === "cancelled") throw new Error("scan is cancelled");
      const evidence = await store.getEvidence(args.scanId);
      const { results, coverage } = evaluateControls(
        catalog.controls,
        catalog.collectors,
        { provider: scan.provider, scopeId: scan.scopeId, records: evidence },
        { controlIds: scan.controlIds, parameters: scan.parameters },
      );
      const summary = await store.finalizeScan(args.scanId, results, coverage);
      const gaps = coverage.filter((c) => c.status !== "evaluated");
      const previous = (await store.listScans(100)).find(
        (candidate) =>
          candidate.id !== scan.id &&
          candidate.status === "evaluated" &&
          candidate.provider === scan.provider &&
          candidate.scopeId === scan.scopeId,
      );
      const notifications = previous
        ? await createNotificationSender()(await store.compareScans(previous.id, scan.id))
        : { enabled: [], sent: [], deduplicated: [], errors: [] };
      for (const channel of notifications.sent) {
        await store.audit({
          actor: actor(),
          tool: "notification_delivery",
          args: { scanId: scan.id, channel },
          success: true,
        });
      }
      for (const delivery of notifications.errors) {
        await store.audit({
          actor: actor(),
          tool: "notification_delivery",
          args: { scanId: scan.id, channel: delivery.channel },
          success: false,
          detail: delivery.error,
        });
      }
      const health = await store.scanHealth(scan.id, 60, expectedCollectorsForScan(scan));
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
        notifications,
        health,
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
    audited("scan_status", async (args: { scanId: string }) => {
      const scan = await store.getScan(args.scanId);
      if (!scan) throw new Error(`unknown scan: ${args.scanId}`);
      return {
        scan,
        health: await store.scanHealth(scan.id, 60, expectedCollectorsForScan(scan)),
        evidenceStats: await store.evidenceStats(args.scanId),
      };
    }),
  );

  server.registerTool(
    "scan_health",
    {
      title: "Check scan health and completeness",
      description:
        "Reports whether a scan is complete and trustworthy, including missing evidence, failed collectors, coverage, and staleness.",
      inputSchema: {
        scanId: z.string(),
        staleAfterMinutes: z.number().int().min(1).max(10080).optional(),
      },
      annotations: readOnly,
    },
    audited("scan_health", async (args: { scanId: string; staleAfterMinutes?: number }) => {
      const scan = await store.getScan(args.scanId);
      return store.scanHealth(args.scanId, args.staleAfterMinutes, expectedCollectorsForScan(scan));
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
    audited("scan_list", async (args: { limit?: number }) => ({
      scans: await store.listScans(args.limit ?? 20),
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
    audited("scan_cancel", async (args: { scanId: string }) => {
      await store.cancelScan(args.scanId);
      return { scanId: args.scanId, status: (await store.getScan(args.scanId))?.status };
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
        owner: z.string().optional(),
        overdue: z.boolean().optional(),
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
    audited("findings_get", async (args: { fingerprint: string }) => {
      const finding = await store.getFinding(args.fingerprint);
      if (!finding) throw new Error(`unknown finding: ${args.fingerprint}`);
      const control = catalog.controls.find((c) => c.id === finding.controlId);
      return {
        finding,
        history: await store.getFindingEvents(args.fingerprint),
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
    "findings_assign",
    {
      title: "Assign finding ownership and due date",
      description:
        "Assign an owner/team and optional remediation due date. Assignment is recorded in finding history.",
      inputSchema: {
        fingerprint: z.string(),
        owner: z.string().min(1).max(300),
        dueAt: z.string().optional().describe("ISO timestamp for the remediation due date"),
      },
      annotations: { ...readOnly, readOnlyHint: false },
    },
    audited("findings_assign", (args: { fingerprint: string; owner: string; dueAt?: string }) =>
      store.assignFinding(args.fingerprint, {
        owner: args.owner,
        dueAt: args.dueAt,
        actor: actor(),
      }),
    ),
  );

  server.registerTool(
    "findings_expire_workflows",
    {
      title: "Expire overdue exceptions",
      description:
        "Return expired risk acceptances and false-positive decisions to new for review.",
      inputSchema: {},
      annotations: { ...readOnly, readOnlyHint: false },
    },
    audited("findings_expire_workflows", async () => ({
      expired: await store.expireWorkflowStates(),
    })),
  );

  server.registerTool(
    "findings_comment",
    {
      title: "Comment on a finding",
      description: "Append an investigation note to a finding's history.",
      inputSchema: { fingerprint: z.string(), comment: z.string().max(5000) },
      annotations: { ...readOnly, readOnlyHint: false },
    },
    audited("findings_comment", async (args: { fingerprint: string; comment: string }) => {
      await store.addFindingComment(args.fingerprint, args.comment, actor());
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
        scopeIds: z
          .array(z.string())
          .min(1)
          .max(20)
          .optional()
          .describe("Multi-scope digest: aggregate + per-scope breakdown for these scopes"),
        allScopes: z
          .boolean()
          .optional()
          .describe("Multi-scope digest across every scope that has scans in this database"),
        sinceDays: z.number().int().min(1).max(365).optional(),
      },
      annotations: readOnly,
    },
    audited(
      "report_data",
      async (args: {
        provider?: Provider;
        scopeId?: string;
        scopeIds?: string[];
        allScopes?: boolean;
        sinceDays?: number;
      }) => {
        if ((args.scopeIds || args.allScopes) && args.scopeId) {
          throw new Error("scopeId cannot be combined with scopeIds/allScopes");
        }
        if (args.scopeIds || args.allScopes) {
          // Multi-scope digest: per-scope breakdown plus an aggregate. Every
          // scope with scans in this (workspace-isolated) database is
          // visible; scopes present but not requested are listed, never
          // silently dropped.
          const known = new Map<string, { provider: Provider; scopeId: string }>();
          for (const scan of await store.listScans(200)) {
            if (args.provider && scan.provider !== args.provider) continue;
            known.set(`${scan.provider}/${scan.scopeId}`, {
              provider: scan.provider,
              scopeId: scan.scopeId,
            });
          }
          const wanted = args.allScopes
            ? [...known.values()]
            : [...known.values()].filter((s) => args.scopeIds!.includes(s.scopeId));
          const missing = args.scopeIds?.filter(
            (id) => ![...known.values()].some((s) => s.scopeId === id),
          );
          const notIncluded = [...known.values()]
            .filter((s) => !wanted.includes(s))
            .map((s) => `${s.provider}/${s.scopeId}`);
          const severityTotals: Record<string, number> = {};
          const controlTotals = new Map<string, { severity: string; count: number }>();
          const totals = {
            newFindingsInWindow: 0,
            resolvedFindingsInWindow: 0,
            currentlyReopened: 0,
            riskAccepted: 0,
            overdueFindings: 0,
            unassignedOpenFindings: 0,
          };
          const scopes = [];
          for (const scope of wanted) {
            const digest = (await store.reportData({
              provider: scope.provider,
              scopeId: scope.scopeId,
              sinceDays: args.sinceDays,
            })) as Record<string, any>;
            for (const [severity, count] of Object.entries(
              digest.openFindingsBySeverity as Record<string, number>,
            )) {
              severityTotals[severity] = (severityTotals[severity] ?? 0) + count;
            }
            for (const control of digest.topFailingControls as Array<{
              controlId: string;
              severity: string;
              count: number;
            }>) {
              const entry = controlTotals.get(control.controlId) ?? {
                severity: control.severity,
                count: 0,
              };
              entry.count += control.count;
              controlTotals.set(control.controlId, entry);
            }
            for (const key of Object.keys(totals) as Array<keyof typeof totals>) {
              totals[key] += (digest[key] as number) ?? 0;
            }
            const latestScan = (digest.recentScans as any[]).find(
              (scan) => scan.status === "evaluated",
            );
            scopes.push({
              provider: scope.provider,
              scopeId: scope.scopeId,
              openFindingsBySeverity: digest.openFindingsBySeverity,
              newFindingsInWindow: digest.newFindingsInWindow,
              resolvedFindingsInWindow: digest.resolvedFindingsInWindow,
              currentlyReopened: digest.currentlyReopened,
              riskAccepted: digest.riskAccepted,
              overdueFindings: digest.overdueFindings,
              unassignedOpenFindings: digest.unassignedOpenFindings,
              topFailingControls: (digest.topFailingControls as any[]).slice(0, 5),
              latestEvaluatedScan: latestScan
                ? {
                    id: latestScan.id,
                    evaluatedAt: latestScan.evaluatedAt,
                    coverageRatio: latestScan.summary?.coverageRatio,
                  }
                : undefined,
            });
          }
          return {
            generatedAt: new Date().toISOString(),
            windowDays: args.sinceDays ?? 30,
            multiScope: true,
            aggregate: {
              openFindingsBySeverity: severityTotals,
              topFailingControls: [...controlTotals.entries()]
                .map(([controlId, entry]) => ({ controlId, ...entry }))
                .sort((a, b) => b.count - a.count)
                .slice(0, 15),
              ...totals,
            },
            scopes,
            ...(missing && missing.length > 0 ? { requestedButNoScans: missing } : {}),
            ...(notIncluded.length > 0 ? { scopesPresentButNotIncluded: notIncluded } : {}),
            note: "Aggregate is the sum of per-scope digests; findings are never deduplicated across scopes.",
          };
        }
        const report = (await store.reportData(args)) as Record<string, unknown>;
        const findings = await store.searchFindings({
          provider: args.provider,
          scopeId: args.scopeId,
          state: ["open", "reopened"],
          limit: 200,
        });
        const frameworks = new Map<string, { findings: number; controls: Set<string> }>();
        for (const finding of findings.findings) {
          const control = catalog.controls.find((item) => item.id === finding.controlId);
          for (const mapping of control?.compliance ?? []) {
            const key = `${mapping.framework}${mapping.version ? ` ${mapping.version}` : ""}`;
            const entry = frameworks.get(key) ?? { findings: 0, controls: new Set<string>() };
            entry.findings += 1;
            entry.controls.add(finding.controlId);
            frameworks.set(key, entry);
          }
        }
        return {
          ...report,
          complianceSummary: [...frameworks.entries()]
            .map(([framework, entry]) => ({
              framework,
              openFindings: entry.findings,
              failingControls: entry.controls.size,
            }))
            .sort(
              (a, b) => b.openFindings - a.openFindings || a.framework.localeCompare(b.framework),
            ),
        };
      },
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
    audited("audit_search", async (args: { limit?: number }) => ({
      entries: await store.searchAudit(args.limit ?? 50),
      chainIntact: (await store.verifyAuditChain()) === null,
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

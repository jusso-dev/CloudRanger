/**
 * Core engine types.
 *
 * The engine is pure: it takes a control catalog plus collected evidence
 * (raw JSON output from read-only cloud CLI commands executed by the agent)
 * and produces deterministic per-resource evaluation results. It performs
 * no I/O and never touches cloud credentials.
 */

export type Provider = "aws" | "azure" | "gcp";

export type Severity = "informational" | "low" | "medium" | "high" | "critical";

/** Technical outcome of evaluating one control against one resource. */
export type EvaluationStatus = "pass" | "fail" | "not_applicable" | "error" | "not_assessed";

/** Lifecycle state of a persisted finding (technical dimension). */
export type FindingState = "open" | "resolved" | "reopened";

/** Workflow state, managed by humans/agents on top of the technical state. */
export type WorkflowState =
  "new" | "acknowledged" | "in_progress" | "risk_accepted" | "false_positive" | "closed";

/** How a collector's evidence is shaped. */
export type CollectorKind = "single" | "per_resource";

/**
 * Declarative post-processing the engine applies to a record's parsed JSON
 * output before evaluation. base64Csv: `contentPath` selects a base64-encoded
 * CSV string (header row required); the decoded rows — one object per row,
 * keyed by header names — replace the output. Raw output is what gets
 * persisted; decoding happens only on the evaluation path.
 */
export interface EvidenceDecode {
  type: "base64Csv";
  contentPath: string;
}

export interface CollectorDefinition {
  /** Stable ID, e.g. "aws.s3.list_buckets". */
  id: string;
  provider: Provider;
  service: string;
  description: string;
  kind: CollectorKind;
  /**
   * The exact read-only CLI command the agent must run. May contain
   * placeholders: {region} (regional collectors), {resource} (per_resource
   * collectors, substituted per parent item), and {account} where needed.
   * Must satisfy the read-only verb allowlist (see safety.ts).
   */
  command: string;
  /** Whether the command must be run once per enabled region. */
  regional: boolean;
  /**
   * For per_resource collectors: the collector whose output enumerates the
   * resources to iterate, and the path (within that output) to the array of
   * items plus the field used as {resource}.
   */
  parent?: {
    collector: string;
    itemsPath: string;
    resourceField: string;
  };
  /** Output format produced by the command. Only JSON is evaluated. */
  outputFormat: "json";
  /** Engine-side decoding applied to the output before evaluation. */
  decode?: EvidenceDecode;
  /**
   * Optional idempotent preparation command the agent runs once before the
   * main command, ignoring its output (e.g. `aws iam generate-credential-report`
   * before `get-credential-report`). Must be on the exact-match preparation
   * allowlist (see safety.ts) — the read-only verb rules alone do not admit it.
   */
  prepareCommand?: string;
  /** Maximum wall-clock time for one attempt. */
  timeoutMs?: number;
  /** Maximum number of attempts for transient provider failures. */
  maxAttempts?: number;
  /** Initial retry delay; subsequent delays use exponential backoff. */
  initialBackoffMs?: number;
  /** Upper bound for exponential retry delay. */
  maxBackoffMs?: number;
  /** Maximum operations from this collector allowed in flight. */
  maxConcurrency?: number;
  /** Human notes: permissions required, quirks, cost warnings. */
  notes?: string;
}

/** One unit of submitted evidence. */
export interface EvidenceRecord {
  collectorId: string;
  /** Region the command ran in, if regional. */
  region?: string;
  /** For per_resource collectors: the resource identifier iterated over. */
  resourceKey?: string;
  /** Parsed JSON output of the command; null when the command errored. */
  output: unknown;
  /** Raw stderr / error text when the command failed. */
  errorText?: string;
  /** CLI exit code. 0 = success. */
  exitCode: number;
  collectedAt: string;
}

/** All evidence gathered for one scan, indexed for evaluation. */
export interface EvidenceBundle {
  provider: Provider;
  /** Account / subscription / project identifier the scan targeted. */
  scopeId: string;
  records: EvidenceRecord[];
}

export interface ComplianceMapping {
  framework: string;
  version?: string;
  controls: string[];
}

/** Attribution to the upstream open-source engine a control was ported from. */
export interface ControlSource {
  engine: "prowler" | "trivy" | "steampipe" | "custom";
  /** Upstream check identifier, e.g. "s3_bucket_public_access_block". */
  id: string;
  license: string;
}

/**
 * Org-tunable parameter declared by a control. Rules reference parameters
 * with `{ $param: "name" }` in value positions; the engine substitutes the
 * effective value (declaration default, overridden per scope/scan) before
 * evaluation. No expressions — typed value substitution only.
 */
export interface ParameterDeclaration {
  type: "number" | "string" | "boolean";
  description: string;
  default: number | string | boolean;
  /** Inclusive bounds, numbers only. */
  min?: number;
  max?: number;
  /** Allowed values; when present, overrides and default must be members. */
  enum?: Array<number | string>;
}

/** Reference to a declared parameter inside an expression value position. */
export interface ParamRef {
  $param: string;
}

export interface ErrorMatchRule {
  /** Substring matched against the collector errorText. */
  contains: string;
  status: Extract<EvaluationStatus, "pass" | "fail" | "not_applicable" | "error">;
  message?: string;
}

export interface ControlDefinition {
  /** Stable CloudRanger ID, e.g. "CR-AWS-S3-001". */
  id: string;
  version: string;
  provider: Provider;
  service: string;
  title: string;
  description: string;
  rationale: string;
  severity: Severity;
  categories: string[];
  source: ControlSource;
  /** Collector this control evaluates. */
  collector: string;
  /** Additional evidence collectors injected beneath `related` for aggregate controls. */
  relatedCollectors?: Array<{ collector: string; as: string }>;
  /**
   * Path within the collector output to the array of resources to evaluate.
   * Omitted for per_resource collectors (each evidence record is a resource)
   * and for account-level single-object checks (use "$" for whole output).
   */
  resourcesPath?: string;
  /**
   * Account/subscription/project-level aggregate check: treat the whole
   * collector output as ONE resource unit (do not split a top-level array),
   * so passWhen can quantify over the entire inventory with
   * anyItem/noneItem/allItems. Pair with resourceIdField "$scope". Ignored for
   * per_resource collectors. Default: false.
   */
  aggregate?: boolean;
  /** Path (relative to a resource) of the field used as the resource ID. */
  resourceIdField: string;
  /** Optional name field for display. */
  resourceNameField?: string;
  /**
   * Org-tunable thresholds referenced by applicableWhen/passWhen via
   * `{ $param: name }`. Defaults must reproduce the control's documented
   * behaviour; scope- or scan-level overrides are validated against the
   * declaration and recorded on findings.
   */
  parameters?: Record<string, ParameterDeclaration>;
  /** Expression: resource is in scope for this control. Default: always. */
  applicableWhen?: Expression;
  /** Expression: resource passes the control. */
  passWhen: Expression;
  /** Map collector command errors to statuses (e.g. missing config = fail). */
  onError?: ErrorMatchRule[];
  failMessage: string;
  passMessage: string;
  remediation: {
    summary: string;
    steps: string[];
    /** Read-only-safe validation command the agent may run to re-check. */
    verifyCommand?: string;
  };
  compliance: ComplianceMapping[];
  references: string[];
  /**
   * Deprecation notice. Deprecated controls are excluded from scans unless
   * explicitly requested; history stays queryable via control revisions.
   */
  deprecated?: {
    reason: string;
    /** Control that replaces this one, when there is one. */
    supersededBy?: string;
  };
}

/** Safe declarative expression AST. No eval, no arbitrary code. */
export type Expression =
  | { op: "equals"; path: string; value: unknown }
  | { op: "notEquals"; path: string; value: unknown }
  | { op: "exists"; path: string }
  | { op: "notExists"; path: string }
  | { op: "in"; path: string; values: unknown[] }
  | { op: "notIn"; path: string; values: unknown[] }
  | { op: "contains"; path: string; value: string }
  | { op: "notContains"; path: string; value: string }
  | { op: "startsWith"; path: string; value: string }
  | { op: "endsWith"; path: string; value: string }
  | { op: "gt"; path: string; value: number | ParamRef }
  | { op: "gte"; path: string; value: number | ParamRef }
  | { op: "lt"; path: string; value: number | ParamRef }
  | { op: "lte"; path: string; value: number | ParamRef }
  | { op: "daysSinceGt"; path: string; value: number | ParamRef }
  | { op: "daysSinceLt"; path: string; value: number | ParamRef }
  | { op: "matches"; path: string; pattern: string }
  | { op: "lengthEquals"; path: string; value: number | ParamRef }
  | { op: "lengthGt"; path: string; value: number | ParamRef }
  | { op: "isEmpty"; path: string }
  | { op: "isPublicCidr"; path: string }
  | { op: "portIncludes"; fromPath: string; toPath: string; value: number }
  | { op: "portStringIncludes"; path: string; value: number }
  | { op: "and"; exprs: Expression[] }
  | { op: "or"; exprs: Expression[] }
  | { op: "not"; expr: Expression }
  | { op: "anyItem"; path: string; condition: Expression }
  | { op: "allItems"; path: string; condition: Expression }
  | { op: "noneItem"; path: string; condition: Expression }
  | {
      op: "anyItemReferencedBy";
      itemsPath: string;
      itemCondition: Expression;
      itemValuePath: string;
      relatedPath: string;
    }
  | {
      /**
       * Declarative cross-resource join. True when any item at itemsPath
       * (supports "[]." flattening, typically under `related.<as>`) whose
       * foreignPath value equals a local key also satisfies `condition`.
       * Local keys come from localPath on the current resource; when that
       * resolves to an array of objects, localItemPath extracts the key
       * field from each. Key equality only — no expressions over keys.
       */
      op: "relationshipExists";
      itemsPath: string;
      localPath: string;
      localItemPath?: string;
      foreignPath: string;
      condition?: Expression;
    };

/** Result of evaluating one control against one resource. */
export interface EvaluationResult {
  controlId: string;
  controlVersion: string;
  provider: Provider;
  service: string;
  severity: Severity;
  status: EvaluationStatus;
  resourceId: string;
  resourceName?: string;
  region?: string;
  message: string;
  /** Values that determined the outcome, extracted from evidence. */
  evidence: unknown;
  /** Effective parameter values used, for controls that declare parameters. */
  effectiveParameters?: Record<string, number | string | boolean>;
  evaluatedAt: string;
}

export interface ControlCoverage {
  controlId: string;
  status: "evaluated" | "missing_evidence" | "evidence_error";
  missingCollectors: string[];
}

export interface EvaluationSummary {
  results: EvaluationResult[];
  coverage: ControlCoverage[];
  /** evaluated controls / requested controls */
  coverageRatio: number;
}

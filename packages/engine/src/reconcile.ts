import type { EvaluationResult, FindingState } from "./types.js";
import { findingFingerprint } from "./fingerprint.js";

/**
 * Pure reconciliation logic: given the prior persisted finding (if any) and a
 * fresh evaluation result, decide what should happen. Persistence lives in
 * @cloudranger/db; this module owns the state machine so it is testable
 * without a database.
 */

export interface PriorFinding {
  fingerprint: string;
  state: FindingState;
  occurrenceCount: number;
  reopenCount: number;
}

export type ReconcileActionType =
  | "create" // first failure ever seen
  | "recur" // still failing: bump last_seen + occurrence
  | "resolve" // was failing, now passes
  | "reopen" // was resolved, failing again
  | "none"; // passing and no open finding, or non-definitive status

export interface ReconcileAction {
  type: ReconcileActionType;
  fingerprint: string;
  result: EvaluationResult;
}

/**
 * Only definitive statuses drive lifecycle transitions. error / not_assessed
 * / not_applicable never resolve an open finding — absence of evidence is
 * not evidence of remediation.
 */
export function reconcileOne(
  scopeId: string,
  result: EvaluationResult,
  prior: PriorFinding | undefined,
): ReconcileAction {
  const fingerprint = findingFingerprint({
    provider: result.provider,
    scopeId,
    controlId: result.controlId,
    resourceId: result.resourceId,
    region: result.region,
  });

  if (result.status === "fail") {
    if (!prior) return { type: "create", fingerprint, result };
    if (prior.state === "resolved") return { type: "reopen", fingerprint, result };
    return { type: "recur", fingerprint, result };
  }

  if (result.status === "pass") {
    if (prior && prior.state !== "resolved") return { type: "resolve", fingerprint, result };
    return { type: "none", fingerprint, result };
  }

  // error / not_applicable / not_assessed: leave any existing finding as-is.
  return { type: "none", fingerprint, result };
}

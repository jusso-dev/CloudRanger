import { createHash } from "node:crypto";
import type { Provider } from "./types.js";

/**
 * Stable finding identity. Excludes scan IDs, timestamps and mutable state
 * so the same misconfiguration maps to the same finding across scans.
 */
export function findingFingerprint(input: {
  provider: Provider;
  scopeId: string;
  controlId: string;
  resourceId: string;
  region?: string;
}): string {
  const canonical = [
    input.provider,
    input.scopeId,
    input.controlId,
    input.resourceId,
    input.region ?? "global",
  ].join("|");
  return createHash("sha256").update(canonical).digest("hex");
}

/** Hash of raw evidence for tamper-evident storage. */
export function evidenceHash(evidence: unknown): string {
  return createHash("sha256").update(stableStringify(evidence)).digest("hex");
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const keys = Object.keys(value as object).sort();
  const parts = keys.map(
    (k) => `${JSON.stringify(k)}:${stableStringify((value as Record<string, unknown>)[k])}`,
  );
  return `{${parts.join(",")}}`;
}

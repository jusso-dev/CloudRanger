import type { Expression } from "./types.js";
import { getPath } from "./path.js";

const MAX_REGEX_LENGTH = 200;

/**
 * Reject regex constructs that enable catastrophic backtracking or
 * backreferences. Conservative: nested quantifiers and backrefs are refused.
 */
export function isSafeRegex(pattern: string): boolean {
  if (pattern.length > MAX_REGEX_LENGTH) return false;
  if (/\\[1-9]/.test(pattern)) return false; // backreferences
  if (/(\+|\*|\{\d+,?\d*\})\s*(\+|\*|\{\d+,?\d*\})/.test(pattern)) return false;
  if (/\([^)]*(\+|\*)[^)]*\)\s*(\+|\*|\{)/.test(pattern)) return false; // (a+)+ style
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}

function isPublicCidr(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const v = value.trim().toLowerCase();
  return (
    v === "0.0.0.0/0" ||
    v === "::/0" ||
    v === "*" ||
    v === "any" ||
    v === "internet" ||
    v === "0.0.0.0" ||
    v === "<nw>/0"
  );
}

function daysSince(value: unknown, now: Date): number | undefined {
  if (typeof value !== "string" && typeof value !== "number") return undefined;
  const t = new Date(value).getTime();
  if (Number.isNaN(t)) return undefined;
  return (now.getTime() - t) / 86_400_000;
}

function containsString(value: unknown, needle: string): boolean {
  if (typeof value === "string") return value.includes(needle);
  if (Array.isArray(value)) return value.some((item) => containsString(item, needle));
  if (value && typeof value === "object")
    return Object.values(value as Record<string, unknown>).some((item) =>
      containsString(item, needle),
    );
  return false;
}

function looselyEquals(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  // CLI JSON frequently stringifies booleans/numbers; compare canonically.
  if (typeof a === "string" && typeof b === "boolean") return a.toLowerCase() === String(b);
  if (typeof b === "string" && typeof a === "boolean") return b.toLowerCase() === String(a);
  if (typeof a === "string" && typeof b === "number") return Number(a) === b;
  if (typeof b === "string" && typeof a === "number") return Number(b) === a;
  return false;
}

export interface ExprContext {
  /** Injected clock so evaluations are reproducible in tests. */
  now: Date;
}

/**
 * Evaluate an expression against a resource object. Returns a boolean —
 * missing data makes predicates false (never true), so absent evidence can
 * never satisfy a "pass" condition by accident. Controls that must treat
 * absence as failure express that with exists/notExists explicitly.
 */
export function evaluateExpression(expr: Expression, resource: unknown, ctx: ExprContext): boolean {
  switch (expr.op) {
    case "equals":
      return looselyEquals(getPath(resource, expr.path), expr.value);
    case "notEquals": {
      const v = getPath(resource, expr.path);
      return v !== undefined && !looselyEquals(v, expr.value);
    }
    case "exists":
      return getPath(resource, expr.path) !== undefined && getPath(resource, expr.path) !== null;
    case "notExists": {
      const v = getPath(resource, expr.path);
      return v === undefined || v === null;
    }
    case "in": {
      const v = getPath(resource, expr.path);
      return expr.values.some((candidate) => looselyEquals(v, candidate));
    }
    case "notIn": {
      const v = getPath(resource, expr.path);
      return v !== undefined && !expr.values.some((candidate) => looselyEquals(v, candidate));
    }
    case "contains": {
      const v = getPath(resource, expr.path);
      if (typeof v === "string") return v.includes(expr.value);
      if (Array.isArray(v)) return v.some((item) => looselyEquals(item, expr.value));
      return false;
    }
    case "notContains": {
      const v = getPath(resource, expr.path);
      if (typeof v === "string") return !v.includes(expr.value);
      if (Array.isArray(v)) return !v.some((item) => looselyEquals(item, expr.value));
      return false;
    }
    case "startsWith": {
      const v = getPath(resource, expr.path);
      return typeof v === "string" && v.startsWith(expr.value);
    }
    case "endsWith": {
      const v = getPath(resource, expr.path);
      return typeof v === "string" && v.endsWith(expr.value);
    }
    case "gt":
    case "gte":
    case "lt":
    case "lte": {
      const raw = getPath(resource, expr.path);
      const n = typeof raw === "string" ? Number(raw) : raw;
      if (typeof n !== "number" || Number.isNaN(n)) return false;
      if (expr.op === "gt") return n > expr.value;
      if (expr.op === "gte") return n >= expr.value;
      if (expr.op === "lt") return n < expr.value;
      return n <= expr.value;
    }
    case "daysSinceGt": {
      const d = daysSince(getPath(resource, expr.path), ctx.now);
      return d !== undefined && d > expr.value;
    }
    case "daysSinceLt": {
      const d = daysSince(getPath(resource, expr.path), ctx.now);
      return d !== undefined && d < expr.value;
    }
    case "matches": {
      const v = getPath(resource, expr.path);
      if (typeof v !== "string") return false;
      if (!isSafeRegex(expr.pattern)) return false;
      return new RegExp(expr.pattern).test(v);
    }
    case "lengthEquals": {
      const v = getPath(resource, expr.path);
      if (Array.isArray(v) || typeof v === "string") return v.length === expr.value;
      return false;
    }
    case "lengthGt": {
      const v = getPath(resource, expr.path);
      if (Array.isArray(v) || typeof v === "string") return v.length > expr.value;
      return false;
    }
    case "isEmpty": {
      const v = getPath(resource, expr.path);
      if (v === undefined || v === null) return true;
      if (Array.isArray(v) || typeof v === "string") return v.length === 0;
      if (typeof v === "object") return Object.keys(v as object).length === 0;
      return false;
    }
    case "isPublicCidr":
      return isPublicCidr(getPath(resource, expr.path));
    case "portIncludes": {
      const fromRaw = getPath(resource, expr.fromPath);
      const toRaw = getPath(resource, expr.toPath);
      const from = typeof fromRaw === "string" ? Number(fromRaw) : fromRaw;
      const to = typeof toRaw === "string" ? Number(toRaw) : toRaw;
      // AWS: absent FromPort/ToPort means all ports. Azure/GCP: "*" or "0-65535".
      if (fromRaw === undefined && toRaw === undefined) return true;
      if (fromRaw === "*" || toRaw === "*") return true;
      if (typeof from !== "number" || typeof to !== "number") return false;
      if (Number.isNaN(from) || Number.isNaN(to)) return false;
      if (from === -1 || to === -1) return true; // AWS "all traffic"
      return expr.value >= from && expr.value <= to;
    }
    case "portStringIncludes": {
      // Azure/GCP style port fields: "22", "20-25", "*", 22, or arrays thereof.
      const v = getPath(resource, expr.path);
      const candidates = Array.isArray(v) ? v : [v];
      for (const candidate of candidates) {
        if (candidate === "*") return true;
        const s = typeof candidate === "number" ? String(candidate) : candidate;
        if (typeof s !== "string" || s.length === 0) continue;
        const range = s.match(/^(\d+)-(\d+)$/);
        if (range) {
          if (expr.value >= Number(range[1]) && expr.value <= Number(range[2])) return true;
        } else if (/^\d+$/.test(s) && Number(s) === expr.value) {
          return true;
        }
      }
      return false;
    }
    case "and":
      return expr.exprs.every((e) => evaluateExpression(e, resource, ctx));
    case "or":
      return expr.exprs.some((e) => evaluateExpression(e, resource, ctx));
    case "not":
      return !evaluateExpression(expr.expr, resource, ctx);
    case "anyItem": {
      const v = getPath(resource, expr.path);
      if (!Array.isArray(v)) return false;
      return v.some((item) => evaluateExpression(expr.condition, item, ctx));
    }
    case "allItems": {
      const v = getPath(resource, expr.path);
      if (!Array.isArray(v)) return false;
      return v.every((item) => evaluateExpression(expr.condition, item, ctx));
    }
    case "noneItem": {
      const v = getPath(resource, expr.path);
      if (!Array.isArray(v)) return true;
      return !v.some((item) => evaluateExpression(expr.condition, item, ctx));
    }
    case "anyItemReferencedBy": {
      const items = getPath(resource, expr.itemsPath);
      const related = getPath(resource, expr.relatedPath);
      if (!Array.isArray(items) || related === undefined || related === null) return false;
      return items.some((item) => {
        if (!evaluateExpression(expr.itemCondition, item, ctx)) return false;
        const value = getPath(item, expr.itemValuePath);
        return typeof value === "string" && value.length > 0 && containsString(related, value);
      });
    }
  }
}

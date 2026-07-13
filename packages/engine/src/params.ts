import type { ControlDefinition, Expression, ParamRef, ParameterDeclaration } from "./types.js";

/**
 * Parameterised controls: declaration validation, override validation, and
 * expression resolution. Substitution is typed values only — a parameter
 * reference is `{ $param: "name" }` in an expression value position, and the
 * engine replaces it with the effective value before evaluation. Unresolved
 * references fail closed (expressions never match a raw ParamRef object).
 */

const PARAM_NAME = /^[a-z][A-Za-z0-9]{0,63}$/;

export function isParamRef(value: unknown): value is ParamRef {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === 1 &&
    typeof (value as ParamRef).$param === "string"
  );
}

/** Collect every `$param` name referenced by an expression tree. */
export function collectParamRefs(expr: Expression, acc: Set<string> = new Set()): Set<string> {
  if ("value" in expr && isParamRef(expr.value)) acc.add(expr.value.$param);
  if ("values" in expr) {
    for (const v of expr.values) if (isParamRef(v)) acc.add(v.$param);
  }
  if (expr.op === "and" || expr.op === "or") for (const e of expr.exprs) collectParamRefs(e, acc);
  if (expr.op === "not") collectParamRefs(expr.expr, acc);
  if (expr.op === "anyItem" || expr.op === "allItems" || expr.op === "noneItem") {
    collectParamRefs(expr.condition, acc);
  }
  if (expr.op === "anyItemReferencedBy") collectParamRefs(expr.itemCondition, acc);
  return acc;
}

function valueMatchesType(value: unknown, decl: ParameterDeclaration): boolean {
  return typeof value === decl.type;
}

function checkValue(name: string, value: unknown, decl: ParameterDeclaration): string | undefined {
  if (!valueMatchesType(value, decl)) {
    return `parameter ${name}: expected ${decl.type}, got ${typeof value}`;
  }
  if (typeof value === "number" && !Number.isFinite(value)) {
    return `parameter ${name}: value must be finite`;
  }
  if (decl.min !== undefined && typeof value === "number" && value < decl.min) {
    return `parameter ${name}: ${value} is below the minimum ${decl.min}`;
  }
  if (decl.max !== undefined && typeof value === "number" && value > decl.max) {
    return `parameter ${name}: ${value} is above the maximum ${decl.max}`;
  }
  if (decl.enum && !decl.enum.some((candidate) => candidate === value)) {
    return `parameter ${name}: ${JSON.stringify(value)} is not one of ${JSON.stringify(decl.enum)}`;
  }
  return undefined;
}

/**
 * Validate a control's parameter declarations and references. Returns issue
 * messages (empty = valid). Enforced at catalog load and custom-document
 * validation so a bad declaration never reaches evaluation.
 */
export function validateControlParameters(control: ControlDefinition): string[] {
  const issues: string[] = [];
  const declared = control.parameters ?? {};
  for (const [name, decl] of Object.entries(declared)) {
    if (!PARAM_NAME.test(name)) issues.push(`parameter ${name}: invalid name`);
    if (decl.min !== undefined && decl.max !== undefined && decl.min > decl.max) {
      issues.push(`parameter ${name}: min ${decl.min} exceeds max ${decl.max}`);
    }
    if ((decl.min !== undefined || decl.max !== undefined) && decl.type !== "number") {
      issues.push(`parameter ${name}: min/max bounds require type number`);
    }
    const defaultIssue = checkValue(name, decl.default, decl);
    if (defaultIssue) issues.push(`${defaultIssue} (default)`);
  }
  const referenced = collectParamRefs(control.passWhen as Expression);
  if (control.applicableWhen) collectParamRefs(control.applicableWhen as Expression, referenced);
  for (const name of referenced) {
    if (!declared[name]) issues.push(`rule references undeclared parameter ${name}`);
  }
  for (const name of Object.keys(declared)) {
    if (!referenced.has(name)) issues.push(`parameter ${name} is declared but never referenced`);
  }
  return issues;
}

/**
 * Validate override values against a control's declarations. Unknown names
 * and out-of-bounds values are rejected — an override can tune a control
 * within its declared range but never silently disable it.
 */
export function validateParameterOverrides(
  control: ControlDefinition,
  overrides: Record<string, unknown>,
): string[] {
  const issues: string[] = [];
  const declared = control.parameters ?? {};
  for (const [name, value] of Object.entries(overrides)) {
    const decl = declared[name];
    if (!decl) {
      issues.push(`parameter ${name} is not declared by ${control.id}`);
      continue;
    }
    const issue = checkValue(name, value, decl);
    if (issue) issues.push(issue);
  }
  return issues;
}

/** Declaration defaults merged with validated overrides. */
export function effectiveParameterValues(
  control: ControlDefinition,
  overrides?: Record<string, unknown>,
): Record<string, number | string | boolean> {
  const values: Record<string, number | string | boolean> = {};
  for (const [name, decl] of Object.entries(control.parameters ?? {})) {
    const override = overrides?.[name];
    values[name] =
      override !== undefined
        ? (override as number | string | boolean)
        : (decl.default as number | string | boolean);
  }
  return values;
}

/** Deep-copy an expression, replacing every ParamRef with its value. */
export function resolveExpression(
  expr: Expression,
  values: Record<string, number | string | boolean>,
): Expression {
  const resolveValue = (v: unknown): unknown =>
    isParamRef(v) && values[v.$param] !== undefined ? values[v.$param] : v;
  const out: Record<string, unknown> = {};
  for (const [key, v] of Object.entries(expr)) {
    if (key === "value") out[key] = resolveValue(v);
    else if (key === "values" && Array.isArray(v)) out[key] = v.map(resolveValue);
    else if (key === "expr") out[key] = resolveExpression(v as Expression, values);
    else if (key === "exprs" && Array.isArray(v)) {
      out[key] = v.map((e) => resolveExpression(e as Expression, values));
    } else if (key === "condition" || key === "itemCondition") {
      out[key] = resolveExpression(v as Expression, values);
    } else out[key] = v;
  }
  return out as unknown as Expression;
}

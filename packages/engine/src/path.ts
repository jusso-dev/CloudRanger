/**
 * Dot-path resolver over parsed JSON. Supports:
 *   "a.b.c"        object traversal
 *   "a.0.b"        array index
 *   "$"            the value itself
 * Path segments never execute code; missing segments yield undefined.
 */
/**
 * Resolve a path that may flatten nested arrays with "[].", e.g.
 * "Reservations[].Instances" — for each element of Reservations, collect the
 * Instances array. Always returns a flat array of matches.
 */
export function flattenPath(value: unknown, path: string): unknown[] {
  const segments = path.split("[].");
  let current: unknown[] = [value];
  for (const [i, segment] of segments.entries()) {
    const next: unknown[] = [];
    for (const item of current) {
      const v = getPath(item, segment);
      if (Array.isArray(v)) next.push(...v);
      else if (i < segments.length - 1 && v !== undefined && v !== null) next.push(v);
    }
    current = next;
  }
  return current;
}

export function getPath(value: unknown, path: string): unknown {
  if (path === "$" || path === "") return value;
  let current: unknown = value;
  for (const segment of path.split(".")) {
    if (current === null || current === undefined) return undefined;
    if (Array.isArray(current)) {
      const idx = Number(segment);
      if (!Number.isInteger(idx)) return undefined;
      current = current[idx];
    } else if (typeof current === "object") {
      current = (current as Record<string, unknown>)[segment];
    } else {
      return undefined;
    }
  }
  return current;
}

/**
 * Dot-path resolver over parsed JSON. Supports:
 *   "a.b.c"        object traversal
 *   "a.0.b"        array index
 *   "$"            the value itself
 * Path segments never execute code; missing segments yield undefined.
 */
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

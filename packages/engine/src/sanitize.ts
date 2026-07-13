/**
 * Deterministic evidence sanitisation for fixture capture.
 *
 * Real CLI output contains account identifiers, emails and addresses that
 * must not land in fixture files. Sanitisation walks the parsed JSON tree and
 * rewrites sensitive tokens to stable placeholder values: the same original
 * always maps to the same placeholder within one run, so cross-references
 * inside the evidence (an account ID appearing in ten ARNs) stay consistent
 * and rules still evaluate identically. Values with rule semantics
 * (0.0.0.0/0, ::/0, private RFC1918 addresses) are preserved verbatim.
 */

const AWS_ACCOUNT = /\b\d{12}\b/g;
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const IPV4 = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;

/** Addresses whose literal value carries rule semantics — never rewritten. */
const PRESERVED_ADDRESSES = new Set(["0.0.0.0", "255.255.255.255", "127.0.0.1"]);

function isPrivateOrSpecialIp(a: number, b: number): boolean {
  if (a === 10 || a === 127 || a === 0 || a >= 224) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

export interface Sanitizer {
  /** Sanitise one parsed JSON value (deep copy; input is not mutated). */
  sanitize(value: unknown): unknown;
  /** Original → placeholder substitutions performed so far. */
  replacements(): Array<{ original: string; placeholder: string }>;
}

/**
 * Create a sanitiser whose mappings are stable across multiple sanitize()
 * calls, so several records captured in one session stay mutually consistent.
 */
export function createSanitizer(): Sanitizer {
  const accounts = new Map<string, string>();
  const uuids = new Map<string, string>();
  const emails = new Map<string, string>();
  const ips = new Map<string, string>();

  const mapped = (store: Map<string, string>, original: string, make: (n: number) => string) => {
    const existing = store.get(original);
    if (existing) return existing;
    const placeholder = make(store.size + 1);
    store.set(original, placeholder);
    return placeholder;
  };

  const sanitizeString = (value: string): string =>
    value
      .replace(AWS_ACCOUNT, (m) => mapped(accounts, m, (n) => String(100000000000 + n)))
      .replace(UUID, (m) =>
        mapped(
          uuids,
          m.toLowerCase(),
          (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
        ),
      )
      .replace(EMAIL, (m) => mapped(emails, m.toLowerCase(), (n) => `user-${n}@example.com`))
      .replace(IPV4, (m, a: string, b: string) => {
        const octetA = Number(a);
        const octetB = Number(b);
        if (octetA > 255 || octetB > 255) return m; // not an address
        if (PRESERVED_ADDRESSES.has(m) || isPrivateOrSpecialIp(octetA, octetB)) return m;
        return mapped(ips, m, (n) => `203.0.113.${n}`);
      });

  const walk = (value: unknown): unknown => {
    if (typeof value === "string") return sanitizeString(value);
    if (Array.isArray(value)) return value.map(walk);
    if (value && typeof value === "object") {
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>).map(([key, v]) => [
          sanitizeString(key),
          walk(v),
        ]),
      );
    }
    return value;
  };

  return {
    sanitize: walk,
    replacements: () =>
      [accounts, uuids, emails, ips].flatMap((store) =>
        [...store.entries()].map(([original, placeholder]) => ({ original, placeholder })),
      ),
  };
}

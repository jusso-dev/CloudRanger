import type { CollectorDefinition, EvidenceRecord } from "./types.js";
import { getPath } from "./path.js";

/**
 * Declarative evidence decoding.
 *
 * Some read-only CLI responses wrap non-JSON payloads inside JSON — the IAM
 * credential report is a base64-encoded CSV in the `Content` field. Decoding
 * happens here, inside the pure engine, so the transport stays "parsed JSON
 * from a read-only command" end to end: agents submit the raw CLI output and
 * never pre-process evidence themselves. Decoded rows never leave the
 * evaluation path; raw payloads are what get persisted.
 */

const MAX_DECODED_BYTES = 5_000_000;
const MAX_ROWS = 50_000;
const MAX_COLUMNS = 256;
const BASE64 = /^[A-Za-z0-9+/=\s]+$/;

export interface CsvDecodeResult {
  rows?: Array<Record<string, string>>;
  error?: string;
}

/**
 * RFC 4180 CSV parser: quoted fields, escaped quotes, CRLF/LF line ends.
 * The first row is the header; every data row becomes an object keyed by
 * header names. Short rows leave missing columns undefined; long rows are an
 * error (they indicate a corrupted report, not a formatting quirk).
 */
export function parseCsv(text: string): { rows?: Array<Record<string, string>>; error?: string } {
  const table: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  let i = 0;
  const pushField = () => {
    row.push(field);
    field = "";
  };
  const pushRow = () => {
    // Ignore completely empty lines (e.g. a trailing newline).
    if (row.length === 1 && row[0] === "") {
      row = [];
      return;
    }
    table.push(row);
    row = [];
  };
  while (i < text.length) {
    const ch = text[i]!;
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i += 1;
        continue;
      }
      field += ch;
      i += 1;
      continue;
    }
    if (ch === '"' && field === "") {
      inQuotes = true;
      i += 1;
      continue;
    }
    if (ch === ",") {
      pushField();
      i += 1;
      continue;
    }
    if (ch === "\n" || ch === "\r") {
      pushField();
      pushRow();
      if (ch === "\r" && text[i + 1] === "\n") i += 1;
      i += 1;
      continue;
    }
    field += ch;
    i += 1;
  }
  if (inQuotes) return { error: "unterminated quoted field" };
  if (field.length > 0 || row.length > 0) {
    pushField();
    pushRow();
  }
  if (table.length === 0) return { error: "empty CSV" };
  const header = table[0]!;
  if (header.length > MAX_COLUMNS) return { error: `more than ${MAX_COLUMNS} columns` };
  if (table.length - 1 > MAX_ROWS) return { error: `more than ${MAX_ROWS} rows` };
  const rows: Array<Record<string, string>> = [];
  for (const cells of table.slice(1)) {
    if (cells.length > header.length) return { error: "row has more fields than the header" };
    const obj: Record<string, string> = {};
    for (const [c, name] of header.entries()) {
      if (c < cells.length) obj[name] = cells[c]!;
    }
    rows.push(obj);
  }
  return { rows };
}

/** Decode a base64-encoded CSV document into row objects. */
export function decodeBase64Csv(content: unknown): CsvDecodeResult {
  if (typeof content !== "string" || content.length === 0) {
    return { error: "decode content is not a non-empty string" };
  }
  const compact = content.replace(/\s+/g, "");
  if (!BASE64.test(compact) || compact.length % 4 !== 0) {
    return { error: "decode content is not valid base64" };
  }
  if (compact.length > (MAX_DECODED_BYTES * 4) / 3 + 4) {
    return { error: `decoded payload exceeds ${MAX_DECODED_BYTES} bytes` };
  }
  const decoded = Buffer.from(compact, "base64");
  if (decoded.byteLength > MAX_DECODED_BYTES) {
    return { error: `decoded payload exceeds ${MAX_DECODED_BYTES} bytes` };
  }
  const parsed = parseCsv(decoded.toString("utf8"));
  if (parsed.error) return { error: `CSV parse failed: ${parsed.error}` };
  return { rows: parsed.rows };
}

/**
 * Apply a collector's declared decode step to one evidence record. Failed
 * commands and absent output pass through untouched; a decode failure turns
 * the record into an error record so evaluation surfaces it per-control
 * (via onError rules or a plain error status) instead of silently passing.
 */
export function decodeEvidenceRecord(
  collector: CollectorDefinition,
  record: EvidenceRecord,
): EvidenceRecord {
  if (!collector.decode) return record;
  if (record.exitCode !== 0 || record.output === null || record.output === undefined) {
    return record;
  }
  if (collector.decode.type === "base64Csv") {
    const content = getPath(record.output, collector.decode.contentPath);
    const result = decodeBase64Csv(content);
    if (result.error) {
      return {
        ...record,
        output: null,
        errorText: `evidence decode (${collector.decode.type} at ${collector.decode.contentPath}) failed: ${result.error}`,
      };
    }
    return { ...record, output: result.rows };
  }
  return record;
}

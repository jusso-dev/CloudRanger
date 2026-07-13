import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { fixturesCapture } from "../src/fixtures-capture.js";

const tmp = mkdtempSync(join(tmpdir(), "cr-fixture-capture-"));
// Isolate from any real operator custom catalog under ~/.cloudranger.
process.env.CLOUDRANGER_CUSTOM_CATALOG = join(tmp, "custom");
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const rawPasswordPolicy = (length: number) =>
  JSON.stringify({
    PasswordPolicy: {
      MinimumPasswordLength: length,
      RequireSymbols: true,
      // Sensitive-looking content the sanitiser must rewrite:
      Note: "owner 987654321098 justin@indigi-managed.au 54.1.2.3",
    },
  });

describe("fixtures capture", () => {
  it(
    "captures, sanitises, validates the verdict, and appends cases",
    { timeout: 60_000 },
    async () => {
      const raw = join(tmp, "raw.json");
      const out = join(tmp, "cases.json");
      writeFileSync(raw, rawPasswordPolicy(16));

      const code = await fixturesCapture({
        control: "CR-AWS-IAM-016",
        expected: "pass",
        name: "captured pass",
        fromFile: raw,
        output: out,
      });
      expect(code).toBe(0);

      const fixtures = JSON.parse(readFileSync(out, "utf8"));
      expect(fixtures).toHaveLength(1);
      const testCase = fixtures[0].cases[0];
      expect(testCase.expected).toBe("pass");
      const note = testCase.records[0].output.PasswordPolicy.Note;
      expect(note).not.toContain("987654321098");
      expect(note).not.toContain("indigi-managed");
      expect(note).not.toContain("54.1.2.3");
      expect(note).toContain("100000000001");
      expect(note).toContain("user-1@example.com");
      expect(note).toContain("203.0.113.1");

      // Appending a second (fail) case to the same file keeps both.
      writeFileSync(raw, rawPasswordPolicy(8));
      const second = await fixturesCapture({
        control: "CR-AWS-IAM-016",
        expected: "fail",
        name: "captured fail",
        fromFile: raw,
        output: out,
      });
      expect(second).toBe(0);
      expect(JSON.parse(readFileSync(out, "utf8"))[0].cases).toHaveLength(2);
    },
  );

  it(
    "refuses to write when the engine disagrees with the declared verdict",
    { timeout: 60_000 },
    async () => {
      const raw = join(tmp, "raw2.json");
      const out = join(tmp, "never-written.json");
      writeFileSync(raw, rawPasswordPolicy(16)); // passes, but we claim fail
      const code = await fixturesCapture({
        control: "CR-AWS-IAM-016",
        expected: "fail",
        fromFile: raw,
        output: out,
      });
      expect(code).toBe(1);
      expect(() => readFileSync(out)).toThrow();
    },
  );

  it("rejects unknown controls and bad expected values", { timeout: 60_000 }, async () => {
    expect(await fixturesCapture({ control: "CR-NOPE-X-999", expected: "pass" })).toBe(1);
    expect(await fixturesCapture({ control: "CR-AWS-IAM-016", expected: "maybe" })).toBe(1);
  });
});

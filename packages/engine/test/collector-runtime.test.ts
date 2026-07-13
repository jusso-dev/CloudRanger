import { describe, expect, it } from "vitest";
import { runCollector } from "../src/index.js";

describe("collector runtime", () => {
  it("retries transient failures with exponential backoff", async () => {
    let calls = 0;
    const delays: number[] = [];
    const result = await runCollector(
      async () => {
        calls += 1;
        if (calls < 3) throw new Error("Rate exceeded");
        return { ok: true };
      },
      { initialBackoffMs: 10, sleep: async (ms) => delays.push(ms) },
    );
    expect(result).toEqual({ value: { ok: true }, attempts: 3 });
    expect(delays).toEqual([10, 20]);
  });

  it("does not retry permanent failures", async () => {
    let calls = 0;
    await expect(
      runCollector(async () => {
        calls += 1;
        throw new Error("AccessDenied");
      }),
    ).rejects.toThrow("AccessDenied");
    expect(calls).toBe(1);
  });

  it("converts a deadline into a timeout error", async () => {
    await expect(
      runCollector(
        () =>
          new Promise((_resolve, reject) => {
            setTimeout(() => reject(new Error("timed out")), 20);
          }),
        { timeoutMs: 1, maxAttempts: 1 },
      ),
    ).rejects.toThrow(/timed out/);
  });
});

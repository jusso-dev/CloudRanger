import { describe, expect, it } from "vitest";
import { runCollector, runCollectorBatch } from "../src/index.js";

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

  it("bounds concurrent collector operations", async () => {
    let active = 0;
    let peak = 0;
    const operations = Array.from({ length: 8 }, (_, value) => async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 2));
      active -= 1;
      return value;
    });
    const results = await runCollectorBatch(operations, { maxConcurrency: 3 });
    expect(peak).toBe(3);
    expect(results.map((result) => result.value)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  });
});

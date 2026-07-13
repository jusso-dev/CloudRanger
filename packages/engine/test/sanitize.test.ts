import { describe, expect, it } from "vitest";
import { createSanitizer } from "../src/sanitize.js";

describe("evidence sanitiser", () => {
  it("rewrites account IDs consistently across strings and records", () => {
    const s = createSanitizer();
    const first = s.sanitize({
      Arn: "arn:aws:iam::987654321098:user/alice",
      Account: "987654321098",
      Other: "arn:aws:iam::111122223333:role/x",
    }) as Record<string, string>;
    expect(first.Arn).toBe("arn:aws:iam::100000000001:user/alice");
    expect(first.Account).toBe("100000000001");
    expect(first.Other).toBe("arn:aws:iam::100000000002:role/x");
    // Second record in the same session keeps the same mapping.
    const second = s.sanitize("987654321098");
    expect(second).toBe("100000000001");
  });

  it("rewrites UUIDs, emails and public IPs with stable placeholders", () => {
    const s = createSanitizer();
    const out = s.sanitize({
      subscription: "9C7E45A1-2B3C-4D5E-8F90-ABCDEF012345",
      owner: "Justin.M@Example.ORG",
      endpoint: "54.12.99.7",
      again: "54.12.99.7",
    }) as Record<string, string>;
    expect(out.subscription).toBe("00000000-0000-4000-8000-000000000001");
    expect(out.owner).toBe("user-1@example.com");
    expect(out.endpoint).toBe("203.0.113.1");
    expect(out.again).toBe("203.0.113.1");
  });

  it("preserves rule-bearing and private addresses", () => {
    const s = createSanitizer();
    const out = s.sanitize({
      open: "0.0.0.0/0",
      any: "0.0.0.0",
      lan: "10.1.2.3",
      rfc1918: "192.168.1.1",
      linkLocal: "169.254.169.254",
      loopback: "127.0.0.1",
    }) as Record<string, string>;
    expect(out.open).toBe("0.0.0.0/0");
    expect(out.any).toBe("0.0.0.0");
    expect(out.lan).toBe("10.1.2.3");
    expect(out.rfc1918).toBe("192.168.1.1");
    expect(out.linkLocal).toBe("169.254.169.254");
    expect(out.loopback).toBe("127.0.0.1");
  });

  it("walks arrays and object keys without mutating the input", () => {
    const s = createSanitizer();
    const input = { list: [{ "arn:aws:s3:::x-987654321098": true }], n: 5, b: null };
    const out = s.sanitize(input) as typeof input;
    expect(Object.keys(out.list[0]!)[0]).toBe("arn:aws:s3:::x-100000000001");
    expect(Object.keys(input.list[0]!)[0]).toBe("arn:aws:s3:::x-987654321098");
    expect(out.n).toBe(5);
    expect(out.b).toBeNull();
    expect(s.replacements()).toEqual([{ original: "987654321098", placeholder: "100000000001" }]);
  });

  it("does not treat long numeric IDs or version strings as addresses", () => {
    const s = createSanitizer();
    expect(s.sanitize("release 300.400.500.600")).toBe("release 300.400.500.600");
  });
});

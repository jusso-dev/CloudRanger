import { describe, expect, it } from "vitest";
import { PACKS, loadDefaultCatalog, resolvePack } from "../src/index.js";

const catalog = loadDefaultCatalog();

describe("control packs", () => {
  it("every pack resolves to at least one control", () => {
    for (const pack of PACKS) {
      const controls = resolvePack(catalog.controls, pack.id);
      expect(controls.length, pack.id).toBeGreaterThan(0);
    }
  });

  it("essential-baseline includes all critical and high controls", () => {
    const resolved = new Set(resolvePack(catalog.controls, "essential-baseline").map((c) => c.id));
    for (const control of catalog.controls) {
      if (control.severity === "critical" || control.severity === "high") {
        expect(resolved.has(control.id), control.id).toBe(true);
      } else {
        expect(resolved.has(control.id), control.id).toBe(false);
      }
    }
  });

  it("provider filter applies", () => {
    const aws = resolvePack(catalog.controls, "public-exposure", "aws");
    expect(aws.length).toBeGreaterThan(0);
    expect(aws.every((c) => c.provider === "aws")).toBe(true);
  });

  it("kubernetes pack spans azure and gcp", () => {
    const k8s = resolvePack(catalog.controls, "kubernetes");
    const providers = new Set(k8s.map((c) => c.provider));
    expect(providers.has("azure")).toBe(true);
    expect(providers.has("gcp")).toBe(true);
  });

  it("unknown pack throws with available list", () => {
    expect(() => resolvePack(catalog.controls, "nonexistent")).toThrow(/Available:/);
  });
});

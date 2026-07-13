import { describe, expect, it } from "vitest";
import { authorizeTool, parseRole } from "../src/authorization.js";

describe("role-based access control", () => {
  it("defaults shared databases to read-only and local databases to admin", () => {
    expect(parseRole(undefined, true)).toBe("reader");
    expect(parseRole(undefined, false)).toBe("admin");
  });

  it("allows readers and auditors to read but not mutate", () => {
    expect(() => authorizeTool("reader", "findings_search")).not.toThrow();
    expect(() => authorizeTool("auditor", "audit_search")).not.toThrow();
    expect(() => authorizeTool("reader", "scan_start")).toThrow(/operator or admin/);
  });

  it("reserves custom control installation for administrators", () => {
    expect(() => authorizeTool("operator", "scan_start")).not.toThrow();
    expect(() => authorizeTool("operator", "catalog_add_custom_control")).toThrow(/admin/);
    expect(() => authorizeTool("admin", "catalog_add_custom_control")).not.toThrow();
    expect(() => authorizeTool("operator", "workspace_set_member")).toThrow(/admin/);
    expect(() => authorizeTool("admin", "workspace_set_member")).not.toThrow();
  });
});

export type CloudRangerRole = "admin" | "operator" | "auditor" | "reader";

const ADMIN_ONLY = new Set([
  "catalog_add_custom_control",
  "workspace_list_members",
  "workspace_set_member",
  "workspace_remove_member",
]);
const MUTATING = new Set([
  "parameters_set",
  "scan_start",
  "evidence_submit",
  "scan_evaluate",
  "scan_cancel",
  "findings_set_status",
  "findings_assign",
  "findings_expire_workflows",
  "findings_comment",
]);

export function parseRole(value: string | undefined, sharedDatabase: boolean): CloudRangerRole {
  if (!value) return sharedDatabase ? "reader" : "admin";
  if (["admin", "operator", "auditor", "reader"].includes(value)) {
    return value as CloudRangerRole;
  }
  throw new Error(`invalid CLOUDRANGER_ROLE: ${value}`);
}

export function authorizeTool(role: CloudRangerRole, tool: string): void {
  if (ADMIN_ONLY.has(tool) && role !== "admin") {
    throw new Error(`${tool} requires the admin role`);
  }
  if (MUTATING.has(tool) && role !== "admin" && role !== "operator") {
    throw new Error(`${tool} requires the operator or admin role`);
  }
}

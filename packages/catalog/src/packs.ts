import type { ControlDefinition, Provider, Severity } from "@cloudranger/engine";
import { loadFrameworkRegistry } from "./compliance.js";

/**
 * Control packs: named selections over the catalog, resolved dynamically so
 * new controls join matching packs automatically. A control matches a pack
 * when it matches ANY listed category (or the severity floor for
 * severity-based packs).
 */
export interface ControlPack {
  id: string;
  title: string;
  description: string;
  /** Match controls whose severity is at or above this floor. */
  minSeverity?: Severity;
  /** Match controls tagged with any of these categories. */
  categories?: string[];
  /**
   * Framework-aligned pack: match controls mapped to this framework, either
   * via the control document's compliance field (version-checked when given)
   * or via the curated mapping registry.
   */
  framework?: { id: string; version?: string };
}

const SEVERITY_ORDER: Severity[] = ["informational", "low", "medium", "high", "critical"];

export const PACKS: ControlPack[] = [
  {
    id: "essential-baseline",
    title: "Essential baseline",
    description: "Every critical and high severity control — the minimum posture bar.",
    minSeverity: "high",
  },
  {
    id: "public-exposure",
    title: "Public exposure",
    description: "Internet-reachable storage, networks, databases and control planes.",
    categories: ["public-exposure"],
  },
  {
    id: "identity",
    title: "Identity security",
    description: "Root/owner protections, MFA, stale and over-privileged credentials.",
    categories: ["identity", "mfa", "credentials", "least-privilege"],
  },
  {
    id: "encryption",
    title: "Encryption",
    description: "Encryption at rest and in transit, key management and secrets hygiene.",
    categories: ["encryption", "encryption-in-transit", "keys", "secrets"],
  },
  {
    id: "logging-detection",
    title: "Logging and detection",
    description: "Audit trails, flow logs, recorder/detector enablement and log integrity.",
    categories: ["logging", "detection", "governance", "integrity"],
  },
  {
    id: "resilience",
    title: "Backup and resilience",
    description: "Backups, versioning, recovery protection, deletion protection and patching.",
    categories: ["resilience", "patching"],
  },
  {
    id: "kubernetes",
    title: "Kubernetes",
    description: "Managed Kubernetes control plane and node posture (AKS, GKE).",
    categories: ["kubernetes"],
  },
  {
    id: "cis-aws-3.0",
    title: "CIS AWS Foundations Benchmark v3.0",
    description:
      "Controls mapped to CIS AWS Foundations Benchmark v3.0 recommendations. Coverage is partial — pair scans with compliance_status to see which recommendations remain unassessed.",
    framework: { id: "cis-aws-foundations", version: "3.0" },
  },
  {
    id: "essential-eight-technical",
    title: "Essential Eight — cloud-technical subset",
    description:
      "Controls evidencing the cloud-posture slice of ACSC Essential Eight strategies (MFA, restricting admin privileges, patching, backups). E8 maturity requires far more than these checks — see compliance_status.",
    framework: { id: "essential-eight" },
  },
];

/** Control IDs mapped to a framework via control documents or the registry. */
function frameworkControlIds(
  controls: ControlDefinition[],
  framework: { id: string; version?: string },
): Set<string> {
  const ids = new Set<string>();
  for (const control of controls) {
    for (const entry of control.compliance) {
      if (entry.framework !== framework.id) continue;
      if (framework.version && entry.version !== framework.version) continue;
      ids.add(control.id);
    }
  }
  for (const mapping of loadFrameworkRegistry().mappings) {
    if (mapping.framework === framework.id) ids.add(mapping.controlId);
  }
  return ids;
}

export function getPack(packId: string): ControlPack | undefined {
  return PACKS.find((p) => p.id === packId);
}

export function controlMatchesPack(control: ControlDefinition, pack: ControlPack): boolean {
  if (pack.minSeverity) {
    if (SEVERITY_ORDER.indexOf(control.severity) >= SEVERITY_ORDER.indexOf(pack.minSeverity)) {
      return true;
    }
  }
  if (pack.categories) {
    return control.categories.some((c) => pack.categories!.includes(c));
  }
  return false;
}

export function resolvePack(
  controls: ControlDefinition[],
  packId: string,
  provider?: Provider,
): ControlDefinition[] {
  const pack = getPack(packId);
  if (!pack)
    throw new Error(`unknown pack: ${packId}. Available: ${PACKS.map((p) => p.id).join(", ")}`);
  const scoped = controls.filter((c) => !provider || c.provider === provider);
  if (pack.framework) {
    const ids = frameworkControlIds(controls, pack.framework);
    return scoped.filter((c) => ids.has(c.id));
  }
  return scoped.filter((c) => controlMatchesPack(c, pack));
}

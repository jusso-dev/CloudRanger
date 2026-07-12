import type { ControlDefinition, Provider, Severity } from "@cloudranger/engine";

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
];

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
  return controls
    .filter((c) => !provider || c.provider === provider)
    .filter((c) => controlMatchesPack(c, pack));
}

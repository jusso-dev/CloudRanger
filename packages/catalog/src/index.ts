import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadCatalog, type LoadedCatalog } from "@cloudranger/engine";

/** Absolute path to the bundled catalog (collectors + controls). */
export function catalogDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "..", "catalog");
}

/** Absolute path to the bundled fixture directory. */
export function fixturesDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures");
}

/**
 * Operator custom catalog directory (controls/ + collectors/ subdirs).
 * Entries here are merged over the bundled catalog; matching IDs override
 * bundled definitions, so operators can tune severities or logic without
 * forking the repo.
 */
export function customCatalogDir(): string {
  return process.env.CLOUDRANGER_CUSTOM_CATALOG ?? join(homedir(), ".cloudranger", "catalog");
}

/** Bundled catalog only (no operator customisations). */
export function loadBundledCatalog(): LoadedCatalog {
  return loadCatalog(catalogDir());
}

/** Bundled catalog merged with the operator's custom catalog directory. */
export function loadDefaultCatalog(): LoadedCatalog {
  return loadCatalog([catalogDir(), customCatalogDir()]);
}

export { PACKS, getPack, resolvePack, controlMatchesPack, type ControlPack } from "./packs.js";
export {
  allFrameworks,
  complianceStatus,
  derivedMappingsFromControls,
  frameworkRequirementTotals,
  loadFrameworkRegistry,
  type ControlEvaluationCounts,
  type FrameworkInfo,
  type FrameworkRegistry,
  type FrameworkRollup,
  type MappingStatus,
  type RequirementMapping,
  type RequirementRollup,
} from "./compliance.js";

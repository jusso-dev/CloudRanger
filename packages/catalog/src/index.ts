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

export function loadDefaultCatalog(): LoadedCatalog {
  return loadCatalog(catalogDir());
}

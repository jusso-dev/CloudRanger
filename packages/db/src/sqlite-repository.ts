import type { CloudRangerRepository } from "./repository.js";
import { CloudRangerStore } from "./index.js";

/** Async facade preserving the existing SQLite implementation and defaults. */
export function createSqliteRepository(path: string): CloudRangerRepository {
  const store = new CloudRangerStore(path);
  return new Proxy({} as CloudRangerRepository, {
    get(_target, property) {
      if (property === "close") return async () => store.close();
      const member = (store as unknown as Record<PropertyKey, unknown>)[property];
      if (typeof member !== "function") return member;
      return async (...args: unknown[]) => member.apply(store, args);
    },
  });
}

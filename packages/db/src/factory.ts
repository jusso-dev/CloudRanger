import type { CloudRangerRepository } from "./repository.js";
import { PostgresCloudRangerStore } from "./postgres-store.js";
import { createSqliteRepository } from "./sqlite-repository.js";

export interface RepositoryConfig {
  sqlitePath: string;
  databaseUrl?: string;
}

/** SQLite is the zero-config default; a PostgreSQL URL selects the shared backend. */
export function createRepository(config: RepositoryConfig): CloudRangerRepository {
  const url = config.databaseUrl ?? process.env.CLOUDRANGER_DATABASE_URL;
  if (!url) return createSqliteRepository(config.sqlitePath);
  if (!/^postgres(?:ql)?:\/\//i.test(url)) {
    throw new Error("CLOUDRANGER_DATABASE_URL must use postgresql:// or postgres://");
  }
  return new PostgresCloudRangerStore(url);
}

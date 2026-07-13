import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./drizzle-schema.js";

export type PostgresDatabase = ReturnType<typeof drizzle<typeof schema>>;

/** Creates a pooled Drizzle connection for shared PostgreSQL deployments. */
export function createPostgresDatabase(connectionString = process.env.CLOUDRANGER_DATABASE_URL): {
  pool: Pool;
  db: PostgresDatabase;
} {
  if (!connectionString) {
    throw new Error("CLOUDRANGER_DATABASE_URL is required for the PostgreSQL backend");
  }
  const pool = new Pool({
    connectionString,
    max: Number(process.env.CLOUDRANGER_DB_POOL_SIZE ?? 10),
  });
  return { pool, db: drizzle(pool, { schema }) };
}

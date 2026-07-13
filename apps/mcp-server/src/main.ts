#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { homedir } from "node:os";
import { join } from "node:path";
import { loadDefaultCatalog } from "@cloudranger/catalog";
import { createRepository } from "@cloudranger/db";
import { createServer } from "./server.js";
import { parseRole } from "./authorization.js";

async function main(): Promise<void> {
  const dbPath = process.env.CLOUDRANGER_DB ?? join(homedir(), ".cloudranger", "cloudranger.db");
  const catalog = loadDefaultCatalog();
  if (catalog.issues.length > 0) {
    for (const issue of catalog.issues) {
      console.error(`[cloudranger] catalog issue in ${issue.file}: ${issue.message}`);
    }
  }
  const store = createRepository({ sqlitePath: dbPath });
  const sharedDatabase = Boolean(process.env.CLOUDRANGER_DATABASE_URL);
  if (sharedDatabase && !process.env.CLOUDRANGER_ACTOR) {
    throw new Error("CLOUDRANGER_ACTOR is required for shared PostgreSQL deployments");
  }
  let workspaceId: string | undefined;
  let role: ReturnType<typeof parseRole>;
  if (sharedDatabase) {
    workspaceId = process.env.CLOUDRANGER_WORKSPACE_ID;
    if (!workspaceId || !/^[a-z0-9][a-z0-9_-]{0,62}$/.test(workspaceId)) {
      throw new Error(
        "CLOUDRANGER_WORKSPACE_ID is required and must be a lowercase slug for shared PostgreSQL deployments",
      );
    }
    if (process.env.CLOUDRANGER_ROLE) {
      throw new Error(
        "CLOUDRANGER_ROLE cannot be used with PostgreSQL; roles are loaded from workspace membership",
      );
    }
    role = await store.initializeWorkspace({
      workspaceId,
      workspaceName: process.env.CLOUDRANGER_WORKSPACE_NAME ?? workspaceId,
      subject: process.env.CLOUDRANGER_ACTOR!,
      displayName: process.env.CLOUDRANGER_ACTOR_DISPLAY_NAME,
      bootstrapAdmin: process.env.CLOUDRANGER_BOOTSTRAP_ADMIN === "true",
    });
  } else {
    role = parseRole(process.env.CLOUDRANGER_ROLE, false);
  }
  const server = createServer({
    store,
    catalog,
    actor: process.env.CLOUDRANGER_ACTOR,
    role,
    workspaceId,
  });
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(
    `[cloudranger] MCP server ready (db: ${process.env.CLOUDRANGER_DATABASE_URL ? "postgresql" : dbPath}, controls: ${catalog.controls.length})`,
  );
}

main().catch((error) => {
  console.error("[cloudranger] fatal:", error);
  process.exit(1);
});

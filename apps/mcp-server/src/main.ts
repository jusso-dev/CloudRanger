#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { homedir } from "node:os";
import { join } from "node:path";
import { loadDefaultCatalog } from "@cloudranger/catalog";
import { createRepository } from "@cloudranger/db";
import { createServer } from "./server.js";

async function main(): Promise<void> {
  const dbPath = process.env.CLOUDRANGER_DB ?? join(homedir(), ".cloudranger", "cloudranger.db");
  const catalog = loadDefaultCatalog();
  if (catalog.issues.length > 0) {
    for (const issue of catalog.issues) {
      console.error(`[cloudranger] catalog issue in ${issue.file}: ${issue.message}`);
    }
  }
  const store = createRepository({ sqlitePath: dbPath });
  const server = createServer({ store, catalog, actor: process.env.CLOUDRANGER_ACTOR });
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

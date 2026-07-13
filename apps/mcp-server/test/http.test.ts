import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { CloudRangerStore } from "@cloudranger/db";
import { loadBundledCatalog } from "@cloudranger/catalog";
import { resolveHttpConfig, startHttpTransport } from "../src/http.js";

const TOKEN = "test-token-0123456789abcdef";
let httpServer: ReturnType<typeof startHttpTransport>;
let baseUrl: string;
let store: CloudRangerStore;

beforeAll(async () => {
  store = new CloudRangerStore(":memory:");
  httpServer = startHttpTransport(
    { store, catalog: loadBundledCatalog(), actor: "http-test" },
    { port: 0, bind: "127.0.0.1", token: TOKEN },
  );
  await new Promise<void>((resolve) => httpServer.once("listening", () => resolve()));
  const { port } = httpServer.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}/`;
});

afterAll(async () => {
  httpServer.close();
  store.close();
});

describe("streamable-HTTP transport", () => {
  it("rejects missing and wrong tokens before any MCP dispatch", async () => {
    const noAuth = await fetch(baseUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", method: "initialize", id: 1 }),
    });
    expect(noAuth.status).toBe(401);

    const wrong = await fetch(baseUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer wrong-token-0123456789abcdef",
      },
      body: JSON.stringify({ jsonrpc: "2.0", method: "initialize", id: 1 }),
    });
    expect(wrong.status).toBe(401);
  });

  it("rejects unknown session IDs and oversized bodies", async () => {
    const unknownSession = await fetch(baseUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${TOKEN}`,
        "mcp-session-id": "not-a-session",
      },
      body: JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 }),
    });
    expect(unknownSession.status).toBe(404);

    const oversized = await fetch(baseUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${TOKEN}`,
        "Content-Length": "9000000",
      },
      body: JSON.stringify({ jsonrpc: "2.0", method: "initialize", id: 1 }),
    }).catch(() => ({ status: 413 }));
    expect(oversized.status).toBe(413);
  });

  it("serves the full tool set over HTTP with a valid token", async () => {
    const client = new Client({ name: "http-test-client", version: "0.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(baseUrl), {
      requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
    });
    await client.connect(transport);
    const tools = await client.listTools();
    const names = tools.tools.map((tool) => tool.name);
    expect(names).toContain("scan_start");
    expect(names).toContain("compliance_status");
    // A real tool round-trip:
    const result = (await client.callTool({
      name: "catalog_list_packs",
      arguments: {},
    })) as { content: Array<{ text: string }> };
    const packs = JSON.parse(result.content[0]!.text);
    expect(packs.packs.some((p: { id: string }) => p.id === "cis-aws-3.0")).toBe(true);
    await client.close();
  });
});

describe("HTTP config safety", () => {
  it("requires a strong token and explicit non-loopback opt-in", () => {
    expect(() => resolveHttpConfig({})).toThrow(/requires CLOUDRANGER_HTTP_TOKEN/);
    expect(() => resolveHttpConfig({ CLOUDRANGER_HTTP_TOKEN: "short" })).toThrow(/at least/);
    expect(() =>
      resolveHttpConfig({ CLOUDRANGER_HTTP_TOKEN: TOKEN, CLOUDRANGER_HTTP_BIND: "0.0.0.0" }),
    ).toThrow(/non-loopback/);
    const ok = resolveHttpConfig({
      CLOUDRANGER_HTTP_TOKEN: TOKEN,
      CLOUDRANGER_HTTP_BIND: "0.0.0.0",
      CLOUDRANGER_HTTP_ALLOW_NONLOOPBACK: "true",
    });
    expect(ok.bind).toBe("0.0.0.0");
    expect(resolveHttpConfig({ CLOUDRANGER_HTTP_TOKEN: TOKEN }).bind).toBe("127.0.0.1");
  });
});

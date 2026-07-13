import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createServer, type ServerDeps } from "./server.js";

/**
 * Optional streamable-HTTP transport. Off unless explicitly requested; stdio
 * remains the default. Security posture:
 *  - Bearer token REQUIRED (even on loopback), compared in constant time,
 *    checked before any request reaches the MCP layer.
 *  - Binds 127.0.0.1 by default; a non-loopback bind requires an explicit
 *    opt-in env and logs a prominent warning.
 *  - DNS-rebinding protection via the SDK's Host/Origin validation.
 *  - Request bodies capped at 4 MB.
 *  - No TLS here by design — terminate TLS at a reverse proxy.
 */

const MAX_BODY_BYTES = 4_000_000;
const MIN_TOKEN_LENGTH = 16;

export interface HttpTransportConfig {
  port: number;
  bind: string;
  token: string;
  /** Extra allowed Origin values (loopback origins are always allowed). */
  allowedOrigins?: string[];
}

export function resolveHttpConfig(env: NodeJS.ProcessEnv): HttpTransportConfig {
  let token = env.CLOUDRANGER_HTTP_TOKEN;
  if (!token && env.CLOUDRANGER_HTTP_TOKEN_FILE) {
    token = readFileSync(env.CLOUDRANGER_HTTP_TOKEN_FILE, "utf8").trim();
  }
  if (!token || token.length < MIN_TOKEN_LENGTH) {
    throw new Error(
      `HTTP transport requires CLOUDRANGER_HTTP_TOKEN (or _FILE) of at least ${MIN_TOKEN_LENGTH} characters — refusing to start without authentication`,
    );
  }
  const bind = env.CLOUDRANGER_HTTP_BIND ?? "127.0.0.1";
  const loopback = bind === "127.0.0.1" || bind === "::1" || bind === "localhost";
  if (!loopback && env.CLOUDRANGER_HTTP_ALLOW_NONLOOPBACK !== "true") {
    throw new Error(
      `refusing to bind ${bind}: non-loopback binds expose the MCP server to the network. Set CLOUDRANGER_HTTP_ALLOW_NONLOOPBACK=true only behind a TLS-terminating reverse proxy.`,
    );
  }
  const port = Number(env.CLOUDRANGER_HTTP_PORT ?? 8484);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid CLOUDRANGER_HTTP_PORT: ${env.CLOUDRANGER_HTTP_PORT}`);
  }
  return {
    port,
    bind,
    token,
    allowedOrigins: env.CLOUDRANGER_HTTP_ALLOWED_ORIGINS?.split(",")
      .map((origin) => origin.trim())
      .filter(Boolean),
  };
}

function tokenMatches(expected: string, header: string | undefined): boolean {
  if (!header?.startsWith("Bearer ")) return false;
  const presented = header.slice("Bearer ".length);
  // Hash both sides so timingSafeEqual gets equal-length buffers and the
  // comparison leaks nothing about token length or content.
  const a = createHash("sha256").update(expected).digest();
  const b = createHash("sha256").update(presented).digest();
  return timingSafeEqual(a, b);
}

export function startHttpTransport(
  deps: ServerDeps,
  config: HttpTransportConfig,
): ReturnType<typeof createHttpServer> {
  const transports = new Map<string, StreamableHTTPServerTransport>();
  // The actual port can differ from config.port (port 0 = ephemeral); the
  // Host/Origin allowlists must use what we really bound to.
  let boundPort = config.port;

  const httpServer = createHttpServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      // Authentication gates EVERYTHING — no MCP code runs without it.
      if (!tokenMatches(config.token, req.headers.authorization)) {
        res
          .writeHead(401, { "Content-Type": "application/json" })
          .end(JSON.stringify({ error: "unauthorized" }));
        return;
      }
      const contentLength = Number(req.headers["content-length"] ?? 0);
      if (contentLength > MAX_BODY_BYTES) {
        res.writeHead(413).end();
        return;
      }
      const sessionId = req.headers["mcp-session-id"] as string | undefined;
      let transport = sessionId ? transports.get(sessionId) : undefined;
      if (!transport) {
        if (sessionId) {
          res
            .writeHead(404, { "Content-Type": "application/json" })
            .end(JSON.stringify({ error: "unknown session" }));
          return;
        }
        // New session: one MCP server instance per session.
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          enableDnsRebindingProtection: true,
          allowedHosts: [
            `${config.bind}:${boundPort}`,
            `127.0.0.1:${boundPort}`,
            `localhost:${boundPort}`,
          ],
          allowedOrigins: [
            `http://127.0.0.1:${boundPort}`,
            `http://localhost:${boundPort}`,
            ...(config.allowedOrigins ?? []),
          ],
          onsessioninitialized: (id: string) => {
            transports.set(id, transport!);
          },
        });
        transport.onclose = () => {
          if (transport?.sessionId) transports.delete(transport.sessionId);
        };
        const server = createServer(deps);
        await server.connect(transport);
      }
      await transport.handleRequest(req, res);
    } catch (error) {
      if (!res.headersSent) {
        res
          .writeHead(500, { "Content-Type": "application/json" })
          .end(JSON.stringify({ error: (error as Error).message }));
      }
    }
  });

  httpServer.listen(config.port, config.bind, () => {
    const address = httpServer.address();
    if (address && typeof address === "object") boundPort = address.port;
    const warning =
      config.bind === "127.0.0.1" || config.bind === "::1" || config.bind === "localhost"
        ? ""
        : " *** WARNING: non-loopback bind — ensure a TLS-terminating reverse proxy and network controls are in front of this listener ***";
    console.error(
      `[cloudranger] MCP streamable-HTTP transport listening on ${config.bind}:${config.port} (token auth required)${warning}`,
    );
  });
  return httpServer;
}

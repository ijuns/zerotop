import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { connect } from "node:net";
import { backendPath, desktopHost, parseAuthorizedRun, parseTicketExchange, runIdFromPath, type AuthorizedRun } from "./routing.ts";
import { cookieValue, createSessionToken, verifySessionToken } from "./session.ts";

const port = integerEnv("PORT", 9001, 1, 65535);
const apiUrl = requiredUrl("PLATFORM_API_URL");
const upstreamPort = integerEnv("DESKTOP_UPSTREAM_PORT", 6080, 1, 65535);
const internalToken = requiredSecret("DESKTOP_GATEWAY_INTERNAL_TOKEN", 24);
const sessionSigningKey = requiredSecret("DESKTOP_SESSION_SIGNING_KEY", 32);
const desktopClient = enumEnv("DESKTOP_CLIENT", "novnc", ["novnc", "webtop"] as const);
const preserveUpstreamPath = booleanEnv("DESKTOP_PRESERVE_UPSTREAM_PATH", false);
const secureCookie = booleanEnv("DESKTOP_COOKIE_SECURE", true);
const sessionCookie = "cg_desktop_session";
const authorizationCache = new Map<string, { expiresAt: number; run: AuthorizedRun }>();

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", "http://gateway.local");
    if (request.method === "GET" && url.pathname === "/health") {
      return json(response, 200, { status: "ok" });
    }
    const runId = runIdFromPath(url.pathname);
    if (!runId) return json(response, 404, { error: { code: "not_found" } });
    if (request.method !== "GET" && request.method !== "HEAD") {
      return json(response, 405, { error: { code: "method_not_allowed" } });
    }
    const ticket = url.searchParams.get("ticket");
    if (ticket) {
      const run = await exchangeTicket(runId, ticket);
      const session = createSessionToken(run, sessionSigningKey);
      const desktopPath = `/sessions/${encodeURIComponent(runId)}/desktop`;
      const websocketPath = `sessions/${encodeURIComponent(runId)}/desktop/websockify`;
      const location = desktopClient === "webtop"
        ? `${desktopPath}/`
        : `${desktopPath}/vnc.html?path=${encodeURIComponent(websocketPath)}&autoconnect=1&resize=scale`;
      const cookieFlags = secureCookie ? "; Secure" : "";
      response.writeHead(302, {
        location,
        "set-cookie": `${sessionCookie}=${encodeURIComponent(session)}; Path=${desktopPath}; HttpOnly${cookieFlags}; SameSite=Strict`,
        "cache-control": "no-store",
        "content-security-policy": "default-src 'none'",
      });
      return response.end();
    }
    const run = await requestRun(request, runId);
    if (url.pathname === `/sessions/${encodeURIComponent(runId)}/desktop`) {
      return json(response, 400, { error: { code: "ticket_required" } });
    }
    return proxyHttp(request, response, run, url);
  } catch (error) {
    const status = error instanceof GatewayError ? error.status : 502;
    return json(response, status, {
      error: {
        code: error instanceof GatewayError ? error.code : "gateway_error",
        message: error instanceof Error ? error.message : "Desktop gateway failure",
      },
    });
  }
});

server.on("upgrade", (request, socket, head) => {
  void (async () => {
    try {
      const url = new URL(request.url ?? "/", "http://gateway.local");
      const runId = runIdFromPath(url.pathname);
      if (!runId) throw new GatewayError(404, "not_found", "Session path was not found");
      const run = await requestRun(request, runId);
      const host = desktopHost(run.namespace);
      const upstream = connect(upstreamPort, host);
      const expiresAt = run.expiresAt ? Date.parse(run.expiresAt) : Number.NaN;
      const expiryTimer = Number.isFinite(expiresAt)
        ? setTimeout(() => {
            socket.destroy();
            upstream.destroy();
          }, Math.max(1, expiresAt - Date.now()))
        : undefined;
      expiryTimer?.unref();
      upstream.setTimeout(15_000, () => upstream.destroy(new Error("Upstream timeout")));
      upstream.once("connect", () => {
        upstream.setTimeout(0);
        const path = upstreamPath(url, runId);
        upstream.write(upgradeRequest(request, host, path));
        if (head.length > 0) upstream.write(head);
        socket.pipe(upstream).pipe(socket);
      });
      upstream.once("error", () => socket.destroy());
      upstream.once("close", () => {
        if (expiryTimer) clearTimeout(expiryTimer);
      });
      socket.once("error", () => upstream.destroy());
      socket.once("close", () => {
        if (expiryTimer) clearTimeout(expiryTimer);
      });
    } catch {
      socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
      socket.destroy();
    }
  })();
});

server.listen(port, "0.0.0.0", () => {
  console.log(JSON.stringify({ level: "info", service: "desktop-gateway", port }));
});

async function authorizeRun(runId: string, authorization: string): Promise<AuthorizedRun> {
  const cacheKey = createHash("sha256").update(`${runId}\0${authorization}`).digest("hex");
  const cached = authorizationCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return cached.run;
  let response: Response;
  try {
    response = await fetch(`${apiUrl}/v1/runs/${encodeURIComponent(runId)}`, {
      headers: { authorization, accept: "application/json" },
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    throw new GatewayError(503, "authorization_unavailable", "Run authorization is unavailable");
  }
  if (response.status === 401 || response.status === 403 || response.status === 404) {
    throw new GatewayError(403, "run_access_denied", "Desktop access was denied");
  }
  if (!response.ok) {
    throw new GatewayError(503, "authorization_unavailable", "Run authorization failed");
  }
  const run = parseAuthorizedRun(await response.json(), runId);
  authorizationCache.set(cacheKey, { expiresAt: Date.now() + 5_000, run });
  if (authorizationCache.size > 2_000) {
    const now = Date.now();
    for (const [key, value] of authorizationCache) {
      if (value.expiresAt <= now) authorizationCache.delete(key);
    }
  }
  return run;
}

async function requestRun(request: IncomingMessage, runId: string): Promise<AuthorizedRun> {
  const session = cookieValue(request.headers.cookie, sessionCookie);
  if (session) {
    try {
      return verifySessionToken(session, runId, sessionSigningKey);
    } catch {
      throw new GatewayError(401, "desktop_session_invalid", "Desktop session is invalid or expired");
    }
  }
  return authorizeRun(runId, bearer(request));
}

async function exchangeTicket(runId: string, ticket: string): Promise<AuthorizedRun> {
  if (!/^[A-Za-z0-9_-]{32,256}$/.test(ticket)) {
    throw new GatewayError(400, "invalid_ticket", "Desktop ticket is malformed");
  }
  let response: Response;
  try {
    response = await fetch(`${apiUrl}/v1/internal/desktop-tickets/exchange`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${internalToken}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({ runId, ticket }),
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    throw new GatewayError(503, "ticket_exchange_unavailable", "Ticket exchange is unavailable");
  }
  if (!response.ok) {
    throw new GatewayError(403, "ticket_rejected", "Desktop ticket was rejected");
  }
  try {
    return parseTicketExchange(await response.json(), runId);
  } catch {
    throw new GatewayError(502, "invalid_ticket_response", "Ticket exchange returned invalid data");
  }
}

function proxyHttp(
  request: IncomingMessage,
  response: ServerResponse,
  run: AuthorizedRun,
  url: URL,
): void {
  const host = desktopHost(run.namespace);
  const upstreamRequest = fetch(
    `http://${host}:${upstreamPort}${upstreamPath(url, run.runId)}`,
    {
      method: request.method,
      headers: {
        accept: String(request.headers.accept ?? "*/*"),
        "accept-language": String(request.headers["accept-language"] ?? ""),
        "accept-encoding": "identity",
        "user-agent": "CODEGATE-Desktop-Gateway/1.0",
      },
      redirect: "manual",
      signal: AbortSignal.timeout(15_000),
    },
  );
  void upstreamRequest
    .then(async (upstream) => {
      const headers: Record<string, string> = {
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      };
      for (const name of [
        "content-type",
        "content-length",
        "etag",
        "last-modified",
        "location",
        "content-security-policy",
        "cross-origin-embedder-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
      ]) {
        const value = upstream.headers.get(name);
        if (value) headers[name] = value;
      }
      response.writeHead(upstream.status, headers);
      if (request.method === "HEAD" || !upstream.body) return response.end();
      const reader = upstream.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!response.write(Buffer.from(value))) {
          await new Promise<void>((resolve) => response.once("drain", resolve));
        }
      }
      response.end();
    })
    .catch(() => {
      if (!response.headersSent) {
        json(response, 502, { error: { code: "desktop_unavailable" } });
      } else {
        response.destroy();
      }
    });
}

function upstreamPath(url: URL, runId: string): string {
  return preserveUpstreamPath
    ? `${url.pathname}${url.search}`
    : backendPath(url.pathname, url.search, runId);
}

function upgradeRequest(request: IncomingMessage, host: string, path: string): string {
  const headers: string[] = [
    `GET ${path} HTTP/1.1`,
    `Host: ${host}:${upstreamPort}`,
    "Connection: Upgrade",
    "Upgrade: websocket",
  ];
  for (const name of [
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-protocol",
    "sec-websocket-extensions",
    "origin",
    "user-agent",
  ]) {
    const value = request.headers[name];
    if (typeof value === "string" && !/[\r\n]/.test(value)) headers.push(`${name}: ${value}`);
  }
  return `${headers.join("\r\n")}\r\n\r\n`;
}

function bearer(request: IncomingMessage): string {
  const value = request.headers.authorization;
  if (!value?.startsWith("Bearer ") || value.length > 8_192) {
    throw new GatewayError(401, "authentication_required", "A bearer token is required");
  }
  return value;
}

function json(response: ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(data),
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
  });
  response.end(data);
}

function requiredUrl(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  const url = new URL(value);
  const developmentHosts = new Set(["codegate-api", "localhost", "127.0.0.1", "host.docker.internal"]);
  if (url.protocol !== "https:" && !developmentHosts.has(url.hostname)) {
    throw new Error(`${name} must use HTTPS outside the cluster`);
  }
  return value.replace(/\/$/, "");
}

function booleanEnv(name: string, fallback: boolean): boolean {
  const value = process.env[name];
  if (value === undefined || value === "") return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be true or false`);
}

function enumEnv<const T extends readonly string[]>(name: string, fallback: T[number], allowed: T): T[number] {
  const value = process.env[name] ?? fallback;
  if (!allowed.includes(value)) throw new Error(`${name} must be one of ${allowed.join(", ")}`);
  return value;
}

function requiredSecret(name: string, minimumLength: number): string {
  const value = process.env[name];
  if (!value || value.length < minimumLength) {
    throw new Error(`${name} must contain at least ${minimumLength} characters`);
  }
  return value;
}

function integerEnv(name: string, fallback: number, min: number, max: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${name} is invalid`);
  return value;
}

class GatewayError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

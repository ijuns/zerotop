import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { fileURLToPath } from "node:url";

import { loadConfig, type GatewayConfig } from "./config.ts";
import { AnthropicMessagesClient } from "./anthropic.ts";
import { GatewayError, ModelGatewayService, type ModelClient } from "./service.ts";

const MAX_REQUEST_BYTES = 1_000_000;

export function createModelGatewayServer(config: GatewayConfig, service = new ModelGatewayService(config, providerClient(config))) {
  let activeRequests = 0;
  const server = createServer(async (request, response) => {
    const startedAt = Date.now();
    let status = 500;
    let errorCode: string | undefined;
    const path = safePath(request.url);
    try {
      if (request.method === "GET" && path === "/health") {
        status = 200;
        send(response, status, { status: "ok", provider: providerLabel(config), modelConfigured: true });
        return;
      }
      if (request.method !== "POST" || !["/v1/generate", "/v1/review", "/v1/rubric"].includes(path)) {
        status = 404;
        send(response, status, { error: { code: "not_found", message: "Route not found" } });
        return;
      }
      requireAuthorization(request, config.internalToken);
      if (!/^application\/json(?:\s*;|$)/i.test(request.headers["content-type"] ?? "")) throw new GatewayError(415, "unsupported_media_type", "Content-Type must be application/json");
      if (activeRequests >= config.maxConcurrency) throw new GatewayError(429, "gateway_busy", "The model gateway concurrency limit was reached");
      activeRequests += 1;
      let output: Record<string, unknown>;
      try {
        const input = await readJson(request);
        output = path === "/v1/generate" ? await service.generate(input)
          : path === "/v1/review" ? await service.review(input)
          : await service.rubric(input);
      } finally {
        activeRequests -= 1;
      }
      status = 200;
      send(response, status, output);
    } catch (error) {
      const failure = error instanceof GatewayError ? error : new GatewayError(500, "internal_error", "The model gateway failed safely");
      status = failure.status;
      errorCode = failure.code;
      send(response, status, {
        error: {
          code: failure.code,
          message: failure.message,
          ...(failure.details ? { details: failure.details } : {}),
        },
      });
    } finally {
      process.stdout.write(`${JSON.stringify({ level: status >= 500 ? "error" : "info", service: "model-gateway", method: request.method, path, status, ...(errorCode ? { errorCode } : {}), durationMs: Date.now() - startedAt })}\n`);
    }
  });
  server.requestTimeout = 125_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxRequestsPerSocket = 100;
  return server;
}

function requireAuthorization(request: IncomingMessage, expected: string): void {
  const value = request.headers.authorization ?? "";
  const supplied = value.startsWith("Bearer ") ? value.slice(7) : "";
  const expectedDigest = createHash("sha256").update(expected).digest();
  const suppliedDigest = createHash("sha256").update(supplied).digest();
  if (!supplied || !timingSafeEqual(expectedDigest, suppliedDigest)) throw new GatewayError(401, "unauthorized", "Invalid internal service token");
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const declaredLength = Number(request.headers["content-length"] ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BYTES) throw new GatewayError(413, "request_too_large", "Request body exceeds its limit");
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    total += bytes.byteLength;
    if (total > MAX_REQUEST_BYTES) throw new GatewayError(413, "request_too_large", "Request body exceeds its limit");
    chunks.push(bytes);
  }
  if (total === 0) throw new GatewayError(400, "invalid_json", "A JSON body is required");
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new GatewayError(400, "invalid_json", "Request body is not valid JSON");
  }
}

function safePath(raw: string | undefined): string {
  try {
    return new URL(raw ?? "/", "http://model-gateway.invalid").pathname;
  } catch {
    return "/invalid";
  }
}

function send(response: ServerResponse, status: number, body: Record<string, unknown>): void {
  if (response.headersSent) return;
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(payload.byteLength),
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
  });
  response.end(payload);
}

async function main(): Promise<void> {
  const config = loadConfig();
  const server = createModelGatewayServer(config);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.port, "0.0.0.0", resolve);
  });
  process.stdout.write(`${JSON.stringify({ level: "info", service: "model-gateway", event: "started", port: config.port, provider: providerLabel(config) })}\n`);
}

function providerClient(config: GatewayConfig): ModelClient {
  return new AnthropicMessagesClient(config);
}

function providerLabel(_config: GatewayConfig): "anthropic-messages" {
  return "anthropic-messages";
}

if (fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    process.stderr.write(`${JSON.stringify({ level: "fatal", service: "model-gateway", message: error instanceof Error ? error.message : "startup failed" })}\n`);
    process.exitCode = 1;
  });
}

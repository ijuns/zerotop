import { randomUUID, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

import type { CreateBuildInput, PublicBuild } from "./contracts.ts";
import { BuilderError } from "./errors.ts";
import { parseCreateBuildInput } from "./validation.ts";

export interface BuilderHttpService {
  create(input: CreateBuildInput, idempotencyKey: string): Promise<PublicBuild>;
  get(id: string): Promise<PublicBuild>;
  cancel(id: string): Promise<PublicBuild>;
}

export function createBuilderHttpHandler(service: BuilderHttpService, internalToken: string): (request: IncomingMessage, response: ServerResponse) => Promise<void> {
  if (internalToken.length < 32) throw new Error("Builder internal token must contain at least 32 characters");
  return async (request, response) => {
    const requestId = safeRequestId(request.headers["x-request-id"]) ?? randomUUID();
    try {
      const url = new URL(request.url ?? "/", "http://builder.internal");
      if (request.method === "GET" && url.pathname === "/health") return json(response, 200, { status: "ok", version: "1.0.0" }, requestId);
      requireBearer(request, internalToken);
      if (request.method === "POST" && url.pathname === "/v1/builds") {
        requireJson(request);
        const idempotencyKey = singleHeader(request.headers["idempotency-key"]);
        if (!idempotencyKey) throw new BuilderError(400, "idempotency_key_required", "Idempotency-Key is required");
        const input = parseCreateBuildInput(await readJson(request));
        return json(response, 202, { data: await service.create(input, idempotencyKey) }, requestId);
      }
      const match = /^\/v1\/builds\/([a-f0-9-]{36})$/i.exec(url.pathname);
      if (match?.[1] && request.method === "GET") return json(response, 200, { data: await service.get(match[1]) }, requestId);
      if (match?.[1] && request.method === "DELETE") return json(response, 200, { data: await service.cancel(match[1]) }, requestId);
      return json(response, 404, { error: { code: "not_found", message: "Route not found", requestId } }, requestId);
    } catch (error) {
      const known = error instanceof BuilderError;
      const status = known ? error.status : 503;
      const code = known ? error.code : "builder_dependency_failure";
      const message = known ? error.message : "The builder could not complete the request";
      if (!known) console.error(JSON.stringify({ level: "error", service: "builder", requestId, error: safeLog(error) }));
      return json(response, status, { error: { code, message, requestId } }, requestId);
    }
  };
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const data = Buffer.from(chunk);
    size += data.length;
    if (size > 4_000_000) throw new BuilderError(413, "request_too_large", "Build request exceeds 4 MB");
    chunks.push(data);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new BuilderError(400, "invalid_json", "Request body is not valid JSON");
  }
}

function requireBearer(request: IncomingMessage, expected: string): void {
  const supplied = request.headers.authorization?.replace(/^Bearer /, "") ?? "";
  const left = Buffer.from(supplied);
  const right = Buffer.from(expected);
  if (left.length !== right.length || !timingSafeEqual(left, right)) throw new BuilderError(401, "unauthorized", "Authorization failed");
}

function requireJson(request: IncomingMessage): void {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers["content-type"] ?? "")) throw new BuilderError(415, "json_required", "Content-Type must be application/json");
}

function json(response: ServerResponse, status: number, body: unknown, requestId: string): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "referrer-policy": "no-referrer",
    "x-request-id": requestId,
  });
  response.end(JSON.stringify(body));
}

function singleHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? undefined : value;
}

function safeRequestId(value: string | string[] | undefined): string | undefined {
  const candidate = singleHeader(value);
  return candidate && /^[a-zA-Z0-9._:-]{1,100}$/.test(candidate) ? candidate : undefined;
}

function safeLog(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).replace(/[\r\n\t]+/g, " ").replace(/(?:token|password|authorization|auth)\s*[=:]\s*\S+/gi, "credential=[redacted]").slice(0, 1_000);
}

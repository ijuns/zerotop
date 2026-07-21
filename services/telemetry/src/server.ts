import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { parseProvision, parseSearch, safeRunId } from "./contracts.ts";
import { ElasticsearchTelemetryStore, TelemetryConflictError } from "./elasticsearch.ts";

const port = integerEnv("PORT", 9201, 1, 65535);
const internalToken = requiredSecret("TELEMETRY_INTERNAL_TOKEN");
const store = new ElasticsearchTelemetryStore({
  url: requiredEnv("ELASTICSEARCH_URL"),
  apiKey: requiredSecret("ELASTICSEARCH_API_KEY"),
});

createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", "http://telemetry.local");
    if (request.method === "GET" && url.pathname === "/health") return json(response, 200, { status: "ok" });
    if (!authorized(request.headers.authorization)) return json(response, 401, { error: { code: "unauthorized" } });
    if (request.method === "POST" && url.pathname === "/v1/runs") {
      const result = await store.provision(parseProvision(await readJson(request)));
      return json(response, result.replayed ? 200 : 201, { data: result });
    }
    const match = url.pathname.match(/^\/v1\/runs\/([^/]+)$/);
    if (match && request.method === "DELETE") {
      await store.delete(safeRunId(decodeURIComponent(match[1]!)));
      response.writeHead(204).end();
      return;
    }
    const search = url.pathname.match(/^\/v1\/runs\/([^/]+)\/search$/);
    if (search && request.method === "POST") {
      const result = await store.search(safeRunId(decodeURIComponent(search[1]!)), parseSearch(await readJson(request)));
      return json(response, 200, { data: result });
    }
    return json(response, 404, { error: { code: "not_found" } });
  } catch (error) {
    const conflict = error instanceof TelemetryConflictError;
    return json(response, conflict ? 409 : 400, {
      error: {
        code: conflict ? "telemetry_manifest_conflict" : "invalid_request",
        message: error instanceof Error ? error.message : "Unknown error",
      },
    });
  }
}).listen(port, "0.0.0.0", () => console.log(JSON.stringify({ level: "info", service: "telemetry", port })));

function authorized(value: string | undefined): boolean {
  const supplied = Buffer.from(value?.startsWith("Bearer ") ? value.slice(7) : "");
  const expected = Buffer.from(internalToken);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > 12_000_000) throw new Error("Request body is too large");
    chunks.push(buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function json(response: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function requiredSecret(name: string): string {
  const value = requiredEnv(name);
  if (value.length < 24) throw new Error(`${name} must contain at least 24 characters`);
  return value;
}

function integerEnv(name: string, fallback: number, minimum: number, maximum: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`${name} is invalid`);
  return value;
}

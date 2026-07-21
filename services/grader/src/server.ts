import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { EvidenceGrader, type EvidenceGradeRequest } from "./grader.ts";

const port = numberEnv("PORT", 9002);
const internalToken = secretEnv("GRADER_INTERNAL_TOKEN");
const grader = new EvidenceGrader({
  elasticsearchUrl: requiredEnv("ELASTICSEARCH_URL"),
  elasticsearchApiKey: secretEnv("ELASTICSEARCH_API_KEY"),
  aiServiceUrl: requiredEnv("AI_SERVICE_URL"),
  aiInternalToken: secretEnv("AI_INTERNAL_TOKEN"),
});

const server = createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/health") {
      return json(response, 200, { status: "ok" });
    }
    if (!authorized(request.headers.authorization)) {
      return json(response, 401, { error: { code: "unauthorized" } });
    }
    if (request.method === "POST" && request.url === "/v1/evidence") {
      const body = (await readJson(request)) as EvidenceGradeRequest;
      const evidence = await grader.grade(body);
      return json(response, 200, { data: { evidence } });
    }
    return json(response, 404, { error: { code: "not_found" } });
  } catch (error) {
    return json(response, 400, {
      error: {
        code: "invalid_request",
        message: error instanceof Error ? error.message : "Unknown error",
      },
    });
  }
});

server.listen(port, "0.0.0.0", () => {
  console.log(JSON.stringify({ level: "info", service: "grader", port }));
});

function authorized(header: string | undefined): boolean {
  const supplied = header?.startsWith("Bearer ") ? header.slice(7) : "";
  const left = Buffer.from(supplied);
  const right = Buffer.from(internalToken);
  return left.length === right.length && timingSafeEqual(left, right);
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const data = Buffer.from(chunk);
    size += data.length;
    if (size > 1_000_000) throw new Error("Request body is too large");
    chunks.push(data);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function json(response: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
  });
  response.end(body);
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function secretEnv(name: string): string {
  const value = requiredEnv(name);
  if (value.length < 24) throw new Error(`${name} must contain at least 24 characters`);
  return value;
}

function numberEnv(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new Error(`${name} is invalid`);
  return value;
}

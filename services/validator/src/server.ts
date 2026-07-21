import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { CliArtifactScanner } from "./artifact-scanner.ts";
import { HttpAiValidationClient, HttpSandboxRunner } from "./clients.ts";
import { ValidationService } from "./validator.ts";

const port = integerEnv("PORT", 9003);
const internalToken = requiredSecret("VALIDATOR_INTERNAL_TOKEN", 24);
const service = new ValidationService({
  artifactScanner: new CliArtifactScanner({
    cosignBin: process.env.COSIGN_BIN,
    syftBin: process.env.SYFT_BIN,
    trivyBin: process.env.TRIVY_BIN,
    craneBin: process.env.CRANE_BIN,
    cosignPublicKeyPath: requiredEnv("COSIGN_PUBLIC_KEY_PATH"),
  }),
  sandboxRunner: new HttpSandboxRunner(
    requiredEnv("SANDBOX_RUNNER_URL"),
    requiredSecret("SANDBOX_RUNNER_INTERNAL_TOKEN", 24),
  ),
  ai: new HttpAiValidationClient(
    requiredEnv("AI_SERVICE_URL"),
    requiredSecret("AI_INTERNAL_TOKEN", 24),
  ),
  allowedRegistries: requiredEnv("TARGET_IMAGE_REGISTRIES")
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean),
});

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", "http://validator.local");
    if (request.method === "GET" && url.pathname === "/health") {
      return json(response, 200, { status: "ok" });
    }
    requireBearer(request, internalToken);
    if (request.method === "POST" && url.pathname === "/v1/validations") {
      const body = await readJson(request);
      const lab = isObject(body) ? body.lab : undefined;
      return json(response, 200, { data: await service.validate(lab) });
    }
    return json(response, 404, { error: { code: "not_found" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Validation failed";
    const status = /authorization/i.test(message) ? 401 : /invalid|must|required|allowed/i.test(message) ? 400 : 502;
    return json(response, status, { error: { code: "validation_failed", message } });
  }
});

server.listen(port, "0.0.0.0", () => {
  console.log(JSON.stringify({ level: "info", service: "validator", port }));
});

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

function requireBearer(request: IncomingMessage, expected: string): void {
  const supplied = request.headers.authorization?.replace(/^Bearer /, "") ?? "";
  const left = Buffer.from(supplied);
  const right = Buffer.from(expected);
  if (left.length !== right.length || !timingSafeEqual(left, right)) throw new Error("Authorization failed");
}

function json(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" });
  response.end(JSON.stringify(body));
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function requiredSecret(name: string, minimumLength: number): string {
  const value = requiredEnv(name);
  if (value.length < minimumLength) throw new Error(`${name} must contain at least ${minimumLength} characters`);
  return value;
}

function integerEnv(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new Error(`${name} is invalid`);
  return value;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

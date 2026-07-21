import { ApiError } from "./errors.ts";
import type { JsonObject } from "./types.ts";

export type EnvironmentBuildStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";

export interface EnvironmentBuildOperation {
  id: string;
  status: EnvironmentBuildStatus;
  createdAt: string;
  updatedAt?: string;
  imageRef?: string;
  imageDigest?: string;
  buildProvenance?: JsonObject;
  consumable?: JsonObject;
  failureCode?: string;
}

export interface EnvironmentBuilder {
  start(input: {
    labId: string;
    labVersion: number;
    requestedBy: string;
    spec: JsonObject;
    idempotencyKey: string;
  }): Promise<EnvironmentBuildOperation>;
  get(buildId: string): Promise<EnvironmentBuildOperation>;
  cancel(buildId: string): Promise<void>;
}

export class HttpEnvironmentBuilder implements EnvironmentBuilder {
  private readonly url: string;
  private readonly token: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: { url: string; token: string; fetchImpl?: typeof fetch }) {
    this.url = safeServiceUrl(options.url);
    if (options.token.length < 24) throw new Error("BUILDER_INTERNAL_TOKEN must contain at least 24 characters");
    this.token = options.token;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async start(input: {
    labId: string;
    labVersion: number;
    requestedBy: string;
    spec: JsonObject;
    idempotencyKey: string;
  }): Promise<EnvironmentBuildOperation> {
    const response = await this.request("/v1/builds", {
      method: "POST",
      headers: { "Idempotency-Key": input.idempotencyKey },
      body: JSON.stringify({
        labId: input.labId,
        labVersion: input.labVersion,
        requestedBy: input.requestedBy,
        spec: input.spec,
      }),
    });
    return parseBuildOperation(response);
  }

  async get(buildId: string): Promise<EnvironmentBuildOperation> {
    return parseBuildOperation(await this.request(`/v1/builds/${encodeURIComponent(identifier(buildId, "buildId"))}`, { method: "GET" }));
  }

  async cancel(buildId: string): Promise<void> {
    await this.request(`/v1/builds/${encodeURIComponent(identifier(buildId, "buildId"))}`, { method: "DELETE" }, true);
  }

  private async request(path: string, options: { method: string; body?: string; headers?: Record<string, string> }, noContent = false): Promise<unknown> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.url}${path}`, {
        method: options.method,
        headers: {
          authorization: `Bearer ${this.token}`,
          accept: "application/json",
          ...(options.body ? { "content-type": "application/json" } : {}),
          ...options.headers,
        },
        ...(options.body ? { body: options.body } : {}),
        signal: AbortSignal.timeout(options.method === "POST" ? 20_000 : 8_000),
      });
    } catch {
      throw new ApiError(503, "BUILDER_UNAVAILABLE", "The environment builder is unavailable.");
    }
    if (noContent && response.status === 404) return null;
    if (!response.ok) {
      throw new ApiError(response.status >= 500 ? 502 : response.status, "BUILDER_REQUEST_FAILED", "The environment builder rejected the request.", { upstreamStatus: response.status });
    }
    if (noContent && response.status === 204) return null;
    return await response.json().catch(() => {
      throw new ApiError(502, "BUILDER_CONTRACT_INVALID", "The environment builder returned malformed JSON.");
    });
  }
}

export class DevelopmentEnvironmentBuilder implements EnvironmentBuilder {
  private readonly operations = new Map<string, EnvironmentBuildOperation>();

  async start(input: { labId: string; spec: JsonObject }): Promise<EnvironmentBuildOperation> {
    const id = `dev-build-${input.labId}`;
    const target = object(input.spec.target);
    const outputRepository = typeof target.outputRepository === "string" ? target.outputRepository : "registry.local/codegate/dev-target";
    const imageDigest = `sha256:${"d".repeat(64)}`;
    const consumable = object(input.spec.consumable);
    const operation: EnvironmentBuildOperation = {
      id,
      status: "succeeded",
      createdAt: new Date().toISOString(),
      imageRef: `${outputRepository}:development`,
      imageDigest,
      buildProvenance: { mode: "development", reproducible: false },
      consumable,
    };
    this.operations.set(id, operation);
    return operation;
  }

  async get(buildId: string): Promise<EnvironmentBuildOperation> {
    const operation = this.operations.get(buildId);
    if (!operation) throw new ApiError(404, "BUILD_NOT_FOUND", "The development build was not found.");
    return operation;
  }

  async cancel(buildId: string): Promise<void> {
    const operation = this.operations.get(buildId);
    if (operation) this.operations.set(buildId, { ...operation, status: "cancelled", updatedAt: new Date().toISOString() });
  }
}

export function parseBuildOperation(value: unknown): EnvironmentBuildOperation {
  const root = object(value);
  const data = Object.keys(object(root.data)).length ? object(root.data) : root;
  const id = identifier(data.id, "build.id");
  const status = data.status;
  if (!new Set(["queued", "running", "succeeded", "failed", "cancelled"]).has(String(status))) {
    throw new ApiError(502, "BUILDER_CONTRACT_INVALID", "The environment builder returned an invalid status.");
  }
  const createdAt = timestamp(data.createdAt, "build.createdAt");
  const result: EnvironmentBuildOperation = { id, status: status as EnvironmentBuildStatus, createdAt };
  if (typeof data.updatedAt === "string") result.updatedAt = timestamp(data.updatedAt, "build.updatedAt");
  if (status === "succeeded") {
    const imageRef = string(data.imageRef, "build.imageRef", 512);
    const imageDigest = string(data.imageDigest, "build.imageDigest", 80).toLowerCase();
    if (!/^[a-z0-9.-]+(?::\d+)?\/[a-z0-9._/-]+(?::[a-z0-9._-]+)?$/i.test(imageRef) || !/^sha256:[a-f0-9]{64}$/.test(imageDigest)) {
      throw new ApiError(502, "BUILDER_CONTRACT_INVALID", "The builder result is not digest-pinned.");
    }
    result.imageRef = imageRef;
    result.imageDigest = imageDigest;
    result.buildProvenance = object(data.buildProvenance);
    result.consumable = object(data.consumable);
  }
  if (typeof data.failureCode === "string") result.failureCode = data.failureCode.slice(0, 128);
  return result;
}

function safeServiceUrl(value: string): string {
  const parsed = new URL(value);
  const internal = parsed.hostname.endsWith(".svc.cluster.local") || !parsed.hostname.includes(".");
  if (parsed.protocol !== "https:" && !internal && parsed.hostname !== "localhost") throw new Error("BUILDER_SERVICE_URL must use HTTPS outside the cluster");
  return value.replace(/\/$/, "");
}

function identifier(value: unknown, name: string): string {
  const result = string(value, name, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(result)) throw new ApiError(502, "BUILDER_CONTRACT_INVALID", `${name} is invalid.`);
  return result;
}

function timestamp(value: unknown, name: string): string {
  const result = string(value, name, 64);
  if (!Number.isFinite(Date.parse(result))) throw new ApiError(502, "BUILDER_CONTRACT_INVALID", `${name} is invalid.`);
  return result;
}

function string(value: unknown, name: string, maximum: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) throw new ApiError(502, "BUILDER_CONTRACT_INVALID", `${name} is invalid.`);
  return value;
}

function object(value: unknown): JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as JsonObject : {};
}

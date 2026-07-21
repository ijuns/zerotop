import { ApiError } from "./errors.ts";
import type { JsonObject } from "./types.ts";

export interface TelemetryEventInput { id: string; document: JsonObject }
export interface TelemetrySearchResult {
  took: number;
  total: number;
  hits: Array<{ id: string; score: number | null; source: JsonObject }>;
}

export interface TelemetryGateway {
  provision(input: { runId: string; expiresAt: string; events: TelemetryEventInput[] }): Promise<void>;
  search(runId: string, query: string, size?: number): Promise<TelemetrySearchResult>;
  destroy(runId: string): Promise<void>;
}

export class HttpTelemetryGateway implements TelemetryGateway {
  private readonly url: string;
  private readonly token: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: { url: string; token: string; fetchImpl?: typeof fetch }) {
    this.url = safeServiceUrl(options.url);
    if (options.token.length < 24) throw new Error("TELEMETRY_INTERNAL_TOKEN must contain at least 24 characters");
    this.token = options.token;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async provision(input: { runId: string; expiresAt: string; events: TelemetryEventInput[] }): Promise<void> {
    await this.request("/v1/runs", { method: "POST", body: JSON.stringify(input) });
  }

  async search(runId: string, query: string, size = 50): Promise<TelemetrySearchResult> {
    const value = await this.request(`/v1/runs/${encodeURIComponent(identifier(runId))}/search`, {
      method: "POST",
      body: JSON.stringify({ query, size }),
    });
    return parseSearchResult(value);
  }

  async destroy(runId: string): Promise<void> {
    await this.request(`/v1/runs/${encodeURIComponent(identifier(runId))}`, { method: "DELETE" }, true);
  }

  private async request(path: string, options: { method: string; body?: string }, noContent = false): Promise<unknown> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.url}${path}`, {
        method: options.method,
        headers: {
          authorization: `Bearer ${this.token}`,
          accept: "application/json",
          ...(options.body ? { "content-type": "application/json" } : {}),
        },
        ...(options.body ? { body: options.body } : {}),
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      throw new ApiError(503, "TELEMETRY_UNAVAILABLE", "The ELK telemetry service is unavailable.");
    }
    if (noContent && response.status === 404) return null;
    if (!response.ok) throw new ApiError(response.status >= 500 ? 502 : response.status, "TELEMETRY_REQUEST_FAILED", "The ELK telemetry service rejected the request.", { upstreamStatus: response.status });
    if (noContent) return null;
    return await response.json().catch(() => {
      throw new ApiError(502, "TELEMETRY_CONTRACT_INVALID", "The ELK telemetry service returned malformed JSON.");
    });
  }
}

export class DevelopmentTelemetryGateway implements TelemetryGateway {
  private readonly events = new Map<string, TelemetryEventInput[]>();
  async provision(input: { runId: string; events: TelemetryEventInput[] }): Promise<void> { this.events.set(input.runId, input.events); }
  async search(runId: string, query: string, size = 50): Promise<TelemetrySearchResult> {
    const normalized = query.toLowerCase();
    const hits = (this.events.get(runId) ?? [])
      .filter((event) => normalized.trim() === "*" || JSON.stringify(event.document).toLowerCase().includes(normalized))
      .slice(0, size);
    return { took: 0, total: hits.length, hits: hits.map((event) => ({ id: event.id, score: 1, source: event.document })) };
  }
  async destroy(runId: string): Promise<void> { this.events.delete(runId); }
}

function parseSearchResult(value: unknown): TelemetrySearchResult {
  const root = object(value);
  const data = Object.keys(object(root.data)).length ? object(root.data) : root;
  const hits = Array.isArray(data.hits) ? data.hits.map((item) => {
    const hit = object(item);
    return {
      id: typeof hit.id === "string" ? hit.id : "",
      score: typeof hit.score === "number" ? hit.score : null,
      source: object(hit.source),
    };
  }).filter((hit) => hit.id) : [];
  if (typeof data.took !== "number" || typeof data.total !== "number") throw new ApiError(502, "TELEMETRY_CONTRACT_INVALID", "The ELK search response is invalid.");
  return { took: data.took, total: data.total, hits };
}

function safeServiceUrl(value: string): string {
  const parsed = new URL(value);
  const internal = parsed.hostname.endsWith(".svc.cluster.local") || !parsed.hostname.includes(".");
  if (parsed.protocol !== "https:" && !internal && parsed.hostname !== "localhost") throw new Error("TELEMETRY_SERVICE_URL must use HTTPS outside the cluster");
  return value.replace(/\/$/, "");
}

function identifier(value: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) throw new ApiError(400, "INVALID_RUN_ID", "runId is invalid.");
  return value;
}

function object(value: unknown): JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as JsonObject : {};
}

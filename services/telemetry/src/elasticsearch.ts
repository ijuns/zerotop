import { createHash } from "node:crypto";
import type { ProvisionTelemetryInput, SearchResult, SearchTelemetryInput } from "./contracts.ts";

export class TelemetryConflictError extends Error {
  constructor() {
    super("A different telemetry manifest already exists for this run");
    this.name = "TelemetryConflictError";
  }
}

export class ElasticsearchTelemetryStore {
  private readonly url: string;
  private readonly apiKey: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: { url: string; apiKey: string; fetchImpl?: typeof fetch }) {
    this.url = safeServiceUrl(options.url);
    if (options.apiKey.length < 24) throw new Error("ELASTICSEARCH_API_KEY must contain at least 24 characters");
    this.apiKey = options.apiKey;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async provision(input: ProvisionTelemetryInput): Promise<{ index: string; eventCount: number; replayed: boolean }> {
    const index = indexForRun(input.runId);
    const manifestHash = hashManifest(input);
    const existing = await this.call(`/${encodeURIComponent(index)}/_doc/__codegate_manifest`, { method: "GET" });
    if (existing.ok) {
      const payload = record(await existing.json().catch(() => null));
      const source = record(payload._source);
      if (source.manifestHash !== manifestHash) throw new TelemetryConflictError();
      return { index, eventCount: input.events.length, replayed: true };
    }
    if (existing.status !== 404) throw await upstreamError(existing, "read telemetry manifest");

    const created = await this.call(`/${encodeURIComponent(index)}`, {
      method: "PUT",
      body: JSON.stringify({
        settings: { number_of_shards: 1, number_of_replicas: 0 },
        mappings: {
          dynamic: true,
          properties: {
            "@timestamp": { type: "date" },
            message: { type: "text", fields: { keyword: { type: "keyword", ignore_above: 256 } } },
            event: { properties: { id: { type: "keyword" }, dataset: { type: "keyword" }, category: { type: "keyword" } } },
            source: { properties: { ip: { type: "ip" } } },
            destination: { properties: { ip: { type: "ip" } } },
            threat: { properties: { technique: { properties: { id: { type: "keyword" } } } } },
            codegate: { properties: { run_id: { type: "keyword" }, expires_at: { type: "date" } } },
          },
        },
      }),
    });
    if (!created.ok) throw await upstreamError(created, "create telemetry index");

    try {
      const documents = [
        { id: "__codegate_manifest", document: { manifestHash, codegate: { run_id: input.runId, expires_at: input.expiresAt } } },
        ...input.events.map((event) => ({
          id: event.id,
          document: { ...event.document, codegate: { ...record(event.document.codegate), run_id: input.runId, expires_at: input.expiresAt } },
        })),
      ];
      const ndjson = documents.flatMap((document) => [
        JSON.stringify({ index: { _index: index, _id: document.id } }),
        JSON.stringify(document.document),
      ]).join("\n") + "\n";
      const bulk = await this.call("/_bulk?refresh=wait_for", { method: "POST", body: ndjson, ndjson: true });
      if (!bulk.ok) throw await upstreamError(bulk, "write telemetry events");
      const result = record(await bulk.json().catch(() => null));
      if (result.errors === true) throw new Error("Elasticsearch rejected one or more telemetry events");
      return { index, eventCount: input.events.length, replayed: false };
    } catch (error) {
      await this.delete(input.runId).catch(() => undefined);
      throw error;
    }
  }

  async search(runId: string, input: SearchTelemetryInput): Promise<SearchResult> {
    const index = indexForRun(runId);
    const response = await this.call(`/${encodeURIComponent(index)}/_search`, {
      method: "POST",
      body: JSON.stringify({
        size: input.size,
        track_total_hits: true,
        timeout: "4s",
        sort: [{ "@timestamp": { order: "desc", unmapped_type: "date" } }, "_score"],
        query: {
          bool: {
            must: [{
              simple_query_string: {
                query: input.query,
                fields: [
                  "@timestamp", "message", "event.*", "host.*", "user.*", "source.*",
                  "destination.*", "process.*", "network.*", "threat.*", "codegate.*",
                ],
                default_operator: "and",
                analyze_wildcard: false,
                flags: "AND|OR|NOT|PHRASE|PRECEDENCE|ESCAPE|WHITESPACE|PREFIX",
              },
            }],
            must_not: [{ ids: { values: ["__codegate_manifest"] } }],
          },
        },
      }),
    });
    if (response.status === 404) return { took: 0, total: 0, hits: [] };
    if (!response.ok) throw await upstreamError(response, "search telemetry");
    const payload = record(await response.json().catch(() => null));
    const hitsRoot = record(payload.hits);
    const totalValue = record(hitsRoot.total).value;
    const hits = (Array.isArray(hitsRoot.hits) ? hitsRoot.hits : []).map((item) => {
      const hit = record(item);
      return {
        id: String(hit._id ?? ""),
        score: typeof hit._score === "number" ? hit._score : null,
        source: record(hit._source),
      };
    }).filter((hit) => hit.id && hit.id !== "__codegate_manifest");
    return {
      took: typeof payload.took === "number" ? payload.took : 0,
      total: typeof totalValue === "number" ? totalValue : hits.length,
      hits,
    };
  }

  async delete(runId: string): Promise<void> {
    const response = await this.call(`/${encodeURIComponent(indexForRun(runId))}`, { method: "DELETE" });
    if (!response.ok && response.status !== 404) throw await upstreamError(response, "delete telemetry index");
  }

  private async call(path: string, options: { method: string; body?: string; ndjson?: boolean }): Promise<Response> {
    return await this.fetchImpl(`${this.url}${path}`, {
      method: options.method,
      headers: {
        authorization: `ApiKey ${this.apiKey}`,
        accept: "application/json",
        ...(options.body ? { "content-type": options.ndjson ? "application/x-ndjson" : "application/json" } : {}),
      },
      ...(options.body ? { body: options.body } : {}),
      signal: AbortSignal.timeout(8_000),
    });
  }
}

export function indexForRun(runId: string): string {
  return `codegate-run-${runId.toLowerCase().replace(/[^a-z0-9-]/g, "-")}`;
}

function hashManifest(input: ProvisionTelemetryInput): string {
  const events = [...input.events]
    .sort((left, right) => left.id.localeCompare(right.id))
    .map((event) => ({ id: event.id, document: canonical(event.document) }));
  return `sha256:${createHash("sha256").update(JSON.stringify({ runId: input.runId, expiresAt: input.expiresAt, events })).digest("hex")}`;
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, canonical(item)]));
}

function safeServiceUrl(value: string): string {
  const parsed = new URL(value);
  const internal = parsed.hostname.endsWith(".svc.cluster.local") || !parsed.hostname.includes(".");
  if (parsed.protocol !== "https:" && !internal && parsed.hostname !== "localhost") throw new Error("ELASTICSEARCH_URL must use HTTPS outside the cluster");
  return value.replace(/\/$/, "");
}

async function upstreamError(response: Response, operation: string): Promise<Error> {
  const detail = (await response.text()).slice(0, 300);
  return new Error(`Elasticsearch could not ${operation} (HTTP ${response.status}): ${detail}`);
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

import type { TelemetryValidationEvent } from "./validation-input.ts";

export interface TelemetryValidationResult {
  indexReady: boolean;
  eventsSearchable: boolean;
}

export interface TelemetryValidator {
  validate(validationId: string, events: TelemetryValidationEvent[]): Promise<TelemetryValidationResult>;
}

export class ElasticsearchTelemetryValidator implements TelemetryValidator {
  private readonly url: string;
  private readonly apiKey: string;
  private readonly fetchImpl: typeof fetch;

  constructor(url: string, apiKey: string, fetchImpl: typeof fetch = fetch) {
    this.url = serviceUrl(url);
    if (apiKey.length < 24) throw new Error("ELASTICSEARCH_API_KEY must contain at least 24 characters");
    this.apiKey = apiKey;
    this.fetchImpl = fetchImpl;
  }

  async validate(validationId: string, events: TelemetryValidationEvent[]): Promise<TelemetryValidationResult> {
    const suffix = validationId.toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 60);
    const index = `codegate-validation-${suffix}`;
    let indexReady = false;
    try {
      const created = await this.call(`/${encodeURIComponent(index)}`, {
        method: "PUT",
        body: JSON.stringify({
          settings: { number_of_shards: 1, number_of_replicas: 0 },
          mappings: {
            dynamic: true,
            properties: {
              "@timestamp": { type: "date" },
              event: { properties: { id: { type: "keyword" }, dataset: { type: "keyword" } } },
              threat: { properties: { technique: { properties: { id: { type: "keyword" } } } } },
            },
          },
        }),
      });
      indexReady = created.ok;
      if (!indexReady) return { indexReady: false, eventsSearchable: false };
      const bulkLines = events.flatMap((event) => [
        JSON.stringify({ index: { _index: index, _id: event.id } }),
        JSON.stringify(event.document),
      ]).join("\n") + "\n";
      const bulk = await this.call("/_bulk?refresh=wait_for", { method: "POST", body: bulkLines, ndjson: true });
      if (!bulk.ok) return { indexReady, eventsSearchable: false };
      const bulkValue = record(await bulk.json().catch(() => null));
      if (bulkValue.errors === true) return { indexReady, eventsSearchable: false };
      const lookup = await this.call(`/${encodeURIComponent(index)}/_mget`, {
        method: "POST",
        body: JSON.stringify({ ids: events.map((event) => event.id) }),
      });
      if (!lookup.ok) return { indexReady, eventsSearchable: false };
      const payload = record(await lookup.json().catch(() => null));
      const found = new Set(
        (Array.isArray(payload.docs) ? payload.docs : [])
          .map(record)
          .filter((document) => document.found === true && typeof document._id === "string")
          .map((document) => String(document._id)),
      );
      return { indexReady, eventsSearchable: events.every((event) => found.has(event.id)) };
    } catch {
      return { indexReady, eventsSearchable: false };
    } finally {
      if (indexReady) await this.call(`/${encodeURIComponent(index)}`, { method: "DELETE" }).catch(() => undefined);
    }
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
      signal: AbortSignal.timeout(10_000),
    });
  }
}

export class DevelopmentTelemetryValidator implements TelemetryValidator {
  async validate(_validationId: string, events: TelemetryValidationEvent[]): Promise<TelemetryValidationResult> {
    return { indexReady: events.length > 0, eventsSearchable: events.length > 0 };
  }
}

function serviceUrl(value: string): string {
  const url = new URL(value);
  const internal = url.hostname.endsWith(".svc.cluster.local") || !url.hostname.includes(".");
  if (url.protocol !== "https:" && !internal && url.hostname !== "localhost") {
    throw new Error("ELASTICSEARCH_URL must use HTTPS outside the cluster");
  }
  return value.replace(/\/$/, "");
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

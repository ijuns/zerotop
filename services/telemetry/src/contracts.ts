export interface TelemetryEvent {
  id: string;
  document: Record<string, unknown>;
}

export interface ProvisionTelemetryInput {
  runId: string;
  expiresAt: string;
  events: TelemetryEvent[];
}

export interface SearchTelemetryInput {
  query: string;
  size: number;
}

export interface SearchHit {
  id: string;
  score: number | null;
  source: Record<string, unknown>;
}

export interface SearchResult {
  took: number;
  total: number;
  hits: SearchHit[];
}

export function parseProvision(value: unknown): ProvisionTelemetryInput {
  const root = record(value, "request");
  const runId = safeIdentifier(root.runId, "runId", 63);
  const expiresAt = stringValue(root.expiresAt, "expiresAt", 64);
  const expiry = Date.parse(expiresAt);
  if (!Number.isFinite(expiry) || expiry <= Date.now() || expiry > Date.now() + 24 * 60 * 60 * 1_000) {
    throw new Error("expiresAt must be within the next 24 hours");
  }
  if (!Array.isArray(root.events) || root.events.length < 1 || root.events.length > 1_000) {
    throw new Error("events must contain 1-1000 entries");
  }
  let bytes = 0;
  const events = root.events.map((item, index) => {
    const event = record(item, `events[${index}]`);
    const id = safeIdentifier(event.id, `events[${index}].id`, 128);
    if (id.startsWith("__codegate_")) throw new Error("event ID uses a reserved prefix");
    const document = record(event.document, `events[${index}].document`);
    bytes += Buffer.byteLength(JSON.stringify(document));
    return { id, document };
  });
  if (bytes > 10_000_000) throw new Error("events exceed the 10 MB limit");
  if (new Set(events.map((event) => event.id)).size !== events.length) throw new Error("event IDs must be unique");
  return { runId, expiresAt: new Date(expiry).toISOString(), events };
}

export function parseSearch(value: unknown): SearchTelemetryInput {
  const root = record(value, "request");
  const query = stringValue(root.query, "query", 1_000).trim();
  if (!query || /[{}\[\]\/\\]|\*\s*(?:$|\s)|(?:^|\s)\*/.test(query) || /~\d*/.test(query)) {
    throw new Error("query contains unsupported or expensive syntax");
  }
  const size = root.size === undefined ? 50 : Number(root.size);
  if (!Number.isInteger(size) || size < 1 || size > 100) throw new Error("size must be an integer between 1 and 100");
  return { query, size };
}

export function safeRunId(value: unknown): string {
  return safeIdentifier(value, "runId", 63);
}

function safeIdentifier(value: unknown, name: string, maximum: number): string {
  const result = stringValue(value, name, maximum);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(result)) throw new Error(`${name} is invalid`);
  return result;
}

function stringValue(value: unknown, name: string, maximum: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) throw new Error(`${name} is invalid`);
  return value;
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value as Record<string, unknown>;
}

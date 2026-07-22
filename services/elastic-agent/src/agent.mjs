import { readFile, writeFile } from "node:fs/promises";

const elasticsearchHost = internalServiceUrl(
  process.env.ELASTICSEARCH_HOST ?? "http://elasticsearch:9200",
  "elasticsearch",
  "9200",
  "ELASTICSEARCH_HOST",
);
const kibanaHost = internalServiceUrl(
  process.env.KIBANA_HOST ?? "http://kibana:5601",
  "kibana",
  "5601",
  "KIBANA_HOST",
);
const index = indexName(process.env.ELASTIC_INDEX ?? "zerotop-logs");
const logPath = process.env.SCENARIO_LOG_PATH ?? "/var/log/zerotop/scenario.ndjson";
const readyPath = "/tmp/zerotop-agent-ready";
const shipped = new Map();
let dataViewReady = false;

for (;;) {
  try {
    await waitForElasticsearch();
    const documents = await readDocuments(logPath);
    const pending = documents.filter((item) => shipped.get(item.id) !== item.digest);
    if (pending.length > 0) await bulkIndex(pending);
    for (const item of pending) shipped.set(item.id, item.digest);
    if (!dataViewReady) {
      await ensureKibanaDataView();
      dataViewReady = true;
    }
    await writeFile(readyPath, new Date().toISOString(), { encoding: "utf8", mode: 0o600 });
    console.log(JSON.stringify({
      level: "info",
      service: "elastic-agent",
      index,
      discovered: documents.length,
      shipped: pending.length,
    }));
  } catch (error) {
    console.error(JSON.stringify({
      level: "warn",
      service: "elastic-agent",
      message: error instanceof Error ? error.message : String(error),
    }));
  }
  await delay(2_000);
}

async function waitForElasticsearch() {
  const response = await fetch(`${elasticsearchHost}/_cluster/health?wait_for_status=yellow&timeout=2s`, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(3_000),
  });
  if (!response.ok) throw new Error(`Elasticsearch readiness returned HTTP ${response.status}`);
}

async function readDocuments(path) {
  const body = await readFile(path, "utf8");
  const lines = body.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
  if (lines.length < 1 || lines.length > 5_000) throw new Error("Scenario log must contain 1-5,000 events");
  return lines.map((line, lineNumber) => {
    if (Buffer.byteLength(line) > 32_000) throw new Error(`Scenario log line ${lineNumber + 1} is too large`);
    let document;
    try {
      document = JSON.parse(line);
    } catch (error) {
      throw new Error(`Scenario log line ${lineNumber + 1} is invalid JSON`, { cause: error });
    }
    if (!isRecord(document)) throw new Error(`Scenario log line ${lineNumber + 1} is not an object`);
    const event = isRecord(document.event) ? document.event : {};
    const id = typeof event.id === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(event.id)
      ? event.id
      : `event-${lineNumber + 1}`;
    return { id, document, digest: digestText(line) };
  });
}

async function bulkIndex(documents) {
  for (let offset = 0; offset < documents.length; offset += 500) {
    const chunk = documents.slice(offset, offset + 500);
    const body = `${chunk.flatMap((item) => [
      JSON.stringify({ index: { _index: index, _id: item.id } }),
      JSON.stringify(item.document),
    ]).join("\n")}\n`;
    const response = await fetch(`${elasticsearchHost}/_bulk?refresh=false`, {
      method: "POST",
      headers: { "content-type": "application/x-ndjson", accept: "application/json" },
      body,
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`Elasticsearch bulk indexing returned HTTP ${response.status}`);
    const result = await response.json();
    if (isRecord(result) && result.errors === true) throw new Error("Elasticsearch rejected one or more events");
  }
  const refresh = await fetch(`${elasticsearchHost}/${encodeURIComponent(index)}/_refresh`, {
    method: "POST",
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(5_000),
  });
  if (!refresh.ok) throw new Error(`Elasticsearch index refresh returned HTTP ${refresh.status}`);
}

async function ensureKibanaDataView() {
  const status = await fetch(`${kibanaHost}/api/status`, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(4_000),
  });
  if (!status.ok) throw new Error(`Kibana readiness returned HTTP ${status.status}`);

  const response = await fetch(`${kibanaHost}/api/data_views/data_view`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
      "kbn-xsrf": "zerotop-runtime",
    },
    body: JSON.stringify({
      data_view: {
        id: `zerotop-${index}`,
        name: `ZeroTOP ${index}`,
        title: index,
        timeFieldName: "@timestamp",
        allowNoIndex: true,
      },
      override: true,
    }),
    signal: AbortSignal.timeout(8_000),
  });
  if (!response.ok && response.status !== 409) {
    throw new Error(`Kibana data view creation returned HTTP ${response.status}`);
  }
}

function internalServiceUrl(value, expectedHost, expectedPort, name) {
  const parsed = new URL(value);
  if (parsed.protocol !== "http:" || parsed.hostname !== expectedHost || parsed.port !== expectedPort) {
    throw new Error(`${name} must point to the isolated runtime service http://${expectedHost}:${expectedPort}`);
  }
  return parsed.toString().replace(/\/$/, "");
}

function indexName(value) {
  const result = value.toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{0,126}$/.test(result) || result.includes("..")) {
    throw new Error("ELASTIC_INDEX is invalid");
  }
  return result;
}

function digestText(value) {
  // A compact, deterministic non-cryptographic digest is sufficient for local
  // change detection; Elasticsearch document IDs provide idempotent writes.
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

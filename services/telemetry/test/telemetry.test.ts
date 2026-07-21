import assert from "node:assert/strict";
import test from "node:test";
import { parseProvision, parseSearch } from "../src/contracts.ts";
import { ElasticsearchTelemetryStore, TelemetryConflictError, indexForRun } from "../src/elasticsearch.ts";

const future = new Date(Date.now() + 60 * 60 * 1_000).toISOString();

test("validates bounded telemetry manifests and safe search syntax", () => {
  const input = parseProvision({
    runId: "run-123",
    expiresAt: future,
    events: [{ id: "evidence-1", document: { "@timestamp": new Date().toISOString(), source: { ip: "192.0.2.3" } } }],
  });
  assert.equal(input.events.length, 1);
  assert.deepEqual(parseSearch({ query: "source.ip:192.0.2.3 AND event.category:network", size: 20 }), {
    query: "source.ip:192.0.2.3 AND event.category:network",
    size: 20,
  });
  assert.throws(() => parseSearch({ query: "message:/expensive.*/" }), /unsupported/);
  assert.throws(() => parseSearch({ query: "*admin" }), /unsupported/);
});

test("creates only the server-derived run index and returns sanitized search hits", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const store = new ElasticsearchTelemetryStore({
    url: "http://elasticsearch:9200",
    apiKey: "a".repeat(24),
    fetchImpl: async (input, init) => {
      const url = String(input);
      requests.push({ url, init });
      if (url.endsWith("/_doc/__codegate_manifest")) return new Response("not found", { status: 404 });
      if (url.endsWith("/_search")) return new Response(JSON.stringify({
        took: 3,
        hits: { total: { value: 2 }, hits: [{ _id: "evidence-1", _score: 1, _source: { event: { category: "network" } } }] },
      }), { status: 200 });
      if (url.endsWith("/_bulk?refresh=wait_for")) return new Response(JSON.stringify({ errors: false }), { status: 200 });
      return new Response(JSON.stringify({ acknowledged: true }), { status: 200 });
    },
  });
  const input = parseProvision({ runId: "run-123", expiresAt: future, events: [{ id: "evidence-1", document: { message: "test" } }] });
  const provisioned = await store.provision(input);
  assert.equal(provisioned.index, "codegate-run-run-123");
  const result = await store.search("run-123", parseSearch({ query: "event.category:network" }));
  assert.equal(result.hits[0]?.id, "evidence-1");
  assert.ok(requests.every((request) => !request.url.includes("..")));
});

test("replays the same manifest and rejects a different manifest", async () => {
  const input = parseProvision({ runId: "run-123", expiresAt: future, events: [{ id: "evidence-1", document: { message: "test" } }] });
  const firstStore = new ElasticsearchTelemetryStore({
    url: "http://elasticsearch:9200",
    apiKey: "a".repeat(24),
    fetchImpl: async () => new Response(JSON.stringify({ _source: { manifestHash: "different" } }), { status: 200 }),
  });
  await assert.rejects(() => firstStore.provision(input), TelemetryConflictError);
});

test("normalizes index names without accepting caller-controlled index syntax", () => {
  assert.equal(indexForRun("Run_ABC.1"), "codegate-run-run-abc-1");
});

import assert from "node:assert/strict";
import test from "node:test";
import { HttpTelemetryGateway } from "../src/telemetry.ts";

test("telemetry client searches only through the run-scoped endpoint", async () => {
  let requested = "";
  const client = new HttpTelemetryGateway({
    url: "http://telemetry:9201",
    token: "t".repeat(24),
    fetchImpl: async (input) => {
      requested = String(input);
      return Response.json({ data: { took: 2, total: 1, hits: [{ id: "evidence-1", score: 1, source: { message: "detected" } }] } });
    },
  });
  const result = await client.search("run-1", "message:detected", 20);
  assert.match(requested, /\/v1\/runs\/run-1\/search$/);
  assert.equal(result.hits[0]?.id, "evidence-1");
});

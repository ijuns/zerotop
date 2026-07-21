import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import type { AddressInfo } from "node:net";
import { createValidationCanaryServer } from "../src/server.ts";

test("serves only the health response", async (context) => {
  const server = createValidationCanaryServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());

  const port = (server.address() as AddressInfo).port;
  const health = await fetch(`http://127.0.0.1:${port}/health`);
  assert.equal(health.status, 200);
  assert.equal(health.headers.get("cache-control"), "no-store");
  assert.deepEqual(await health.json(), { status: "ok" });

  const missing = await fetch(`http://127.0.0.1:${port}/`);
  assert.equal(missing.status, 404);
});

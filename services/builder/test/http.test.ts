import assert from "node:assert/strict";
import { createServer } from "node:http";
import { test } from "node:test";

import type { CreateBuildInput, PublicBuild } from "../src/contracts.ts";
import { createBuilderHttpHandler, type BuilderHttpService } from "../src/http.ts";
import { validBlueInput } from "./fixtures.ts";

const TOKEN = "builder-internal-token-that-is-long-enough";
const BUILD_ID = "11111111-1111-4111-8111-111111111111";

class StubService implements BuilderHttpService {
  createCalls: Array<{ input: CreateBuildInput; key: string }> = [];

  async create(input: CreateBuildInput, idempotencyKey: string): Promise<PublicBuild> {
    this.createCalls.push({ input, key: idempotencyKey });
    return result("running");
  }

  async get(): Promise<PublicBuild> { return result("running"); }
  async cancel(): Promise<PublicBuild> { return result("cancelled"); }
}

test("HTTP boundary enforces bearer auth, JSON, idempotency, and security headers", async () => {
  const service = new StubService();
  const server = createServer(createBuilderHttpHandler(service, TOKEN));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Test server did not bind TCP");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const health = await fetch(`${base}/health`);
    assert.equal(health.status, 200);
    assert.equal(health.headers.get("cache-control"), "no-store");
    assert.equal(health.headers.get("content-security-policy"), "default-src 'none'; frame-ancestors 'none'");

    const unauthorized = await fetch(`${base}/v1/builds/${BUILD_ID}`);
    assert.equal(unauthorized.status, 401);
    assert.equal((await unauthorized.json() as any).error.code, "unauthorized");

    const missingKey = await fetch(`${base}/v1/builds`, {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify(validBlueInput()),
    });
    assert.equal(missingKey.status, 400);

    const created = await fetch(`${base}/v1/builds`, {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json", "idempotency-key": "request-12345" },
      body: JSON.stringify(validBlueInput()),
    });
    assert.equal(created.status, 202);
    assert.equal((await created.json() as any).data.status, "running");
    assert.equal(service.createCalls[0]?.key, "request-12345");

    const cancelled = await fetch(`${base}/v1/builds/${BUILD_ID}`, { method: "DELETE", headers: { authorization: `Bearer ${TOKEN}` } });
    assert.equal(cancelled.status, 200);
    assert.equal((await cancelled.json() as any).data.status, "cancelled");
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

function result(status: PublicBuild["status"]): PublicBuild {
  return {
    id: BUILD_ID,
    labId: "lab-cve-2026-12345",
    labVersion: 3,
    status,
    statusUrl: `/v1/builds/${BUILD_ID}`,
    createdAt: "2026-07-21T10:00:00.000Z",
  };
}

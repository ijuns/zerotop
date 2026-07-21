import assert from "node:assert/strict";
import test from "node:test";
import { HttpEnvironmentBuilder, parseBuildOperation } from "../src/environment-builder.ts";

test("environment builder client authenticates and preserves idempotency", async () => {
  let request: RequestInit | undefined;
  const client = new HttpEnvironmentBuilder({
    url: "http://builder:9004",
    token: "x".repeat(24),
    fetchImpl: async (_input, init) => {
      request = init;
      return Response.json({ data: { id: "build-1", status: "queued", createdAt: "2026-07-21T00:00:00.000Z" } }, { status: 202 });
    },
  });
  const result = await client.start({ labId: "lab-1", labVersion: 1, requestedBy: "user-1", spec: {}, idempotencyKey: "builder-idempotency-1" });
  assert.equal(result.status, "queued");
  assert.equal(new Headers(request?.headers).get("authorization"), `Bearer ${"x".repeat(24)}`);
  assert.equal(new Headers(request?.headers).get("idempotency-key"), "builder-idempotency-1");
});

test("successful builder results require a digest and consumable contract", () => {
  const result = parseBuildOperation({
    data: {
      id: "build-1",
      status: "succeeded",
      createdAt: "2026-07-21T00:00:00.000Z",
      imageRef: "registry.codegate.local/ranges/lab-1:1",
      imageDigest: `sha256:${"a".repeat(64)}`,
      buildProvenance: { builder: "buildkit" },
      consumable: { target: { service: { port: 80, protocol: "http" } } },
    },
  });
  assert.equal(result.imageDigest, `sha256:${"a".repeat(64)}`);
  assert.throws(() => parseBuildOperation({ data: { ...result, imageDigest: "sha256:short" } }), /digest-pinned/);
});

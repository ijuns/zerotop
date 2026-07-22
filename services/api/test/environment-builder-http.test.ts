import assert from "node:assert/strict";
import test from "node:test";
import { DevelopmentEnvironmentBuilder, HttpEnvironmentBuilder, parseBuildOperation } from "../src/environment-builder.ts";

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

test("development builder binds an external AI spec to the approved local target image", async () => {
  const imageDigest = `sha256:${"b".repeat(64)}`;
  const builder = new DevelopmentEnvironmentBuilder({
    targetImage: `codegate/local-target@${imageDigest}`,
  });
  const runtimeContract = {
    kind: "http-v1", uid: 65_532, gid: 65_532, protocol: "http", port: 8_080,
    writablePaths: ["/tmp"], readOnlyRootFilesystem: true, bindAddress: "0.0.0.0",
    healthPath: "/health", fingerprintPath: "/version",
  };
  const topology = {
    schemaVersion: 1, team: "red", isolation: "per_run",
    workstation: { role: "attack_operator", desktopImage: "kali", entrypoint: "target" },
    target: { role: "vulnerable_target", hostname: "target" },
  };
  const result = await builder.start({
    labId: "lab-external-red",
    labVersion: 1,
    requestedBy: "user_dev",
    idempotencyKey: "development-builder-test",
    spec: {
      schemaVersion: 1,
      team: "red",
      source: { promptDigest: `sha256:${"c".repeat(64)}`, cveIds: [] },
      scenario: { summary: "Bounded local target", mitreTechniques: ["T1190"] },
      target: {
        name: "local-target",
        baseImage: `codegate/local-target@${imageDigest}`,
        outputRepository: "codegate/local-target",
        service: { port: 8_080, protocol: "http" },
        runtimeContract,
        packages: [],
        artifacts: [],
        functionalProbes: [{ id: "health", kind: "http", method: "GET", path: "/health", expectedStatuses: [200], bodyIncludes: ["ok"] }],
        vulnerabilityProbes: [{ id: "fingerprint", kind: "http", method: "GET", path: "/version", expectedStatuses: [200], bodyIncludes: ["http-v1"], findingId: "scenario-local" }],
      },
      topology,
      learning: { title: "로컬 실습", summary: "격리된 실습", sections: [] },
      questions: [{ id: "q1", type: "free_text", prompt: "관찰 결과를 설명하세요.", points: 10 }],
      grading: { hiddenRefs: [{ questionId: "q1", refId: "grading://q1", rubricDigest: `sha256:${"d".repeat(64)}` }] },
    },
  });

  assert.equal(result.imageRef, "codegate/local-target");
  assert.equal(result.imageDigest, imageDigest);
  assert.equal(result.buildProvenance?.canonicalImage, `codegate/local-target@${imageDigest}`);
  const consumable = result.consumable as Record<string, unknown>;
  const target = consumable.target as Record<string, unknown>;
  assert.equal(target.canonicalImage, `codegate/local-target@${imageDigest}`);
  assert.deepEqual(target.expectedCves, []);
  assert.deepEqual(consumable.topology, topology);
  assert.deepEqual(
    (target.validation as Record<string, unknown>).service,
    { port: 8_080, protocol: "http" },
  );
});

test("development builder rejects malformed configured target coordinates", () => {
  assert.throws(
    () => new DevelopmentEnvironmentBuilder({ targetImage: "codegate/local-target:latest" }),
    /digest-pinned OCI image/,
  );
});

import assert from "node:assert/strict";
import test from "node:test";

import { ApiError } from "../src/errors.ts";
import { HttpRuntimeAdapter } from "../src/runtime.ts";

test("HTTP runtime adapter provisions through the authenticated control plane", async () => {
  let capturedUrl = "";
  let capturedInit: RequestInit | undefined;
  const adapter = new HttpRuntimeAdapter({
    serviceUrl: "http://codegate-runtime:9000/",
    internalToken: "internal-secret",
    targetImage: `registry.codegate.internal/ranges/target@sha256:${"a".repeat(64)}`,
    desktopPublicUrl: "https://desktop.codegate.example",
    fetchImpl: async (input, init) => {
      capturedUrl = String(input);
      capturedInit = init;
      return Response.json(
        {
          id: "ignored-by-adapter",
          status: "provisioning",
          namespace: "range-run-fixture",
          expiresAt: "2026-07-21T12:00:00.000Z",
          browserDesktop: {
            gatewayPath: "/sessions/run-fixture/desktop",
            protocol: "websocket",
          },
          openVpn: {
            profileId: "profile-fixture",
            endpoint: "vpn.codegate.example:1194",
            assignedIp: "10.77.1.10",
            allowedCidr: "10.77.0.0/16",
            expiresAt: "2026-07-21T12:00:00.000Z",
          },
        },
        { status: 202 },
      );
    },
  });

  const run = await adapter.createRun(
    {
      id: "lab-fixture",
      desktopImage: "kali",
      config: {
        target: {
          imageRef: "registry.codegate.internal/ranges/lab-target",
          imageDigest: `sha256:${"b".repeat(64)}`,
          source: "lab_spec",
          service: { port: 8080, protocol: "http" },
          runtimeContract: {
            kind: "http-v1", uid: 65532, gid: 65532, protocol: "http", port: 8080,
            writablePaths: ["/tmp"], readOnlyRootFilesystem: true, bindAddress: "0.0.0.0",
            healthPath: "/health", fingerprintPath: "/version",
          },
        },
      },
    },
    "user-fixture",
    "openvpn",
  );
  assert.equal(capturedUrl, "http://codegate-runtime:9000/v1/runs/provision");
  assert.equal(
    new Headers(capturedInit?.headers).get("authorization"),
    "Bearer internal-secret",
  );
  const request = JSON.parse(String(capturedInit?.body)) as Record<string, unknown>;
  assert.equal(request.desktopImage, "kali");
  assert.equal(request.accessMethod, "openvpn");
  assert.equal(
    request.targetImage,
    `registry.codegate.internal/ranges/lab-target@sha256:${"b".repeat(64)}`,
  );
  assert.deepEqual(request.targetService, { port: 8080, protocol: "http" });
  assert.equal((request.targetRuntimeContract as Record<string, unknown>).kind, "http-v1");
  assert.equal(run.status, "provisioning");
  assert.equal(run.openvpnProfile?.profileId, "profile-fixture");
});

test("HTTP runtime adapter supplies the fixed ABI for a development template target", async () => {
  let capturedBody: Record<string, unknown> = {};
  const adapter = new HttpRuntimeAdapter({
    serviceUrl: "http://codegate-runtime:9000",
    internalToken: "internal-secret",
    targetImage: `local.codegate.invalid/codegate/local-target@sha256:${"0".repeat(64)}`,
    allowTemplateFallback: true,
    fetchImpl: async (_input, init) => {
      capturedBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return Response.json({
        status: "provisioning",
        namespace: "range-run-fixture",
        expiresAt: "2026-07-21T12:00:00.000Z",
        browserDesktop: { gatewayPath: "/sessions/run-fixture/desktop", protocol: "websocket" },
      }, { status: 202 });
    },
  });

  await adapter.createRun({
    id: "lab-fixture",
    desktopImage: "ubuntu",
    config: { target: { source: "template_fallback" } },
  }, "user-fixture", "browser_desktop");

  assert.deepEqual(capturedBody.targetService, { port: 8080, protocol: "http" });
  assert.deepEqual(capturedBody.targetRuntimeContract, {
    kind: "http-v1", uid: 65532, gid: 65532, protocol: "http", port: 8080,
    writablePaths: ["/tmp"], readOnlyRootFilesystem: true, bindAddress: "0.0.0.0",
    healthPath: "/health", fingerprintPath: "/version",
  });
});

test("HTTP runtime adapter explicitly rejects a TCP target without a supported runtime ABI", async () => {
  const adapter = new HttpRuntimeAdapter({
    serviceUrl: "http://codegate-runtime:9000",
    internalToken: "internal-secret",
    fetchImpl: async () => { throw new Error("must not call runtime"); },
  });
  await assert.rejects(
    adapter.createRun({
      id: "lab-fixture",
      config: {
        target: {
          imageRef: "registry.codegate.internal/ranges/lab-target",
          imageDigest: `sha256:${"b".repeat(64)}`,
        },
        validation: { service: { port: 2222, protocol: "tcp" } },
      },
    }, "user-fixture", "browser_desktop"),
    (error: unknown) => error instanceof ApiError && error.code === "LAB_TARGET_RUNTIME_CONTRACT_INVALID",
  );
});

test("HTTP runtime adapter rejects conflicting target service contracts", async () => {
  const adapter = new HttpRuntimeAdapter({
    serviceUrl: "http://codegate-runtime:9000",
    internalToken: "internal-secret",
    fetchImpl: async () => { throw new Error("must not call runtime"); },
  });
  await assert.rejects(
    adapter.createRun({
      id: "lab-fixture",
      config: {
        target: {
          imageRef: "registry.codegate.internal/ranges/lab-target",
          imageDigest: `sha256:${"b".repeat(64)}`,
          service: { port: 8080, protocol: "http" },
          runtimeContract: {
            kind: "http-v1", uid: 65532, gid: 65532, protocol: "http", port: 8080,
            writablePaths: ["/tmp"], readOnlyRootFilesystem: true, bindAddress: "0.0.0.0",
            healthPath: "/health", fingerprintPath: "/version",
          },
        },
        validation: { service: { port: 9090, protocol: "http" } },
      },
    }, "user-fixture", "browser_desktop"),
    (error: unknown) => error instanceof ApiError && error.code === "LAB_TARGET_SERVICE_MISMATCH",
  );
});

test("HTTP runtime adapter reads bounded readiness status", async () => {
  let capturedAuthorization = "";
  const adapter = new HttpRuntimeAdapter({
    serviceUrl: "http://codegate-runtime:9000",
    internalToken: "internal-secret",
    fetchImpl: async (_input, init) => {
      capturedAuthorization = new Headers(init?.headers).get("authorization") ?? "";
      return Response.json({
        id: "run-fixture",
        status: "failed",
        namespace: "range-run-fixture",
        expiresAt: "2026-07-21T12:00:00.000Z",
        checks: {
          workstationVmi: true,
          targetWorkload: false,
          desktopEndpoints: false,
        },
        reason: "Runtime readiness deadline was exceeded",
      });
    },
  });

  const status = await adapter.getRunStatus("run-fixture");
  assert.equal(capturedAuthorization, "Bearer internal-secret");
  assert.equal(status.status, "failed");
  assert.equal(status.checks.targetWorkload, false);
  assert.match(status.reason ?? "", /deadline/);
});

test("HTTP runtime adapter destroys a run through the authenticated control plane", async () => {
  let capturedUrl = "";
  let capturedInit: RequestInit | undefined;
  const adapter = new HttpRuntimeAdapter({
    serviceUrl: "http://codegate-runtime:9000/",
    internalToken: "internal-secret",
    fetchImpl: async (input, init) => {
      capturedUrl = String(input);
      capturedInit = init;
      return new Response(null, { status: 204 });
    },
  });

  await adapter.destroyRun("run/fixture");

  assert.equal(
    capturedUrl,
    "http://codegate-runtime:9000/v1/runs/run%2Ffixture",
  );
  assert.equal(capturedInit?.method, "DELETE");
  assert.equal(
    new Headers(capturedInit?.headers).get("authorization"),
    "Bearer internal-secret",
  );
});

test("HTTP runtime adapter treats an already absent run as destroyed", async () => {
  const adapter = new HttpRuntimeAdapter({
    serviceUrl: "http://codegate-runtime:9000",
    internalToken: "internal-secret",
    fetchImpl: async () => new Response(null, { status: 404 }),
  });

  await adapter.destroyRun("run-fixture");
});

test("HTTP runtime adapter reports rejected destroy requests", async () => {
  const adapter = new HttpRuntimeAdapter({
    serviceUrl: "http://codegate-runtime:9000",
    internalToken: "internal-secret",
    fetchImpl: async () => new Response(null, { status: 409 }),
  });

  await assert.rejects(
    adapter.destroyRun("run-fixture"),
    (error: unknown) =>
      error instanceof ApiError &&
      error.status === 502 &&
      error.code === "RUNTIME_DESTROY_FAILED" &&
      (error.details as { status?: number }).status === 409,
  );
});

test("HTTP runtime adapter reports unavailable destroy requests", async () => {
  const adapter = new HttpRuntimeAdapter({
    serviceUrl: "http://codegate-runtime:9000",
    internalToken: "internal-secret",
    fetchImpl: async () => {
      throw new Error("connection refused");
    },
  });

  await assert.rejects(
    adapter.destroyRun("run-fixture"),
    (error: unknown) =>
      error instanceof ApiError &&
      error.status === 503 &&
      error.code === "RUNTIME_SERVICE_UNAVAILABLE",
  );
});

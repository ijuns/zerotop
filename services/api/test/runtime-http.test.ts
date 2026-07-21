import assert from "node:assert/strict";
import test from "node:test";

import { ApiError } from "../src/errors.ts";
import { buildDevelopmentCapabilityFixtures } from "../src/development-fixtures.ts";
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
        topology: {
          schemaVersion: 1,
          team: "red",
          isolation: "per_run",
          workstation: { role: "attack_operator", desktopImage: "kali", entrypoint: "target" },
          target: { role: "vulnerable_target", hostname: "target" },
        },
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
  assert.equal((request.topology as Record<string, unknown>).team, "red");
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
    teamType: "blue",
    desktopImage: "ubuntu",
    config: {
      target: { source: "template_fallback" },
      telemetry: {
        events: [{
          id: "development-template-event",
          document: {
            "@timestamp": "2026-07-21T10:00:00.000Z",
            event: { category: "process" },
            threat: { technique: { id: ["T1059.001"] } },
          },
        }],
      },
    },
  }, "user-fixture", "browser_desktop");

  assert.deepEqual(capturedBody.targetService, { port: 8080, protocol: "http" });
  assert.deepEqual(capturedBody.targetRuntimeContract, {
    kind: "http-v1", uid: 65532, gid: 65532, protocol: "http", port: 8080,
    writablePaths: ["/tmp"], readOnlyRootFilesystem: true, bindAddress: "0.0.0.0",
    healthPath: "/health", fingerprintPath: "/version",
  });
});

test("HTTP runtime adapter migrates a legacy Blue Lab to an ELK topology", async () => {
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
        namespace: "range-run-blue-legacy",
        expiresAt: "2026-07-21T12:00:00.000Z",
        browserDesktop: { gatewayPath: "/sessions/run-blue-legacy/desktop", protocol: "websocket" },
      }, { status: 202 });
    },
  });
  const events = [{
    id: "legacy-blue-event",
    document: {
      "@timestamp": "2026-07-21T10:00:00.000Z",
      event: { category: "process" },
      threat: { technique: { id: ["T1059.001", "T1041"] } },
      process: { name: "powershell.exe" },
    },
  }];

  await adapter.createRun({
    id: "lab-blue-legacy",
    teamType: "blue",
    desktopImage: "ubuntu",
    config: {
      target: { source: "template_fallback" },
      telemetry: { events, indexPattern: "legacy-index-*" },
    },
  }, "user-fixture", "browser_desktop");

  const topology = capturedBody.topology as Record<string, unknown>;
  const runtimeTelemetry = topology.telemetry as Record<string, unknown>;
  const generation = runtimeTelemetry.generation as Record<string, unknown>;
  assert.deepEqual({ ...topology, telemetry: { ...runtimeTelemetry, generation: undefined } }, {
    schemaVersion: 1,
    team: "blue",
    isolation: "per_run",
    workstation: { role: "soc_analyst", desktopImage: "ubuntu", entrypoint: "kibana" },
    target: { role: "monitored_target", hostname: "target" },
    telemetry: {
      stack: "elastic",
      collector: "elastic_agent",
      generator: "scenario_log_generator",
      index: "zerotop-logs-*",
      events,
      generation: undefined,
    },
  });
  assert.equal(generation.schemaVersion, 1);
  assert.equal(generation.profile, "powershell_rce_exfiltration");
  assert.equal(generation.totalEvents, 1_200);
  assert.equal(generation.timeRangeMinutes, 60);
  assert.match(String(generation.seed), /^[a-f0-9]{32}$/);
  assert.ok(Number.isFinite(Date.parse(String(generation.timelineAnchor))));
});

test("HTTP runtime adapter migrates a legacy Red Lab without defensive telemetry", async () => {
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
        namespace: "range-run-red-legacy",
        expiresAt: "2026-07-21T12:00:00.000Z",
      }, { status: 202 });
    },
  });

  await adapter.createRun({
    id: "lab-red-legacy",
    team: "red",
    desktopImage: "kali",
    config: {
      target: { source: "template_fallback" },
      telemetry: { events: [{ id: "must-not-be-used" }] },
    },
  }, "user-fixture", "openvpn");

  const topology = capturedBody.topology as Record<string, unknown>;
  const target = topology.target as Record<string, unknown>;
  const exercise = target.exercise as Record<string, unknown>;
  assert.deepEqual({ ...topology, target: { ...target, exercise: undefined } }, {
    schemaVersion: 1,
    team: "red",
    isolation: "per_run",
    workstation: { role: "attack_operator", desktopImage: "kali", entrypoint: "target" },
    target: { role: "vulnerable_target", hostname: "target", exercise: undefined },
  });
  assert.equal(exercise.schemaVersion, 1);
  assert.equal(typeof exercise.profile, "string");
  assert.equal("telemetry" in topology, false);
});

test("personal development fixture Labs include deployable runtime contracts", async () => {
  const capturedBodies: Record<string, unknown>[] = [];
  const adapter = new HttpRuntimeAdapter({
    serviceUrl: "http://codegate-runtime:9000",
    internalToken: "internal-secret",
    targetImage: `local.codegate.invalid/codegate/local-target@sha256:${"0".repeat(64)}`,
    allowTemplateFallback: true,
    fetchImpl: async (_input, init) => {
      capturedBodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return Response.json({
        status: "provisioning",
        namespace: "range-personal-fixture",
        expiresAt: "2026-07-21T12:00:00.000Z",
        browserDesktop: { gatewayPath: "/sessions/run-personal/desktop", protocol: "websocket" },
      }, { status: 202 });
    },
  });
  const fixtures = buildDevelopmentCapabilityFixtures(new Date("2026-07-21T10:00:00.000Z"));
  const blue = fixtures.labs.find((lab) =>
    lab.ownerUserId === "user_personal_blue" && lab.teamType === "blue"
  );
  const red = fixtures.labs.find((lab) =>
    lab.ownerUserId === "user_personal_red" && lab.teamType === "red"
  );
  assert.ok(blue);
  assert.ok(red);

  await adapter.createRun({
    id: blue.id,
    teamType: blue.teamType,
    desktopImage: blue.environment,
    config: blue.config,
  }, blue.ownerUserId, "browser_desktop");
  await adapter.createRun({
    id: red.id,
    teamType: red.teamType,
    desktopImage: red.environment,
    config: red.config,
  }, red.ownerUserId, "browser_desktop");

  assert.equal(capturedBodies.length, 2);
  const blueTopology = capturedBodies[0].topology as Record<string, unknown>;
  const redTopology = capturedBodies[1].topology as Record<string, unknown>;
  assert.equal(blueTopology.team, "blue");
  assert.equal(
    ((blueTopology.telemetry as Record<string, unknown>).events as unknown[]).length > 0,
    true,
  );
  assert.equal(redTopology.team, "red");
  assert.equal(
    typeof ((redTopology.target as Record<string, unknown>).exercise as Record<string, unknown>).profile,
    "string",
  );
});

test("HTTP runtime adapter fails closed when a legacy Blue Lab has no valid events", async () => {
  let runtimeCalled = false;
  const adapter = new HttpRuntimeAdapter({
    serviceUrl: "http://codegate-runtime:9000",
    internalToken: "internal-secret",
    targetImage: `local.codegate.invalid/codegate/local-target@sha256:${"0".repeat(64)}`,
    allowTemplateFallback: true,
    fetchImpl: async () => {
      runtimeCalled = true;
      throw new Error("must not call runtime");
    },
  });

  await assert.rejects(
    adapter.createRun({
      id: "lab-blue-legacy",
      teamType: "blue",
      desktopImage: "ubuntu",
      config: {
        target: { source: "template_fallback" },
        telemetry: {
          events: [{ id: "invalid-event", document: { "@timestamp": "2026-07-21T10:00:00.000Z" } }],
        },
      },
    }, "user-fixture", "browser_desktop"),
    (error: unknown) =>
      error instanceof ApiError
      && error.status === 409
      && error.code === "LAB_RUNTIME_TOPOLOGY_INVALID",
  );
  assert.equal(runtimeCalled, false);
});

test("HTTP runtime adapter continues to reject an invalid explicit topology", async () => {
  let runtimeCalled = false;
  const adapter = new HttpRuntimeAdapter({
    serviceUrl: "http://codegate-runtime:9000",
    internalToken: "internal-secret",
    targetImage: `local.codegate.invalid/codegate/local-target@sha256:${"0".repeat(64)}`,
    allowTemplateFallback: true,
    fetchImpl: async () => {
      runtimeCalled = true;
      throw new Error("must not call runtime");
    },
  });

  await assert.rejects(
    adapter.createRun({
      id: "lab-explicit-invalid",
      desktopImage: "kali",
      config: {
        target: { source: "template_fallback" },
        topology: {
          schemaVersion: 1,
          team: "red",
          isolation: "per_run",
          workstation: { role: "attack_operator", desktopImage: "kali", entrypoint: "kibana" },
          target: { role: "vulnerable_target", hostname: "target" },
        },
      },
    }, "user-fixture", "browser_desktop"),
    (error: unknown) =>
      error instanceof ApiError
      && error.status === 409
      && error.code === "LAB_RUNTIME_TOPOLOGY_INVALID",
  );
  assert.equal(runtimeCalled, false);
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

import assert from "node:assert/strict";
import test from "node:test";

import {
  DockerRuntimeAdapter,
  type DockerCommandResult,
  type DockerCommandRunner,
} from "../src/docker-adapter.ts";
import type { ProvisionRunRequest } from "../src/contracts.ts";

const now = Date.parse("2026-07-22T00:00:00.000Z");
const expiresAt = "2026-07-22T02:00:00.000Z";

test("provisions isolated desktop and target containers with bounded resources", async () => {
  const runner = new RecordingRunner((args) => {
    if (matches(args, "container", "ls")) return output("");
    if (matches(args, "network", "create")) return output("codegate-local-desktops-run-123\n");
    if (matches(args, "network", "connect")) return output("");
    if (matches(args, "container", "create")) return output(args.includes("desktop") ? "desktop-id\n" : "target-id\n");
    if (matches(args, "container", "start")) return output(`${args.at(-1)}\n`);
    throw new Error(`Unexpected docker command: ${args.join(" ")}`);
  });
  const adapter = dockerRuntime(runner);

  const result = await adapter.provision(request());

  assert.equal(result.status, "provisioning");
  assert.equal(result.namespace, "range-run-123");
  assert.deepEqual(result.browserDesktop, {
    gatewayPath: "/sessions/run-123/desktop",
    protocol: "websocket",
  });

  const creates = runner.calls.filter((args) => matches(args, "container", "create"));
  assert.equal(creates.length, 2);
  const target = creates.find((args) => args.at(-1) === "codegate/local-target:development");
  const desktop = creates.find((args) => args.at(-1) === "lscr.io/linuxserver/webtop:ubuntu-xfce");
  assert.ok(target);
  assert.ok(desktop);
  assertOption(target, "--pull", "never");
  assertOption(target, "--network", "codegate-local-desktops-run-123");
  assertOption(target, "--network-alias", "target.range-run-123.svc.cluster.local");
  assertOption(target, "--read-only");
  assertOption(target, "--cap-drop", "ALL");
  assertOption(target, "--user", "65532:65532");
  assertOption(desktop, "--pull", "missing");
  assertOption(desktop, "--network-alias", "desktop.range-run-123.svc.cluster.local");
  assertOption(desktop, "--memory", "4g");
  assertOption(desktop, "--cpus", "2");
  assertOption(desktop, "--pids-limit", "1024");
  assertOption(desktop, "--shm-size", "1g");
  assertOption(desktop, "--env", "CUSTOM_PORT=6080");
  assertOption(desktop, "--env", "SUBFOLDER=/sessions/run-123/desktop/");
  const networkCreate = runner.calls.find((args) => matches(args, "network", "create"));
  assert.ok(networkCreate);
  assertOption(networkCreate, "--internal");
  assertOption(networkCreate, "--label", "codegate.ai.run-id=run-123");
  assert.deepEqual(
    runner.calls.find((args) => matches(args, "network", "connect")),
    ["network", "connect", "--alias", "desktop-gateway", "codegate-local-desktops-run-123", "codegate-local-desktop-gateway"],
  );
  for (const command of creates) {
    assert.equal(command.includes("--privileged"), false);
    assert.equal(command.includes("--volume"), false);
    assert.equal(command.includes("-v"), false);
    assertOption(command, "--label", "codegate.ai.managed-by=codegate-runtime");
    assertOption(command, "--label", "codegate.ai.run-id=run-123");
    assertOption(command, "--label", "codegate.ai.namespace=range-run-123");
    assertOption(command, "--label", "codegate.ai.access-method=browser_desktop");
  }
  adapter.close();
});

test("fails before containers when the per-run internal network cannot be created", async () => {
  const runner = new RecordingRunner((args) => {
    if (matches(args, "container", "ls")) return output("");
    if (matches(args, "network", "create")) throw new Error("network create denied");
    if (matches(args, "network", "disconnect") || matches(args, "network", "rm") || matches(args, "volume", "rm")) return output("");
    throw new Error(`Unexpected docker command: ${args.join(" ")}`);
  });
  const adapter = dockerRuntime(runner);
  await assert.rejects(() => adapter.provision(request()), /network create denied/);
  assert.equal(runner.calls.some((args) => matches(args, "container", "create")), false);
  adapter.close();
});

test("reports ready only when the desktop health check and target are running", async () => {
  const runner = inspectionRunner([
    inspectRecord("desktop-id", "desktop", { running: true, status: "running", health: "healthy" }),
    inspectRecord("target-id", "target", { running: true, status: "running" }),
  ]);
  const adapter = dockerRuntime(runner);

  const result = await adapter.get("run-123");

  assert.equal(result.status, "ready");
  assert.deepEqual(result.checks, {
    workstationVmi: true,
    targetWorkload: true,
    desktopEndpoints: true,
  });
  adapter.close();
});

test("surfaces an unhealthy desktop as a failed run", async () => {
  const runner = inspectionRunner([
    inspectRecord("desktop-id", "desktop", { running: true, status: "running", health: "unhealthy" }),
    inspectRecord("target-id", "target", { running: true, status: "running" }),
  ]);
  const adapter = dockerRuntime(runner);

  const result = await adapter.get("run-123");

  assert.equal(result.status, "failed");
  assert.match(result.reason ?? "", /desktop.*unhealthy/);
  adapter.close();
});

test("blue-team topology provisions analyst desktop, ELK, monitored target, agent and scenario logs", async () => {
  const runner = new RecordingRunner((args) => {
    if (matches(args, "container", "ls")) return output("");
    if (matches(args, "network", "create") || matches(args, "network", "connect") || matches(args, "volume", "create")) return output("");
    if (matches(args, "container", "create") || matches(args, "container", "start")) return output("");
    throw new Error(`Unexpected docker command: ${args.join(" ")}`);
  });
  const adapter = dockerRuntime(runner);

  await adapter.provision(blueRequest());

  const creates = runner.calls.filter((args) => matches(args, "container", "create"));
  assert.equal(creates.length, 6);
  for (const role of ["desktop", "target", "elasticsearch", "kibana", "elastic-agent", "scenario-log-generator"]) {
    const command = creates.find((args) => args.includes(`codegate.ai.role=${role}`));
    assert.ok(command, `missing ${role} container`);
    assertOption(command, "--network", "codegate-local-desktops-run-123");
    assertOption(command, "--label", "codegate.ai.team=blue");
  }
  const target = creates.find((args) => args.includes("codegate.ai.role=target"));
  const agent = creates.find((args) => args.includes("codegate.ai.role=elastic-agent"));
  const generator = creates.find((args) => args.includes("codegate.ai.role=scenario-log-generator"));
  assert.ok(target && agent && generator);
  assert.ok(target.some((item) => item.includes("target=/var/log/zerotop")));
  assertOption(agent, "--env", "ELASTICSEARCH_HOST=http://elasticsearch:9200");
  assertOption(agent, "--env", "KIBANA_HOST=http://kibana:5601");
  assert.ok(agent.some((item) => item.includes("target=/var/log/zerotop,readonly")));
  const encodedEvents = optionValue(generator, "--env", "SCENARIO_EVENTS_BASE64=")?.split("=", 2)[1];
  assert.ok(encodedEvents);
  assert.match(Buffer.from(encodedEvents, "base64").toString("utf8"), /blue-q1-evidence/);
  adapter.close();
});

test("blue-team readiness requires every ELK pipeline role", async () => {
  const records = [
    inspectRecord("desktop-id", "desktop", { running: true, status: "running", health: "healthy" }, expiresAt, "blue"),
    inspectRecord("target-id", "target", { running: true, status: "running" }, expiresAt, "blue"),
    inspectRecord("es-id", "elasticsearch", { running: true, status: "running", health: "healthy" }, expiresAt, "blue"),
    inspectRecord("kibana-id", "kibana", { running: true, status: "running", health: "healthy" }, expiresAt, "blue"),
    inspectRecord("agent-id", "elastic-agent", { running: true, status: "running", health: "healthy" }, expiresAt, "blue"),
    inspectRecord("logs-id", "scenario-log-generator", { running: true, status: "running", health: "healthy" }, expiresAt, "blue"),
  ];
  const adapter = dockerRuntime(inspectionRunner(records));

  const result = await adapter.get("run-123");

  assert.equal(result.status, "ready");
  assert.deepEqual(result.checks, {
    workstationVmi: true,
    targetWorkload: true,
    desktopEndpoints: true,
    elasticsearch: true,
    kibana: true,
    telemetryAgent: true,
    scenarioLogs: true,
  });
  adapter.close();
});

test("destroy removes every container carrying the run label", async () => {
  const runner = new RecordingRunner((args) => {
    if (matches(args, "container", "ls")) {
      assertOption(args, "--filter", "label=codegate.ai.run-id=run-123");
      return output("desktop-id\ntarget-id\nextra-id\n");
    }
    if (matches(args, "container", "rm")) return output("desktop-id\ntarget-id\nextra-id\n");
    if (matches(args, "network", "disconnect") || matches(args, "network", "rm") || matches(args, "volume", "rm")) return output("");
    throw new Error(`Unexpected docker command: ${args.join(" ")}`);
  });
  const adapter = dockerRuntime(runner);

  await adapter.destroy("run-123");

  const remove = runner.calls.find((args) => matches(args, "container", "rm"));
  assert.deepEqual(remove, ["container", "rm", "--force", "desktop-id", "target-id", "extra-id"]);
  adapter.close();
});

test("TTL cleanup removes all containers belonging to an expired managed run", async () => {
  const records = [
    inspectRecord("desktop-id", "desktop", { running: true, status: "running", health: "healthy" }, "2026-07-21T23:59:59.000Z"),
    inspectRecord("target-id", "target", { running: true, status: "running" }, "2026-07-21T23:59:59.000Z"),
  ];
  const runner = new RecordingRunner((args) => {
    if (matches(args, "container", "ls")) {
      if (args.includes("label=codegate.ai.managed-by=codegate-runtime")) return output("desktop-id\ntarget-id\n");
      assertOption(args, "--filter", "label=codegate.ai.run-id=run-123");
      return output("desktop-id\ntarget-id\n");
    }
    if (matches(args, "container", "inspect")) return json(records);
    if (matches(args, "container", "rm")) return output("desktop-id\ntarget-id\n");
    if (matches(args, "network", "disconnect") || matches(args, "network", "rm") || matches(args, "volume", "rm")) return output("");
    throw new Error(`Unexpected docker command: ${args.join(" ")}`);
  });
  const adapter = dockerRuntime(runner);

  await adapter.cleanupExpired();

  assert.deepEqual(
    runner.calls.find((args) => matches(args, "container", "rm")),
    ["container", "rm", "--force", "desktop-id", "target-id"],
  );
  adapter.close();
});

test("rejects OpenVPN access instead of returning a simulated profile", async () => {
  const runner = new RecordingRunner(() => output(""));
  const adapter = dockerRuntime(runner);
  await assert.rejects(
    () => adapter.provision({ ...request(), accessMethod: "both" }),
    /browser_desktop access only/,
  );
  assert.equal(runner.calls.length, 0);
  adapter.close();
});

class RecordingRunner implements DockerCommandRunner {
  readonly calls: string[][] = [];
  private readonly handler: (args: string[]) => DockerCommandResult;

  constructor(handler: (args: string[]) => DockerCommandResult) {
    this.handler = handler;
  }

  async run(args: readonly string[]): Promise<DockerCommandResult> {
    const copy = [...args];
    this.calls.push(copy);
    return this.handler(copy);
  }
}

function dockerRuntime(commandRunner: DockerCommandRunner): DockerRuntimeAdapter {
  return new DockerRuntimeAdapter({ commandRunner, cleanupIntervalMs: 0, now: () => now });
}

function inspectionRunner(records: unknown[]): RecordingRunner {
  return new RecordingRunner((args) => {
    if (matches(args, "container", "ls")) return output("desktop-id\ntarget-id\n");
    if (matches(args, "container", "inspect")) return json(records);
    throw new Error(`Unexpected docker command: ${args.join(" ")}`);
  });
}

function inspectRecord(
  id: string,
  role: "desktop" | "target" | "elasticsearch" | "kibana" | "elastic-agent" | "scenario-log-generator",
  state: { running: boolean; status: string; health?: string },
  expiration = expiresAt,
  team?: "blue" | "red",
): unknown {
  return {
    Id: id,
    Name: `/codegate-${role}-range-run-123`,
    Config: {
      Labels: {
        "codegate.ai.managed-by": "codegate-runtime",
        "codegate.ai.run-id": "run-123",
        "codegate.ai.namespace": "range-run-123",
        "codegate.ai.expires-at": expiration,
        "codegate.ai.access-method": "browser_desktop",
        "codegate.ai.role": role,
        ...(team ? { "codegate.ai.team": team } : {}),
      },
    },
    State: {
      Running: state.running,
      Status: state.status,
      ExitCode: 0,
      ...(state.health ? { Health: { Status: state.health } } : {}),
    },
  };
}

function blueRequest(): ProvisionRunRequest {
  return {
    ...request(),
    topology: {
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
        generation: {
          schemaVersion: 1,
          profile: "powershell_rce_exfiltration",
          totalEvents: 1_200,
          timeRangeMinutes: 60,
          seed: "docker-test-seed",
          timelineAnchor: "2026-07-22T00:00:00.000Z",
        },
        events: [{
          id: "blue-q1-evidence",
          document: {
            "@timestamp": "2026-07-22T00:00:00.000Z",
            event: { dataset: "zerotop.endpoint" },
            threat: { technique: { id: ["T1059.001"] } },
          },
        }],
      },
    },
  };
}

function request(): ProvisionRunRequest {
  return {
    runId: "run-123",
    labId: "lab-123",
    userId: "user-123",
    desktopImage: "ubuntu",
    accessMethod: "browser_desktop",
    ttlMinutes: 120,
    targetImage: "codegate/local-target:development",
    targetService: { port: 8080, protocol: "http" },
    targetRuntimeContract: {
      kind: "http-v1",
      uid: 65532,
      gid: 65532,
      protocol: "http",
      port: 8080,
      writablePaths: ["/tmp"],
      readOnlyRootFilesystem: true,
      bindAddress: "0.0.0.0",
      healthPath: "/health",
      fingerprintPath: "/version",
    },
  };
}

function matches(args: readonly string[], ...prefix: string[]): boolean {
  return prefix.every((item, index) => args[index] === item);
}

function output(stdout: string): DockerCommandResult {
  return { stdout, stderr: "" };
}

function json(value: unknown): DockerCommandResult {
  return output(JSON.stringify(value));
}

function assertOption(args: readonly string[], option: string, value?: string): void {
  const indexes = args.flatMap((item, index) => item === option ? [index] : []);
  assert.ok(indexes.length > 0, `Expected ${option} in ${args.join(" ")}`);
  if (value !== undefined) {
    assert.ok(indexes.some((index) => args[index + 1] === value), `Expected ${option} ${value} in ${args.join(" ")}`);
  }
}

function optionValue(args: readonly string[], option: string, prefix: string): string | undefined {
  const indexes = args.flatMap((item, index) => item === option ? [index] : []);
  return indexes.map((index) => args[index + 1]).find((value) => value?.startsWith(prefix));
}

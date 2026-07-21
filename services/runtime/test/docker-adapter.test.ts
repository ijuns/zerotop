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
    if (matches(args, "network", "inspect")) return json({ Name: "codegate-local-desktops", Internal: true });
    if (matches(args, "container", "ls")) return output("");
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
  assertOption(target, "--network", "codegate-local-desktops");
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

test("requires the shared desktop network to be internal", async () => {
  const runner = new RecordingRunner((args) => {
    if (matches(args, "container", "ls")) return output("");
    if (matches(args, "network", "inspect")) return json({ Name: "codegate-local-desktops", Internal: false });
    throw new Error(`Unexpected docker command: ${args.join(" ")}`);
  });
  const adapter = dockerRuntime(runner);
  await assert.rejects(() => adapter.provision(request()), /must be internal/);
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

test("destroy removes every container carrying the run label", async () => {
  const runner = new RecordingRunner((args) => {
    if (matches(args, "container", "ls")) {
      assertOption(args, "--filter", "label=codegate.ai.run-id=run-123");
      return output("desktop-id\ntarget-id\nextra-id\n");
    }
    if (matches(args, "container", "rm")) return output("desktop-id\ntarget-id\nextra-id\n");
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
      assertOption(args, "--filter", "label=codegate.ai.managed-by=codegate-runtime");
      return output("desktop-id\ntarget-id\n");
    }
    if (matches(args, "container", "inspect")) return json(records);
    if (matches(args, "container", "rm")) return output("desktop-id\ntarget-id\n");
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
  role: "desktop" | "target",
  state: { running: boolean; status: string; health?: string },
  expiration = expiresAt,
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

function request(): ProvisionRunRequest {
  return {
    runId: "run-123",
    labId: "lab-123",
    userId: "user-123",
    desktopImage: "ubuntu",
    accessMethod: "browser_desktop",
    ttlMinutes: 120,
    targetImage: `registry.example/target@sha256:${"a".repeat(64)}`,
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

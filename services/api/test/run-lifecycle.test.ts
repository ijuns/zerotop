import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { createApplication } from "../src/app.ts";
import {
  createDatabase,
  SqliteDevelopmentRepository,
} from "../src/database.ts";
import type { LabGenerationInput, RuntimeRunInput } from "../src/types.ts";

const database = createDatabase(":memory:");
const repository = new SqliteDevelopmentRepository(database);
const destroyedRuns: string[] = [];
const destroyedTelemetry: string[] = [];
const application = createApplication({
  repository,
  authMode: "dev",
  // The timer would race the assertions; each test drives the sweep itself.
  runSweepIntervalMs: 0,
  runtime: {
    createRun: () => Promise.reject(new Error("not used")),
    getRunStatus: () => Promise.reject(new Error("not used")),
    destroyRun(runId) {
      destroyedRuns.push(runId);
    },
  },
  telemetryGateway: {
    async provision() {},
    async search() {
      return { took: 0, total: 0, hits: [] };
    },
    async destroy(runId: string) {
      destroyedTelemetry.push(runId);
    },
  },
});
let baseUrl = "";

before(async () => {
  await new Promise<void>((resolve, reject) => {
    application.server.once("error", reject);
    application.server.listen(0, "127.0.0.1", resolve);
  });
  const address = application.server.address();
  assert.ok(address && typeof address !== "string");
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await application.close();
});

async function api(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    userId?: string;
    idempotencyKey?: string;
  } = {},
) {
  const headers = new Headers();
  if (options.body !== undefined) headers.set("content-type", "application/json");
  if (options.userId) headers.set("x-user-id", options.userId);
  if (options.idempotencyKey) headers.set("idempotency-key", options.idempotencyKey);
  const response = await fetch(`${baseUrl}${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  return { response, payload: (await response.json()) as Record<string, unknown> };
}

function data(payload: Record<string, unknown>): Record<string, unknown> {
  return payload.data as Record<string, unknown>;
}

const labInput: LabGenerationInput = {
  title: "Lifecycle Lab",
  prompt: "lifecycle",
  team: "red",
  questionTypes: ["single_choice"],
  desktopImage: "ubuntu",
  accessMethod: "browser_desktop",
  accessModes: ["browser_desktop"],
  config: {},
  gradingQuestions: [],
  cveIds: [],
};

async function register(handle: string): Promise<string> {
  const result = await api("/v1/auth/register", {
    method: "POST",
    body: {
      email: `${handle}@example.test`,
      handle,
      displayName: handle,
      affiliation: "Test Affiliation",
      consent: { terms: true, privacy: true },
      accountType: "personal",
    },
  });
  assert.equal(result.response.status, 201);
  return String((data(result.payload).user as Record<string, unknown>).id);
}

function seedRun(
  userId: string,
  labId: string,
  id: string,
  expiresAt: string,
  status: RuntimeRunInput["status"] = "ready",
): void {
  repository.createRun({
    id,
    labId,
    userId,
    status,
    environment: "ubuntu",
    accessMethod: "browser_desktop",
    browserUrl: "http://desktop.local/session",
    openvpnProfile: null,
    expiresAt,
    metadata: {},
    createdAt: new Date().toISOString(),
  });
}

function statusOf(runId: string): string {
  const row = database
    .prepare("SELECT status FROM runtime_runs WHERE id = ?")
    .get(runId) as { status: string };
  return row.status;
}

test("the sweep expires overdue runs and leaves live ones alone", async () => {
  const userId = await register("lifecycle_sweeper");
  const labId = String(
    (repository.createLab(userId, labInput) as Record<string, unknown>).id,
  );
  const past = new Date(Date.now() - 60_000).toISOString();
  const future = new Date(Date.now() + 3_600_000).toISOString();
  seedRun(userId, labId, "run_overdue", past);
  seedRun(userId, labId, "run_overdue_provisioning", past, "provisioning");
  seedRun(userId, labId, "run_live", future);

  destroyedRuns.length = 0;
  destroyedTelemetry.length = 0;
  const expired = await application.sweepExpiredRuns();

  assert.deepEqual(
    [...expired].sort(),
    ["run_overdue", "run_overdue_provisioning"],
  );
  assert.equal(statusOf("run_overdue"), "expired");
  assert.equal(statusOf("run_overdue_provisioning"), "expired");
  assert.equal(statusOf("run_live"), "ready");

  // Both planes are released, and the live run is untouched.
  assert.deepEqual([...destroyedRuns].sort(), [
    "run_overdue",
    "run_overdue_provisioning",
  ]);
  assert.deepEqual([...destroyedTelemetry].sort(), [
    "run_overdue",
    "run_overdue_provisioning",
  ]);

  // Access details are cleared so an expired run cannot be reconnected to.
  const cleared = database
    .prepare("SELECT browser_url, metadata_json FROM runtime_runs WHERE id = ?")
    .get("run_overdue") as { browser_url: string | null; metadata_json: string };
  assert.equal(cleared.browser_url, null);
  assert.equal(
    (JSON.parse(cleared.metadata_json) as Record<string, Record<string, unknown>>)
      .termination.reason,
    "ttl_expired",
  );

  const audited = database
    .prepare(
      "SELECT count(*) AS total FROM audit_logs WHERE action = 'runtime.expired'",
    )
    .get() as { total: number };
  assert.equal(audited.total, 2);

  // Re-sweeping is a no-op: expired runs have left the active set.
  destroyedRuns.length = 0;
  assert.deepEqual(await application.sweepExpiredRuns(), []);
  assert.deepEqual(destroyedRuns, []);
});

test("suspending an account tears down its running environments", async () => {
  const userId = await register("lifecycle_suspended");
  const otherId = await register("lifecycle_bystander");
  const labId = String(
    (repository.createLab(userId, labInput) as Record<string, unknown>).id,
  );
  const future = new Date(Date.now() + 3_600_000).toISOString();
  seedRun(userId, labId, "run_suspended_a", future);
  seedRun(userId, labId, "run_suspended_b", future, "provisioning");
  seedRun(otherId, labId, "run_untouched", future);

  destroyedRuns.length = 0;
  destroyedTelemetry.length = 0;
  const suspended = await api(
    `/v1/admin/users/${encodeURIComponent(userId)}/suspension`,
    {
      method: "POST",
      idempotencyKey: "suspend-with-runs",
      body: { suspended: true, reason: "policy violation" },
    },
  );
  assert.equal(suspended.response.status, 200);
  assert.deepEqual(
    [...(data(suspended.payload).terminatedRuns as string[])].sort(),
    ["run_suspended_a", "run_suspended_b"],
  );

  assert.equal(statusOf("run_suspended_a"), "stopped");
  assert.equal(statusOf("run_suspended_b"), "stopped");
  // Another user's environment must survive.
  assert.equal(statusOf("run_untouched"), "ready");
  assert.deepEqual([...destroyedRuns].sort(), [
    "run_suspended_a",
    "run_suspended_b",
  ]);
  assert.deepEqual([...destroyedTelemetry].sort(), [
    "run_suspended_a",
    "run_suspended_b",
  ]);

  const terminated = database
    .prepare("SELECT metadata_json FROM runtime_runs WHERE id = 'run_suspended_a'")
    .get() as { metadata_json: string };
  assert.equal(
    (JSON.parse(terminated.metadata_json) as Record<string, Record<string, unknown>>)
      .termination.reason,
    "account_suspended",
  );

  const auditMetadata = database
    .prepare(
      `SELECT metadata_json FROM audit_logs
        WHERE action = 'admin.user_suspended' AND resource_id = ?`,
    )
    .get(userId) as { metadata_json: string };
  assert.equal(
    (JSON.parse(auditMetadata.metadata_json) as Record<string, unknown>)
      .terminatedRuns,
    2,
  );

  // Reinstating restores access but does not resurrect the environments.
  const reinstated = await api(
    `/v1/admin/users/${encodeURIComponent(userId)}/suspension`,
    {
      method: "POST",
      idempotencyKey: "reinstate-with-runs",
      body: { suspended: false },
    },
  );
  assert.equal(reinstated.response.status, 200);
  assert.deepEqual(data(reinstated.payload).terminatedRuns, []);
  assert.equal(statusOf("run_suspended_a"), "stopped");
});

test("a runtime adapter failure still removes the run from the active set", async () => {
  const userId = await register("lifecycle_adapter_down");
  const labId = String(
    (repository.createLab(userId, labInput) as Record<string, unknown>).id,
  );
  seedRun(userId, labId, "run_adapter_down", new Date(Date.now() - 1_000).toISOString());

  const failing = createApplication({
    repository,
    authMode: "dev",
    runSweepIntervalMs: 0,
    runtime: {
      createRun: () => Promise.reject(new Error("not used")),
      getRunStatus: () => Promise.reject(new Error("not used")),
      destroyRun: () => Promise.reject(new Error("runtime plane unreachable")),
    },
  });
  try {
    const expired = await failing.sweepExpiredRuns();
    assert.deepEqual(expired, ["run_adapter_down"]);
    assert.equal(statusOf("run_adapter_down"), "expired");
  } finally {
    // Shares the repository with the suite; close only the server.
    failing.server.close();
  }
});

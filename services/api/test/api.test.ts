import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { createApplication } from "../src/app.ts";
import {
  createDatabase,
  SqliteDevelopmentRepository,
} from "../src/database.ts";
import { hashOrganizationJoinCode } from "../src/security.ts";
import type { OidcVerifier } from "@codegate/auth";

const noopTelemetryGateway = {
  async provision() {},
  async search() { return { took: 0, total: 0, hits: [] }; },
  async destroy() {},
};
const noopEnvironmentBuilder = {
  async start(): Promise<never> { throw new Error("not used"); },
  async get(): Promise<never> { throw new Error("not used"); },
  async cancel() {},
};

const database = createDatabase(":memory:");
const repository = new SqliteDevelopmentRepository(database);
const evidenceRequests: unknown[] = [];
const application = createApplication({
  repository,
  authMode: "dev",
  evidenceGrader: {
    grade(input) {
      evidenceRequests.push(input);
      return [];
    },
  },
});
let baseUrl = "";

before(async () => {
  await new Promise<void>((resolve, reject) => {
    application.server.once("error", reject);
    application.server.listen(0, "127.0.0.1", () => resolve());
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
    authorization?: string;
    origin?: string;
  } = {},
) {
  const headers = new Headers();
  if (options.body !== undefined) headers.set("content-type", "application/json");
  if (options.userId) headers.set("x-user-id", options.userId);
  if (options.idempotencyKey) {
    headers.set("idempotency-key", options.idempotencyKey);
  }
  if (options.authorization) headers.set("authorization", options.authorization);
  if (options.origin) headers.set("origin", options.origin);
  const response = await fetch(`${baseUrl}${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const payload = (await response.json()) as Record<string, unknown>;
  return { response, payload };
}

function data(payload: Record<string, unknown>): Record<string, unknown> {
  return payload.data as Record<string, unknown>;
}

test("health and seeded development identity are available with CORS", async () => {
  const health = await api("/health", { origin: "http://localhost:3000" });
  assert.equal(health.response.status, 200);
  assert.equal(
    health.response.headers.get("access-control-allow-origin"),
    "http://localhost:3000",
  );
  assert.equal(health.payload.status, "ok");

  const ingressHealth = await api("/api/health", { origin: "http://localhost:3000" });
  assert.equal(ingressHealth.response.status, 200);
  assert.equal(ingressHealth.payload.status, "ok");

  const apiary = await api("/apiary/health");
  assert.equal(apiary.response.status, 404);

  const denied = await api("/health", { origin: "https://untrusted.example" });
  assert.equal(denied.response.status, 403);
  assert.equal(denied.response.headers.get("access-control-allow-origin"), null);

  const me = await api("/v1/me");
  assert.equal(me.response.status, 200);
  const user = data(me.payload).user as Record<string, unknown>;
  assert.equal(user.id, "user_dev");

  const ingressMe = await api("/api/v1/me");
  assert.equal(ingressMe.response.status, 200);
  const ingressUser = data(ingressMe.payload).user as Record<string, unknown>;
  assert.equal(ingressUser.id, "user_dev");

  const organization = user.organization as Record<string, unknown>;
  assert.equal(organization.name, "Security Lab");
});

test("registration supports personal accounts and one organization membership", async () => {
  const personal = await api("/v1/auth/register", {
    method: "POST",
    body: {
      email: "personal@example.test",
      handle: "personal_user",
      displayName: "Personal User",
      password: "strong-password",
      accountType: "personal",
    },
  });
  assert.equal(personal.response.status, 201);
  const personalUser = data(personal.payload).user as Record<string, unknown>;
  assert.equal(personalUser.organization, null);

  const joined = await api("/v1/auth/register", {
    method: "POST",
    body: {
      email: "analyst@example.test",
      handle: "security_analyst",
      displayName: "Security Analyst",
      accountType: "organization",
      organizationJoinCode: "security-lab",
    },
  });
  assert.equal(joined.response.status, 201);
  const joinedUser = data(joined.payload).user as Record<string, unknown>;
  assert.equal(
    (joinedUser.organization as Record<string, unknown>).id,
    "org_security_lab",
  );

  const duplicate = await api("/v1/auth/register", {
    method: "POST",
    body: {
      email: "analyst@example.test",
      handle: "another_handle",
      displayName: "Duplicate",
    },
  });
  assert.equal(duplicate.response.status, 409);
  assert.equal(
    (duplicate.payload.error as Record<string, unknown>).code,
    "ACCOUNT_EXISTS",
  );

  database
    .prepare(
      `INSERT INTO organizations
        (id, name, slug, join_code_hash, join_code_rotated_at, created_at)
       VALUES (?, 'Second Org', 'second-org', ?, ?, ?)`,
    )
    .run(
      "org_second",
      hashOrganizationJoinCode("SECOND"),
      "2026-01-01T00:00:00.000Z",
      "2026-01-01T00:00:00.000Z",
    );
  assert.throws(() =>
    database
      .prepare(
        `INSERT INTO organization_memberships
          (user_id, organization_id, role, created_at)
         VALUES (?, 'org_second', 'member', '2026-01-01T00:00:00.000Z')`,
      )
      .run(String(joinedUser.id)),
  );
});

test("blue-team generation enforces ELK plus MITRE and is idempotent", async () => {
  const invalid = await api("/v1/labs/generate", {
    method: "POST",
    idempotencyKey: "blue-invalid-001",
    body: {
      title: "Invalid blue lab",
      prompt: "This request intentionally omits the MITRE question type.",
      team: "blue",
      desktopImage: "ubuntu",
      accessMethod: "both",
      questionTypes: ["elk_search"],
    },
  });
  assert.equal(invalid.response.status, 400);
  assert.equal(
    (invalid.payload.error as Record<string, unknown>).code,
    "INVALID_BLUE_QUESTION_TYPES",
  );

  const request = {
    title: "Impossible travel investigation",
    prompt: "Find the compromised identity and map its technique.",
    team: "blue",
    desktopImage: "ubuntu",
    accessMethod: "both",
    questionTypes: ["elk_search", "mitre_attack"],
  };
  const first = await api("/v1/labs/generate", {
    method: "POST",
    idempotencyKey: "blue-generate-001",
    body: request,
  });
  assert.equal(first.response.status, 201);
  const firstLab = data(first.payload).lab as Record<string, unknown>;
  assert.equal(firstLab.desktopImage, "ubuntu");
  assert.equal(firstLab.accessMethod, "both");
  assert.deepEqual(firstLab.questionTypes, ["elk_search", "mitre_attack"]);
  const learning = (firstLab.config as Record<string, unknown>)
    .learning as Record<string, unknown>;
  assert.equal(learning.title, request.title);
  assert.equal((learning.sections as unknown[]).length, 6);
  assert.equal((learning.objectives as unknown[]).length, 4);
  const topology = (firstLab.config as Record<string, unknown>)
    .topology as Record<string, unknown>;
  assert.equal(topology.team, "blue");
  assert.equal((topology.workstation as Record<string, unknown>).entrypoint, "kibana");
  assert.equal((topology.target as Record<string, unknown>).role, "monitored_target");
  const runtimeTelemetry = topology.telemetry as Record<string, unknown>;
  assert.equal(runtimeTelemetry.collector, "elastic_agent");
  assert.equal(runtimeTelemetry.generator, "scenario_log_generator");

  const replay = await api("/v1/labs/generate", {
    method: "POST",
    idempotencyKey: "blue-generate-001",
    body: request,
  });
  assert.equal(replay.response.status, 201);
  assert.equal(replay.response.headers.get("idempotent-replayed"), "true");
  assert.equal(
    (data(replay.payload).lab as Record<string, unknown>).id,
    firstLab.id,
  );

  const keyReuse = await api("/v1/labs/generate", {
    method: "POST",
    idempotencyKey: "blue-generate-001",
    body: { ...request, title: "A different lab" },
  });
  assert.equal(keyReuse.response.status, 409);
  assert.equal(
    (keyReuse.payload.error as Record<string, unknown>).code,
    "IDEMPOTENCY_KEY_REUSED",
  );

  const missingKey = await api("/v1/labs/generate", {
    method: "POST",
    body: request,
  });
  assert.equal(missingKey.response.status, 400);
  assert.equal(
    (missingKey.payload.error as Record<string, unknown>).code,
    "IDEMPOTENCY_KEY_REQUIRED",
  );

  const detail = await api(`/v1/labs/${firstLab.id}`);
  assert.equal(detail.response.status, 200);
  const validation = await api(`/v1/labs/${firstLab.id}/validate`, {
    method: "POST",
  });
  assert.equal(validation.response.status, 200);
  assert.equal(data(validation.payload).decision, "pass");
  const evidence = data(validation.payload).evidence as Record<string, unknown>[];
  assert.equal(evidence.length, 6);
  assert.ok(evidence.every((item) => item.outcome === "pass"));

  const deployment = await api(`/v1/labs/${firstLab.id}/deploy`, {
    method: "POST",
    idempotencyKey: "blue-deploy-001",
    body: { accessMethod: "browser_desktop" },
  });
  assert.equal(deployment.response.status, 201);
  const run = data(deployment.payload).run as Record<string, unknown>;
  assert.equal(run.desktopImage, "ubuntu");
  assert.equal(run.accessMethod, "browser_desktop");
  assert.equal(
    (run.browserDesktop as Record<string, unknown>).protocol,
    "noVNC",
  );

  const deployReplay = await api(`/v1/labs/${firstLab.id}/deploy`, {
    method: "POST",
    idempotencyKey: "blue-deploy-001",
    body: { accessMethod: "browser_desktop" },
  });
  assert.equal(
    (data(deployReplay.payload).run as Record<string, unknown>).id,
    run.id,
  );

  const runDetail = await api(`/v1/runs/${run.id}`);
  assert.equal(runDetail.response.status, 200);
  assert.equal((data(runDetail.payload).run as Record<string, unknown>).id, run.id);

  const elkSearch = await api(`/v1/runs/${run.id}/elk/search`, {
    method: "POST",
    body: { query: "*", size: 25 },
  });
  assert.equal(elkSearch.response.status, 200);
  const elkResult = data(elkSearch.payload).result as Record<string, unknown>;
  assert.equal(typeof elkResult.took, "number");
  assert.equal(elkResult.total, 1_200);
  const elkHits = elkResult.hits as Array<Record<string, unknown>>;
  assert.equal(elkHits.length, 25);
});

test("unsafe labs are quarantined and cannot be deployed", async () => {
  const generated = await api("/v1/labs/generate", {
    method: "POST",
    idempotencyKey: "unsafe-red-generate",
    body: {
      name: "Unsafe payload fixture",
      description: "Exercise the compatibility aliases with unsafe payload evidence.",
      teamType: "red",
      environment: "kali",
      accessModes: ["browser_desktop", "openvpn"],
      questionTypes: ["free_text", "mitre_attack"],
      safety: { payloadMasked: false, allowLiveMalware: true },
    },
  });
  assert.equal(generated.response.status, 201);
  const lab = data(generated.payload).lab as Record<string, unknown>;

  const validation = await api(`/v1/labs/${lab.id}/validate`, { method: "POST" });
  assert.equal(data(validation.payload).decision, "quarantine");

  const deployment = await api(`/v1/labs/${lab.id}/deploy`, {
    method: "POST",
    idempotencyKey: "unsafe-red-deploy",
    body: { accessMethod: "openvpn" },
  });
  assert.equal(deployment.response.status, 409);
  assert.equal(
    (deployment.payload.error as Record<string, unknown>).code,
    "LAB_NOT_VALIDATED",
  );
});

test("red-team labs support the four allowed question types and OpenVPN", async () => {
  const invalid = await api("/v1/labs/generate", {
    method: "POST",
    idempotencyKey: "red-invalid-001",
    body: {
      title: "Invalid red lab",
      prompt: "This request intentionally selects a blue-only question type.",
      team: "red",
      desktopImage: "kali",
      accessMethod: "both",
      questionTypes: ["elk_search"],
    },
  });
  assert.equal(invalid.response.status, 400);

  const generated = await api("/v1/labs/generate", {
    method: "POST",
    idempotencyKey: "red-generate-001",
    body: {
      title: "Web foothold analysis",
      prompt: "Analyze a safely simulated web foothold and map the attack chain.",
      team: "red",
      desktopImage: "kali",
      accessMethod: "both",
      questionTypes: [
        "single_choice",
        "multiple_choice",
        "free_text",
        "mitre_attack",
      ],
    },
  });
  assert.equal(generated.response.status, 201);
  const lab = data(generated.payload).lab as Record<string, unknown>;
  assert.equal(lab.desktopImage, "kali");

  const validation = await api(`/v1/labs/${lab.id}/validate`, { method: "POST" });
  assert.equal(data(validation.payload).decision, "pass");

  const deployment = await api(`/v1/labs/${lab.id}/deploy`, {
    method: "POST",
    idempotencyKey: "red-openvpn-deploy",
    body: { accessMethod: "openvpn" },
  });
  assert.equal(deployment.response.status, 201);
  const run = data(deployment.payload).run as Record<string, unknown>;
  const openVpn = run.openVpn as Record<string, unknown>;
  assert.equal(run.desktopImage, "kali");
  assert.equal(openVpn.protocol, "udp");
  assert.equal(openVpn.simulated, true);
  assert.equal(typeof openVpn.endpoint, "string");

  const combinedDeployment = await api(`/v1/labs/${lab.id}/deploy`, {
    method: "POST",
    idempotencyKey: "red-combined-deploy",
    body: { accessMethod: "both" },
  });
  assert.equal(combinedDeployment.response.status, 201);
  const combinedRun = data(combinedDeployment.payload).run as Record<string, unknown>;
  assert.equal(combinedRun.accessMethod, "both");
  assert.equal(typeof combinedRun.browserDesktop, "object");
  assert.equal(typeof combinedRun.openVpn, "object");
  const combinedDesktopTicket = await api(
    `/v1/runs/${combinedRun.id}/desktop-ticket`,
    { method: "POST" },
  );
  const combinedVpnTicket = await api(
    `/v1/runs/${combinedRun.id}/openvpn-ticket`,
    { method: "POST" },
  );
  assert.equal(combinedDesktopTicket.response.status, 201);
  assert.equal(combinedVpnTicket.response.status, 201);

  const redElkSearch = await api(`/v1/runs/${combinedRun.id}/elk/search`, {
    method: "POST",
    body: { query: "*" },
  });
  assert.equal(redElkSearch.response.status, 409);
  assert.equal(
    (redElkSearch.payload.error as Record<string, unknown>).code,
    "ELK_NOT_ENABLED",
  );
});

test("personal accounts can create, validate and deploy owner-scoped Blue and Red Labs", async () => {
  const cases = [
    {
      userId: "user_personal_blue",
      team: "blue",
      desktopImage: "ubuntu",
      questionTypes: ["elk_search", "mitre_attack"],
    },
    {
      userId: "user_personal_red",
      team: "red",
      desktopImage: "kali",
      questionTypes: ["single_choice", "multiple_choice", "free_text", "mitre_attack"],
    },
  ] as const;

  for (const item of cases) {
    const generated = await api("/v1/labs/generate", {
      method: "POST",
      userId: item.userId,
      idempotencyKey: `personal-${item.team}-generate-001`,
      body: {
        title: `Personal ${item.team} deployment`,
        prompt: "개인 사용자가 소유한 격리 실습 환경의 전체 배포 흐름을 확인합니다.",
        team: item.team,
        desktopImage: item.desktopImage,
        accessMethod: "browser_desktop",
        questionTypes: [...item.questionTypes],
      },
    });
    assert.equal(generated.response.status, 201);
    const lab = data(generated.payload).lab as Record<string, unknown>;
    assert.equal((lab.organization as unknown) ?? null, null);

    const hiddenFromOtherPersonalUser = await api(`/v1/labs/${lab.id}`, {
      userId: item.userId === "user_personal_blue" ? "user_personal_red" : "user_personal_blue",
    });
    assert.equal(hiddenFromOtherPersonalUser.response.status, 404);

    const validation = await api(`/v1/labs/${lab.id}/validate`, {
      method: "POST",
      userId: item.userId,
    });
    assert.equal(validation.response.status, 200);
    assert.equal(data(validation.payload).decision, "pass");

    const deployment = await api(`/v1/labs/${lab.id}/deploy`, {
      method: "POST",
      userId: item.userId,
      idempotencyKey: `personal-${item.team}-deploy-001`,
      body: { accessMethod: "browser_desktop" },
    });
    assert.equal(deployment.response.status, 201);
    const run = data(deployment.payload).run as Record<string, unknown>;
    assert.equal(run.userId, item.userId);
    assert.equal(run.desktopImage, item.desktopImage);
  }
});

test("organization members see shared labs and audit logs capture mutations once", async () => {
  const analyst = database
    .prepare("SELECT id FROM users WHERE email = 'analyst@example.test'")
    .get() as { id: string };
  const list = await api("/v1/labs", { userId: analyst.id });
  assert.equal(list.response.status, 200);
  const labs = data(list.payload).labs as unknown[];
  assert.equal(labs.length, 3);

  const actions = database
    .prepare("SELECT actor_user_id, action FROM audit_logs ORDER BY created_at, id")
    .all() as { actor_user_id: string; action: string }[];
  assert.ok(actions.some((item) => item.action === "auth.user_registered"));
  assert.ok(actions.some((item) => item.action === "lab.validation_completed"));
  assert.ok(actions.some((item) => item.action === "runtime.deployed"));
  assert.equal(
    actions.filter(
      (item) => item.actor_user_id === "user_dev" && item.action === "lab.generated",
    ).length,
    3,
    "idempotent replay must not create a second lab or audit event",
  );

  const tables = database
    .prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'challenge_results'",
    )
    .all();
  assert.equal(tables.length, 1);
});

test("GET run refreshes provisioning state and persists terminal readiness", async () => {
  const row = database
    .prepare(
      `SELECT id FROM runtime_runs
        WHERE user_id = 'user_dev'
        ORDER BY created_at ASC LIMIT 1`,
    )
    .get() as { id: string };
  database
    .prepare("UPDATE runtime_runs SET status = 'provisioning' WHERE id = ?")
    .run(row.id);

  const refreshed = await api(`/v1/runs/${row.id}`);
  assert.equal(refreshed.response.status, 200);
  const run = data(refreshed.payload).run as Record<string, unknown>;
  assert.equal(run.status, "ready");
  const metadata = run.metadata as Record<string, unknown>;
  const readiness = metadata.runtimeReadiness as Record<string, unknown>;
  assert.equal(readiness.status, "ready");
  assert.equal(
    database.prepare("SELECT status FROM runtime_runs WHERE id = ?").get(row.id)?.status,
    "ready",
  );
});

test("reports and rankings enforce roles and the actor organization tenant", async () => {
  const completed = database
    .prepare(
      `SELECT rr.id AS run_id, rr.lab_id
         FROM runtime_runs rr
        WHERE rr.user_id = 'user_dev'
        ORDER BY rr.created_at ASC LIMIT 1`,
    )
    .get() as { run_id: string; lab_id: string };
  database
    .prepare(
      `INSERT INTO challenge_results
        (id, lab_id, user_id, run_id, score, max_score, answers_json,
         evidence_json, skills_json, completed_at)
       VALUES (?, ?, 'user_dev', ?, 80, 100, '{}', '{}', ?, ?)`,
    )
    .run(
      "result_reporting_fixture",
      completed.lab_id,
      completed.run_id,
      JSON.stringify({
        investigation: {
          label: "Investigation",
          points: 80,
          maxPoints: 100,
        },
      }),
      new Date().toISOString(),
    );

  const personal = await api("/v1/reports/me");
  assert.equal(personal.response.status, 200);
  const personalReport = data(personal.payload).report as Record<string, unknown>;
  assert.equal(personalReport.scope, "personal");
  assert.equal(personalReport.overallScore, 80);

  const organization = await api("/v1/reports/organization");
  assert.equal(organization.response.status, 200);
  assert.equal(
    (data(organization.payload).report as Record<string, unknown>).scope,
    "organization",
  );

  const analyst = database
    .prepare("SELECT id FROM users WHERE email = 'analyst@example.test'")
    .get() as { id: string };
  const forbiddenOrganization = await api("/v1/reports/organization", {
    userId: analyst.id,
  });
  assert.equal(forbiddenOrganization.response.status, 403);
  assert.equal(
    (forbiddenOrganization.payload.error as Record<string, unknown>).code,
    "ORG_ADMIN_REQUIRED",
  );

  const forbiddenPlatform = await api("/v1/admin/reports/platform", {
    userId: analyst.id,
  });
  assert.equal(forbiddenPlatform.response.status, 403);
  const platform = await api("/v1/admin/reports/platform");
  assert.equal(platform.response.status, 200);

  const globalRanking = await api("/v1/rankings?scope=global&period=all_time");
  assert.equal(globalRanking.response.status, 200);
  const globalResult = data(globalRanking.payload).ranking as Record<string, unknown>;
  assert.equal((globalResult.entries as unknown[]).length, 1);

  const organizationRanking = await api(
    "/v1/rankings?scope=organization&period=all_time",
    { userId: analyst.id },
  );
  assert.equal(organizationRanking.response.status, 200);
  const organizationResult = data(organizationRanking.payload)
    .ranking as Record<string, unknown>;
  assert.equal((organizationResult.entries as unknown[]).length, 1);
});

test("run submission keeps answer keys private and uses only trusted server evidence", async () => {
  const run = database
    .prepare(
      `SELECT rr.id, rr.lab_id
         FROM runtime_runs rr
         JOIN labs l ON l.id = rr.lab_id
        WHERE rr.user_id = 'user_dev' AND l.team_type = 'red'
        ORDER BY rr.created_at DESC LIMIT 1`,
    )
    .get() as { id: string; lab_id: string };
  database
    .prepare(
      `INSERT INTO trusted_grade_evidence
        (id, run_id, question_id, source, passed, score_ratio,
         policy_version, evidence_reference, created_at)
       VALUES (?, ?, 'red-q3', 'ai_rubric', 1, 0.5, ?, ?, ?)`,
    )
    .run(
      "evidence_red_free_text",
      run.id,
      "rubric-v1",
      "ai-grade/red-q3/fixture",
      new Date().toISOString(),
    );

  const answers = [
    { questionId: "red-q1", response: "bounded-enumeration" },
    { questionId: "red-q2", response: ["process-lineage", "auth-context", "network-flow"] },
    { questionId: "red-q3", response: "A concise evidence-backed explanation." },
    { questionId: "red-q4", response: "T1059.004" },
  ];
  const forbiddenEvidence = await api(`/v1/runs/${run.id}/submit`, {
    method: "POST",
    idempotencyKey: "red-submit-forbidden-evidence",
    body: { answers, trustedEvidence: [] },
  });
  assert.equal(forbiddenEvidence.response.status, 400);
  assert.equal(
    (forbiddenEvidence.payload.error as Record<string, unknown>).code,
    "CLIENT_GRADE_EVIDENCE_FORBIDDEN",
  );

  const submitted = await api(`/v1/runs/${run.id}/submit`, {
    method: "POST",
    idempotencyKey: "red-submit-valid-001",
    body: { answers },
  });
  assert.equal(submitted.response.status, 201);
  const grade = data(submitted.payload).grade as Record<string, unknown>;
  assert.equal(grade.score, 86);
  assert.equal(grade.passed, true);
  assert.doesNotMatch(JSON.stringify(submitted.payload), /answerKey/i);
  assert.equal(evidenceRequests.length, 1);
  const graderRequest = evidenceRequests[0] as Record<string, unknown>;
  assert.equal(
    (graderRequest.run as Record<string, unknown>).id,
    run.id,
  );
  assert.equal(
    (graderRequest.questions as Array<Record<string, unknown>>).length,
    4,
  );

  const resultId = String(
    (data(submitted.payload).result as Record<string, unknown>).id,
  );
  const storedResult = database
    .prepare("SELECT evidence_json FROM challenge_results WHERE id = ?")
    .get(resultId) as { evidence_json: string };
  const storedGradeEvidence = JSON.parse(storedResult.evidence_json) as Record<
    string,
    unknown
  >;
  assert.equal(
    (
      storedGradeEvidence.trustedEvidence as Array<Record<string, unknown>>
    )[0].questionId,
    "red-q3",
  );

  const replay = await api(`/v1/runs/${run.id}/submit`, {
    method: "POST",
    idempotencyKey: "red-submit-valid-001",
    body: { answers },
  });
  assert.equal(replay.response.headers.get("idempotent-replayed"), "true");
  assert.equal(
    (data(replay.payload).result as Record<string, unknown>).id,
    (data(submitted.payload).result as Record<string, unknown>).id,
  );

  const duplicate = await api(`/v1/runs/${run.id}/submit`, {
    method: "POST",
    idempotencyKey: "red-submit-second-key",
    body: { answers },
  });
  assert.equal(duplicate.response.status, 409);
  assert.equal(
    (duplicate.payload.error as Record<string, unknown>).code,
    "RUN_ALREADY_SUBMITTED",
  );

  const scoreEvents = database
    .prepare("SELECT id FROM score_events WHERE result_id = ?")
    .all(String((data(submitted.payload).result as Record<string, unknown>).id));
  assert.equal(scoreEvents.length, 1);
  assert.throws(() =>
    database
      .prepare("UPDATE score_events SET points_delta = 0 WHERE id = ?")
      .run((scoreEvents[0] as { id: string }).id),
  );
});

test("desktop access exchanges a hashed short-lived ticket for run-lived access", async () => {
  const browserRun = database
    .prepare(
      `SELECT id, expires_at FROM runtime_runs
        WHERE user_id = 'user_dev' AND access_method = 'browser_desktop'
        ORDER BY created_at ASC LIMIT 1`,
    )
    .get() as { id: string; expires_at: string };
  const issued = await api(`/v1/runs/${browserRun.id}/desktop-ticket`, {
    method: "POST",
  });
  assert.equal(issued.response.status, 201);
  const ticketData = data(issued.payload) as Record<string, unknown>;
  const ticket = String(ticketData.ticket);
  assert.ok(ticket.length >= 40);
  assert.match(
    String(ticketData.gatewayUrl),
    new RegExp(`/sessions/${browserRun.id}/desktop\\?ticket=`),
  );

  const stored = database
    .prepare("SELECT ticket_hash, expires_at, consumed_at, created_at FROM access_tickets WHERE run_id = ?")
    .get(browserRun.id) as {
      ticket_hash: string;
      expires_at: string;
      consumed_at: string | null;
      created_at: string;
    };
  assert.notEqual(stored.ticket_hash, ticket);
  assert.equal(stored.ticket_hash.length, 64);
  assert.equal(stored.consumed_at, null);
  assert.equal(Date.parse(stored.expires_at) - Date.parse(stored.created_at), 5 * 60_000);
  assert.equal(ticketData.expiresAt, stored.expires_at);

  const exchanged = await api("/v1/internal/desktop-tickets/exchange", {
    method: "POST",
    authorization: "Bearer desktop-gateway-dev-token",
    body: { ticket },
  });
  assert.equal(exchanged.response.status, 200);
  const access = data(exchanged.payload).access as Record<string, unknown>;
  assert.equal(access.runId, browserRun.id);
  assert.equal(typeof access.namespace, "string");
  assert.equal(access.expiresAt, browserRun.expires_at);
  assert.equal(access.ticketExpiresAt, ticketData.expiresAt);
  assert.notEqual(access.expiresAt, access.ticketExpiresAt);

  const replay = await api("/v1/internal/desktop-tickets/exchange", {
    method: "POST",
    authorization: "Bearer desktop-gateway-dev-token",
    body: { ticket },
  });
  assert.equal(replay.response.status, 410);
  assert.equal(
    (replay.payload.error as Record<string, unknown>).code,
    "DESKTOP_TICKET_EXPIRED",
  );
  const consumedAudit = database
    .prepare(
      "SELECT id FROM audit_logs WHERE action = 'desktop_ticket.consumed' AND resource_id = ?",
    )
    .all(browserRun.id);
  assert.equal(consumedAudit.length, 1);
});

test("OpenVPN profile metadata uses the same one-time download pattern", async () => {
  const vpnRun = database
    .prepare(
      `SELECT id FROM runtime_runs
        WHERE user_id = 'user_dev' AND access_method = 'openvpn'
        ORDER BY created_at DESC LIMIT 1`,
    )
    .get() as { id: string };
  const issued = await api(`/v1/runs/${vpnRun.id}/openvpn-ticket`, {
    method: "POST",
  });
  assert.equal(issued.response.status, 201);
  const ticketData = data(issued.payload);
  assert.match(String(ticketData.downloadUrl), /\/download\?ticket=/);
  assert.match(String(ticketData.downloadUrl), /^http:\/\/localhost:9100\//);

  const exchanged = await api("/v1/internal/openvpn-tickets/exchange", {
    method: "POST",
    authorization: "Bearer openvpn-download-dev-token",
    body: { ticket: ticketData.ticket },
  });
  assert.equal(exchanged.response.status, 200);
  const access = data(exchanged.payload).access as Record<string, unknown>;
  assert.equal(access.runId, vpnRun.id);
  assert.equal(
    (access.openVpn as Record<string, unknown>).protocol,
    "udp",
  );

  const replay = await api("/v1/internal/openvpn-tickets/exchange", {
    method: "POST",
    authorization: "Bearer openvpn-download-dev-token",
    body: { ticket: ticketData.ticket },
  });
  assert.equal(replay.response.status, 410);
});

test("OIDC authentication uses verified roles and separates onboarding from registration", async () => {
  const verifier = {
    async verify(token: string) {
      assert.equal(token, "verified-token");
      return {
        subject: "keycloak-subject-org-admin",
        email: "oidc-admin@example.test",
        displayName: "OIDC Admin",
        roles: ["org_admin"],
        mode: "oidc",
      };
    },
  } as unknown as OidcVerifier;
  const oidc = createApplication({
    authMode: "oidc",
    repositoryMode: "sqlite",
    databasePath: ":memory:",
    oidcVerifier: verifier,
    allowedOrigins: ["https://console.example"],
    runtime: {
      createRun: () => Promise.reject(new Error("not used")),
      getRunStatus: () => Promise.reject(new Error("not used")),
      destroyRun: () => Promise.reject(new Error("not used")),
    },
    labGenerator: { generate: (input) => input },
    evidenceGrader: { grade: () => [] },
    labValidator: { validate: () => Promise.reject(new Error("not used")) },
    telemetryGateway: noopTelemetryGateway,
    environmentBuilder: noopEnvironmentBuilder,
  });
  await new Promise<void>((resolve, reject) => {
    oidc.server.once("error", reject);
    oidc.server.listen(0, "127.0.0.1", resolve);
  });
  const address = oidc.server.address();
  assert.ok(address && typeof address !== "string");
  const oidcBase = `http://127.0.0.1:${address.port}`;
  const headers = {
    authorization: "Bearer verified-token",
    "content-type": "application/json",
    origin: "https://console.example",
  };

  try {
    const passwordRegistration = await fetch(`${oidcBase}/v1/auth/register`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        email: "ignored@example.test",
        handle: "ignored_user",
        displayName: "Ignored",
      }),
    });
    assert.equal(passwordRegistration.status, 403);

    const onboarding = await fetch(`${oidcBase}/v1/auth/onboarding`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        handle: "oidc_org_admin",
        accountType: "organization",
        organizationJoinCode: "SECURITY-LAB",
      }),
    });
    assert.equal(onboarding.status, 201);
    assert.equal(
      onboarding.headers.get("access-control-allow-origin"),
      "https://console.example",
    );
    const onboarded = (await onboarding.json()) as Record<string, unknown>;
    const oidcUser = data(onboarded).user as Record<string, unknown>;
    assert.equal(
      (oidcUser.organization as Record<string, unknown>).role,
      "org_admin",
    );

    const me = await fetch(`${oidcBase}/v1/me`, {
      headers: { authorization: "Bearer verified-token" },
    });
    assert.equal(me.status, 200);
    const organizationReport = await fetch(`${oidcBase}/v1/reports/organization`, {
      headers: { authorization: "Bearer verified-token" },
    });
    assert.equal(organizationReport.status, 200);

    const spoofed = await fetch(`${oidcBase}/v1/me`, {
      headers: { "x-user-id": "user_dev" },
    });
    assert.equal(spoofed.status, 401);
  } finally {
    await oidc.close();
  }
});

test("X-User-Id is rejected unless AUTH_MODE=dev", async () => {
  const verifier = {
    async verify() {
      return {
        subject: "unused",
        roles: ["individual"],
        mode: "oidc",
      };
    },
  } as unknown as OidcVerifier;
  const production = createApplication({
    databasePath: ":memory:",
    repositoryMode: "sqlite",
    authMode: "oidc",
    oidcVerifier: verifier,
    runtime: {
      createRun: () => Promise.reject(new Error("not used")),
      getRunStatus: () => Promise.reject(new Error("not used")),
      destroyRun: () => Promise.reject(new Error("not used")),
    },
    labGenerator: { generate: (input) => input },
    evidenceGrader: { grade: () => [] },
    labValidator: { validate: () => Promise.reject(new Error("not used")) },
    telemetryGateway: noopTelemetryGateway,
    environmentBuilder: noopEnvironmentBuilder,
  });
  await new Promise<void>((resolve, reject) => {
    production.server.once("error", reject);
    production.server.listen(0, "127.0.0.1", resolve);
  });
  const address = production.server.address();
  assert.ok(address && typeof address !== "string");

  try {
    const response = await fetch(`http://127.0.0.1:${address.port}/v1/me`, {
      headers: { "x-user-id": "user_dev" },
    });
    assert.equal(response.status, 401);
    const payload = (await response.json()) as Record<string, unknown>;
    assert.equal(
      (payload.error as Record<string, unknown>).code,
      "DEV_AUTH_DISABLED",
    );
  } finally {
    await production.close();
  }
});

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
const destroyedRuns: string[] = [];
const application = createApplication({
  repository,
  authMode: "dev",
  runtime: {
    createRun: () => Promise.reject(new Error("not used")),
    getRunStatus: () => Promise.reject(new Error("not used")),
    destroyRun(runId) {
      destroyedRuns.push(runId);
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
  if (options.idempotencyKey) {
    headers.set("idempotency-key", options.idempotencyKey);
  }
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

function errorCode(payload: Record<string, unknown>): unknown {
  return (payload.error as Record<string, unknown>).code;
}

test("admin APIs enforce RBAC, tenant isolation, secret handling and idempotent mutations", async () => {
  const personal = await api("/v1/auth/register", {
    method: "POST",
    body: {
      email: "ordinary-admin-test@example.test",
      handle: "ordinary_admin_test",
      displayName: "Ordinary User",
      affiliation: "Test Affiliation",
      consent: { terms: true, privacy: true },
      password: "strong-password",
      accountType: "personal",
    },
  });
  assert.equal(personal.response.status, 201);
  const ordinaryId = String(
    (data(personal.payload).user as Record<string, unknown>).id,
  );

  const forbiddenOverview = await api("/v1/admin/overview", {
    userId: ordinaryId,
  });
  assert.equal(forbiddenOverview.response.status, 403);
  assert.equal(errorCode(forbiddenOverview.payload), "PLATFORM_ADMIN_REQUIRED");

  const forbiddenCreate = await api("/v1/admin/organizations", {
    method: "POST",
    userId: ordinaryId,
    idempotencyKey: "ordinary-create-org",
    body: { name: "Forbidden Org", slug: "forbidden-org" },
  });
  assert.equal(forbiddenCreate.response.status, 403);

  const overview = await api("/v1/admin/overview");
  assert.equal(overview.response.status, 200);
  assert.ok(
    Number(
      (
        data(overview.payload).overview as Record<string, unknown>
      ).organizations,
    ) >= 1,
  );

  const createBody = { name: "Threat Research", slug: "threat-research" };
  const created = await api("/v1/admin/organizations", {
    method: "POST",
    idempotencyKey: "create-threat-research",
    body: createBody,
  });
  assert.equal(created.response.status, 201);
  const createdData = data(created.payload);
  const organization = createdData.organization as Record<string, unknown>;
  const organizationId = String(organization.id);
  const firstJoinCode = String(createdData.joinCode);
  assert.match(firstJoinCode, /^cg_[A-Za-z0-9_-]{32}$/);
  assert.equal(createdData.joinCodeReturned, true);
  assert.equal("joinCodeHash" in organization, false);

  const storedOrganization = database
    .prepare(
      "SELECT join_code_hash FROM organizations WHERE id = ?",
    )
    .get(organizationId) as { join_code_hash: string };
  assert.equal(
    storedOrganization.join_code_hash,
    hashOrganizationJoinCode(firstJoinCode),
  );
  assert.notEqual(storedOrganization.join_code_hash, firstJoinCode);

  const storedCreate = database
    .prepare(
      `SELECT response_json FROM idempotency_records
        WHERE user_id = 'user_dev' AND operation = 'admin.organization.create'
          AND idempotency_key = 'create-threat-research'`,
    )
    .get() as { response_json: string };
  assert.doesNotMatch(storedCreate.response_json, new RegExp(firstJoinCode));
  assert.equal(
    (
      data(JSON.parse(storedCreate.response_json) as Record<string, unknown>)
    ).joinCode,
    null,
  );

  const createReplay = await api("/v1/admin/organizations", {
    method: "POST",
    idempotencyKey: "create-threat-research",
    body: createBody,
  });
  assert.equal(createReplay.response.status, 201);
  assert.equal(createReplay.response.headers.get("idempotent-replayed"), "true");
  assert.equal(data(createReplay.payload).joinCode, null);
  assert.doesNotMatch(JSON.stringify(createReplay.payload), new RegExp(firstJoinCode));

  const orgAdminRegistration = await api("/v1/auth/register", {
    method: "POST",
    body: {
      email: "org-admin@example.test",
      handle: "threat_org_admin",
      displayName: "Threat Org Admin",
      affiliation: "Test Affiliation",
      consent: { terms: true, privacy: true },
      accountType: "organization",
      organizationJoinCode: firstJoinCode,
    },
  });
  assert.equal(orgAdminRegistration.response.status, 201);
  const orgAdminId = String(
    (data(orgAdminRegistration.payload).user as Record<string, unknown>).id,
  );
  database
    .prepare(
      "UPDATE organization_memberships SET role = 'org_admin' WHERE user_id = ?",
    )
    .run(orgAdminId);

  const memberRegistration = await api("/v1/auth/register", {
    method: "POST",
    body: {
      email: "org-member@example.test",
      handle: "threat_org_member",
      displayName: "Threat Org Member",
      affiliation: "Test Affiliation",
      consent: { terms: true, privacy: true },
      accountType: "organization",
      organizationJoinCode: firstJoinCode,
    },
  });
  assert.equal(memberRegistration.response.status, 201);
  const memberId = String(
    (data(memberRegistration.payload).user as Record<string, unknown>).id,
  );

  const orgAdminPlatformView = await api("/v1/admin/users", {
    userId: orgAdminId,
  });
  assert.equal(orgAdminPlatformView.response.status, 403);

  const members = await api(
    "/v1/admin/organization/members?page=1&pageSize=100",
    { userId: orgAdminId },
  );
  assert.equal(members.response.status, 200);
  const memberItems = data(members.payload).items as Record<string, unknown>[];
  const memberIds = new Set(memberItems.map((item) => String(item.id)));
  assert.deepEqual(memberIds, new Set([orgAdminId, memberId]));
  assert.equal(memberIds.has("user_dev"), false);

  const tenantOverride = await api(
    "/v1/admin/organization/members?organizationId=org_security_lab",
    { userId: orgAdminId },
  );
  assert.equal(tenantOverride.response.status, 400);
  assert.equal(errorCode(tenantOverride.payload), "UNSUPPORTED_ADMIN_FILTER");

  const filteredUsers = await api(
    `/v1/admin/users?organizationId=${encodeURIComponent(
      organizationId,
    )}&page=1&pageSize=1`,
  );
  assert.equal(filteredUsers.response.status, 200);
  const userPage = data(filteredUsers.payload);
  assert.equal((userPage.items as unknown[]).length, 1);
  assert.equal(
    (userPage.pagination as Record<string, unknown>).total,
    2,
  );
  assert.doesNotMatch(JSON.stringify(filteredUsers.payload), /password_hash/i);

  const rotated = await api(
    `/v1/admin/organizations/${encodeURIComponent(
      organizationId,
    )}/rotate-join-code`,
    {
      method: "POST",
      idempotencyKey: "rotate-threat-research",
      body: {},
    },
  );
  assert.equal(rotated.response.status, 200);
  const secondJoinCode = String(data(rotated.payload).joinCode);
  assert.match(secondJoinCode, /^cg_[A-Za-z0-9_-]{32}$/);
  assert.notEqual(secondJoinCode, firstJoinCode);
  const storedRotation = database
    .prepare(
      `SELECT o.join_code_hash, i.response_json
         FROM organizations o
         JOIN idempotency_records i ON i.resource_id = o.id
        WHERE o.id = ?
          AND i.operation = ?
          AND i.idempotency_key = ?`,
    )
    .get(
      organizationId,
      `admin.organization.rotate_join_code:${organizationId}`,
      "rotate-threat-research",
    ) as { join_code_hash: string; response_json: string };
  assert.equal(
    storedRotation.join_code_hash,
    hashOrganizationJoinCode(secondJoinCode),
  );
  assert.doesNotMatch(storedRotation.response_json, new RegExp(secondJoinCode));

  const rotateReplay = await api(
    `/v1/admin/organizations/${encodeURIComponent(
      organizationId,
    )}/rotate-join-code`,
    {
      method: "POST",
      idempotencyKey: "rotate-threat-research",
      body: {},
    },
  );
  assert.equal(rotateReplay.response.status, 200);
  assert.equal(rotateReplay.response.headers.get("idempotent-replayed"), "true");
  assert.equal(data(rotateReplay.payload).joinCode, null);
  assert.doesNotMatch(JSON.stringify(rotateReplay.payload), new RegExp(secondJoinCode));

  const oldCodeRejected = await api("/v1/auth/register", {
    method: "POST",
    body: {
      email: "old-code@example.test",
      handle: "old_code_user",
      displayName: "Old Code User",
      affiliation: "Test Affiliation",
      consent: { terms: true, privacy: true },
      accountType: "organization",
      organizationJoinCode: firstJoinCode,
    },
  });
  assert.equal(oldCodeRejected.response.status, 404);
  assert.equal(errorCode(oldCodeRejected.payload), "ORGANIZATION_NOT_FOUND");

  const newCodeAccepted = await api("/v1/auth/register", {
    method: "POST",
    body: {
      email: "new-code@example.test",
      handle: "new_code_user",
      displayName: "New Code User",
      affiliation: "Test Affiliation",
      consent: { terms: true, privacy: true },
      accountType: "organization",
      organizationJoinCode: secondJoinCode,
    },
  });
  assert.equal(newCodeAccepted.response.status, 201);

  const generated = await api("/v1/labs/generate", {
    method: "POST",
    idempotencyKey: "admin-quarantine-lab",
    body: {
      title: "Admin quarantine invariant",
      prompt: "Investigate the generated ELK evidence and map the ATT&CK technique.",
      team: "blue",
      desktopImage: "ubuntu",
      accessMethod: "both",
      questionTypes: ["elk_search", "mitre_attack"],
    },
  });
  assert.equal(generated.response.status, 201);
  const labId = String(
    (data(generated.payload).lab as Record<string, unknown>).id,
  );

  const quarantined = await api(
    `/v1/admin/labs/${encodeURIComponent(labId)}/quarantine`,
    {
      method: "POST",
      idempotencyKey: "quarantine-by-admin",
      body: { reason: "Unsafe target image pending review" },
    },
  );
  assert.equal(quarantined.response.status, 200);
  const quarantinedLab = data(quarantined.payload).lab as Record<string, unknown>;
  assert.equal(quarantinedLab.validationStatus, "quarantined");
  assert.equal("config" in quarantinedLab, false);
  assert.doesNotMatch(JSON.stringify(quarantined.payload), /correctAnswer/i);

  const quarantineReplay = await api(
    `/v1/admin/labs/${encodeURIComponent(labId)}/quarantine`,
    {
      method: "POST",
      idempotencyKey: "quarantine-by-admin",
      body: { reason: "Unsafe target image pending review" },
    },
  );
  assert.equal(quarantineReplay.response.status, 200);
  assert.equal(
    quarantineReplay.response.headers.get("idempotent-replayed"),
    "true",
  );

  const validationAfterQuarantine = await api(
    `/v1/labs/${encodeURIComponent(labId)}/validate`,
    { method: "POST", body: {} },
  );
  assert.equal(validationAfterQuarantine.response.status, 200);
  assert.equal(
    (
      data(validationAfterQuarantine.payload).lab as Record<string, unknown>
    ).validationStatus,
    "quarantined",
  );

  const quarantinedList = await api(
    "/v1/admin/labs?status=quarantined&page=1&pageSize=100",
  );
  assert.equal(quarantinedList.response.status, 200);
  assert.equal(
    (data(quarantinedList.payload).items as Record<string, unknown>[]).some(
      (item) => item.id === labId,
    ),
    true,
  );
  assert.doesNotMatch(JSON.stringify(quarantinedList.payload), /correctAnswer/i);

  const runId = "run_admin_termination_test";
  const timestamp = new Date().toISOString();
  database
    .prepare(
      `INSERT INTO runtime_runs
        (id, lab_id, user_id, status, environment, access_method, browser_url,
         openvpn_profile_json, expires_at, metadata_json, created_at)
       VALUES (?, ?, 'user_dev', 'ready', 'ubuntu', 'both', ?, ?, ?, ?, ?)`,
    )
    .run(
      runId,
      labId,
      "https://desktop.example.invalid/private-session",
      JSON.stringify({ profileId: "secret-profile", privateKey: "never-return" }),
      new Date(Date.now() + 60_000).toISOString(),
      JSON.stringify({ namespace: "runtime-admin-test" }),
      timestamp,
    );

  const runList = await api("/v1/admin/runs?status=ready&pageSize=100");
  assert.equal(runList.response.status, 200);
  assert.doesNotMatch(JSON.stringify(runList.payload), /private-session|never-return/);

  const terminated = await api(
    `/v1/admin/runs/${encodeURIComponent(runId)}/terminate`,
    {
      method: "POST",
      idempotencyKey: "terminate-admin-run",
      body: { reason: "Operator requested shutdown" },
    },
  );
  assert.equal(terminated.response.status, 200);
  assert.equal(
    (data(terminated.payload).run as Record<string, unknown>).status,
    "stopped",
  );
  assert.deepEqual(destroyedRuns, [runId]);

  const terminateReplay = await api(
    `/v1/admin/runs/${encodeURIComponent(runId)}/terminate`,
    {
      method: "POST",
      idempotencyKey: "terminate-admin-run",
      body: { reason: "Operator requested shutdown" },
    },
  );
  assert.equal(terminateReplay.response.status, 200);
  assert.equal(
    terminateReplay.response.headers.get("idempotent-replayed"),
    "true",
  );
  assert.deepEqual(destroyedRuns, [runId]);

  const stoppedRow = database
    .prepare(
      "SELECT status, browser_url, openvpn_profile_json FROM runtime_runs WHERE id = ?",
    )
    .get(runId) as {
    status: string;
    browser_url: string | null;
    openvpn_profile_json: string | null;
  };
  assert.equal(stoppedRow.status, "stopped");
  assert.equal(stoppedRow.browser_url, null);
  assert.equal(stoppedRow.openvpn_profile_json, null);

  const auditCounts = database
    .prepare(
      `SELECT action, count(*) AS count FROM audit_logs
        WHERE action IN (
          'admin.organization_created',
          'admin.organization_join_code_rotated',
          'admin.lab_quarantined',
          'admin.runtime_terminated'
        )
        GROUP BY action`,
    )
    .all() as { action: string; count: number }[];
  assert.deepEqual(
    Object.fromEntries(auditCounts.map((item) => [item.action, item.count])),
    {
      "admin.lab_quarantined": 1,
      "admin.organization_created": 1,
      "admin.organization_join_code_rotated": 1,
      "admin.runtime_terminated": 1,
    },
  );
});

test("admin authorization requires both verified token and database roles", async () => {
  const oidcDatabase = createDatabase(":memory:");
  const oidcRepository = new SqliteDevelopmentRepository(oidcDatabase);
  const subjects: Record<
    string,
    { subject: string; roles: string[]; email: string; displayName: string }
  > = {
    "token-only-admin": {
      subject: "token-only-admin-subject",
      roles: ["platform_admin"],
      email: "token-only-admin@example.test",
      displayName: "Token Only Admin",
    },
    "database-only-admin": {
      subject: "database-only-admin-subject",
      roles: ["individual"],
      email: "database-only-admin@example.test",
      displayName: "Database Only Admin",
    },
    "token-only-org-admin": {
      subject: "token-only-org-admin-subject",
      roles: ["org_admin"],
      email: "token-only-org-admin@example.test",
      displayName: "Token Only Org Admin",
    },
  };
  const verifier = {
    async verify(token: string) {
      const principal = subjects[token];
      if (!principal) throw new Error("unknown test token");
      return { ...principal, mode: "oidc" };
    },
  } as unknown as OidcVerifier;
  const oidcApplication = createApplication({
    repository: oidcRepository,
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
  await oidcApplication.ready;
  const createdAt = new Date().toISOString();
  oidcDatabase
    .prepare(
      `INSERT INTO users
        (id, email, handle, display_name, external_subject, platform_role,
         created_at)
       VALUES
        ('user_token_only_admin', 'token-only-admin@example.test',
         'token_only_admin', 'Token Only Admin', 'token-only-admin-subject',
         'user', ?),
        ('user_database_only_admin', 'database-only-admin@example.test',
         'database_only_admin', 'Database Only Admin',
         'database-only-admin-subject', 'platform_admin', ?),
        ('user_token_only_org_admin', 'token-only-org-admin@example.test',
         'token_only_org_admin', 'Token Only Org Admin',
         'token-only-org-admin-subject', 'user', ?)`,
    )
    .run(createdAt, createdAt, createdAt);
  oidcDatabase
    .prepare(
      `INSERT INTO organization_memberships
        (user_id, organization_id, role, created_at)
       VALUES ('user_token_only_org_admin', 'org_security_lab', 'member', ?)`,
    )
    .run(createdAt);

  await new Promise<void>((resolve, reject) => {
    oidcApplication.server.once("error", reject);
    oidcApplication.server.listen(0, "127.0.0.1", resolve);
  });
  const address = oidcApplication.server.address();
  assert.ok(address && typeof address !== "string");
  const oidcBaseUrl = `http://127.0.0.1:${address.port}`;

  try {
    for (const token of ["token-only-admin", "database-only-admin"]) {
      const response = await fetch(`${oidcBaseUrl}/v1/admin/overview`, {
        headers: { authorization: `Bearer ${token}` },
      });
      assert.equal(response.status, 403);
      const payload = (await response.json()) as Record<string, unknown>;
      assert.equal(errorCode(payload), "PLATFORM_ADMIN_REQUIRED");
    }

    const orgResponse = await fetch(
      `${oidcBaseUrl}/v1/admin/organization/members`,
      {
        headers: { authorization: "Bearer token-only-org-admin" },
      },
    );
    assert.equal(orgResponse.status, 403);
    const orgPayload = (await orgResponse.json()) as Record<string, unknown>;
    assert.equal(errorCode(orgPayload), "ORG_ADMIN_REQUIRED");
  } finally {
    await oidcApplication.close();
  }
});

test("legacy SQLite join codes migrate to hashes without breaking organization creation", () => {
  const legacyDatabase = createDatabase(":memory:");
  legacyDatabase.exec(
    `CREATE TABLE organizations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE COLLATE NOCASE,
      join_code TEXT NOT NULL UNIQUE COLLATE NOCASE,
      created_at TEXT NOT NULL
    );
    INSERT INTO organizations (id, name, slug, join_code, created_at)
    VALUES (
      'org_legacy', 'Legacy Org', 'legacy-org', 'LEGACY-CODE',
      '2026-01-01T00:00:00.000Z'
    );`,
  );
  const legacyRepository = new SqliteDevelopmentRepository(legacyDatabase);
  try {
    legacyRepository.initialize();
    const migrated = legacyDatabase
      .prepare(
        "SELECT join_code, join_code_hash FROM organizations WHERE id = 'org_legacy'",
      )
      .get() as { join_code: string; join_code_hash: string };
    assert.equal(
      migrated.join_code_hash,
      hashOrganizationJoinCode("LEGACY-CODE"),
    );
    assert.equal(migrated.join_code, migrated.join_code_hash);
    assert.notEqual(migrated.join_code, "LEGACY-CODE");

    const createdAt = new Date().toISOString();
    const created = legacyRepository.createOrganization({
      id: "org_after_legacy_migration",
      name: "Created After Migration",
      slug: "created-after-migration",
      joinCodeHash: hashOrganizationJoinCode("NEW-CODE"),
      createdAt,
    }) as Record<string, unknown>;
    assert.equal(created.id, "org_after_legacy_migration");
    const stored = legacyDatabase
      .prepare(
        `SELECT join_code, join_code_hash FROM organizations
          WHERE id = 'org_after_legacy_migration'`,
      )
      .get() as { join_code: string; join_code_hash: string };
    assert.equal(stored.join_code, stored.join_code_hash);
    assert.notEqual(stored.join_code, "NEW-CODE");
  } finally {
    legacyRepository.close();
  }
});

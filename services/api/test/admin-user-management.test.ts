import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { createApplication } from "../src/app.ts";
import {
  createDatabase,
  SqliteDevelopmentRepository,
} from "../src/database.ts";

const database = createDatabase(":memory:");
const repository = new SqliteDevelopmentRepository(database);
const application = createApplication({
  repository,
  authMode: "dev",
  runtime: {
    createRun: () => Promise.reject(new Error("not used")),
    getRunStatus: () => Promise.reject(new Error("not used")),
    destroyRun() {},
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

function record(value: unknown): Record<string, unknown> {
  return value as Record<string, unknown>;
}

test("platform role and suspension mutations enforce their guardrails", async () => {
  const created = await api("/v1/admin/organizations", {
    method: "POST",
    idempotencyKey: "create-ops-guild",
    body: { name: "Ops Guild", slug: "ops-guild" },
  });
  assert.equal(created.response.status, 201);
  const joinCode = String(data(created.payload).joinCode);

  const outsiderId = await join(joinCode, "guild_outsider");
  const memberId = await join(joinCode, "guild_bystander");

  const selfDemotion = await api("/v1/admin/users/user_dev/platform-role", {
    method: "POST",
    idempotencyKey: "self-demote",
    body: { platformRole: "user" },
  });
  assert.equal(selfDemotion.response.status, 409);
  assert.equal(errorCode(selfDemotion.payload), "CANNOT_MODIFY_SELF");

  const byNonAdmin = await api(
    `/v1/admin/users/${encodeURIComponent(memberId)}/platform-role`,
    {
      method: "POST",
      userId: memberId,
      idempotencyKey: "non-admin-promote",
      body: { platformRole: "platform_admin" },
    },
  );
  assert.equal(byNonAdmin.response.status, 403);

  const badRole = await api(
    `/v1/admin/users/${encodeURIComponent(outsiderId)}/platform-role`,
    {
      method: "POST",
      idempotencyKey: "bad-role",
      body: { platformRole: "superuser" },
    },
  );
  assert.equal(badRole.response.status, 400);
  assert.equal(errorCode(badRole.payload), "INVALID_PLATFORM_ROLE");

  const missingUser = await api("/v1/admin/users/user_absent/platform-role", {
    method: "POST",
    idempotencyKey: "missing-user",
    body: { platformRole: "platform_admin" },
  });
  assert.equal(missingUser.response.status, 404);
  assert.equal(errorCode(missingUser.payload), "USER_NOT_FOUND");

  const promoted = await api(
    `/v1/admin/users/${encodeURIComponent(outsiderId)}/platform-role`,
    {
      method: "POST",
      idempotencyKey: "promote-outsider",
      body: { platformRole: "platform_admin", reason: "on-call rotation" },
    },
  );
  assert.equal(promoted.response.status, 200);
  assert.equal(
    record(data(promoted.payload).user).platformRole,
    "platform_admin",
  );

  // The promotion is real: the target can now reach a platform-admin route.
  const promotedAccess = await api("/v1/admin/overview", { userId: outsiderId });
  assert.equal(promotedAccess.response.status, 200);

  const promoteReplay = await api(
    `/v1/admin/users/${encodeURIComponent(outsiderId)}/platform-role`,
    {
      method: "POST",
      idempotencyKey: "promote-outsider",
      body: { platformRole: "platform_admin", reason: "on-call rotation" },
    },
  );
  assert.equal(promoteReplay.response.headers.get("idempotent-replayed"), "true");

  const auditedRole = database
    .prepare(
      `SELECT metadata_json FROM audit_logs
        WHERE action = 'admin.user_platform_role_changed' AND resource_id = ?`,
    )
    .get(outsiderId) as { metadata_json: string };
  const roleMetadata = JSON.parse(auditedRole.metadata_json) as Record<string, unknown>;
  assert.equal(roleMetadata.previousRole, "user");
  assert.equal(roleMetadata.platformRole, "platform_admin");
  assert.equal(roleMetadata.reason, "on-call rotation");

  const suspended = await api(
    `/v1/admin/users/${encodeURIComponent(outsiderId)}/suspension`,
    {
      method: "POST",
      idempotencyKey: "suspend-outsider",
      body: { suspended: true, reason: "policy violation" },
    },
  );
  assert.equal(suspended.response.status, 200);
  assert.ok(record(data(suspended.payload).user).disabledAt);

  // Suspension revokes access even though the platform_admin role survives.
  const suspendedAccess = await api("/v1/admin/overview", { userId: outsiderId });
  assert.equal(suspendedAccess.response.status, 403);
  assert.equal(errorCode(suspendedAccess.payload), "ACCOUNT_SUSPENDED");

  const badSuspension = await api(
    `/v1/admin/users/${encodeURIComponent(memberId)}/suspension`,
    {
      method: "POST",
      idempotencyKey: "bad-suspension",
      body: { suspended: "yes" },
    },
  );
  assert.equal(badSuspension.response.status, 400);
  assert.equal(errorCode(badSuspension.payload), "INVALID_SUSPENSION");

  const reinstated = await api(
    `/v1/admin/users/${encodeURIComponent(outsiderId)}/suspension`,
    {
      method: "POST",
      idempotencyKey: "reinstate-outsider",
      body: { suspended: false },
    },
  );
  assert.equal(reinstated.response.status, 200);
  assert.equal(record(data(reinstated.payload).user).disabledAt, null);
  const restoredAccess = await api("/v1/admin/overview", { userId: outsiderId });
  assert.equal(restoredAccess.response.status, 200);
});

test("organization membership mutations respect owner-only transitions", async () => {
  const created = await api("/v1/admin/organizations", {
    method: "POST",
    idempotencyKey: "create-blue-cell",
    body: { name: "Blue Cell", slug: "blue-cell" },
  });
  assert.equal(created.response.status, 201);
  const joinCode = String(data(created.payload).joinCode);

  const ownerId = await join(joinCode, "cell_owner");
  const adminId = await join(joinCode, "cell_admin");
  const memberId = await join(joinCode, "cell_member");
  setMembershipRole(ownerId, "owner");
  setMembershipRole(adminId, "org_admin");

  const memberSelf = await api(
    `/v1/admin/organization/members/${encodeURIComponent(adminId)}/role`,
    {
      method: "POST",
      userId: adminId,
      idempotencyKey: "member-self",
      body: { role: "member" },
    },
  );
  assert.equal(memberSelf.response.status, 409);
  assert.equal(errorCode(memberSelf.payload), "CANNOT_MODIFY_SELF");

  const ownerTarget = await api(
    `/v1/admin/organization/members/${encodeURIComponent(ownerId)}/role`,
    {
      method: "POST",
      userId: adminId,
      idempotencyKey: "owner-target",
      body: { role: "member" },
    },
  );
  assert.equal(ownerTarget.response.status, 409);
  assert.equal(errorCode(ownerTarget.payload), "OWNER_IMMUTABLE");

  // A member of another tenant reads as absent rather than forbidden.
  const crossTenant = await api(
    "/v1/admin/organization/members/user_dev/role",
    {
      method: "POST",
      userId: adminId,
      idempotencyKey: "cross-tenant",
      body: { role: "member" },
    },
  );
  assert.equal(crossTenant.response.status, 404);
  assert.equal(errorCode(crossTenant.payload), "MEMBER_NOT_FOUND");

  const promotedMember = await api(
    `/v1/admin/organization/members/${encodeURIComponent(memberId)}/role`,
    {
      method: "POST",
      userId: adminId,
      idempotencyKey: "promote-member",
      body: { role: "org_admin", reason: "shift lead" },
    },
  );
  assert.equal(promotedMember.response.status, 200);
  assert.equal(
    record(data(promotedMember.payload).member).organizationRole,
    "org_admin",
  );

  // An org_admin cannot strip a peer of access; only the owner can.
  const peerDemotion = await api(
    `/v1/admin/organization/members/${encodeURIComponent(memberId)}/role`,
    {
      method: "POST",
      userId: adminId,
      idempotencyKey: "peer-demote",
      body: { role: "member" },
    },
  );
  assert.equal(peerDemotion.response.status, 403);
  assert.equal(errorCode(peerDemotion.payload), "ORGANIZATION_OWNER_REQUIRED");

  const ownerDemotion = await api(
    `/v1/admin/organization/members/${encodeURIComponent(memberId)}/role`,
    {
      method: "POST",
      userId: ownerId,
      idempotencyKey: "owner-demote",
      body: { role: "member" },
    },
  );
  assert.equal(ownerDemotion.response.status, 200);
  assert.equal(
    record(data(ownerDemotion.payload).member).organizationRole,
    "member",
  );

  const removed = await api(
    `/v1/admin/organization/members/${encodeURIComponent(memberId)}/remove`,
    {
      method: "POST",
      userId: adminId,
      idempotencyKey: "remove-member",
      body: { reason: "left the team" },
    },
  );
  assert.equal(removed.response.status, 200);
  assert.equal(data(removed.payload).removed, true);

  const remaining = await api(
    "/v1/admin/organization/members?page=1&pageSize=100",
    { userId: adminId },
  );
  const remainingIds = new Set(
    (data(remaining.payload).items as Record<string, unknown>[]).map((item) =>
      String(item.id),
    ),
  );
  assert.equal(remainingIds.has(memberId), false);
  assert.ok(remainingIds.has(ownerId));

  // The account survives the removal; only the membership is gone.
  const orphaned = database
    .prepare("SELECT id FROM users WHERE id = ?")
    .get(memberId) as { id: string } | undefined;
  assert.equal(orphaned?.id, memberId);
});

test("the audit log is readable, filterable and platform-admin only", async () => {
  const created = await api("/v1/admin/organizations", {
    method: "POST",
    idempotencyKey: "create-audit-org",
    body: { name: "Audit Org", slug: "audit-org" },
  });
  assert.equal(created.response.status, 201);
  const organizationId = String(
    record(data(created.payload).organization).id,
  );
  const readerId = await join(String(data(created.payload).joinCode), "audit_reader");

  const forbidden = await api("/v1/admin/audit-logs", { userId: readerId });
  assert.equal(forbidden.response.status, 403);
  assert.equal(errorCode(forbidden.payload), "PLATFORM_ADMIN_REQUIRED");

  const all = await api("/v1/admin/audit-logs?page=1&pageSize=50");
  assert.equal(all.response.status, 200);
  const items = data(all.payload).items as Record<string, unknown>[];
  assert.ok(items.length > 0);

  // Newest first.
  const times = items.map((item) => Date.parse(String(item.createdAt)));
  assert.deepEqual(times, [...times].sort((a, b) => b - a));

  const creation = items.find(
    (item) => item.action === "admin.organization_created" &&
      item.resourceId === organizationId,
  );
  assert.ok(creation, "organization creation should be audited");
  assert.equal(record(creation).resourceType, "organization");
  assert.equal(record(record(creation).actor).id, "user_dev");
  assert.equal(record(record(creation).metadata).slug, "audit-org");

  const byAction = await api(
    "/v1/admin/audit-logs?action=admin.organization_created&pageSize=50",
  );
  assert.equal(byAction.response.status, 200);
  const actions = new Set(
    (data(byAction.payload).items as Record<string, unknown>[]).map((item) =>
      String(item.action),
    ),
  );
  assert.deepEqual(actions, new Set(["admin.organization_created"]));

  const byResource = await api("/v1/admin/audit-logs?resourceType=user&pageSize=50");
  assert.equal(byResource.response.status, 200);
  const resourceTypes = new Set(
    (data(byResource.payload).items as Record<string, unknown>[]).map((item) =>
      String(item.resourceType),
    ),
  );
  assert.deepEqual(resourceTypes, new Set(["user"]));

  const bySearch = await api(
    `/v1/admin/audit-logs?search=${encodeURIComponent(organizationId)}&pageSize=50`,
  );
  assert.equal(bySearch.response.status, 200);
  const searched = data(bySearch.payload).items as Record<string, unknown>[];
  assert.ok(searched.length > 0);
  assert.ok(searched.every((item) => String(item.resourceId) === organizationId));

  const malformedAction = await api("/v1/admin/audit-logs?action=DROP%20TABLE");
  assert.equal(malformedAction.response.status, 400);
  assert.equal(errorCode(malformedAction.payload), "INVALID_ADMIN_FILTER");

  const badResource = await api("/v1/admin/audit-logs?resourceType=secrets");
  assert.equal(badResource.response.status, 400);
  assert.equal(errorCode(badResource.payload), "INVALID_ADMIN_FILTER");

  const unsupported = await api("/v1/admin/audit-logs?organizationId=org_x");
  assert.equal(unsupported.response.status, 400);
  assert.equal(errorCode(unsupported.payload), "UNSUPPORTED_ADMIN_FILTER");
});

test("registration requires consent and derives a handle from the email", async () => {
  const base = {
    displayName: "동의 테스트",
    affiliation: "한빛금융 보안관제팀",
    accountType: "personal" as const,
    password: "strong-password",
  };

  const noConsent = await api("/v1/auth/register", {
    method: "POST",
    body: { ...base, email: "consent-missing@example.test" },
  });
  assert.equal(noConsent.response.status, 400);
  assert.equal(errorCode(noConsent.payload), "CONSENT_REQUIRED");

  const partialConsent = await api("/v1/auth/register", {
    method: "POST",
    body: {
      ...base,
      email: "consent-partial@example.test",
      consent: { terms: true, privacy: false },
    },
  });
  assert.equal(partialConsent.response.status, 400);
  assert.equal(errorCode(partialConsent.payload), "CONSENT_REQUIRED");

  const noAffiliation = await api("/v1/auth/register", {
    method: "POST",
    body: {
      ...base,
      affiliation: "   ",
      email: "affiliation-missing@example.test",
      consent: { terms: true, privacy: true },
    },
  });
  assert.equal(noAffiliation.response.status, 400);
  assert.equal(errorCode(noAffiliation.payload), "INVALID_AFFILIATION");

  const created = await api("/v1/auth/register", {
    method: "POST",
    body: {
      ...base,
      email: "Jane.Doe+tag@example.test",
      consent: { terms: true, privacy: true },
    },
  });
  assert.equal(created.response.status, 201);
  const user = record(data(created.payload).user);
  // The email is lower-cased first, then '.' and '+' are dropped as they are
  // not valid handle characters.
  assert.equal(user.handle, "janedoetag");
  assert.equal(user.affiliation, "한빛금융 보안관제팀");

  // A different email that reduces to the same seed gets a suffixed handle.
  const collided = await api("/v1/auth/register", {
    method: "POST",
    body: {
      ...base,
      email: "jane.doe.tag@other.test",
      consent: { terms: true, privacy: true },
    },
  });
  assert.equal(collided.response.status, 201);
  assert.equal(record(data(collided.payload).user).handle, "janedoetag2");

  const stored = database
    .prepare(
      `SELECT affiliation, terms_agreed_at, terms_version,
              privacy_agreed_at, privacy_version
         FROM users WHERE id = ?`,
    )
    .get(String(user.id)) as Record<string, string | null>;
  assert.equal(stored.affiliation, "한빛금융 보안관제팀");
  assert.ok(stored.terms_agreed_at, "terms agreement time is recorded");
  assert.ok(stored.privacy_agreed_at, "privacy agreement time is recorded");
  assert.equal(stored.terms_version, "2026-07-22");
  assert.equal(stored.privacy_version, "2026-07-22");
});

test("releasing a quarantine restores a draft that must be re-validated", async () => {
  const generated = await api("/v1/labs/generate", {
    method: "POST",
    idempotencyKey: "release-lab-generate",
    body: {
      title: "Release invariant",
      prompt: "Investigate the generated ELK evidence and map the ATT&CK technique.",
      team: "blue",
      desktopImage: "ubuntu",
      accessMethod: "both",
      questionTypes: ["elk_search", "mitre_attack"],
    },
  });
  assert.equal(generated.response.status, 201);
  const labId = String(record(data(generated.payload).lab).id);

  // A lab that is not quarantined cannot be released.
  const premature = await api(
    `/v1/admin/labs/${encodeURIComponent(labId)}/release`,
    { method: "POST", idempotencyKey: "premature-release", body: {} },
  );
  assert.equal(premature.response.status, 409);
  assert.equal(errorCode(premature.payload), "LAB_NOT_QUARANTINED");

  const quarantined = await api(
    `/v1/admin/labs/${encodeURIComponent(labId)}/quarantine`,
    {
      method: "POST",
      idempotencyKey: "release-flow-quarantine",
      body: { reason: "suspected unsafe target" },
    },
  );
  assert.equal(quarantined.response.status, 200);
  assert.equal(record(data(quarantined.payload).lab).validationStatus, "quarantined");

  const released = await api(
    `/v1/admin/labs/${encodeURIComponent(labId)}/release`,
    {
      method: "POST",
      idempotencyKey: "release-flow-release",
      body: { reason: "false positive confirmed" },
    },
  );
  assert.equal(released.response.status, 200);
  const lab = record(data(released.payload).lab);
  // Draft, not validated: the pre-quarantine status is not retained.
  assert.equal(lab.validationStatus, "draft");
  assert.equal(lab.quarantineReason ?? null, null);

  const stored = database
    .prepare(
      `SELECT validation_status, admin_quarantined_at, admin_quarantined_by,
              admin_quarantine_reason FROM labs WHERE id = ?`,
    )
    .get(labId) as Record<string, unknown>;
  assert.equal(stored.validation_status, "draft");
  assert.equal(stored.admin_quarantined_at, null);
  assert.equal(stored.admin_quarantined_by, null);
  assert.equal(stored.admin_quarantine_reason, null);

  const replay = await api(
    `/v1/admin/labs/${encodeURIComponent(labId)}/release`,
    {
      method: "POST",
      idempotencyKey: "release-flow-release",
      body: { reason: "false positive confirmed" },
    },
  );
  assert.equal(replay.response.headers.get("idempotent-replayed"), "true");

  const audited = database
    .prepare(
      `SELECT metadata_json FROM audit_logs
        WHERE action = 'admin.lab_quarantine_released' AND resource_id = ?`,
    )
    .get(labId) as { metadata_json: string };
  const metadata = JSON.parse(audited.metadata_json) as Record<string, unknown>;
  assert.equal(metadata.reason, "false positive confirmed");
  assert.equal(metadata.restoredStatus, "draft");
});

test("accounts without recorded consent are gated until they agree", async () => {
  const created = await api("/v1/auth/register", {
    method: "POST",
    body: {
      email: "legacy.account@example.test",
      displayName: "레거시 계정",
      affiliation: "한빛금융",
      password: "strong-password",
      accountType: "personal",
      consent: { terms: true, privacy: true },
    },
  });
  assert.equal(created.response.status, 201);
  const userId = String(record(data(created.payload).user).id);

  // Simulate an account that predates the consent requirement.
  database
    .prepare(
      `UPDATE users SET terms_agreed_at = NULL, terms_version = NULL,
              privacy_agreed_at = NULL, privacy_version = NULL WHERE id = ?`,
    )
    .run(userId);

  const blocked = await api("/v1/labs", { userId });
  assert.equal(blocked.response.status, 403);
  assert.equal(errorCode(blocked.payload), "CONSENT_REQUIRED");

  // /v1/me stays reachable so the client can learn why it was blocked.
  const me = await api("/v1/me", { userId });
  assert.equal(me.response.status, 200);
  assert.equal(data(me.payload).consentRequired, true);
  assert.equal(data(me.payload).termsVersion, "2026-07-22");

  const refused = await api("/v1/me/consent", {
    method: "POST",
    userId,
    body: { consent: { terms: true, privacy: false } },
  });
  assert.equal(refused.response.status, 400);
  assert.equal(errorCode(refused.payload), "CONSENT_REQUIRED");

  const agreed = await api("/v1/me/consent", {
    method: "POST",
    userId,
    body: { consent: { terms: true, privacy: true } },
  });
  assert.equal(agreed.response.status, 200);
  assert.equal(data(agreed.payload).consentRequired, false);

  // Service access is restored.
  const allowed = await api("/v1/labs", { userId });
  assert.equal(allowed.response.status, 200);

  const stored = database
    .prepare(
      "SELECT terms_agreed_at, terms_version, privacy_version FROM users WHERE id = ?",
    )
    .get(userId) as Record<string, string | null>;
  assert.ok(stored.terms_agreed_at);
  assert.equal(stored.terms_version, "2026-07-22");
  assert.equal(stored.privacy_version, "2026-07-22");

  const audited = database
    .prepare(
      `SELECT count(*) AS total FROM audit_logs
        WHERE action = 'auth.consent_recorded' AND resource_id = ?`,
    )
    .get(userId) as { total: number };
  assert.equal(audited.total, 1);

  // A future document version re-gates the same account.
  database
    .prepare("UPDATE users SET privacy_version = '2020-01-01' WHERE id = ?")
    .run(userId);
  const regated = await api("/v1/labs", { userId });
  assert.equal(regated.response.status, 403);
  assert.equal(errorCode(regated.payload), "CONSENT_REQUIRED");
});

test("audit records carry a source address", async () => {
  const created = await api("/v1/admin/organizations", {
    method: "POST",
    idempotencyKey: "create-ip-org",
    body: { name: "IP Org", slug: "ip-org" },
  });
  assert.equal(created.response.status, 201);

  const entry = await api(
    "/v1/admin/audit-logs?action=admin.organization_created&pageSize=1",
  );
  const item = record((data(entry.payload).items as unknown[])[0]);
  // The loopback address the test client connects from.
  assert.match(String(item.actorIp), /127\.0\.0\.1|::1|::ffff:127\.0\.0\.1/);

  // A forged header is ignored while TRUST_PROXY_HEADERS is off.
  const forged = await fetch(`${baseUrl}/v1/admin/organizations`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "idempotency-key": "forged-ip-org",
      "x-forwarded-for": "203.0.113.7",
    },
    body: JSON.stringify({ name: "Forged Org", slug: "forged-org" }),
  });
  assert.equal(forged.status, 201);
  const after = await api(
    "/v1/admin/audit-logs?action=admin.organization_created&pageSize=1",
  );
  const newest = record((data(after.payload).items as unknown[])[0]);
  assert.notEqual(newest.actorIp, "203.0.113.7");

  // System-initiated events have no request context and no address.
  const sweptIp = database
    .prepare("SELECT actor_ip FROM audit_logs WHERE action = 'runtime.expired'")
    .get() as { actor_ip: string | null } | undefined;
  if (sweptIp) assert.equal(sweptIp.actor_ip, null);
});

test("the organization audit log is scoped to governance events only", async () => {
  const created = await api("/v1/admin/organizations", {
    method: "POST",
    idempotencyKey: "create-scoped-org",
    body: { name: "Scoped Org", slug: "scoped-org" },
  });
  assert.equal(created.response.status, 201);
  const organizationId = String(record(data(created.payload).organization).id);
  const joinCode = String(data(created.payload).joinCode);

  const ownerId = await join(joinCode, "scoped_owner");
  const memberId = await join(joinCode, "scoped_member");
  setMembershipRole(ownerId, "owner");

  const promoted = await api(
    `/v1/admin/organization/members/${encodeURIComponent(memberId)}/role`,
    {
      method: "POST",
      userId: ownerId,
      idempotencyKey: "scoped-promote",
      body: { role: "org_admin", reason: "shift lead" },
    },
  );
  assert.equal(promoted.response.status, 200);

  const plainMember = await join(joinCode, "scoped_plain");
  const forbidden = await api("/v1/admin/organization/audit-logs", {
    userId: plainMember,
  });
  assert.equal(forbidden.response.status, 403);
  assert.equal(errorCode(forbidden.payload), "ORG_ADMIN_REQUIRED");

  const logs = await api("/v1/admin/organization/audit-logs?pageSize=50", {
    userId: ownerId,
  });
  assert.equal(logs.response.status, 200);
  const items = (data(logs.payload).items as Record<string, unknown>[]);
  assert.ok(items.length > 0);

  // Only organization governance events, never member workspace activity.
  const types = new Set(items.map((item) => String(item.resourceType)));
  assert.deepEqual(types, new Set(["organization", "organization_membership"]));
  const actions = new Set(items.map((item) => String(item.action)));
  assert.ok(actions.has("admin.organization_member_role_changed"));
  assert.ok(actions.has("admin.organization_created"));
  assert.equal(actions.has("auth.user_registered"), false);
  assert.equal(actions.has("lab.generated"), false);

  // Tenant isolation: nothing from another organization leaks in.
  for (const item of items) {
    const metadata = record(item.metadata);
    const belongs =
      item.resourceId === organizationId ||
      metadata.organizationId === organizationId;
    assert.ok(belongs, `entry ${String(item.id)} escaped the tenant scope`);
  }

  // resourceType is not an accepted filter on this endpoint.
  const unsupported = await api(
    "/v1/admin/organization/audit-logs?resourceType=user",
    { userId: ownerId },
  );
  assert.equal(unsupported.response.status, 400);
  assert.equal(errorCode(unsupported.payload), "UNSUPPORTED_ADMIN_FILTER");
});

async function join(joinCode: string, handle: string): Promise<string> {
  const result = await api("/v1/auth/register", {
    method: "POST",
    body: {
      email: `${handle}@example.test`,
      handle,
      displayName: handle,
      affiliation: "Test Affiliation",
      consent: { terms: true, privacy: true },
      accountType: "organization",
      organizationJoinCode: joinCode,
    },
  });
  assert.equal(result.response.status, 201);
  return String(record(data(result.payload).user).id);
}

function setMembershipRole(userId: string, role: string): void {
  database
    .prepare("UPDATE organization_memberships SET role = ? WHERE user_id = ?")
    .run(role, userId);
}

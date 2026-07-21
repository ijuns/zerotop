import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { createApplication } from "../src/app.ts";
import {
  createDatabase,
  SqliteDevelopmentRepository,
} from "../src/database.ts";
import { createSessionToken, verifySessionToken } from "../src/security.ts";

const database = createDatabase(":memory:");
const repository = new SqliteDevelopmentRepository(database);
const application = createApplication({
  repository,
  authMode: "local",
  sessionSecret: "test-session-secret",
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
  options: { method?: string; body?: unknown; token?: string } = {},
) {
  const headers = new Headers();
  if (options.body !== undefined) headers.set("content-type", "application/json");
  if (options.token) headers.set("authorization", `Bearer ${options.token}`);
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

function errorCode(payload: Record<string, unknown>): unknown {
  return (payload.error as Record<string, unknown>).code;
}

const CREDENTIALS = {
  email: "pilot@example.test",
  displayName: "테스트 파일럿",
  affiliation: "보안관제팀",
  password: "correct horse battery",
  accountType: "personal" as const,
  consent: { terms: true, privacy: true },
};

test("register signs in, and the session token authorizes requests", async () => {
  // Without a session, protected routes are refused.
  const anon = await api("/v1/labs");
  assert.equal(anon.response.status, 401);
  assert.equal(errorCode(anon.payload), "AUTHENTICATION_REQUIRED");

  const registered = await api("/v1/auth/register", {
    method: "POST",
    body: CREDENTIALS,
  });
  assert.equal(registered.response.status, 201);
  const token = String(
    (data(registered.payload).session as Record<string, unknown>).token,
  );
  assert.ok(token, "registration returns a session token");
  // Local mode returns a session token, not the dev X-User-Id escape hatch.
  assert.equal("developmentAuth" in data(registered.payload), false);

  const me = await api("/v1/me", { token });
  assert.equal(me.response.status, 200);
  assert.equal(
    (data(me.payload).user as Record<string, unknown>).email,
    "pilot@example.test",
  );
});

test("login verifies the password and rejects bad credentials uniformly", async () => {
  const wrongPassword = await api("/v1/auth/login", {
    method: "POST",
    body: { email: CREDENTIALS.email, password: "wrong" },
  });
  assert.equal(wrongPassword.response.status, 401);
  assert.equal(errorCode(wrongPassword.payload), "INVALID_CREDENTIALS");

  // An unknown email yields the same error, revealing nothing.
  const unknownEmail = await api("/v1/auth/login", {
    method: "POST",
    body: { email: "ghost@example.test", password: "whatever" },
  });
  assert.equal(unknownEmail.response.status, 401);
  assert.equal(errorCode(unknownEmail.payload), "INVALID_CREDENTIALS");

  const ok = await api("/v1/auth/login", {
    method: "POST",
    body: { email: CREDENTIALS.email, password: CREDENTIALS.password },
  });
  assert.equal(ok.response.status, 200);
  const token = String((data(ok.payload).session as Record<string, unknown>).token);
  const me = await api("/v1/me", { token });
  assert.equal(me.response.status, 200);

  // The login is audited.
  const userId = String((data(me.payload).user as Record<string, unknown>).id);
  const audited = database
    .prepare(
      "SELECT count(*) AS total FROM audit_logs WHERE action = 'auth.login' AND resource_id = ?",
    )
    .get(userId) as { total: number };
  assert.equal(audited.total, 1);
});

test("tampered, unsigned and expired tokens are refused", async () => {
  const secret = "test-session-secret";
  const valid = createSessionToken("user_x", secret);
  assert.equal(verifySessionToken(valid, secret), "user_x");
  // Wrong secret.
  assert.equal(verifySessionToken(valid, "other-secret"), null);
  // Flipped signature.
  const [payload] = valid.split(".");
  assert.equal(verifySessionToken(`${payload}.deadbeef`, secret), null);
  // Already expired.
  const expired = createSessionToken("user_x", secret, -1);
  assert.equal(verifySessionToken(expired, secret), null);

  const forged = await api("/v1/labs", { token: `${payload}.deadbeef` });
  assert.equal(forged.response.status, 401);
});

test("password registration and login are unavailable outside local mode", async () => {
  const devApp = createApplication({
    repository: new SqliteDevelopmentRepository(createDatabase(":memory:")),
    authMode: "dev",
    runtime: {
      createRun: () => Promise.reject(new Error("not used")),
      getRunStatus: () => Promise.reject(new Error("not used")),
      destroyRun() {},
    },
  });
  await new Promise<void>((resolve, reject) => {
    devApp.server.once("error", reject);
    devApp.server.listen(0, "127.0.0.1", resolve);
  });
  const address = devApp.server.address();
  assert.ok(address && typeof address !== "string");
  const devBase = `http://127.0.0.1:${address.port}`;
  try {
    const login = await fetch(`${devBase}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "a@b.test", password: "x" }),
    });
    // Login is local-only; dev mode does not expose it.
    assert.equal(login.status, 404);
  } finally {
    await devApp.close();
  }
});

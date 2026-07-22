import assert from "node:assert/strict";
import test from "node:test";
import {
  cookieValue,
  createDesktopSession,
  createSessionToken,
  desktopSessionCookie,
  verifySessionToken,
} from "../src/session.ts";

const key = "a-production-secret-that-is-at-least-32-bytes";
const now = Date.parse("2026-07-21T12:00:00.000Z");

test("creates run-bound expiring desktop sessions", () => {
  const token = createSessionToken(
    {
      runId: "run_123",
      namespace: "range-run-123",
      status: "ready",
      expiresAt: "2026-07-21T13:00:00.000Z",
    },
    key,
    now,
  );
  assert.equal(verifySessionToken(token, "run_123", key, now).namespace, "range-run-123");
  assert.throws(() => verifySessionToken(token, "run_other", key, now), /mismatch/);
  assert.throws(() => verifySessionToken(token, "run_123", key, now + 3_600_001), /expired/);
});

test("rejects modified session tokens and parses cookie values", () => {
  const token = createSessionToken(
    { runId: "run_123", namespace: "range-run-123", status: "ready" },
    key,
    now,
  );
  assert.throws(() => verifySessionToken(`${token}x`, "run_123", key, now), /signature/);
  assert.equal(cookieValue(`other=1; cg_desktop_session=${encodeURIComponent(token)}`, "cg_desktop_session"), token);
});

test("keeps the one-time exchange separate from a run-lived browser session", () => {
  const runExpiresAt = "2026-07-21T14:00:00.000Z";
  const session = createDesktopSession(
    {
      runId: "run_123",
      namespace: "range-run-123",
      status: "ready",
      expiresAt: runExpiresAt,
    },
    key,
    now,
    4 * 60 * 60 * 1000,
  );
  assert.equal(session.expiresAt, runExpiresAt);
  assert.equal(verifySessionToken(session.token, "run_123", key, now).expiresAt, runExpiresAt);

  const cookie = desktopSessionCookie(
    "cg_desktop_session",
    session.token,
    "/sessions/run_123/desktop",
    session.expiresAt,
    true,
    now,
  );
  assert.match(cookie, /Max-Age=7200/);
  assert.match(cookie, /Expires=Tue, 21 Jul 2026 14:00:00 GMT/);
  assert.match(cookie, /; HttpOnly; Secure; SameSite=Strict$/);
});

test("caps browser sessions independently of a longer-running environment", () => {
  const session = createDesktopSession(
    {
      runId: "run_123",
      namespace: "range-run-123",
      status: "ready",
      expiresAt: "2026-07-22T12:00:00.000Z",
    },
    key,
    now,
    4 * 60 * 60 * 1000,
  );
  assert.equal(session.expiresAt, "2026-07-21T16:00:00.000Z");
  assert.throws(
    () => createDesktopSession(
      {
        runId: "run_123",
        namespace: "range-run-123",
        status: "ready",
        expiresAt: "2026-07-21T12:00:00.500Z",
      },
      key,
      now,
    ),
    /expired/,
  );
});

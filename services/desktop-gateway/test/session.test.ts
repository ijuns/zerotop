import assert from "node:assert/strict";
import test from "node:test";
import { cookieValue, createSessionToken, verifySessionToken } from "../src/session.ts";

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

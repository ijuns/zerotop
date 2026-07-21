import assert from "node:assert/strict";
import test from "node:test";

import { ServiceError } from "../src/errors.ts";
import {
  parseBootstrapRequest,
  parseIssueProfileRequest,
} from "../src/input.ts";

const now = new Date("2026-07-21T00:00:00.000Z");

function validRequest() {
  return {
    runId: "run-fixture-1",
    userId: "user-fixture-1",
    namespace: "range-run-fixture-1",
    expiresAt: "2026-07-21T02:00:00.000Z",
    gatewayEndpoint: "vpn-range-run-fixture-1.example.test:1194",
    allowedCidr: "10.42.0.0/16",
    isolationMode: "per_run_gateway",
    routes: [{ namespace: "range-run-fixture-1" }],
  };
}

test("runtime profile contract enforces TTL, route and per-run isolation", () => {
  const parsed = parseIssueProfileRequest(validRequest(), {
    now,
    maxTtlMinutes: 240,
    allowedCidr: "10.42.0.0/16",
  });
  assert.equal(parsed.isolationMode, "per_run_gateway");
  assert.deepEqual(parsed.routes, [{ namespace: parsed.namespace }]);

  const serverPolicyRequest = validRequest();
  delete (serverPolicyRequest as Partial<ReturnType<typeof validRequest>>).allowedCidr;
  assert.equal(
    parseIssueProfileRequest(serverPolicyRequest, {
      now,
      maxTtlMinutes: 240,
      allowedCidr: "10.42.0.0/16",
    }).allowedCidr,
    "10.42.0.0/16",
  );

  assert.throws(
    () =>
      parseIssueProfileRequest(
        { ...validRequest(), routes: [{ namespace: "range-other" }] },
        { now, maxTtlMinutes: 240, allowedCidr: "10.42.0.0/16" },
      ),
    (error: unknown) =>
      error instanceof ServiceError && error.code === "invalid_request",
  );
  assert.throws(() =>
    parseIssueProfileRequest(
      { ...validRequest(), expiresAt: "2026-07-21T05:00:00.000Z" },
      { now, maxTtlMinutes: 240, allowedCidr: "10.42.0.0/16" },
    ),
  );
  assert.throws(() =>
    parseIssueProfileRequest(
      { ...validRequest(), extraRoute: "0.0.0.0/0" },
      { now, maxTtlMinutes: 240, allowedCidr: "10.42.0.0/16" },
    ),
  );
});

test("gateway bootstrap accepts only the run/profile/strong-token contract", () => {
  const result = parseBootstrapRequest({
    runId: "run-fixture-1",
    profileId: "vpn-profile-1",
    bootstrapToken: "a".repeat(43),
  });
  assert.equal(result.profileId, "vpn-profile-1");
  assert.throws(() =>
    parseBootstrapRequest({ ...result, bootstrapToken: "weak" }),
  );
});

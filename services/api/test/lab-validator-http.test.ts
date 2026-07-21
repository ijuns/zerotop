import assert from "node:assert/strict";
import test from "node:test";

import { ApiError } from "../src/errors.ts";
import { HttpLabValidator } from "../src/lab-validator.ts";

test("HTTP validator authenticates and preserves automatic gate evidence", async () => {
  let request: RequestInit | undefined;
  const validator = new HttpLabValidator({
    serviceUrl: "http://validator.internal:9003",
    internalToken: "validator-internal-token-123456",
    fetchImpl: async (_url, init) => {
      request = init;
      return Response.json({
        data: {
          decision: "pass",
          status: "validated",
          evidence: [
            {
              id: "evidence_signature",
              checkName: "image_signature",
              outcome: "pass",
              details: { signatureVerified: true },
            },
          ],
          validation: {
            policyVersion: "publish-policy/test",
            decision: "pass",
          },
        },
      });
    },
  });
  const result = await validator.validate({ id: "lab_123" });
  assert.equal(request?.headers instanceof Headers, false);
  assert.equal(
    (request?.headers as Record<string, string>).authorization,
    "Bearer validator-internal-token-123456",
  );
  assert.equal(result.status, "validated");
  assert.equal(result.evidence[0].checkName, "image_signature");
});

test("HTTP validator rejects contradictory pass evidence", async () => {
  const validator = new HttpLabValidator({
    serviceUrl: "http://validator.internal:9003",
    internalToken: "validator-internal-token-123456",
    fetchImpl: async () =>
      Response.json({
        decision: "pass",
        status: "validated",
        evidence: [
          {
            id: "evidence_failed",
            checkName: "sandbox_isolation",
            outcome: "fail",
            details: { crossRunBlocked: false },
          },
        ],
      }),
  });
  await assert.rejects(
    validator.validate({ id: "lab_unsafe" }),
    (error: unknown) =>
      error instanceof ApiError && error.code === "VALIDATOR_CONTRACT_INVALID",
  );
});

import assert from "node:assert/strict";
import test from "node:test";

import { runtimeContractDigest, unexpectedCriticalVulnerabilities, validateOciRuntimeConfig } from "../src/artifact-scanner.ts";
import type { PublishDecision } from "../src/contracts.ts";
import { ValidationService } from "../src/validator.ts";

const runtimeContract = {
  kind: "http-v1" as const,
  uid: 65532 as const,
  gid: 65532 as const,
  protocol: "http" as const,
  port: 8080 as const,
  writablePaths: ["/tmp"] as ["/tmp"],
  readOnlyRootFilesystem: true as const,
  bindAddress: "0.0.0.0" as const,
  healthPath: "/health" as const,
  fingerprintPath: "/version" as const,
};

const lab = {
  id: "lab_secure",
  team: "blue",
  config: {
    target: {
      imageRef: "registry.codegate.internal/ranges/web",
      imageDigest: `sha256:${"a".repeat(64)}`,
      expectedCves: ["CVE-2025-12345"],
      runtimeContract,
    },
  },
};

test("verifies the immutable OCI config against the hardened runtime ABI", () => {
  const config = {
    config: {
      User: "65532:65532",
      ExposedPorts: { "8080/tcp": {} },
      Env: ["NODE_ENV=production", "HOST=0.0.0.0", "PORT=8080"],
      Cmd: ["node", "/opt/codegate/target/server.mjs"],
      Labels: {
        "io.codegate.runtime.contract": "http-v1",
        "io.codegate.runtime.contract.digest": runtimeContractDigest(runtimeContract),
        "io.codegate.runtime.uid": "65532",
        "io.codegate.runtime.port": "8080",
      },
    },
  };
  assert.doesNotThrow(() => validateOciRuntimeConfig(config, runtimeContract));
  const wrongUser = structuredClone(config);
  wrongUser.config.User = "0";
  assert.throws(() => validateOciRuntimeConfig(wrongUser, runtimeContract), /user does not match/);
});

test("counts only unexpected critical vulnerabilities", () => {
  const ids = unexpectedCriticalVulnerabilities(
    {
      Results: [
        {
          Vulnerabilities: [
            { VulnerabilityID: "CVE-2025-12345", Severity: "CRITICAL" },
            { VulnerabilityID: "CVE-2026-99999", Severity: "CRITICAL" },
            { VulnerabilityID: "CVE-2026-11111", Severity: "HIGH" },
          ],
        },
      ],
    },
    ["CVE-2025-12345"],
  );
  assert.deepEqual(ids, ["CVE-2026-99999"]);
});

test("combines independent supply-chain, sandbox and AI evidence", async () => {
  const checks = [
    "static_policy",
    "immutable_image",
    "image_signature",
    "sbom",
    "unexpected_vulnerabilities",
    "sandbox_function",
    "sandbox_isolation",
    "sandbox_cleanup",
    "assessment",
    "blue_telemetry",
    "independent_ai_review",
  ].map((id) => ({ id, label: id, passed: true, mandatory: true, details: {} }));
  const publish: PublishDecision = {
    labId: "lab_secure",
    decision: "pass",
    status: "approved",
    score: 100,
    checks,
    policyVersion: "publish-policy/test",
    createdAt: "2026-07-21T00:00:00.000Z",
  };
  const validation = new ValidationService({
    allowedRegistries: ["registry.codegate.internal"],
    artifactScanner: {
      async scan(target) {
        return { imageDigest: target.digest, signatureVerified: true, ociConfigVerified: true, runtimeContractVerified: true, sbomGenerated: true, scanCompleted: true, unexpectedCriticalCount: 0, unexpectedCriticalIds: [] };
      },
    },
    sandboxRunner: {
      async validate() {
        return {
          sandbox: { provisioned: true, functionalChecksPassed: true, intendedVulnerabilityConfirmed: true, egressBlocked: true, controlPlaneBlocked: true, crossRunBlocked: true, cleanupConfirmed: true },
          assessment: { questionsRendered: true, gradingVerified: true, answerLeakageDetected: false, elkIndexReady: true, expectedEventsSearchable: true, mitreMappingsVerified: true },
        };
      },
    },
    ai: {
      async review() {
        return { reviewer: "model-gateway/reviewer", independent: true, passed: true, confidence: 0.98, riskScore: 0.02, traceId: "trace-validation-123" };
      },
      async publish() {
        return publish;
      },
    },
  });
  const result = await validation.validate(lab);
  assert.equal(result.decision, "pass");
  assert.equal(result.status, "validated");
  assert.equal((result.evidence as unknown[]).length, checks.length);
});

test("rejects an unapproved registry before any scanner executes", async () => {
  let scanned = false;
  const validation = new ValidationService({
    allowedRegistries: ["registry.codegate.internal"],
    artifactScanner: { async scan() { scanned = true; throw new Error("not expected"); } },
    sandboxRunner: { async validate() { throw new Error("not expected"); } },
    ai: { async review() { throw new Error("not expected"); }, async publish() { throw new Error("not expected"); } },
  });
  await assert.rejects(
    validation.validate({ ...lab, config: { target: { ...lab.config.target, imageRef: "docker.io/untrusted/image" } } }),
    /registry is not allowed/,
  );
  assert.equal(scanned, false);
});

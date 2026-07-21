import assert from "node:assert/strict";
import test from "node:test";
import { validateProvisionRequest } from "../src/input.ts";

const request = {
  runId: "run-47a2",
  labId: "lab-webshell",
  userId: "user-1",
  desktopImage: "kali",
  accessMethod: "both",
  ttlMinutes: 90,
  targetImage: "registry.codegate.internal/ranges/webshell@sha256:" + "a".repeat(64),
  targetService: { port: 8080, protocol: "http" },
  targetRuntimeContract: {
    kind: "http-v1", uid: 65532, gid: 65532, protocol: "http", port: 8080,
    writablePaths: ["/tmp"], readOnlyRootFilesystem: true, bindAddress: "0.0.0.0",
    healthPath: "/health", fingerprintPath: "/version",
  },
};

test("accepts a digest-pinned target from an allow-listed production registry", () => {
  const result = validateProvisionRequest(request, {
    runtimeMode: "kubevirt",
    allowedTargetRegistries: ["registry.codegate.internal"],
  });
  assert.equal(result.targetImage, request.targetImage);
  assert.deepEqual(result.targetService, request.targetService);
  assert.equal(result.targetRuntimeContract.kind, "http-v1");
});

test("rejects mutable or untrusted production target images", () => {
  assert.throws(
    () =>
      validateProvisionRequest(
        { ...request, targetImage: "docker.io/vendor/target:latest" },
        {
          runtimeMode: "kubevirt",
          allowedTargetRegistries: ["registry.codegate.internal"],
        },
      ),
    /not allow-listed/,
  );
  assert.throws(
    () =>
      validateProvisionRequest(
        { ...request, targetImage: "registry.codegate.internal/vendor/target:latest" },
        {
          runtimeMode: "kubevirt",
          allowedTargetRegistries: ["registry.codegate.internal"],
        },
      ),
    /sha256 digest/,
  );
});

test("accepts a bounded local target reference in Docker mode", () => {
  const result = validateProvisionRequest(
    { ...request, targetImage: "codegate/local-target:development", accessMethod: "browser_desktop" },
    { runtimeMode: "docker" },
  );
  assert.equal(result.targetImage, "codegate/local-target:development");
});

test("rejects unsafe identifiers and excessive TTL", () => {
  assert.throws(
    () => validateProvisionRequest({ ...request, runId: "../../admin" }, { runtimeMode: "local" }),
    /safe identifier/,
  );
  assert.throws(
    () => validateProvisionRequest({ ...request, ttlMinutes: 1440 }, { runtimeMode: "local" }),
    /between 10 and 240/,
  );
  assert.throws(
    () => validateProvisionRequest({ ...request, targetService: { port: 0, protocol: "http" } }, { runtimeMode: "local" }),
    /targetService.port/,
  );
  assert.throws(
    () => validateProvisionRequest({ ...request, targetService: { port: 8080, protocol: "udp" } }, { runtimeMode: "local" }),
    /targetService.protocol/,
  );
  assert.throws(
    () => validateProvisionRequest({ ...request, targetRuntimeContract: { ...request.targetRuntimeContract, uid: 0 } }, { runtimeMode: "local" }),
    /invalid or unsupported/,
  );
});

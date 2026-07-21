import assert from "node:assert/strict";
import test from "node:test";
import { KubeVirtSandboxValidator } from "../src/sandbox.ts";
import { buildValidationBaseResources, buildValidationProbeJob } from "../src/validation-manifests.ts";
import { parseSandboxValidationRequest } from "../src/validation-input.ts";
import type { KubernetesApplier, KubernetesValidationInspection } from "../src/adapter.ts";
import type { KubernetesObject } from "../src/manifests.ts";

const digest = "sha256:" + "a".repeat(64);

function requestValue(team: "blue" | "red" = "red") {
  const questionTypes = team === "blue" ? ["elk_search", "mitre_attack"] : ["single_choice", "free_text", "mitre_attack"];
  return {
    image: `registry.codegate.local/ranges/target:1@${digest}`,
    lab: {
      id: "lab-123",
      team,
      config: {
        target: {
          imageRef: "registry.codegate.local/ranges/target:1",
          imageDigest: digest,
          expectedCves: ["CVE-2025-12345"],
          runtimeContract: {
            kind: "http-v1", uid: 65532, gid: 65532, protocol: "http", port: 8080,
            writablePaths: ["/tmp"], readOnlyRootFilesystem: true, bindAddress: "0.0.0.0",
            healthPath: "/health", fingerprintPath: "/version",
          },
        },
        scenario: { mitreTechniques: ["T1190"] },
        questions: questionTypes.map((type, index) => ({ id: `q-${index}`, type, prompt: `Question ${index}`, points: 20 })),
        validation: {
          service: { port: 8080, protocol: "http" },
          functionalProbes: [{ id: "health", kind: "http", method: "GET", path: "/health", expectedStatuses: [200], bodyIncludes: ["ready"] }],
          vulnerabilityProbes: [{ id: "fingerprint", cveId: "CVE-2025-12345", kind: "http", method: "GET", path: "/version", expectedStatuses: [200], bodyIncludes: ["1.2.3"] }],
          ...(team === "blue" ? { telemetry: { events: [{ id: "q-0-elk-evidence", document: { "@timestamp": "2026-07-21T00:00:00Z", event: { dataset: "http" } } }] } } : {}),
        },
      },
    },
  };
}

test("parses a digest-bound red-team validation contract", () => {
  const input = parseSandboxValidationRequest(requestValue(), ["registry.codegate.local"]);
  assert.equal(input.labId, "lab-123");
  assert.equal(input.expectedCves[0], "CVE-2025-12345");
  assert.equal(input.answerLeakageDetected, false);
  assert.equal(input.mitreMappingsVerified, true);
});

test("rejects missing CVE coverage and answer leakage", () => {
  const value = requestValue();
  value.lab.config.validation.vulnerabilityProbes[0]!.cveId = "CVE-2025-99999";
  assert.throws(() => parseSandboxValidationRequest(value, ["registry.codegate.local"]), /No black-box vulnerability probe/);
  const leaked = requestValue();
  Object.assign(leaked.lab.config.questions[0]!, { answerKey: { optionIds: ["a"] } });
  assert.equal(parseSandboxValidationRequest(leaked, ["registry.codegate.local"]).answerLeakageDetected, true);
});

test("rejects conflicting target and validation service contracts", () => {
  const value = requestValue();
  Object.assign(value.lab.config.target, { service: { port: 9090, protocol: "http" } });
  assert.throws(
    () => parseSandboxValidationRequest(value, ["registry.codegate.local"]),
    /target.service and validation.service must match/,
  );
});

test("builds a restricted target Deployment, default-deny network, and hardened probe Job", () => {
  const input = parseSandboxValidationRequest(requestValue(), ["registry.codegate.local"]);
  const options = {
    namespace: "validation-123",
    validationId: "val-123",
    expiresAt: "2026-07-21T00:10:00.000Z",
    probeImage: `registry.codegate.local/system/probe@sha256:${"b".repeat(64)}`,
    activeDeadlineSeconds: 120,
  };
  const base = buildValidationBaseResources(input, options);
  const namespace = base.find((item) => item.kind === "Namespace");
  assert.equal(namespace?.metadata.labels?.["pod-security.kubernetes.io/enforce"], "restricted");
  assert.equal(base.filter((item) => item.kind === "VirtualMachine").length, 0);
  const target = base.find((item) => item.kind === "Deployment" && item.metadata.name === "target");
  const pod = (target?.spec as any).template.spec;
  const container = pod.containers[0];
  assert.equal(container.image, input.image);
  assert.equal(pod.automountServiceAccountToken, false);
  assert.equal(pod.securityContext.runAsNonRoot, true);
  assert.equal(pod.securityContext.runAsUser, 65532);
  assert.equal(pod.securityContext.seccompProfile.type, "RuntimeDefault");
  assert.equal(container.securityContext.readOnlyRootFilesystem, true);
  assert.equal(container.securityContext.allowPrivilegeEscalation, false);
  assert.deepEqual(container.securityContext.capabilities.drop, ["ALL"]);
  assert.deepEqual(container.startupProbe.tcpSocket, { port: "http" });
  assert.equal(pod.volumes[0].emptyDir.sizeLimit, "64Mi");
  assert.ok(base.some((item) => item.kind === "NetworkPolicy" && item.metadata.name === "default-deny"));
  assert.ok(base.some((item) => item.kind === "NetworkPolicy" && item.metadata.name === "allow-probe-dns"));
  const job = buildValidationProbeJob(input, { ...options, probePlanBase64Url: "eyJzY2hlbWFWZXJzaW9uIjoxfQ" });
  assert.equal(job.kind, "Job");
  const spec = job.spec as Record<string, unknown>;
  assert.equal(spec.backoffLimit, 0);
});

test("returns evidence from the signed probe output and confirms cleanup", async () => {
  const input = parseSandboxValidationRequest(requestValue(), ["registry.codegate.local"]);
  const applied: KubernetesObject[] = [];
  let probeCreated = false;
  let deleted = false;
  const probeOutput = JSON.stringify({
    schemaVersion: 1,
    functional: [{ id: "health", passed: true }],
    vulnerability: [{ id: "fingerprint", cveId: "CVE-2025-12345", passed: true }],
    network: { egressBlocked: true, controlPlaneBlocked: true, crossRunBlocked: true },
    completedAt: "2026-07-21T00:00:00.000Z",
  });
  const kubernetes: KubernetesApplier = {
    apply: async (resource) => { applied.push(resource); if (resource.kind === "Job") probeCreated = true; },
    inspectRun: async () => null,
    deleteNamespace: async () => { deleted = true; },
    inspectValidation: async (): Promise<KubernetesValidationInspection> => ({
      targetReady: true,
      targetFailed: false,
      probeState: probeCreated ? "succeeded" : "not_created",
      ...(probeCreated ? { probeOutput } : {}),
    }),
    getServiceClusterIp: async () => "10.43.22.7",
    serviceHasReadyEndpoints: async () => true,
    namespaceExists: async () => !deleted,
  };
  const validator = new KubeVirtSandboxValidator(
    kubernetes,
    { validate: async () => ({ indexReady: true, eventsSearchable: true }) },
    {
      probeImage: `registry.codegate.local/system/probe@sha256:${"b".repeat(64)}`,
      timeoutSeconds: 60,
      externalProbeHost: "1.1.1.1",
      externalProbePort: 443,
      controlPlaneHost: "10.43.0.1",
      controlPlanePort: 443,
      canaryNamespace: "codegate-runtime-system",
      canaryService: "validation-canary",
      canaryPort: 8080,
    },
  );
  const result = await validator.validate(input);
  assert.equal(result.sandbox.provisioned, true);
  assert.equal(result.sandbox.intendedVulnerabilityConfirmed, true);
  assert.equal(result.sandbox.cleanupConfirmed, true);
  assert.equal(result.assessment.exploitPathLimitedToSandbox, true);
  assert.ok(applied.some((item) => item.kind === "Job"));
});

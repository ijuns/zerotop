import assert from "node:assert/strict";
import { test } from "node:test";

import { BuildCatalog } from "../src/catalog.ts";
import type { BuildRecord } from "../src/contracts.ts";
import { assertControlledDockerfile, renderComponentPolicy, renderControlledDockerfile } from "../src/dockerfile.ts";
import { extractImageDigest, extractRegistryCa, resourcePath } from "../src/kubernetes.ts";
import { REGISTRY_CA_SECRET_NAME, buildResources, registryCaSecret } from "../src/manifests.ts";
import { sha256Canonical } from "../src/validation.ts";
import { ARTIFACT_URL, BASE_IMAGE, HEX_B, HEX_C, OUTPUT_REPOSITORY, PACKAGE_IMAGE, PACKAGE_RUNTIME_KIND, validBlueInput } from "./fixtures.ts";

function catalog(): BuildCatalog {
  return new BuildCatalog({
    baseImages: [BASE_IMAGE],
    outputRepositories: [OUTPUT_REPOSITORY],
    packages: {
      "nginx-lab@1.2.3": { imageRef: PACKAGE_IMAGE, sourcePath: "/opt/codegate/package/", destination: "/opt/codegate/packages/nginx-lab/", runtimeKind: PACKAGE_RUNTIME_KIND },
    },
    artifacts: { [HEX_C]: { url: ARTIFACT_URL } },
  });
}

function record(): BuildRecord {
  const input = validBlueInput();
  const resolvedPackages = catalog().resolve(input.spec).resolvedPackages;
  return {
    id: "11111111-1111-4111-8111-111111111111",
    labId: input.labId,
    labVersion: input.labVersion,
    requestedBy: input.requestedBy,
    idempotencyKey: "request-12345",
    requestDigest: sha256Canonical(input),
    specDigest: sha256Canonical(input.spec),
    spec: input.spec,
    resolvedPackages,
    status: "queued",
    namespace: "cg-build-111111111111111111111111",
    jobName: "environment-build",
    createdAt: "2026-07-21T10:00:00.000Z",
    deadlineAt: "2026-07-21T10:15:00.000Z",
  };
}

test("catalog requires exact digest and URL matches", () => {
  const input = validBlueInput();
  assert.equal(catalog().resolve(input.spec).resolvedPackages[0]?.imageRef, PACKAGE_IMAGE);
  input.spec.target.artifacts[0]!.url = "https://artifacts.example.com/other";
  assert.throws(() => catalog().resolve(input.spec), /not allowlisted/);
});

test("catalog rejects unsafe or extended artifact coordinates", () => {
  const options = {
    baseImages: [BASE_IMAGE],
    outputRepositories: [OUTPUT_REPOSITORY],
    packages: {},
    artifacts: { [HEX_C]: { url: "https://127.0.0.1/artifact" } },
  };
  assert.throws(() => new BuildCatalog(options), /public HTTPS/);
  assert.throws(() => new BuildCatalog({ ...options, artifacts: { [HEX_C]: { url: ARTIFACT_URL, extra: true } as any } }), /public HTTPS/);
});

test("catalog rejects package image instruction injection", () => {
  assert.throws(() => new BuildCatalog({
    baseImages: [BASE_IMAGE],
    outputRepositories: [OUTPUT_REPOSITORY],
    packages: {
      "nginx-lab@1.2.3": { imageRef: `evil\nRUN id@sha256:${HEX_B}`, sourcePath: "/package/", destination: "/target/", runtimeKind: PACKAGE_RUNTIME_KIND },
    },
    artifacts: { [HEX_C]: { url: ARTIFACT_URL } },
  }), /imageRef must be digest-pinned/);
});

test("controlled Dockerfile has no executable instructions", () => {
  const dockerfile = renderControlledDockerfile(record());
  assertControlledDockerfile(dockerfile);
  assert.match(dockerfile, new RegExp(`FROM ${BASE_IMAGE}`));
  assert.match(dockerfile, new RegExp(`ADD --link --checksum=sha256:${HEX_C}`));
  assert.match(dockerfile, /io\.codegate\.runtime\.contract="http-v1"/);
  assert.match(dockerfile, /io\.codegate\.runtime\.contract\.digest="sha256:[a-f0-9]{64}"/);
  assert.match(dockerfile, /COPY --link \["codegate-component-policy\.json","\/opt\/codegate\/component-policy\.json"\]/);
  assert.match(dockerfile, /io\.codegate\.component\.policy\.digest="sha256:[a-f0-9]{64}"/);
  assert.doesNotMatch(dockerfile, /^\s*(RUN|CMD|ENTRYPOINT|SHELL|ARG|ENV)\b/im);
});

test("component policy binds catalog runtime kinds to package IDs", () => {
  const policy = JSON.parse(renderComponentPolicy(record().resolvedPackages));
  assert.deepEqual(policy, {
    schemaVersion: "codegate-component-policy/v1",
    components: [{ componentId: "nginx-lab", runtimeKind: PACKAGE_RUNTIME_KIND }],
  });
});

test("catalog package helpers can only populate their fixed component directory", () => {
  assert.throws(() => new BuildCatalog({
    baseImages: [BASE_IMAGE],
    outputRepositories: [OUTPUT_REPOSITORY],
    packages: {
      "nginx-lab@1.2.3": { imageRef: PACKAGE_IMAGE, sourcePath: "/opt/codegate/package/", destination: "/usr/local/bin/", runtimeKind: PACKAGE_RUNTIME_KIND },
    },
    artifacts: { [HEX_C]: { url: ARTIFACT_URL } },
  }), /destination must match its component ID/);
});

test("build Job is rootless, isolated, bounded, and command-fixed", () => {
  const resources = buildResources(record(), {
    buildkitImage: `moby/buildkit@sha256:${HEX_B}`,
    registrySecretName: "build-registry-auth",
    cpuRequest: "500m",
    cpuLimit: "2",
    memoryRequest: "1Gi",
    memoryLimit: "4Gi",
    ephemeralStorageLimit: "12Gi",
    activeDeadlineSeconds: 900,
    ttlSecondsAfterFinished: 600,
    egressCidrs: ["198.51.100.0/24"],
    egressPorts: [443],
  });
  assert.deepEqual(resources.map((item) => item.kind), ["Namespace", "ResourceQuota", "LimitRange", "ServiceAccount", "NetworkPolicy", "NetworkPolicy", "NetworkPolicy", "ConfigMap", "Job"]);
  const job = resources.at(-1) as Record<string, any>;
  const context = resources.find((item) => item.kind === "ConfigMap") as Record<string, any>;
  assert.equal(JSON.parse(context.data["codegate-component-policy.json"]).components[0].runtimeKind, PACKAGE_RUNTIME_KIND);
  const podSpec = job.spec.template.spec;
  const container = podSpec.containers[0];
  assert.equal(podSpec.automountServiceAccountToken, false);
  assert.deepEqual(container.command, ["buildctl-daemonless.sh"]);
  assert.equal(container.securityContext.runAsNonRoot, true);
  assert.equal(container.securityContext.privileged, false);
  assert.equal(container.securityContext.allowPrivilegeEscalation, false);
  assert.deepEqual(container.securityContext.capabilities.drop, ["ALL"]);
  assert.deepEqual(container.env.slice(-2), [
    { name: "SSL_CERT_DIR", value: "/etc/ssl/certs" },
    { name: "SSL_CERT_FILE", value: "/etc/codegate/registry-ca/ca.crt" },
  ]);
  assert.deepEqual(container.volumeMounts.at(-1), {
    name: "registry-ca",
    mountPath: "/etc/codegate/registry-ca",
    readOnly: true,
  });
  assert.equal(podSpec.volumes.at(-1).secret.secretName, REGISTRY_CA_SECRET_NAME);
  assert.equal(job.spec.activeDeadlineSeconds, 900);
});

test("copied registry CA is immutable and contains no credential material", () => {
  const encoded = Buffer.from("-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n").toString("base64");
  assert.deepEqual(registryCaSecret("cg-build-fixture", encoded), {
    apiVersion: "v1",
    kind: "Secret",
    metadata: {
      name: REGISTRY_CA_SECRET_NAME,
      namespace: "cg-build-fixture",
      labels: { "app.kubernetes.io/name": "codegate-builder" },
    },
    type: "Opaque",
    immutable: true,
    data: { "ca.crt": encoded },
  });
  assert.equal(extractRegistryCa({ type: "Opaque", data: { "ca.crt": encoded } }), encoded);
  assert.throws(
    () => extractRegistryCa({ type: "Opaque", data: { "ca.crt": Buffer.from("-----BEGIN PRIVATE KEY-----").toString("base64") } }),
    /malformed/,
  );
});

test("extracts only a digest-pinned BuildKit output", () => {
  const digest = `sha256:${"d".repeat(64)}`;
  const taggedRef = `${OUTPUT_REPOSITORY}:build-11111111-1111-4111-8111-111111111111`;
  assert.deepEqual(extractImageDigest(`metadata containerimage.digest=\"${digest}\"`, taggedRef), {
    imageDigest: digest,
    imageRef: taggedRef,
  });
  assert.throws(() => extractImageDigest("completed without metadata", OUTPUT_REPOSITORY), /output digest/);
});

test("maps Kubernetes resources to namespaced API paths", () => {
  assert.equal(resourcePath({ apiVersion: "batch/v1", kind: "Job", metadata: { name: "job", namespace: "range" } }), "/apis/batch/v1/namespaces/range/jobs/job");
});

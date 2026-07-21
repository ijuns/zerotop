import { createServer } from "node:http";

import { catalogFromEnvironment } from "./catalog.ts";
import { createBuilderHttpHandler } from "./http.ts";
import { inClusterBuildRunner } from "./kubernetes.ts";
import { PostgresBuildRepository } from "./postgres.ts";
import { BuildService } from "./service.ts";
import { CosignImageSigner } from "./signer.ts";

const port = integerEnvironment("PORT", 9004, 1, 65_535);
const internalToken = requiredSecret("BUILDER_INTERNAL_TOKEN", 32);
const timeoutSeconds = integerEnvironment("BUILD_TIMEOUT_SECONDS", 900, 60, 3_600);
const repository = new PostgresBuildRepository(requiredEnvironment("DATABASE_URL"));
await repository.migrate();

const targetRegistrySecretName = environment("BUILD_REGISTRY_TARGET_SECRET", "build-registry-auth");
const runner = await inClusterBuildRunner({
  sourceRegistrySecretNamespace: requiredEnvironment("BUILD_REGISTRY_SECRET_NAMESPACE"),
  sourceRegistrySecretName: requiredEnvironment("BUILD_REGISTRY_SECRET_NAME"),
  targetRegistrySecretName,
  manifests: {
    buildkitImage: requiredEnvironment("BUILDKIT_IMAGE"),
    registrySecretName: targetRegistrySecretName,
    cpuRequest: environment("BUILD_CPU_REQUEST", "500m"),
    cpuLimit: environment("BUILD_CPU_LIMIT", "2"),
    memoryRequest: environment("BUILD_MEMORY_REQUEST", "1Gi"),
    memoryLimit: environment("BUILD_MEMORY_LIMIT", "4Gi"),
    ephemeralStorageLimit: environment("BUILD_EPHEMERAL_STORAGE_LIMIT", "12Gi"),
    activeDeadlineSeconds: timeoutSeconds,
    ttlSecondsAfterFinished: integerEnvironment("BUILD_JOB_TTL_SECONDS", 600, 60, 86_400),
    egressCidrs: csvEnvironment("BUILD_EGRESS_CIDRS"),
    egressPorts: csvEnvironment("BUILD_EGRESS_PORTS", "443").map((value) => strictInteger(value, "BUILD_EGRESS_PORTS", 1, 65_535)),
  },
});
const service = new BuildService({
  repository,
  runner,
  catalog: catalogFromEnvironment(),
  timeoutSeconds,
  builderId: environment("BUILDER_ID", "https://codegate.ai/builders/environment-builder/v1"),
  imageSigner: new CosignImageSigner({
    cosignBin: process.env.COSIGN_BIN,
    keyRef: requiredEnvironment("COSIGN_KEY_REF"),
    publicKeyPath: requiredEnvironment("COSIGN_PUBLIC_KEY_PATH"),
    passwordFile: requiredEnvironment("COSIGN_PASSWORD_FILE"),
    dockerConfigDirectory: requiredEnvironment("DOCKER_CONFIG"),
  }),
});

const server = createServer(createBuilderHttpHandler(service, internalToken));

const reconcileTimer = setInterval(() => {
  void service.reconcileActive().catch((error) => console.error(JSON.stringify({ level: "error", service: "builder", event: "reconcile_failed", error: safeLog(error) })));
}, integerEnvironment("RECONCILE_INTERVAL_MS", 5_000, 1_000, 60_000));
reconcileTimer.unref();

server.listen(port, "0.0.0.0", () => {
  console.log(JSON.stringify({ level: "info", service: "builder", version: "1.0.0", port }));
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    clearInterval(reconcileTimer);
    server.close(() => void repository.close().finally(() => process.exit(0)));
    setTimeout(() => process.exit(1), 10_000).unref();
  });
}

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function requiredSecret(name: string, minimum: number): string {
  const value = requiredEnvironment(name);
  if (value.length < minimum) throw new Error(`${name} must contain at least ${minimum} characters`);
  return value;
}

function environment(name: string, fallback: string): string {
  return process.env[name]?.trim() || fallback;
}

function integerEnvironment(name: string, fallback: number, minimum: number, maximum: number): number {
  return strictInteger(process.env[name] ?? fallback, name, minimum, maximum);
}

function strictInteger(value: string | number, name: string, minimum: number, maximum: number): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  return parsed;
}

function csvEnvironment(name: string, fallback?: string): string[] {
  const value = process.env[name]?.trim() || fallback;
  if (!value) throw new Error(`${name} is required`);
  const entries = value.split(",").map((item) => item.trim()).filter(Boolean);
  if (entries.length === 0 || new Set(entries).size !== entries.length) throw new Error(`${name} must contain unique comma-separated values`);
  return entries;
}

function safeLog(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).replace(/[\r\n\t]+/g, " ").replace(/(?:token|password|authorization|auth)\s*[=:]\s*\S+/gi, "credential=[redacted]").slice(0, 1_000);
}

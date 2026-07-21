import { readFile } from "node:fs/promises";

import type { BuildRecord } from "./contracts.ts";
import { BuilderError } from "./errors.ts";
import {
  REGISTRY_CA_SECRET_NAME,
  buildResources,
  registryAuthSecret,
  registryCaSecret,
  type BuildManifestOptions,
  type KubernetesObject,
} from "./manifests.ts";

export type KubernetesBuildPhase = "pending" | "running" | "succeeded" | "failed" | "missing";

export interface KubernetesBuildInspection {
  phase: KubernetesBuildPhase;
  log?: string;
  reason?: string;
}

export interface BuildRunner {
  start(record: BuildRecord): Promise<void>;
  inspect(record: BuildRecord): Promise<KubernetesBuildInspection>;
  cleanup(record: BuildRecord): Promise<void>;
}

export interface KubernetesHttpBuildRunnerOptions {
  baseUrl: string;
  bearerToken: string;
  sourceRegistrySecretNamespace: string;
  sourceRegistrySecretName: string;
  targetRegistrySecretName: string;
  manifests: BuildManifestOptions;
  fieldManager?: string;
  fetchImpl?: typeof fetch;
}

export class KubernetesHttpBuildRunner implements BuildRunner {
  private readonly options: KubernetesHttpBuildRunnerOptions;
  private readonly fetchImpl: typeof fetch;

  constructor(options: KubernetesHttpBuildRunnerOptions) {
    this.options = options;
    this.fetchImpl = options.fetchImpl ?? fetch;
    if (!/^https:\/\//.test(options.baseUrl)) throw new Error("Kubernetes API URL must use HTTPS");
    if (!options.bearerToken) throw new Error("Kubernetes bearer token is required");
  }

  async start(record: BuildRecord): Promise<void> {
    const resources = buildResources(record, this.options.manifests);
    const [namespace, ...namespaced] = resources;
    if (!namespace) throw new Error("Build resources are empty");
    try {
      await this.apply(namespace);
      const dockerConfig = await this.readDockerConfigSecret();
      const registryCa = await this.readRegistryCaSecret();
      await this.apply(registryAuthSecret(record.namespace, this.options.targetRegistrySecretName, dockerConfig));
      await this.apply(registryCaSecret(record.namespace, registryCa));
      for (const resource of namespaced) await this.apply(resource);
    } catch (error) {
      await this.cleanup(record).catch(() => undefined);
      throw error;
    }
  }

  async inspect(record: BuildRecord): Promise<KubernetesBuildInspection> {
    const path = `/apis/batch/v1/namespaces/${encodeURIComponent(record.namespace)}/jobs/${encodeURIComponent(record.jobName)}`;
    const job = await this.getJson(path);
    if (!job) return { phase: "missing", reason: "build_job_missing" };
    const status = object(job.status);
    const conditions = list(status.conditions).map(object);
    const complete = conditions.some((item) => item.type === "Complete" && item.status === "True") || Number(status.succeeded ?? 0) > 0;
    const failed = conditions.find((item) => item.type === "Failed" && item.status === "True");
    if (complete) return { phase: "succeeded", log: await this.readJobLog(record) };
    if (failed || Number(status.failed ?? 0) > 0) {
      const reason = safeDiagnostic(failed?.reason ?? failed?.message ?? "build_job_failed");
      return { phase: "failed", reason, log: await this.readJobLog(record) };
    }
    if (Number(status.active ?? 0) > 0) return { phase: "running" };
    return { phase: "pending" };
  }

  async cleanup(record: BuildRecord): Promise<void> {
    const response = await this.fetchImpl(
      `${this.options.baseUrl.replace(/\/$/, "")}/api/v1/namespaces/${encodeURIComponent(record.namespace)}`,
      {
        method: "DELETE",
        headers: this.headers("application/json"),
        body: JSON.stringify({ propagationPolicy: "Background", gracePeriodSeconds: 0 }),
        signal: AbortSignal.timeout(20_000),
      },
    );
    if (!response.ok && response.status !== 404) throw new Error(`Kubernetes namespace cleanup failed (${response.status})`);
    if (response.status === 404) return;
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      if (!await this.getJson(`/api/v1/namespaces/${encodeURIComponent(record.namespace)}`)) return;
      await delay(500);
    }
    throw new Error("Kubernetes namespace cleanup was not confirmed before the deadline");
  }

  private async apply(resource: KubernetesObject): Promise<void> {
    const query = new URLSearchParams({ fieldManager: this.options.fieldManager ?? "codegate-builder", force: "true" });
    const response = await this.fetchImpl(
      `${this.options.baseUrl.replace(/\/$/, "")}${resourcePath(resource)}?${query}`,
      {
        method: "PATCH",
        headers: this.headers("application/apply-patch+yaml"),
        body: JSON.stringify(resource),
        signal: AbortSignal.timeout(20_000),
      },
    );
    if (!response.ok) {
      const responseText = await response.text();
      throw new Error(`Kubernetes apply ${resource.kind}/${resource.metadata.name} failed (${response.status}): ${safeDiagnostic(responseText)}`);
    }
  }

  private async readDockerConfigSecret(): Promise<string> {
    const path = `/api/v1/namespaces/${encodeURIComponent(this.options.sourceRegistrySecretNamespace)}/secrets/${encodeURIComponent(this.options.sourceRegistrySecretName)}`;
    const secret = await this.getJson(path);
    if (!secret) throw new Error("Source registry credential Secret is missing");
    const encoded = object(secret.data)[".dockerconfigjson"];
    if (typeof encoded !== "string" || encoded.length < 8 || encoded.length > 100_000) throw new Error("Source registry credential Secret is malformed");
    let decoded: unknown;
    try {
      decoded = JSON.parse(Buffer.from(encoded, "base64").toString("utf8")) as unknown;
    } catch {
      throw new Error("Source registry credential Secret is malformed");
    }
    const auths = object(object(decoded).auths);
    if (Object.keys(auths).length === 0) throw new Error("Source registry credential Secret has no registry entries");
    return encoded;
  }

  private async readRegistryCaSecret(): Promise<string> {
    const path = `/api/v1/namespaces/${encodeURIComponent(this.options.sourceRegistrySecretNamespace)}/secrets/${REGISTRY_CA_SECRET_NAME}`;
    const secret = await this.getJson(path);
    return extractRegistryCa(secret);
  }

  private async readJobLog(record: BuildRecord): Promise<string> {
    const selector = encodeURIComponent(`job-name=${record.jobName}`);
    const pods = await this.getJson(`/api/v1/namespaces/${encodeURIComponent(record.namespace)}/pods?labelSelector=${selector}`);
    const items = list(pods?.items).map(object);
    const pod = items.find((item) => object(item.status).phase === "Succeeded")
      ?? items.find((item) => object(item.status).phase === "Failed")
      ?? items[0];
    const name = object(pod?.metadata).name;
    if (typeof name !== "string" || !name) return "";
    const response = await this.fetchImpl(
      `${this.options.baseUrl.replace(/\/$/, "")}/api/v1/namespaces/${encodeURIComponent(record.namespace)}/pods/${encodeURIComponent(name)}/log?container=buildkit&tailLines=400&limitBytes=262144`,
      { method: "GET", headers: this.headers("text/plain"), signal: AbortSignal.timeout(20_000) },
    );
    if (!response.ok) return "";
    return (await response.text()).slice(-262_144);
  }

  private async getJson(path: string): Promise<Record<string, unknown> | null> {
    const response = await this.fetchImpl(`${this.options.baseUrl.replace(/\/$/, "")}${path}`, {
      method: "GET",
      headers: this.headers("application/json"),
      signal: AbortSignal.timeout(20_000),
    });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`Kubernetes read failed (${response.status})`);
    const result: unknown = await response.json();
    if (typeof result !== "object" || result === null || Array.isArray(result)) throw new Error("Kubernetes returned a malformed resource");
    return result as Record<string, unknown>;
  }

  private headers(acceptOrContentType: string): Record<string, string> {
    return {
      authorization: `Bearer ${this.options.bearerToken}`,
      accept: acceptOrContentType === "application/apply-patch+yaml" ? "application/json" : acceptOrContentType,
      ...(acceptOrContentType === "application/apply-patch+yaml" || acceptOrContentType === "application/json" ? { "content-type": acceptOrContentType } : {}),
    };
  }
}

export function extractRegistryCa(secret: unknown): string {
  if (!secret || typeof secret !== "object" || Array.isArray(secret) || object(secret).type !== "Opaque") {
    throw new Error("Source registry CA Secret is missing or has the wrong type");
  }
  const data = object(object(secret).data);
  if (Object.keys(data).length !== 1 || typeof data["ca.crt"] !== "string") {
    throw new Error("Source registry CA Secret must contain only ca.crt");
  }
  const encoded = data["ca.crt"];
  if (encoded.length < 64 || encoded.length > 200_000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new Error("Source registry CA certificate is malformed");
  }
  const pem = Buffer.from(encoded, "base64").toString("utf8");
  if (
    !pem.startsWith("-----BEGIN CERTIFICATE-----")
    || !pem.trimEnd().endsWith("-----END CERTIFICATE-----")
    || pem.includes("PRIVATE KEY")
  ) throw new Error("Source registry CA certificate is malformed");
  return encoded;
}

export async function inClusterBuildRunner(options: Omit<KubernetesHttpBuildRunnerOptions, "baseUrl" | "bearerToken">): Promise<KubernetesHttpBuildRunner> {
  const host = process.env.KUBERNETES_SERVICE_HOST;
  const port = process.env.KUBERNETES_SERVICE_PORT_HTTPS ?? "443";
  if (!host) throw new Error("KUBERNETES_SERVICE_HOST is required");
  const tokenPath = process.env.KUBERNETES_TOKEN_FILE ?? "/var/run/secrets/kubernetes.io/serviceaccount/token";
  const bearerToken = (await readFile(tokenPath, "utf8")).trim();
  return new KubernetesHttpBuildRunner({ ...options, baseUrl: `https://${host}:${port}`, bearerToken });
}

export function extractImageDigest(log: string, expectedImageRef: string): { imageDigest: string; imageRef: string } {
  if (expectedImageRef.includes("@") || !/^[a-z0-9.-]+(?::\d+)?\/[a-z0-9._/-]+(?::[a-z0-9._-]+)?$/i.test(expectedImageRef)) {
    throw new Error("Expected image reference is invalid");
  }
  const matches = [...log.matchAll(/(?:containerimage\.digest["'=:\s]+|digest:\s*)(sha256:[a-f0-9]{64})/gi)];
  const last = matches.at(-1)?.[1]?.toLowerCase();
  if (!last) throw new BuilderError(502, "build_digest_missing", "BuildKit completed without a verifiable output digest");
  return { imageDigest: last, imageRef: expectedImageRef };
}

export function resourcePath(resource: KubernetesObject): string {
  const namespace = resource.metadata.namespace ? encodeURIComponent(resource.metadata.namespace) : undefined;
  const prefix = namespace ? `namespaces/${namespace}/` : "";
  const name = encodeURIComponent(resource.metadata.name);
  const key = `${resource.apiVersion}:${resource.kind}`;
  const plurals: Record<string, string> = {
    "v1:Namespace": "namespaces", "v1:ResourceQuota": "resourcequotas", "v1:LimitRange": "limitranges",
    "v1:ServiceAccount": "serviceaccounts", "v1:ConfigMap": "configmaps", "v1:Secret": "secrets",
    "batch/v1:Job": "jobs", "networking.k8s.io/v1:NetworkPolicy": "networkpolicies",
  };
  const plural = plurals[key];
  if (!plural) throw new Error(`Unsupported Kubernetes resource ${key}`);
  return resource.apiVersion === "v1" ? `/api/v1/${prefix}${plural}/${name}` : `/apis/${resource.apiVersion}/${prefix}${plural}/${name}`;
}

function safeDiagnostic(value: unknown): string {
  return String(value ?? "build_failed").replace(/[\r\n\t]+/g, " ").replace(/(?:token|password|authorization|auth)\s*[=:]\s*\S+/gi, "credential=[redacted]").slice(0, 1_000);
}

function object(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

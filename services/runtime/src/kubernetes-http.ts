import { readFile } from "node:fs/promises";
import type { KubernetesApplier, KubernetesRunInspection, KubernetesValidationInspection } from "./adapter.ts";
import type { KubernetesObject } from "./manifests.ts";

export interface KubernetesHttpOptions {
  baseUrl: string;
  bearerToken: string;
  fieldManager?: string;
  fetchImpl?: typeof fetch;
}

export class KubernetesHttpApplier implements KubernetesApplier {
  private readonly baseUrl: string;
  private readonly bearerToken: string;
  private readonly fieldManager: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: KubernetesHttpOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.bearerToken = options.bearerToken;
    this.fieldManager = options.fieldManager ?? "codegate-runtime";
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async apply(resource: KubernetesObject): Promise<void> {
    const path = resourcePath(resource);
    const query = new URLSearchParams({ fieldManager: this.fieldManager, force: "true" });
    const response = await this.fetchImpl(`${this.baseUrl}${path}?${query}`, {
      method: "PATCH",
      headers: {
        authorization: `Bearer ${this.bearerToken}`,
        accept: "application/json",
        "content-type": "application/apply-patch+yaml",
      },
      body: JSON.stringify(resource),
      signal: AbortSignal.timeout(20_000),
    });
    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`Kubernetes apply ${resource.kind}/${resource.metadata.name} failed (${response.status}): ${detail.slice(0, 500)}`);
    }
  }

  async deleteNamespace(name: string): Promise<void> {
    const response = await this.fetchImpl(`${this.baseUrl}/api/v1/namespaces/${encodeURIComponent(name)}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${this.bearerToken}`, accept: "application/json" },
      signal: AbortSignal.timeout(20_000),
    });
    if (!response.ok && response.status !== 404) throw new Error(`Kubernetes namespace deletion failed (${response.status})`);
  }

  async inspectRun(namespace: string): Promise<KubernetesRunInspection | null> {
    const encodedNamespace = encodeURIComponent(namespace);
    const namespaceObject = await this.getJson(`/api/v1/namespaces/${encodedNamespace}`);
    if (!namespaceObject) return null;

    const metadata = record(namespaceObject.metadata);
    const annotations = record(metadata.annotations);
    const accessMethod = String(annotations["codegate.ai/access-method"] ?? "");
    if (!isAccessMethod(accessMethod)) {
      throw new Error(`Run namespace ${namespace} has no valid access-method annotation`);
    }
    const expiresAt = requiredTimestamp(annotations["codegate.ai/expires-at"], "expires-at", namespace);
    const readinessDeadline = requiredTimestamp(
      annotations["codegate.ai/readiness-deadline"],
      "readiness-deadline",
      namespace,
    );

    const browserRequired = accessMethod === "browser_desktop" || accessMethod === "both";
    const vpnRequired = accessMethod === "openvpn" || accessMethod === "both";
    const [workstationVmi, targetDeployment, desktopEndpoints, vpnPods, vpnService] = await Promise.all([
      this.getJson(`/apis/kubevirt.io/v1/namespaces/${encodedNamespace}/virtualmachineinstances/workstation`),
      this.getJson(`/apis/apps/v1/namespaces/${encodedNamespace}/deployments/target`),
      browserRequired
        ? this.getJson(`/api/v1/namespaces/${encodedNamespace}/endpoints/desktop`)
        : Promise.resolve(null),
      vpnRequired
        ? this.getJson(`/api/v1/namespaces/${encodedNamespace}/pods?labelSelector=${encodeURIComponent("codegate.ai/role=vpn-gateway")}`)
        : Promise.resolve(null),
      vpnRequired
        ? this.getJson(`/api/v1/namespaces/${encodedNamespace}/services/openvpn-gateway`)
        : Promise.resolve(null),
    ]);

    const checks = {
      workstationVmi: vmiReady(workstationVmi),
      targetWorkload: deploymentAvailable(targetDeployment),
      ...(browserRequired ? { desktopEndpoints: endpointsReady(desktopEndpoints) } : {}),
      ...(vpnRequired ? { vpnPod: podListReady(vpnPods), vpnService: loadBalancerReady(vpnService) } : {}),
    };
    const failureReason = firstFailureReason([
      namedVmiFailure("workstation", workstationVmi),
      deploymentFailure("target", targetDeployment),
      vpnRequired ? podListFailure(vpnPods) : undefined,
    ]);
    return { expiresAt, readinessDeadline, checks, ...(failureReason ? { failureReason } : {}) };
  }

  async inspectValidation(namespace: string): Promise<KubernetesValidationInspection | null> {
    const encodedNamespace = encodeURIComponent(namespace);
    const namespaceObject = await this.getJson(`/api/v1/namespaces/${encodedNamespace}`);
    if (!namespaceObject) return null;
    const [targetDeployment, job, pods] = await Promise.all([
      this.getJson(`/apis/apps/v1/namespaces/${encodedNamespace}/deployments/target`),
      this.getJson(`/apis/batch/v1/namespaces/${encodedNamespace}/jobs/sandbox-probe`),
      this.getJson(`/api/v1/namespaces/${encodedNamespace}/pods?labelSelector=${encodeURIComponent("job-name=sandbox-probe")}`),
    ]);
    const jobStatus = record(job?.status);
    const succeeded = Number(jobStatus.succeeded ?? 0) > 0;
    const failed = Number(jobStatus.failed ?? 0) > 0 || conditionFailed(jobStatus.conditions);
    const podItems = array(pods?.items).map(record);
    const pod = podItems.find((item) => record(item.status).phase === "Succeeded")
      ?? podItems.find((item) => record(item.status).phase === "Failed")
      ?? podItems[0];
    const podName = String(record(pod?.metadata).name ?? "");
    let probeOutput: string | undefined;
    if ((succeeded || failed) && podName) {
      probeOutput = await this.getText(
        `/api/v1/namespaces/${encodedNamespace}/pods/${encodeURIComponent(podName)}/log?container=probe&tailLines=20&limitBytes=65536`,
      ) ?? undefined;
    }
    const targetFailure = deploymentFailure("Validation target", targetDeployment);
    return {
      targetReady: deploymentAvailable(targetDeployment),
      targetFailed: targetFailure !== undefined,
      probeState: !job ? "not_created" : succeeded ? "succeeded" : failed ? "failed" : "running",
      ...(probeOutput ? { probeOutput } : {}),
      ...(targetFailure ? { failureReason: targetFailure } : {}),
    };
  }

  async getServiceClusterIp(namespace: string, name: string): Promise<string | null> {
    const service = await this.getJson(
      `/api/v1/namespaces/${encodeURIComponent(namespace)}/services/${encodeURIComponent(name)}`,
    );
    const clusterIp = record(service?.spec).clusterIP;
    return typeof clusterIp === "string" && clusterIp && clusterIp !== "None" ? clusterIp : null;
  }

  async serviceHasReadyEndpoints(namespace: string, name: string): Promise<boolean> {
    const endpoints = await this.getJson(
      `/api/v1/namespaces/${encodeURIComponent(namespace)}/endpoints/${encodeURIComponent(name)}`,
    );
    return array(endpoints?.subsets).some((subset) => array(record(subset).addresses).some((address) => {
      const ip = record(address).ip;
      return typeof ip === "string" && ip.length > 0;
    }));
  }

  async namespaceExists(name: string): Promise<boolean> {
    return (await this.getJson(`/api/v1/namespaces/${encodeURIComponent(name)}`)) !== null;
  }

  private async getJson(path: string): Promise<Record<string, unknown> | null> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "GET",
      headers: { authorization: `Bearer ${this.bearerToken}`, accept: "application/json" },
      signal: AbortSignal.timeout(20_000),
    });
    if (response.status === 404) return null;
    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`Kubernetes read ${path} failed (${response.status}): ${detail.slice(0, 500)}`);
    }
    const value: unknown = await response.json();
    if (!isRecord(value)) throw new Error(`Kubernetes read ${path} returned a malformed object`);
    return value;
  }

  private async getText(path: string): Promise<string | null> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "GET",
      headers: { authorization: `Bearer ${this.bearerToken}`, accept: "text/plain" },
      signal: AbortSignal.timeout(20_000),
    });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`Kubernetes read ${path} failed (${response.status})`);
    return (await response.text()).slice(0, 65_536);
  }
}

export async function inClusterKubernetesApplier(): Promise<KubernetesHttpApplier> {
  const host = process.env.KUBERNETES_SERVICE_HOST;
  const port = process.env.KUBERNETES_SERVICE_PORT_HTTPS ?? "443";
  if (!host) throw new Error("KUBERNETES_SERVICE_HOST is required in kubevirt runtime mode");
  const tokenPath = process.env.KUBERNETES_TOKEN_FILE ?? "/var/run/secrets/kubernetes.io/serviceaccount/token";
  const bearerToken = (await readFile(tokenPath, "utf8")).trim();
  if (!bearerToken) throw new Error("Kubernetes service account token is empty");
  return new KubernetesHttpApplier({ baseUrl: `https://${host}:${port}`, bearerToken });
}

export function resourcePath(resource: KubernetesObject): string {
  const namespace = resource.metadata.namespace ? encodeURIComponent(resource.metadata.namespace) : undefined;
  const name = encodeURIComponent(resource.metadata.name);
  const prefix = namespace ? `namespaces/${namespace}/` : "";
  const plural = pluralFor(resource.apiVersion, resource.kind);
  if (resource.apiVersion === "v1") return `/api/v1/${prefix}${plural}/${name}`;
  return `/apis/${resource.apiVersion}/${prefix}${plural}/${name}`;
}

function pluralFor(apiVersion: string, kind: string): string {
  const key = `${apiVersion}:${kind}`;
  const resources: Record<string, string> = {
    "v1:Namespace": "namespaces",
    "v1:ResourceQuota": "resourcequotas",
    "v1:ServiceAccount": "serviceaccounts",
    "v1:Service": "services",
    "v1:Secret": "secrets",
    "apps/v1:Deployment": "deployments",
    "batch/v1:Job": "jobs",
    "networking.k8s.io/v1:NetworkPolicy": "networkpolicies",
    "kubevirt.io/v1:VirtualMachine": "virtualmachines",
  };
  const plural = resources[key];
  if (!plural) throw new Error(`Unsupported Kubernetes resource ${key}`);
  return plural;
}

function isAccessMethod(value: string): value is "browser_desktop" | "openvpn" | "both" {
  return value === "browser_desktop" || value === "openvpn" || value === "both";
}

function requiredTimestamp(value: unknown, field: string, namespace: string): string {
  const timestamp = String(value ?? "");
  if (!Number.isFinite(Date.parse(timestamp))) {
    throw new Error(`Run namespace ${namespace} has no valid ${field} annotation`);
  }
  return timestamp;
}

function vmiReady(value: Record<string, unknown> | null): boolean {
  const status = record(value?.status);
  return status.phase === "Running" && conditionReady(status.conditions);
}

function namedVmiFailure(name: string, value: Record<string, unknown> | null): string | undefined {
  const phase = String(record(value?.status).phase ?? "");
  return phase === "Failed" ? `${name} VMI entered the Failed phase` : undefined;
}

function deploymentAvailable(value: Record<string, unknown> | null): boolean {
  if (!value) return false;
  const metadata = record(value.metadata);
  const status = record(value.status);
  const generation = Number(metadata.generation ?? 0);
  const observedGeneration = Number(status.observedGeneration ?? 0);
  return generation > 0 && observedGeneration >= generation &&
    Number(status.availableReplicas ?? 0) >= 1 && conditionStatus(status.conditions, "Available", "True");
}

function deploymentFailure(name: string, value: Record<string, unknown> | null): string | undefined {
  if (!value) return undefined;
  const conditions = array(record(value.status).conditions).map(record);
  const failed = conditions.find((condition) =>
    (condition.type === "Progressing" && condition.status === "False" && condition.reason === "ProgressDeadlineExceeded") ||
    (condition.type === "ReplicaFailure" && condition.status === "True")
  );
  if (!failed) return undefined;
  const reason = typeof failed.reason === "string" ? ` (${failed.reason})` : "";
  return `${name} Deployment failed${reason}`;
}

function endpointsReady(value: Record<string, unknown> | null): boolean {
  const subsets = array(value?.subsets);
  return subsets.some((subset) => array(record(subset).addresses).length > 0);
}

function podListReady(value: Record<string, unknown> | null): boolean {
  return array(value?.items).some((item) => {
    const status = record(record(item).status);
    const metadata = record(record(item).metadata);
    return !metadata.deletionTimestamp && status.phase === "Running" && conditionReady(status.conditions);
  });
}

function podListFailure(value: Record<string, unknown> | null): string | undefined {
  const failed = array(value?.items).find((item) => record(record(item).status).phase === "Failed");
  return failed ? "OpenVPN gateway Pod entered the Failed phase" : undefined;
}

function loadBalancerReady(value: Record<string, unknown> | null): boolean {
  const spec = record(value?.spec);
  const status = record(value?.status);
  const loadBalancer = record(status.loadBalancer);
  const ingress = array(loadBalancer.ingress);
  return typeof spec.clusterIP === "string" && spec.clusterIP !== "" && spec.clusterIP !== "None" && ingress.some((item) => {
    const entry = record(item);
    return typeof entry.ip === "string" || typeof entry.hostname === "string";
  });
}

function conditionReady(value: unknown): boolean {
  return array(value).some((condition) => {
    const item = record(condition);
    return item.type === "Ready" && item.status === "True";
  });
}

function conditionFailed(value: unknown): boolean {
  return array(value).some((condition) => {
    const item = record(condition);
    return item.type === "Failed" && item.status === "True";
  });
}

function conditionStatus(value: unknown, type: string, status: string): boolean {
  return array(value).some((condition) => {
    const item = record(condition);
    return item.type === type && item.status === status;
  });
}

function firstFailureReason(values: Array<string | undefined>): string | undefined {
  return values.find((value): value is string => typeof value === "string");
}

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function record(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

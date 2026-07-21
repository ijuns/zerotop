import type {
  AccessMethod,
  ProvisionedRun,
  ProvisionRunRequest,
  RuntimeAdapter,
  RuntimeReadinessChecks,
  RuntimeRunStatus,
} from "./contracts.ts";
import { buildRunResources, namespaceForRun, type KubernetesObject, type RuntimeImages } from "./manifests.ts";
import type { OpenVpnIssuer, OpenVpnProfile, OpenVpnProvision } from "./openvpn.ts";

export interface KubernetesApplier {
  apply(resource: KubernetesObject): Promise<void>;
  inspectRun(namespace: string): Promise<KubernetesRunInspection | null>;
  deleteNamespace(name: string): Promise<void>;
  inspectValidation?(namespace: string): Promise<KubernetesValidationInspection | null>;
  getServiceClusterIp?(namespace: string, name: string): Promise<string | null>;
  serviceHasReadyEndpoints?(namespace: string, name: string): Promise<boolean>;
  namespaceExists?(name: string): Promise<boolean>;
}

export interface KubernetesRunInspection {
  expiresAt: string;
  readinessDeadline: string;
  checks: RuntimeReadinessChecks;
  failureReason?: string;
}

export interface KubernetesValidationInspection {
  targetReady: boolean;
  targetFailed: boolean;
  probeState: "not_created" | "running" | "succeeded" | "failed";
  probeOutput?: string;
  failureReason?: string;
}

export class RuntimeRunNotFoundError extends Error {
  constructor(runId: string) {
    super(`Runtime run ${runId} was not found`);
    this.name = "RuntimeRunNotFoundError";
  }
}

export class LocalRuntimeAdapter implements RuntimeAdapter {
  private readonly vpnIssuer: OpenVpnIssuer;
  private readonly runs = new Map<string, RuntimeRunStatus>();

  constructor(vpnIssuer: OpenVpnIssuer) {
    this.vpnIssuer = vpnIssuer;
  }

  async provision(request: ProvisionRunRequest): Promise<ProvisionedRun> {
    const namespace = namespaceForRun(request.runId);
    const expiresAt = new Date(Date.now() + request.ttlMinutes * 60_000).toISOString();
    const openVpn = hasVpn(request.accessMethod)
      ? await this.vpnIssuer.issue({
          runId: request.runId,
          userId: request.userId,
          namespace,
          expiresAt,
          gatewayEndpoint: "vpn.local.codegate.invalid:1194",
          allowedCidr: "10.42.0.0/16",
        })
      : undefined;
    const result = connectionResult(request, namespace, expiresAt, openVpn?.profile, "ready");
    this.runs.set(request.runId, {
      id: request.runId,
      status: "ready",
      namespace,
      expiresAt,
      checks: readyChecks(request.accessMethod),
    });
    return result;
  }

  async get(runId: string): Promise<RuntimeRunStatus> {
    const run = this.runs.get(runId);
    if (!run) throw new RuntimeRunNotFoundError(runId);
    return run;
  }

  async destroy(runId: string): Promise<void> {
    await this.vpnIssuer.revoke(runId);
    this.runs.delete(runId);
  }
}

export class KubeVirtRuntimeAdapter implements RuntimeAdapter {
  private readonly kubernetes: KubernetesApplier;
  private readonly vpnIssuer: OpenVpnIssuer;
  private readonly images: RuntimeImages;
  private readonly vpnGateway: { image: string; baseDomain: string; issuerUrl: string; allowedCidr: string };
  private readonly readinessTimeoutSeconds: number;

  constructor(
    kubernetes: KubernetesApplier,
    vpnIssuer: OpenVpnIssuer,
    images: RuntimeImages,
    vpnGateway: { image: string; baseDomain: string; issuerUrl: string; allowedCidr: string },
    readinessTimeoutSeconds = 600,
  ) {
    this.kubernetes = kubernetes;
    this.vpnIssuer = vpnIssuer;
    this.images = images;
    this.vpnGateway = vpnGateway;
    this.readinessTimeoutSeconds = readinessTimeoutSeconds;
  }

  async provision(request: ProvisionRunRequest): Promise<ProvisionedRun> {
    const namespace = namespaceForRun(request.runId);
    const expiresAt = new Date(Date.now() + request.ttlMinutes * 60_000).toISOString();
    let openVpn: OpenVpnProvision | undefined;
    if (hasVpn(request.accessMethod)) {
      openVpn = await this.vpnIssuer.issue({
        runId: request.runId,
        userId: request.userId,
        namespace,
        expiresAt,
        gatewayEndpoint: gatewayEndpoint(namespace, this.vpnGateway.baseDomain),
        allowedCidr: this.vpnGateway.allowedCidr,
      });
    }
    const resources = buildRunResources(
      request,
      this.images,
      openVpn
        ? {
            image: this.vpnGateway.image,
            issuerUrl: this.vpnGateway.issuerUrl,
            hostname: openVpn.profile.endpoint.split(":", 1)[0],
            provision: openVpn,
          }
        : undefined,
      this.readinessTimeoutSeconds,
    );
    try {
      for (const resource of resources) await this.kubernetes.apply(resource);
    } catch (error) {
      if (openVpn) await this.vpnIssuer.revoke(request.runId).catch(() => undefined);
      throw error;
    }
    return connectionResult(request, namespace, expiresAt, openVpn?.profile, "provisioning");
  }

  async get(runId: string): Promise<RuntimeRunStatus> {
    const namespace = namespaceForRun(runId);
    const inspection = await this.kubernetes.inspectRun(namespace);
    if (!inspection) throw new RuntimeRunNotFoundError(runId);
    const allReady = Object.values(inspection.checks).every((ready) => ready === true);
    if (allReady) {
      return {
        id: runId,
        status: "ready",
        namespace,
        expiresAt: inspection.expiresAt,
        checks: inspection.checks,
      };
    }
    const deadlinePassed = Date.now() >= Date.parse(inspection.readinessDeadline);
    const failureReason = inspection.failureReason ?? (deadlinePassed
      ? `Runtime readiness deadline ${inspection.readinessDeadline} was exceeded`
      : undefined);
    return {
      id: runId,
      status: failureReason ? "failed" : "provisioning",
      namespace,
      expiresAt: inspection.expiresAt,
      checks: inspection.checks,
      ...(failureReason ? { reason: failureReason } : {}),
    };
  }

  async destroy(runId: string): Promise<void> {
    await this.vpnIssuer.revoke(runId);
    await this.kubernetes.deleteNamespace(namespaceForRun(runId));
  }
}

function connectionResult(
  request: ProvisionRunRequest,
  namespace: string,
  expiresAt: string,
  openVpn: OpenVpnProfile | undefined,
  status: "provisioning" | "ready",
): ProvisionedRun {
  const result: ProvisionedRun = { id: request.runId, status, namespace, expiresAt };
  if (hasBrowser(request.accessMethod)) {
    result.browserDesktop = { gatewayPath: `/sessions/${request.runId}/desktop`, protocol: "websocket" };
  }
  if (hasVpn(request.accessMethod)) {
    if (!openVpn) throw new Error("OpenVPN provisioning metadata is missing");
    result.openVpn = openVpn;
  }
  return result;
}

const hasBrowser = (method: AccessMethod) => method === "browser_desktop" || method === "both";
const hasVpn = (method: AccessMethod) => method === "openvpn" || method === "both";

function readyChecks(method: AccessMethod): RuntimeReadinessChecks {
  return {
    workstationVmi: true,
    targetWorkload: true,
    ...(hasBrowser(method) ? { desktopEndpoints: true } : {}),
    ...(hasVpn(method) ? { vpnPod: true, vpnService: true } : {}),
  };
}

function gatewayEndpoint(namespace: string, baseDomain: string): string {
  const normalized = baseDomain.toLowerCase().replace(/^\.+|\.+$/g, "");
  if (!/^[a-z0-9.-]+$/.test(normalized) || !normalized.includes(".")) {
    throw new Error("OPENVPN_GATEWAY_BASE_DOMAIN must be a DNS domain");
  }
  return `vpn-${namespace}.${normalized}:1194`;
}

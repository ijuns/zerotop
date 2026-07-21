import { createHash, randomUUID } from "node:crypto";

import type { RuntimeAdapter } from "./ports.ts";
import { ApiError } from "./errors.ts";
import type {
  JsonObject,
  LabAccessMethod,
  RuntimeRunInput,
  RuntimeRunStatusInput,
} from "./types.ts";
import { parseTargetRuntimeContract, type TargetRuntimeContract } from "./target-runtime-contract.ts";

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assignedVpnAddress(runId: string): string {
  const digest = createHash("sha256").update(runId, "utf8").digest();
  return `10.77.${(digest[0] % 200) + 1}.${(digest[1] % 200) + 10}`;
}

/** Development-only runtime adapter. Replace with a Kubernetes/KubeVirt adapter in production. */
export class DevelopmentRuntimeSimulator implements RuntimeAdapter {
  createRun(labValue: unknown, userId: string, accessMethod: LabAccessMethod): RuntimeRunInput {
    const lab = isObject(labValue) ? labValue : {};
    const labId = String(lab.id);
    const environment =
      (lab.desktopImage ?? lab.environment) === "kali" ? "kali" : "ubuntu";
    const id = `run_${randomUUID()}`;
    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + 2 * 60 * 60 * 1000);
    const desktop = environment === "ubuntu" ? "Ubuntu SOC Desktop" : "Kali Attack Box";
    const image =
      environment === "ubuntu"
        ? "codegate/ubuntu-soc:development"
        : "codegate/kali-attack:development";
    const metadata: JsonObject = {
      runtime: "simulator",
      provisioner: "local-runtime-adapter",
      namespace: `local-${id.slice(4, 16)}`,
      desktop,
      image,
      isolatedNetwork: true,
      note: "Development metadata only; replace this adapter with KubeVirt in production.",
    };

    let browserUrl: string | null = null;
    let openvpnProfile: JsonObject | null = null;
    if (accessMethod === "browser_desktop" || accessMethod === "both") {
      browserUrl = `http://localhost:6080/vnc.html?path=websockify/${id}`;
    }
    if (accessMethod === "openvpn" || accessMethod === "both") {
      openvpnProfile = {
        profileId: `ovpn_${id.slice(4)}`,
        endpoint: "vpn.local.codegate.invalid:1194",
        assignedIp: assignedVpnAddress(id),
        allowedCidr: "10.77.0.0/16",
        gateway: "vpn.local.codegate.invalid:1194",
        protocol: "udp",
        network: "10.77.0.0/16",
        assignedAddress: assignedVpnAddress(id),
        downloadPath: `/v1/runs/${id}/openvpn-config`,
        expiresAt: expiresAt.toISOString(),
        simulated: true,
      };
    }

    return {
      id,
      labId,
      userId,
      status: "ready",
      environment,
      accessMethod,
      browserUrl,
      openvpnProfile,
      expiresAt: expiresAt.toISOString(),
      metadata,
      createdAt: createdAt.toISOString(),
    };
  }

  getRunStatus(runId: string): RuntimeRunStatusInput {
    return {
      id: runId,
      status: "ready",
      namespace: `local-${runId.replace(/^run_/, "").slice(0, 12)}`,
      expiresAt: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
      checks: { workstationVmi: true, targetWorkload: true },
    };
  }

  destroyRun(_runId: string): void {
    // The development simulator owns no external runtime resources.
  }
}

interface HttpRuntimeAdapterOptions {
  serviceUrl: string;
  internalToken: string;
  targetImage?: string;
  allowedTargetRegistries?: string[];
  allowTemplateFallback?: boolean;
  desktopPublicUrl?: string;
  fetchImpl?: typeof fetch;
}

/** Production runtime adapter for the isolated runtime control-plane service. */
export class HttpRuntimeAdapter implements RuntimeAdapter {
  private readonly serviceUrl: string;
  private readonly internalToken: string;
  private readonly targetImage: string;
  private readonly allowedTargetRegistries: string[];
  private readonly allowTemplateFallback: boolean;
  private readonly desktopPublicUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: HttpRuntimeAdapterOptions) {
    if (!options.serviceUrl || !options.internalToken) {
      throw new Error(
        "Runtime service URL and internal token are required.",
      );
    }
    this.serviceUrl = options.serviceUrl.replace(/\/$/, "");
    this.internalToken = options.internalToken;
    this.targetImage = options.targetImage ?? "";
    this.allowedTargetRegistries = (
      options.allowedTargetRegistries ?? ["registry.codegate.internal"]
    ).map((item) => item.trim().toLowerCase());
    this.allowTemplateFallback = options.allowTemplateFallback === true;
    this.desktopPublicUrl = (options.desktopPublicUrl ?? options.serviceUrl).replace(
      /\/$/,
      "",
    );
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async createRun(
    labValue: unknown,
    userId: string,
    accessMethod: LabAccessMethod,
  ): Promise<RuntimeRunInput> {
    const lab = isObject(labValue) ? labValue : {};
    const id = `run_${randomUUID()}`;
    const labId = String(lab.id);
    const desktopImage =
      (lab.desktopImage ?? lab.environment) === "kali" ? "kali" : "ubuntu";
    const targetImage = this.approvedTargetImage(lab);
    const targetRuntimeContract = this.approvedTargetRuntimeContract(lab);
    const targetService = this.approvedTargetService(lab, targetRuntimeContract);
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.serviceUrl}/v1/runs/provision`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.internalToken}`,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({
          runId: id,
          labId,
          userId,
          desktopImage,
          accessMethod,
          ttlMinutes: 120,
          targetImage,
          targetService,
          targetRuntimeContract,
        }),
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      throw new ApiError(
        503,
        "RUNTIME_SERVICE_UNAVAILABLE",
        "The runtime control-plane service is unavailable.",
      );
    }
    const payload = (await response.json().catch(() => null)) as unknown;
    if (!response.ok || !isObject(payload)) {
      throw new ApiError(
        502,
        "RUNTIME_PROVISION_FAILED",
        "The runtime control plane rejected the provisioning request.",
        { status: response.status },
      );
    }

    const browser = isObject(payload.browserDesktop)
      ? payload.browserDesktop
      : null;
    const openVpn = isObject(payload.openVpn) ? payload.openVpn : null;
    const expiresAt =
      typeof payload.expiresAt === "string"
        ? payload.expiresAt
        : new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();
    const status = payload.status === "ready" ? "ready" : "provisioning";
    const gatewayPath = browser?.gatewayPath;
    const browserUrl =
      typeof gatewayPath === "string"
        ? new URL(gatewayPath, `${this.desktopPublicUrl}/`).toString()
        : null;

    return {
      id,
      labId,
      userId,
      status,
      environment: desktopImage,
      accessMethod,
      browserUrl,
      openvpnProfile: openVpn,
      expiresAt,
      metadata: {
        runtime: "service",
        namespace: payload.namespace ?? null,
        desktop: desktopImage === "ubuntu" ? "Ubuntu SOC Desktop" : "Kali Attack Box",
        isolatedNetwork: true,
      },
      createdAt: new Date().toISOString(),
    };
  }

  async getRunStatus(runId: string): Promise<RuntimeRunStatusInput> {
    let response: Response;
    try {
      response = await this.fetchImpl(
        `${this.serviceUrl}/v1/runs/${encodeURIComponent(runId)}`,
        {
          method: "GET",
          headers: {
            authorization: `Bearer ${this.internalToken}`,
            accept: "application/json",
          },
          signal: AbortSignal.timeout(10_000),
        },
      );
    } catch {
      throw new ApiError(
        503,
        "RUNTIME_SERVICE_UNAVAILABLE",
        "The runtime control-plane service is unavailable.",
      );
    }
    if (response.status === 404) {
      return {
        id: runId,
        status: "failed",
        namespace: "",
        expiresAt: new Date().toISOString(),
        checks: {},
        reason: "The runtime namespace no longer exists.",
      };
    }
    const payload = (await response.json().catch(() => null)) as unknown;
    if (!response.ok || !isObject(payload)) {
      throw new ApiError(
        502,
        "RUNTIME_STATUS_FAILED",
        "The runtime control plane rejected the status request.",
        { status: response.status },
      );
    }
    if (
      payload.id !== runId ||
      (payload.status !== "provisioning" && payload.status !== "ready" && payload.status !== "failed") ||
      typeof payload.namespace !== "string" ||
      typeof payload.expiresAt !== "string" ||
      !Number.isFinite(Date.parse(payload.expiresAt)) ||
      !isBooleanRecord(payload.checks)
    ) {
      throw new ApiError(
        502,
        "RUNTIME_STATUS_INVALID",
        "The runtime control plane returned an invalid status response.",
      );
    }
    return {
      id: runId,
      status: payload.status,
      namespace: payload.namespace,
      expiresAt: payload.expiresAt,
      checks: payload.checks,
      ...(typeof payload.reason === "string" ? { reason: payload.reason.slice(0, 500) } : {}),
    };
  }

  async destroyRun(runId: string): Promise<void> {
    let response: Response;
    try {
      response = await this.fetchImpl(
        `${this.serviceUrl}/v1/runs/${encodeURIComponent(runId)}`,
        {
          method: "DELETE",
          headers: {
            authorization: `Bearer ${this.internalToken}`,
            accept: "application/json",
          },
          signal: AbortSignal.timeout(10_000),
        },
      );
    } catch {
      throw new ApiError(
        503,
        "RUNTIME_SERVICE_UNAVAILABLE",
        "The runtime control-plane service is unavailable.",
      );
    }
    if (response.status === 404 || response.ok) {
      return;
    }
    throw new ApiError(
      502,
      "RUNTIME_DESTROY_FAILED",
      "The runtime control plane rejected the destroy request.",
      { status: response.status },
    );
  }

  private approvedTargetImage(lab: Record<string, unknown>): string {
    const config = isObject(lab.config) ? lab.config : {};
    const target = isObject(config.target) ? config.target : {};
    const imageRef = typeof target.imageRef === "string" ? target.imageRef : "";
    const imageDigest =
      typeof target.imageDigest === "string" ? target.imageDigest : "";
    const registry = imageRef.split("/", 1)[0].toLowerCase();
    const validReference =
      /^[a-z0-9.-]+(?::\d+)?\/[a-z0-9._/-]+(?::[a-z0-9._-]+)?$/i.test(
        imageRef,
      ) && !imageRef.includes("@");
    if (
      validReference &&
      /^sha256:[a-f0-9]{64}$/i.test(imageDigest) &&
      this.allowedTargetRegistries.includes(registry)
    ) {
      return `${imageRef}@${imageDigest.toLowerCase()}`;
    }
    if (
      target.source === "template_fallback" &&
      this.allowTemplateFallback &&
      this.targetImage
    ) {
      return this.targetImage;
    }
    throw new ApiError(
      409,
      "LAB_TARGET_IMAGE_NOT_APPROVED",
      "The validated lab has no approved digest-pinned target image.",
    );
  }

  private approvedTargetRuntimeContract(lab: Record<string, unknown>): TargetRuntimeContract {
    const config = isObject(lab.config) ? lab.config : {};
    const target = isObject(config.target) ? config.target : {};
    const runtimeContract = parseTargetRuntimeContract(target.runtimeContract);
    if (runtimeContract) return runtimeContract;
    if (target.source === "template_fallback" && this.allowTemplateFallback) {
      return developmentTargetRuntimeContract();
    }
    throw new ApiError(
      409,
      "LAB_TARGET_RUNTIME_CONTRACT_INVALID",
      "The validated lab has no supported target runtime contract.",
    );
  }

  private approvedTargetService(
    lab: Record<string, unknown>,
    runtimeContract: TargetRuntimeContract,
  ): { port: number; protocol: "http" | "tcp" } {
    const config = isObject(lab.config) ? lab.config : {};
    const target = isObject(config.target) ? config.target : {};
    const validation = isObject(config.validation) ? config.validation : {};
    const targetService = parseTargetService(target.service, "target.service");
    const validationService = parseTargetService(validation.service, "validation.service");
    if (
      targetService &&
      validationService &&
      (targetService.port !== validationService.port || targetService.protocol !== validationService.protocol)
    ) {
      throw new ApiError(
        409,
        "LAB_TARGET_SERVICE_MISMATCH",
        "The target and validation service contracts do not match.",
      );
    }
    const service = targetService ?? validationService;
    if (
      service
      && (service.port !== runtimeContract.port || service.protocol !== runtimeContract.protocol)
    ) {
      throw new ApiError(
        409,
        "LAB_TARGET_RUNTIME_CONTRACT_MISMATCH",
        "The target service conflicts with the hardened target runtime contract.",
      );
    }
    if (service) return service;
    if (target.source === "template_fallback" && this.allowTemplateFallback) {
      return { port: runtimeContract.port, protocol: runtimeContract.protocol };
    }
    throw new ApiError(
      409,
      "LAB_TARGET_SERVICE_INVALID",
      "The validated lab has no approved target service port and protocol.",
    );
  }
}

function developmentTargetRuntimeContract(): TargetRuntimeContract {
  return {
    kind: "http-v1",
    uid: 65_532,
    gid: 65_532,
    protocol: "http",
    port: 8_080,
    writablePaths: ["/tmp"],
    readOnlyRootFilesystem: true,
    bindAddress: "0.0.0.0",
    healthPath: "/health",
    fingerprintPath: "/version",
  };
}

function isBooleanRecord(value: unknown): value is JsonObject {
  return isObject(value) && Object.values(value).every((item) => typeof item === "boolean");
}

function parseTargetService(
  value: unknown,
  fieldName: string,
): { port: number; protocol: "http" | "tcp" } | null {
  if (value === undefined) return null;
  if (!isObject(value)) {
    throw new ApiError(409, "LAB_TARGET_SERVICE_INVALID", `${fieldName} must be an object.`);
  }
  const port = Number(value.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new ApiError(409, "LAB_TARGET_SERVICE_INVALID", `${fieldName}.port must be an integer between 1 and 65535.`);
  }
  if (value.protocol !== "http" && value.protocol !== "tcp") {
    throw new ApiError(409, "LAB_TARGET_SERVICE_INVALID", `${fieldName}.protocol must be http or tcp.`);
  }
  return { port, protocol: value.protocol };
}

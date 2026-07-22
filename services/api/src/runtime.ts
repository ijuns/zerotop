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
import { blueTelemetryGeneration } from "./blue-telemetry.ts";
import { buildRedExercise } from "./red-exercise.ts";

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
    const config = isObject(lab.config) ? lab.config : {};
    const topology = isObject(config.topology) ? config.topology : null;
    const metadata: JsonObject = {
      runtime: "simulator",
      provisioner: "local-runtime-adapter",
      namespace: `local-${id.slice(4, 16)}`,
      desktop,
      image,
      isolatedNetwork: true,
      ...(topology ? { team: topology.team ?? null, topology } : {}),
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
    const topology = this.approvedRuntimeTopology(lab, desktopImage, new Date().toISOString());
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
          ...(topology ? { topology } : {}),
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
        ...(topology ? { team: topology.team, topology } : {}),
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

  private approvedRuntimeTopology(
    lab: Record<string, unknown>,
    desktopImage: "ubuntu" | "kali",
    timelineAnchor: string,
  ): JsonObject | null {
    const config = isObject(lab.config) ? lab.config : {};
    const builderSpec = isObject(config.builderSpec) ? config.builderSpec : {};
    const candidate = isObject(config.topology)
      ? config.topology
      : isObject(builderSpec.topology)
        ? builderSpec.topology
        : null;
    if (!candidate) {
      return this.legacyRuntimeTopology(lab, config, desktopImage, timelineAnchor);
    }
    const team = candidate.team;
    const workstation = isObject(candidate.workstation) ? candidate.workstation : {};
    const target = isObject(candidate.target) ? candidate.target : {};
    const blue = team === "blue";
    if (
      (team !== "blue" && team !== "red")
      || candidate.schemaVersion !== 1
      || candidate.isolation !== "per_run"
      || desktopImage !== (blue ? "ubuntu" : "kali")
      || workstation.role !== (blue ? "soc_analyst" : "attack_operator")
      || workstation.desktopImage !== desktopImage
      || workstation.entrypoint !== (blue ? "kibana" : "target")
      || target.role !== (blue ? "monitored_target" : "vulnerable_target")
      || target.hostname !== "target"
    ) {
      throw new ApiError(409, "LAB_RUNTIME_TOPOLOGY_INVALID", "The validated Lab has an invalid team runtime topology.");
    }
    if (!blue) {
      if (candidate.telemetry !== undefined) {
        throw new ApiError(409, "LAB_RUNTIME_TOPOLOGY_INVALID", "Red-team topology must not contain a defensive telemetry stack.");
      }
      return {
        ...candidate,
        target: {
          ...target,
          exercise: redExerciseForLab(lab, config),
        },
      } as JsonObject;
    }
    const telemetry = isObject(candidate.telemetry) ? candidate.telemetry : {};
    if (
      telemetry.stack !== "elastic"
      || telemetry.collector !== "elastic_agent"
      || telemetry.generator !== "scenario_log_generator"
      || typeof telemetry.index !== "string"
      || !Array.isArray(telemetry.events)
      || telemetry.events.length < 1
    ) {
      throw new ApiError(409, "LAB_RUNTIME_TOPOLOGY_INVALID", "Blue-team topology requires ELK, an Elastic Agent and scenario telemetry events.");
    }
    let generation: JsonObject;
    try {
      generation = blueTelemetryGeneration(lab, config, telemetry.generation, timelineAnchor) as unknown as JsonObject;
    } catch (error) {
      throw new ApiError(
        409,
        "LAB_RUNTIME_TOPOLOGY_INVALID",
        error instanceof Error ? error.message : "The Blue-team telemetry generation plan is invalid.",
      );
    }
    return {
      ...candidate,
      telemetry: { ...telemetry, generation },
    } as JsonObject;
  }

  private legacyRuntimeTopology(
    lab: Record<string, unknown>,
    config: Record<string, unknown>,
    desktopImage: "ubuntu" | "kali",
    timelineAnchor: string,
  ): JsonObject {
    const team = lab.team ?? lab.teamType;
    if (team !== "blue" && team !== "red") {
      throw new ApiError(
        409,
        "LAB_RUNTIME_TOPOLOGY_INVALID",
        "The legacy Lab has no valid team for runtime topology migration.",
      );
    }

    const expectedDesktop = team === "blue" ? "ubuntu" : "kali";
    if (desktopImage !== expectedDesktop) {
      throw new ApiError(
        409,
        "LAB_RUNTIME_TOPOLOGY_INVALID",
        "The legacy Lab team and desktop image do not match.",
      );
    }

    if (team === "red") {
      return {
        schemaVersion: 1,
        team: "red",
        isolation: "per_run",
        workstation: {
          role: "attack_operator",
          desktopImage: "kali",
          entrypoint: "target",
        },
        target: {
          role: "vulnerable_target",
          hostname: "target",
          exercise: redExerciseForLab(lab, config),
        },
      };
    }

    const telemetry = isObject(config.telemetry) ? config.telemetry : {};
    const events = approvedLegacyTelemetryEvents(telemetry.events);
    if (!events) {
      throw new ApiError(
        409,
        "LAB_RUNTIME_TOPOLOGY_INVALID",
        "The legacy Blue-team Lab requires valid scenario telemetry events before it can be deployed.",
      );
    }
    let generation: JsonObject;
    try {
      generation = blueTelemetryGeneration(lab, config, telemetry.generation, timelineAnchor) as unknown as JsonObject;
    } catch (error) {
      throw new ApiError(
        409,
        "LAB_RUNTIME_TOPOLOGY_INVALID",
        error instanceof Error ? error.message : "The legacy Blue-team telemetry generation plan is invalid.",
      );
    }
    return {
      schemaVersion: 1,
      team: "blue",
      isolation: "per_run",
      workstation: {
        role: "soc_analyst",
        desktopImage: "ubuntu",
        entrypoint: "kibana",
      },
      target: { role: "monitored_target", hostname: "target" },
      telemetry: {
        stack: "elastic",
        collector: "elastic_agent",
        generator: "scenario_log_generator",
        index: "zerotop-logs-*",
        events,
        generation,
      },
    };
  }
}

function redExerciseForLab(
  lab: Record<string, unknown>,
  config: Record<string, unknown>,
): JsonObject {
  const target = isObject(config.target) ? config.target : {};
  const scenario = isObject(config.scenario) ? config.scenario : {};
  const cveCandidates = [
    ...(Array.isArray(lab.cveIds) ? lab.cveIds : []),
    ...(Array.isArray(target.expectedCves) ? target.expectedCves : []),
  ];
  const attackCandidates = [
    ...(Array.isArray(scenario.mitreTechniques) ? scenario.mitreTechniques : []),
    ...(Array.isArray(scenario.attackChain)
      ? scenario.attackChain.map((item) => isObject(item) ? item.id : null)
      : []),
  ];
  return buildRedExercise({
    title: typeof lab.title === "string" ? lab.title : "Red Team Lab",
    prompt: typeof lab.prompt === "string" ? lab.prompt : "격리된 대상의 취약 조건을 검증합니다.",
    cveIds: cveCandidates.filter((item): item is string => typeof item === "string"),
    attackTechniqueIds: attackCandidates.filter((item): item is string => typeof item === "string"),
  });
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

function approvedLegacyTelemetryEvents(value: unknown): unknown[] | null {
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) return null;
  try {
    for (const item of value) {
      if (!isObject(item) || typeof item.id !== "string" || !isObject(item.document)) {
        return null;
      }
      if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(item.id)) return null;
      if (
        typeof item.document["@timestamp"] !== "string"
        || !isObject(item.document.event)
        || !isObject(item.document.threat)
        || containsAnswerMaterial(item.document)
      ) {
        return null;
      }
      const documentSize = Buffer.byteLength(JSON.stringify(item.document), "utf8");
      if (documentSize > 32_000) return null;
    }
    const encodedSize = Buffer.byteLength(JSON.stringify(value), "utf8");
    return encodedSize <= 256_000 ? value : null;
  } catch {
    return null;
  }
}

function containsAnswerMaterial(value: unknown, depth = 0): boolean {
  if (depth > 12) return true;
  if (Array.isArray(value)) {
    return value.some((item) => containsAnswerMaterial(item, depth + 1));
  }
  if (!isObject(value)) return false;
  return Object.entries(value).some(
    ([key, item]) =>
      /^(?:answer|answerkey|correct(?:answer|option|options?)?|solution|flag)$/i.test(key)
      || containsAnswerMaterial(item, depth + 1),
  );
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

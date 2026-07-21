import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";
import type { KubernetesApplier, KubernetesValidationInspection } from "./adapter.ts";
import type { TelemetryValidator } from "./elasticsearch-validation.ts";
import { buildValidationBaseResources, buildValidationProbeJob } from "./validation-manifests.ts";
import { validationNamespace, type SandboxValidationInput } from "./validation-input.ts";

export interface SandboxResponse {
  sandbox: {
    provisioned: boolean;
    functionalChecksPassed: boolean;
    intendedVulnerabilityConfirmed: boolean;
    egressBlocked: boolean;
    controlPlaneBlocked: boolean;
    crossRunBlocked: boolean;
    cleanupConfirmed: boolean;
  };
  assessment: {
    questionsRendered: boolean;
    gradingVerified: boolean;
    answerLeakageDetected: boolean;
    elkIndexReady?: boolean;
    expectedEventsSearchable?: boolean;
    mitreMappingsVerified?: boolean;
    exploitPathLimitedToSandbox?: boolean;
  };
  diagnostics: { validationId: string; failureCode?: string };
}

export interface SandboxValidator {
  validate(input: SandboxValidationInput): Promise<SandboxResponse>;
}

export interface KubeVirtSandboxOptions {
  probeImage: string;
  timeoutSeconds: number;
  externalProbeHost: string;
  externalProbePort: number;
  controlPlaneHost: string;
  controlPlanePort: number;
  canaryNamespace: string;
  canaryService: string;
  canaryPort: number;
}

export class KubeVirtSandboxValidator implements SandboxValidator {
  private readonly kubernetes: KubernetesApplier;
  private readonly telemetry: TelemetryValidator;
  private readonly options: KubeVirtSandboxOptions;

  constructor(
    kubernetes: KubernetesApplier,
    telemetry: TelemetryValidator,
    options: KubeVirtSandboxOptions,
  ) {
    this.kubernetes = kubernetes;
    this.telemetry = telemetry;
    this.options = options;
    if (!kubernetes.inspectValidation || !kubernetes.getServiceClusterIp || !kubernetes.serviceHasReadyEndpoints || !kubernetes.namespaceExists) {
      throw new Error("The Kubernetes adapter does not implement sandbox validation controls");
    }
    if (!/@sha256:[a-f0-9]{64}$/i.test(options.probeImage)) throw new Error("SANDBOX_PROBE_IMAGE must be digest-pinned");
  }

  async validate(input: SandboxValidationInput): Promise<SandboxResponse> {
    const validationId = `val-${randomBytes(12).toString("hex")}`;
    const namespace = validationNamespace(input.labId, validationId);
    const expiresAt = new Date(Date.now() + (this.options.timeoutSeconds + 180) * 1_000).toISOString();
    const deadline = Date.now() + this.options.timeoutSeconds * 1_000;
    const response = emptyResponse(input, validationId);
    let resourcesCreated = false;
    try {
      const base = buildValidationBaseResources(input, {
        namespace,
        validationId,
        expiresAt,
        probeImage: this.options.probeImage,
        activeDeadlineSeconds: this.options.timeoutSeconds,
      });
      for (const resource of base) await this.kubernetes.apply(resource);
      resourcesCreated = true;
      await this.waitForTarget(namespace, deadline);
      response.sandbox.provisioned = true;

      const canaryIp = await this.kubernetes.getServiceClusterIp!(this.options.canaryNamespace, this.options.canaryService);
      const canaryReady = await this.kubernetes.serviceHasReadyEndpoints!(this.options.canaryNamespace, this.options.canaryService);
      if (!canaryIp || !canaryReady) throw new SandboxFailure("cross_run_canary_unavailable");
      const plan = {
        schemaVersion: 1,
        target: { host: "target", port: input.service.port, protocol: input.service.protocol },
        functionalProbes: input.functionalProbes,
        vulnerabilityProbes: input.vulnerabilityProbes,
        isolation: {
          external: { host: this.options.externalProbeHost, port: this.options.externalProbePort },
          controlPlane: { host: this.options.controlPlaneHost, port: this.options.controlPlanePort },
          crossRun: { host: canaryIp, port: this.options.canaryPort },
        },
        requestTimeoutMs: Math.min(5_000, Math.max(500, Math.floor(this.options.timeoutSeconds * 100))),
      };
      const encodedPlan = Buffer.from(JSON.stringify(plan), "utf8").toString("base64url");
      await this.kubernetes.apply(buildValidationProbeJob(input, {
        namespace,
        validationId,
        expiresAt,
        probeImage: this.options.probeImage,
        activeDeadlineSeconds: Math.max(30, Math.min(180, this.options.timeoutSeconds)),
        probePlanBase64Url: encodedPlan,
      }));
      const inspection = await this.waitForProbe(namespace, deadline);
      const observation = parseProbeOutput(inspection.probeOutput, input);
      response.sandbox.functionalChecksPassed = observation.functionalPassed;
      response.sandbox.intendedVulnerabilityConfirmed = observation.vulnerabilityPassed;
      response.sandbox.egressBlocked = observation.egressBlocked;
      response.sandbox.controlPlaneBlocked = observation.controlPlaneBlocked;
      response.sandbox.crossRunBlocked = observation.crossRunBlocked;
      if (input.team === "red") {
        response.assessment.exploitPathLimitedToSandbox =
          observation.egressBlocked && observation.controlPlaneBlocked && observation.crossRunBlocked;
      }
      if (input.team === "blue") {
        const telemetry = await this.telemetry.validate(validationId, input.telemetryEvents);
        response.assessment.elkIndexReady = telemetry.indexReady;
        response.assessment.expectedEventsSearchable = telemetry.eventsSearchable;
      }
    } catch (error) {
      response.diagnostics.failureCode = error instanceof SandboxFailure
        ? error.code
        : "sandbox_dependency_failure";
    } finally {
      if (resourcesCreated) {
        await this.kubernetes.deleteNamespace(namespace).catch(() => undefined);
        response.sandbox.cleanupConfirmed = await this.waitForDeletion(namespace, Date.now() + 60_000);
      }
    }
    return response;
  }

  private async waitForTarget(namespace: string, deadline: number): Promise<void> {
    while (Date.now() < deadline) {
      const status = await this.kubernetes.inspectValidation!(namespace);
      if (!status) throw new SandboxFailure("validation_namespace_missing");
      if (status.targetFailed) throw new SandboxFailure("target_workload_failed");
      if (status.targetReady) return;
      await delay(2_000);
    }
    throw new SandboxFailure("target_readiness_timeout");
  }

  private async waitForProbe(namespace: string, deadline: number): Promise<KubernetesValidationInspection> {
    while (Date.now() < deadline) {
      const status = await this.kubernetes.inspectValidation!(namespace);
      if (!status) throw new SandboxFailure("validation_namespace_missing");
      if (status.probeState === "succeeded") return status;
      if (status.probeState === "failed") throw new SandboxFailure("probe_job_failed");
      await delay(2_000);
    }
    throw new SandboxFailure("probe_timeout");
  }

  private async waitForDeletion(namespace: string, deadline: number): Promise<boolean> {
    while (Date.now() < deadline) {
      if (!await this.kubernetes.namespaceExists!(namespace)) return true;
      await delay(1_000);
    }
    return false;
  }
}

export class DevelopmentSandboxValidator implements SandboxValidator {
  private readonly telemetry: TelemetryValidator;

  constructor(telemetry: TelemetryValidator) {
    this.telemetry = telemetry;
  }

  async validate(input: SandboxValidationInput): Promise<SandboxResponse> {
    const response = emptyResponse(input, "development-sandbox");
    response.sandbox = {
      provisioned: true,
      functionalChecksPassed: true,
      intendedVulnerabilityConfirmed: true,
      egressBlocked: true,
      controlPlaneBlocked: true,
      crossRunBlocked: true,
      cleanupConfirmed: true,
    };
    if (input.team === "blue") {
      const result = await this.telemetry.validate("development-sandbox", input.telemetryEvents);
      response.assessment.elkIndexReady = result.indexReady;
      response.assessment.expectedEventsSearchable = result.eventsSearchable;
    } else {
      response.assessment.exploitPathLimitedToSandbox = true;
    }
    return response;
  }
}

function emptyResponse(input: SandboxValidationInput, validationId: string): SandboxResponse {
  return {
    sandbox: {
      provisioned: false,
      functionalChecksPassed: false,
      intendedVulnerabilityConfirmed: false,
      egressBlocked: false,
      controlPlaneBlocked: false,
      crossRunBlocked: false,
      cleanupConfirmed: false,
    },
    assessment: {
      questionsRendered: input.questionsRendered,
      gradingVerified: input.gradingVerified,
      answerLeakageDetected: input.answerLeakageDetected,
      ...(input.team === "blue"
        ? { elkIndexReady: false, expectedEventsSearchable: false, mitreMappingsVerified: input.mitreMappingsVerified }
        : { exploitPathLimitedToSandbox: false }),
    },
    diagnostics: { validationId },
  };
}

function parseProbeOutput(value: string | undefined, input: SandboxValidationInput): {
  functionalPassed: boolean;
  vulnerabilityPassed: boolean;
  egressBlocked: boolean;
  controlPlaneBlocked: boolean;
  crossRunBlocked: boolean;
} {
  if (!value) throw new SandboxFailure("probe_output_missing");
  const lines = value.trim().split(/\r?\n/).filter(Boolean);
  const raw = lines.at(-1);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw ?? "");
  } catch {
    throw new SandboxFailure("probe_output_invalid");
  }
  const root = record(parsed);
  if (root.schemaVersion !== 1) throw new SandboxFailure("probe_output_invalid");
  const functional = observations(root.functional, input.functionalProbes.map((item) => item.id));
  const vulnerability = observations(root.vulnerability, input.vulnerabilityProbes.map((item) => item.id));
  const network = record(root.network);
  const egressBlocked = network.egressBlocked === true;
  const controlPlaneBlocked = network.controlPlaneBlocked === true;
  const crossRunBlocked = network.crossRunBlocked === true;
  const coveredCves = new Set(
    vulnerability
      .filter((item) => item.passed === true && typeof item.cveId === "string")
      .map((item) => String(item.cveId).toUpperCase()),
  );
  return {
    functionalPassed: functional.every((item) => item.passed === true),
    vulnerabilityPassed:
      vulnerability.every((item) => item.passed === true) &&
      input.expectedCves.every((cve) => coveredCves.has(cve)),
    egressBlocked,
    controlPlaneBlocked,
    crossRunBlocked,
  };
}

function observations(value: unknown, expectedIds: string[]): Array<Record<string, unknown>> {
  if (!Array.isArray(value) || value.length !== expectedIds.length) throw new SandboxFailure("probe_output_invalid");
  const rows = value.map(record);
  const ids = rows.map((item) => String(item.id ?? ""));
  if ([...ids].sort().join("|") !== [...expectedIds].sort().join("|")) throw new SandboxFailure("probe_output_invalid");
  return rows;
}

class SandboxFailure extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
    this.name = "SandboxFailure";
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

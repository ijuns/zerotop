import type { ProvisionRunRequest } from "./contracts.ts";
import { parseTargetRuntimeContract } from "./runtime-contract.ts";

export interface ProvisionValidationOptions {
  runtimeMode: string;
  allowedTargetRegistries?: string[];
}

export function validateProvisionRequest(
  value: unknown,
  options: ProvisionValidationOptions,
): ProvisionRunRequest {
  if (!isRecord(value)) throw new Error("Request body must be an object");

  const runId = validateRunId(value.runId);
  const labId = safeIdentifier(value.labId, "labId");
  const userId = safeIdentifier(value.userId, "userId");
  if (value.desktopImage !== "ubuntu" && value.desktopImage !== "kali") {
    throw new Error("desktopImage must be ubuntu or kali");
  }
  if (!["browser_desktop", "openvpn", "both"].includes(String(value.accessMethod))) {
    throw new Error("accessMethod must be browser_desktop, openvpn or both");
  }
  if (
    !Number.isInteger(value.ttlMinutes) ||
    Number(value.ttlMinutes) < 10 ||
    Number(value.ttlMinutes) > 240
  ) {
    throw new Error("ttlMinutes must be an integer between 10 and 240");
  }
  if (typeof value.targetImage !== "string" || value.targetImage.length > 512) {
    throw new Error("targetImage must be a valid image reference");
  }
  validateTargetImage(value.targetImage, options);
  if (!isRecord(value.targetService)) {
    throw new Error("targetService must be an object");
  }
  const targetPort = Number(value.targetService.port);
  if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
    throw new Error("targetService.port must be an integer between 1 and 65535");
  }
  if (value.targetService.protocol !== "http" && value.targetService.protocol !== "tcp") {
    throw new Error("targetService.protocol must be http or tcp");
  }
  const targetRuntimeContract = parseTargetRuntimeContract(value.targetRuntimeContract);
  if (
    targetPort !== targetRuntimeContract.port
    || value.targetService.protocol !== targetRuntimeContract.protocol
  ) throw new Error("targetService must match targetRuntimeContract");

  return {
    runId,
    labId,
    userId,
    desktopImage: value.desktopImage,
    accessMethod: value.accessMethod as ProvisionRunRequest["accessMethod"],
    ttlMinutes: Number(value.ttlMinutes),
    targetImage: value.targetImage,
    targetService: {
      port: targetPort,
      protocol: value.targetService.protocol,
    },
    targetRuntimeContract,
  };
}

export function validateRunId(value: unknown): string {
  return safeIdentifier(value, "runId");
}

function safeIdentifier(value: unknown, field: string): string {
  if (
    typeof value !== "string" ||
    !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$/.test(value)
  ) {
    throw new Error(`${field} must be a 1-63 character safe identifier`);
  }
  return value;
}

function validateTargetImage(
  image: string,
  options: ProvisionValidationOptions,
): void {
  if (options.runtimeMode === "docker") {
    // Docker mode substitutes a locally built, operator-selected target image.
    // Still reject malformed input so the control-plane contract stays bounded.
    if (!image || /[\s\0]/.test(image) || image.startsWith("-")) {
      throw new Error("targetImage must be a valid image reference");
    }
    return;
  }
  if (options.runtimeMode === "local") {
    if (!/@sha256:[a-f0-9]{64}$/i.test(image)) {
      throw new Error("targetImage must be pinned by sha256 digest");
    }
    return;
  }
  const registries = (options.allowedTargetRegistries ?? [])
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  if (registries.length === 0) {
    throw new Error("At least one target image registry must be allow-listed");
  }
  const registry = image.split("/", 1)[0].toLowerCase();
  if (!registries.includes(registry)) {
    throw new Error("targetImage registry is not allow-listed");
  }
  if (!/@sha256:[a-f0-9]{64}$/i.test(image)) {
    throw new Error("targetImage must be pinned by sha256 digest");
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

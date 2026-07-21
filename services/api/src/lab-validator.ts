import { ApiError } from "./errors.ts";
import type { LabValidationResult, LabValidator } from "./ports.ts";
import type { JsonObject, ValidationEvidenceInput } from "./types.ts";
import { evaluateLab } from "./validation.ts";

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export class DevelopmentLabValidator implements LabValidator {
  private readonly allowedTargetRegistries: string[];

  constructor(allowedTargetRegistries = ["registry.codegate.internal"]) {
    this.allowedTargetRegistries = allowedTargetRegistries;
  }

  validate(lab: unknown): LabValidationResult {
    return evaluateLab(lab, {
      allowedTargetRegistries: this.allowedTargetRegistries,
      allowTemplateFallback: true,
    });
  }
}

interface HttpLabValidatorOptions {
  serviceUrl: string;
  internalToken: string;
  fetchImpl?: typeof fetch;
}

/** Production boundary for supply-chain, sandbox, assessment and AI review gates. */
export class HttpLabValidator implements LabValidator {
  private readonly serviceUrl: string;
  private readonly internalToken: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: HttpLabValidatorOptions) {
    if (!options.serviceUrl || options.internalToken.length < 24) {
      throw new Error("Validator service URL and a strong internal token are required.");
    }
    this.serviceUrl = options.serviceUrl.replace(/\/$/, "");
    this.internalToken = options.internalToken;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async validate(lab: unknown): Promise<LabValidationResult> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.serviceUrl}/v1/validations`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.internalToken}`,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({ lab }),
        signal: AbortSignal.timeout(180_000),
      });
    } catch {
      throw new ApiError(
        503,
        "VALIDATOR_SERVICE_UNAVAILABLE",
        "The automatic validation service is unavailable.",
      );
    }
    const payload = (await response.json().catch(() => null)) as unknown;
    if (!response.ok) {
      throw new ApiError(
        502,
        "VALIDATOR_SERVICE_REJECTED_REQUEST",
        "The automatic validation service rejected the lab.",
        { status: response.status },
      );
    }
    return parseValidationResult(payload);
  }
}

export function parseValidationResult(value: unknown): LabValidationResult {
  const root = isObject(value) ? value : {};
  const payload = isObject(root.data) ? root.data : root;
  const decision = payload.decision;
  const status = payload.status;
  const rawEvidence = payload.evidence;
  if (
    (decision !== "pass" && decision !== "quarantine") ||
    (status !== "validated" && status !== "quarantined") ||
    !Array.isArray(rawEvidence) ||
    rawEvidence.length === 0
  ) {
    throw invalidContract();
  }
  const evidence: ValidationEvidenceInput[] = rawEvidence.map((item) => {
    if (!isObject(item)) throw invalidContract();
    const id = item.id;
    const checkName = item.checkName ?? item.check;
    const outcome = item.outcome;
    const details = item.details;
    if (
      typeof id !== "string" ||
      id.length < 3 ||
      typeof checkName !== "string" ||
      checkName.length < 2 ||
      (outcome !== "pass" && outcome !== "fail") ||
      !isObject(details)
    ) {
      throw invalidContract();
    }
    return { id, checkName, outcome, details: details as JsonObject };
  });
  if ((decision === "pass") !== evidence.every((item) => item.outcome === "pass")) {
    throw invalidContract();
  }
  return {
    decision,
    status,
    evidence,
    ...(isObject(payload.validation)
      ? { validation: payload.validation as JsonObject }
      : {}),
  };
}

function invalidContract(): ApiError {
  return new ApiError(
    502,
    "VALIDATOR_CONTRACT_INVALID",
    "The automatic validation service returned invalid evidence.",
  );
}

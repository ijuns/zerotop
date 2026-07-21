import { createHash } from "node:crypto";

import {
  BLUE_QUESTION_TYPES,
  RED_QUESTION_TYPES,
  type JsonObject,
  type ValidationEvidenceInput,
} from "./types.ts";

interface ValidationResult {
  decision: "pass" | "quarantine";
  status: "validated" | "quarantined";
  evidence: ValidationEvidenceInput[];
}

interface ValidationOptions {
  allowedTargetRegistries?: string[];
  allowTemplateFallback?: boolean;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stableEvidenceId(labId: string, checkName: string): string {
  const digest = createHash("sha256")
    .update(`${labId}:${checkName}`, "utf8")
    .digest("hex")
    .slice(0, 20);
  return `evidence_${digest}`;
}

export function evaluateLab(
  labValue: unknown,
  options: ValidationOptions = {},
): ValidationResult {
  const lab = isObject(labValue) ? labValue : {};
  const labId = typeof lab.id === "string" ? lab.id : "unknown";
  const teamType = lab.team ?? lab.teamType;
  const environment = lab.desktopImage ?? lab.environment;
  const questionTypes = Array.isArray(lab.questionTypes) ? lab.questionTypes : [];
  const config = isObject(lab.config) ? lab.config : {};
  const telemetry = isObject(config.telemetry) ? config.telemetry : {};
  const safety = isObject(config.safety) ? config.safety : {};
  const scenario = isObject(config.scenario) ? config.scenario : {};
  const target = isObject(config.target) ? config.target : {};
  const techniques = Array.isArray(scenario.mitreTechniques)
    ? scenario.mitreTechniques
    : [];

  const evidence: ValidationEvidenceInput[] = [];
  const add = (
    checkName: string,
    passed: boolean,
    details: JsonObject,
  ): void => {
    evidence.push({
      id: stableEvidenceId(labId, checkName),
      checkName,
      outcome: passed ? "pass" : "fail",
      details,
    });
  };

  const questionPolicyPassed =
    teamType === "blue"
      ? questionTypes.length === BLUE_QUESTION_TYPES.length &&
        BLUE_QUESTION_TYPES.every((type) => questionTypes.includes(type))
      : teamType === "red" &&
        questionTypes.length > 0 &&
        questionTypes.every((type) => RED_QUESTION_TYPES.includes(type as never));
  add("question_policy", questionPolicyPassed, {
    teamType,
    selected: questionTypes,
    policy:
      teamType === "blue"
        ? "elk_search + mitre_attack are both required"
        : "red-team question types are allow-listed",
  });

  const expectedEnvironment = teamType === "blue" ? "ubuntu" : "kali";
  add("environment_alignment", environment === expectedEnvironment, {
    expected: expectedEnvironment,
    actual: environment,
  });

  const elkReady =
    teamType !== "blue" ||
    (telemetry.elkEnabled === true &&
      typeof telemetry.indexPattern === "string" &&
      telemetry.indexPattern.length > 0);
  add("elk_readiness", elkReady, {
    required: teamType === "blue",
    elkEnabled: telemetry.elkEnabled === true,
    indexPattern: telemetry.indexPattern ?? null,
  });

  const payloadSafe =
    safety.payloadMasked === true && safety.allowLiveMalware !== true;
  add("payload_safety", payloadSafe, {
    payloadMasked: safety.payloadMasked === true,
    liveMalwareDisabled: safety.allowLiveMalware !== true,
  });

  const attackMappingValid =
    techniques.length > 0 &&
    techniques.every(
      (technique) =>
        typeof technique === "string" && /^T\d{4}(?:\.\d{3})?$/.test(technique),
    );
  add("mitre_attack_mapping", attackMappingValid, {
    techniques,
    format: "MITRE ATT&CK technique IDs",
  });

  const allowedTargetRegistries = (
    options.allowedTargetRegistries ?? ["registry.codegate.internal"]
  ).map((item) => item.trim().toLowerCase());
  const targetIsFallback =
    target.source === "template_fallback" || Object.keys(target).length === 0;
  const imageRef = typeof target.imageRef === "string" ? target.imageRef : "";
  const imageDigest =
    typeof target.imageDigest === "string" ? target.imageDigest : "";
  const registry = imageRef.split("/", 1)[0].toLowerCase();
  const digestPinned = /^sha256:[a-f0-9]{64}$/i.test(imageDigest);
  const referenceValid =
    /^[a-z0-9.-]+(?::\d+)?\/[a-z0-9._/-]+(?::[a-z0-9._-]+)?$/i.test(
      imageRef,
    ) && !imageRef.includes("@");
  const targetApproved = targetIsFallback
    ? options.allowTemplateFallback !== false
    : referenceValid &&
      digestPinned &&
      allowedTargetRegistries.includes(registry);
  add("target_image_policy", targetApproved, {
    source: target.source ?? null,
    registry: registry || null,
    registryAllowed: registry ? allowedTargetRegistries.includes(registry) : false,
    digestPinned,
    templateFallbackAllowed: options.allowTemplateFallback !== false,
  });

  const passed = evidence.every((item) => item.outcome === "pass");
  return {
    decision: passed ? "pass" : "quarantine",
    status: passed ? "validated" : "quarantined",
    evidence,
  };
}

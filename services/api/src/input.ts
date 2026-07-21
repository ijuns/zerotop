import { createHash } from "node:crypto";

import { ApiError } from "./errors.ts";
import {
  ACCESS_METHODS,
  BLUE_QUESTION_TYPES,
  RED_QUESTION_TYPES,
  type AccessMethod,
  type JsonObject,
  type LabAccessMethod,
  type LabGenerationInput,
  type QuestionType,
  type RegistrationInput,
  type TeamType,
} from "./types.ts";
import {
  buildTrainingContent,
  KOREAN_CONTENT_REVISION,
} from "./training-content.ts";
import { buildRedExercise } from "./red-exercise.ts";

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireObject(value: unknown): Record<string, unknown> {
  if (!isObject(value)) {
    throw new ApiError(400, "INVALID_JSON_BODY", "The request body must be a JSON object.");
  }
  return value;
}

function optionalTrimmedString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function generatedRuntimeTopology(
  team: TeamType,
  events: JsonObject[],
  title: string,
  prompt: string,
  scenarioProfile: string,
  cveIds: string[],
  attackTechniqueIds: string[],
): JsonObject {
  if (team === "blue") {
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
        generation: {
          schemaVersion: 1,
          profile: scenarioProfile,
          totalEvents: 1_200,
          timeRangeMinutes: 60,
          seed: createHash("sha256").update(`${title}\n${prompt}`).digest("hex").slice(0, 32),
          timelineAnchor: new Date().toISOString(),
        },
      },
    };
  }
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
      exercise: buildRedExercise({ title, prompt, cveIds, attackTechniqueIds }),
    },
  };
}

export function normalizeRegistration(value: unknown): RegistrationInput {
  const body = requireObject(value);
  const email = optionalTrimmedString(body.email)?.toLowerCase();
  const handle = optionalTrimmedString(body.handle);
  const displayName = optionalTrimmedString(body.displayName ?? body.display_name);
  const password = optionalTrimmedString(body.password);
  const organizationId = optionalTrimmedString(
    body.organizationId ?? body.organization_id,
  );
  const organizationJoinCode = optionalTrimmedString(
    body.organizationJoinCode ?? body.organization_join_code ?? body.joinCode,
  )?.toUpperCase();
  const rawAccountType =
    body.accountType ??
    body.account_type ??
    (organizationId || organizationJoinCode ? "organization" : "personal");

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new ApiError(400, "INVALID_EMAIL", "A valid email address is required.");
  }
  if (!handle || !/^[A-Za-z0-9_-]{3,24}$/.test(handle)) {
    throw new ApiError(
      400,
      "INVALID_HANDLE",
      "Handle must be 3-24 characters using letters, numbers, '_' or '-'.",
    );
  }
  if (!displayName || displayName.length > 80) {
    throw new ApiError(
      400,
      "INVALID_DISPLAY_NAME",
      "Display name is required and must not exceed 80 characters.",
    );
  }
  if (password && password.length < 8) {
    throw new ApiError(
      400,
      "WEAK_PASSWORD",
      "Password must contain at least 8 characters when provided.",
    );
  }
  if (rawAccountType !== "personal" && rawAccountType !== "organization") {
    throw new ApiError(
      400,
      "INVALID_ACCOUNT_TYPE",
      "accountType must be 'personal' or 'organization'.",
    );
  }
  if (rawAccountType === "organization" && !organizationId && !organizationJoinCode) {
    throw new ApiError(
      400,
      "ORGANIZATION_REQUIRED",
      "An organizationId or organizationJoinCode is required to join an organization.",
    );
  }

  return {
    email,
    handle,
    displayName,
    password,
    accountType: rawAccountType,
    organizationId,
    organizationJoinCode,
  };
}

export function normalizeLabGeneration(value: unknown): LabGenerationInput {
  const body = requireObject(value);
  const rawTeamType = body.team ?? body.teamType ?? body.team_type;
  if (rawTeamType !== "blue" && rawTeamType !== "red") {
    throw new ApiError(
      400,
      "INVALID_TEAM_TYPE",
      "teamType must be either 'blue' or 'red'.",
    );
  }
  const teamType: TeamType = rawTeamType;

  const rawQuestionTypes = body.questionTypes ?? body.question_types;
  if (!Array.isArray(rawQuestionTypes) || rawQuestionTypes.length === 0) {
    throw new ApiError(
      400,
      "QUESTION_TYPES_REQUIRED",
      "At least one question type is required.",
    );
  }
  if (!rawQuestionTypes.every((item) => typeof item === "string")) {
    throw new ApiError(
      400,
      "INVALID_QUESTION_TYPES",
      "Every question type must be a string.",
    );
  }

  const questionTypes = [...new Set(rawQuestionTypes)] as QuestionType[];
  if (questionTypes.length !== rawQuestionTypes.length) {
    throw new ApiError(
      400,
      "DUPLICATE_QUESTION_TYPE",
      "Question types must not contain duplicates.",
    );
  }

  if (teamType === "blue") {
    const hasExactBlueSet =
      questionTypes.length === BLUE_QUESTION_TYPES.length &&
      BLUE_QUESTION_TYPES.every((type) => questionTypes.includes(type));
    if (!hasExactBlueSet) {
      throw new ApiError(
        400,
        "INVALID_BLUE_QUESTION_TYPES",
        "Blue-team labs require exactly 'elk_search' and 'mitre_attack'.",
        { allowed: BLUE_QUESTION_TYPES },
      );
    }
  } else if (!questionTypes.every((type) => RED_QUESTION_TYPES.includes(type as never))) {
    throw new ApiError(
      400,
      "INVALID_RED_QUESTION_TYPES",
      "Red-team labs only allow single_choice, multiple_choice, free_text and mitre_attack.",
      { allowed: RED_QUESTION_TYPES },
    );
  }

  const expectedEnvironment = teamType === "blue" ? "ubuntu" : "kali";
  const rawEnvironment =
    body.desktopImage ?? body.desktop_image ?? body.environment;
  if (rawEnvironment === undefined) {
    throw new ApiError(
      400,
      "DESKTOP_IMAGE_REQUIRED",
      "desktopImage is required and must match the selected team.",
      { expected: expectedEnvironment },
    );
  }
  if (rawEnvironment !== expectedEnvironment) {
    throw new ApiError(
      400,
      "ENVIRONMENT_TEAM_MISMATCH",
      `${teamType}-team labs use the ${expectedEnvironment} environment.`,
      { expected: expectedEnvironment },
    );
  }

  const canonicalAccessMethod = body.accessMethod ?? body.access_method;
  const legacyAccessModes = body.accessModes ?? body.access_modes;
  let accessMethod: LabAccessMethod;
  let accessModes: AccessMethod[];
  if (canonicalAccessMethod !== undefined) {
    if (
      canonicalAccessMethod !== "browser_desktop" &&
      canonicalAccessMethod !== "openvpn" &&
      canonicalAccessMethod !== "both"
    ) {
      throw new ApiError(
        400,
        "INVALID_ACCESS_METHOD",
        "accessMethod must be browser_desktop, openvpn or both.",
      );
    }
    accessMethod = canonicalAccessMethod;
    accessModes =
      accessMethod === "both"
        ? [...ACCESS_METHODS]
        : [accessMethod as AccessMethod];
  } else if (Array.isArray(legacyAccessModes)) {
    if (
      legacyAccessModes.length === 0 ||
      !legacyAccessModes.every(
        (item) => typeof item === "string" && ACCESS_METHODS.includes(item as never),
      )
    ) {
      throw new ApiError(
        400,
        "INVALID_ACCESS_MODES",
        "accessModes must contain browser_desktop and/or openvpn.",
        { allowed: ACCESS_METHODS },
      );
    }
    accessModes = [...new Set(legacyAccessModes)] as AccessMethod[];
    accessMethod = accessModes.length === 2 ? "both" : accessModes[0];
  } else {
    throw new ApiError(
      400,
      "ACCESS_METHOD_REQUIRED",
      "accessMethod is required.",
      { allowed: ["browser_desktop", "openvpn", "both"] },
    );
  }

  const difficulty = body.difficulty ?? "intermediate";
  if (!["beginner", "intermediate", "advanced", "expert"].includes(String(difficulty))) {
    throw new ApiError(
      400,
      "INVALID_DIFFICULTY",
      "difficulty must be beginner, intermediate, advanced or expert.",
    );
  }

  const scenario = isObject(body.scenario) ? body.scenario : {};
  const rawTechniques =
    body.mitreTechniques ?? scenario.mitreTechniques ??
    (teamType === "blue" ? ["T1078", "T1059.001"] : ["T1190", "T1059.004"]);
  if (
    !Array.isArray(rawTechniques) ||
    !rawTechniques.every((item) => typeof item === "string")
  ) {
    throw new ApiError(
      400,
      "INVALID_MITRE_TECHNIQUES",
      "mitreTechniques must be an array of technique IDs.",
    );
  }

  const suppliedSafety = isObject(body.safety) ? body.safety : {};
  const suppliedTelemetry = isObject(body.telemetry) ? body.telemetry : {};
  const suppliedTarget = isObject(body.target) ? body.target : null;
  const rawCveIds = body.cveIds ?? body.cve_ids ?? [];
  if (!Array.isArray(rawCveIds) || rawCveIds.length > 20) {
    throw new ApiError(400, "INVALID_CVE_IDS", "cveIds must contain at most 20 CVE identifiers.");
  }
  const cveIds = [...new Set(rawCveIds.map((item) => {
    if (typeof item !== "string" || !/^CVE-\d{4}-\d{4,7}$/i.test(item)) {
      throw new ApiError(400, "INVALID_CVE_IDS", "cveIds contains an invalid CVE identifier.");
    }
    return item.toUpperCase();
  }))];
  const title = optionalTrimmedString(body.title ?? body.name);
  const suppliedPrompt = optionalTrimmedString(body.prompt ?? body.description);
  if (!title || title.length < 3 || title.length > 120) {
    throw new ApiError(
      400,
      "INVALID_TITLE",
      "title is required and must contain 3-120 characters.",
    );
  }
  if (suppliedPrompt && (suppliedPrompt.length < 10 || suppliedPrompt.length > 5000)) {
    throw new ApiError(
      400,
      "INVALID_PROMPT",
      "prompt must contain 10-5000 characters when provided.",
    );
  }
  if (!suppliedPrompt && cveIds.length === 0) {
    throw new ApiError(
      400,
      "PROMPT_OR_CVE_REQUIRED",
      "At least one of prompt or cveIds is required.",
    );
  }
  const prompt = suppliedPrompt ??
    `${cveIds.join(", ")} 취약점의 적용 조건과 영향 범위, 방어 관측 지점을 격리된 환경에서 안전하게 분석합니다.`;
  const generated = buildTrainingContent({
    team: teamType,
    title,
    prompt,
    questionTypes,
    mitreTechniques: rawTechniques as string[],
    cveIds,
  });
  const blueTelemetryEvents = generated.telemetryEvents;

  return {
    title,
    prompt,
    team: teamType,
    questionTypes,
    desktopImage: expectedEnvironment,
    accessMethod,
    accessModes,
    config: {
      generator: { kind: "local-simulator", version: 1 },
      contentRevision: KOREAN_CONTENT_REVISION,
      topology: generatedRuntimeTopology(
        teamType,
        blueTelemetryEvents,
        title,
        prompt,
        generated.scenarioProfile,
        cveIds,
        generated.attackChain.map((item) => item.id),
      ),
      difficulty,
      scenario: {
        ...scenario,
        objective:
          optionalTrimmedString(body.objective ?? scenario.objective) ?? prompt,
        summary: generated.scenarioSummary,
        logSources: generated.logSources,
        mitreTechniques: generated.attackChain.map((item) => item.id),
        attackChain: generated.attackChain,
      },
      learning: generated.learning,
      telemetry: {
        ...suppliedTelemetry,
        elkEnabled:
          suppliedTelemetry.elkEnabled === undefined
            ? teamType === "blue"
            : suppliedTelemetry.elkEnabled,
        indexPattern:
          optionalTrimmedString(suppliedTelemetry.indexPattern) ?? "zerotop-logs-*",
        ...(teamType === "blue" ? { events: blueTelemetryEvents } : {}),
      },
      safety: {
        ...suppliedSafety,
        payloadMasked:
          suppliedSafety.payloadMasked === undefined
            ? true
            : suppliedSafety.payloadMasked,
        allowLiveMalware: suppliedSafety.allowLiveMalware === true,
      },
      target: suppliedTarget
        ? {
            imageRef: optionalTrimmedString(suppliedTarget.imageRef) ?? null,
            imageDigest: optionalTrimmedString(suppliedTarget.imageDigest) ?? null,
            expectedCves: cveIds,
            source: "lab_spec",
          }
        : {
            imageRef: null,
            imageDigest: null,
            expectedCves: cveIds,
            source: "template_fallback",
          },
      questions: generated.publicQuestions,
    },
    gradingQuestions: generated.gradingQuestions,
    cveIds,
  };
}

export function normalizeAccessMethod(value: unknown): LabAccessMethod {
  const body = requireObject(value);
  const method = body.accessMethod ?? body.access_method;
  if (
    method !== "browser_desktop" &&
    method !== "openvpn" &&
    method !== "both"
  ) {
    throw new ApiError(
      400,
      "INVALID_ACCESS_METHOD",
      "accessMethod must be 'browser_desktop', 'openvpn' or 'both'.",
      { allowed: [...ACCESS_METHODS, "both"] },
    );
  }
  return method;
}

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

function generatedQuestions(
  teamType: TeamType,
  questionTypes: QuestionType[],
  mitreTechniques: string[],
): { publicQuestions: JsonObject[]; gradingQuestions: JsonObject[] } {
  const prompts: Record<QuestionType, string> = {
    elk_search: "Use the ELK evidence to identify the first suspicious source address.",
    single_choice: "Select the action that best advances the attack scenario.",
    multiple_choice: "Select every artifact produced by the simulated attack.",
    free_text: "Explain the attack path and the evidence supporting your conclusion.",
    mitre_attack: "Map the observed behavior to the correct MITRE ATT&CK technique.",
  };

  const gradingQuestions: JsonObject[] = [];
  const publicQuestions = questionTypes.map((type, index) => {
    const id = `${teamType}-q${index + 1}`;
    const points = type === "mitre_attack" ? 20 : 30;
    const options =
      type === "single_choice"
        ? [
            { id: "option-a", label: "Enumerate the exposed service safely" },
            { id: "option-b", label: "Disable all audit telemetry" },
            { id: "option-c", label: "Run an unscoped destructive payload" },
          ]
        : type === "multiple_choice"
          ? [
              { id: "artifact-a", label: "Process execution event" },
              { id: "artifact-b", label: "Authentication event" },
              { id: "artifact-c", label: "Unrelated marketing cookie" },
            ]
          : undefined;
    const answerKey =
      type === "single_choice"
        ? { optionIds: ["option-a"] }
        : type === "multiple_choice"
          ? { optionIds: ["artifact-a", "artifact-b"] }
          : type === "mitre_attack"
            ? { techniqueIds: [mitreTechniques[0]] }
            : type === "elk_search"
              ? { expectedEvidenceIds: [`${id}-elk-evidence`] }
              : { rubricId: `${id}-analysis-rubric-v1` };
    gradingQuestions.push({ id, type, points, answerKey });
    return {
      id,
      type,
      prompt: prompts[type],
      points,
      ...(options ? { options } : {}),
    };
  });
  return { publicQuestions, gradingQuestions };
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
  const prompt = optionalTrimmedString(body.prompt ?? body.description);
  if (!title || title.length < 3 || title.length > 120) {
    throw new ApiError(
      400,
      "INVALID_TITLE",
      "title is required and must contain 3-120 characters.",
    );
  }
  if (!prompt || prompt.length < 10 || prompt.length > 5000) {
    throw new ApiError(
      400,
      "INVALID_PROMPT",
      "prompt is required and must contain 10-5000 characters.",
    );
  }
  const generated = generatedQuestions(
    teamType,
    questionTypes,
    rawTechniques as string[],
  );

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
      difficulty,
      scenario: {
        ...scenario,
        objective:
          optionalTrimmedString(body.objective ?? scenario.objective) ?? prompt,
        mitreTechniques: rawTechniques,
      },
      learning: {
        title,
        summary: "격리된 실습 환경에서 공격 조건, 관찰 증거와 완화 절차를 순서대로 학습합니다.",
        prerequisites: ["TCP/IP 기초", "Linux 명령행 기초"],
        objectives: [
          "대상 서비스의 공격 표면과 취약 조건을 식별합니다.",
          "관찰한 증거를 MITRE ATT&CK 기법에 연결합니다.",
          "탐지 및 완화 방안을 근거와 함께 설명합니다.",
        ],
        sections: [
          {
            id: "scenario-context",
            title: "위협 시나리오와 영향 범위",
            bodyMarkdown: `## ${title}\n\n${prompt}\n\n외부 시스템이 아닌 제공된 격리 대상만 분석합니다.`,
          },
          {
            id: "investigation-workflow",
            title: "분석 및 검증 절차",
            bodyMarkdown:
              "서비스 노출 조건을 확인하고, 실행·인증·네트워크 증거를 시간순으로 정리한 뒤 ATT&CK 기법, 탐지 지점과 완화 조치를 함께 기록합니다.",
          },
        ],
      },
      telemetry: {
        ...suppliedTelemetry,
        elkEnabled:
          suppliedTelemetry.elkEnabled === undefined
            ? teamType === "blue"
            : suppliedTelemetry.elkEnabled,
        indexPattern:
          optionalTrimmedString(suppliedTelemetry.indexPattern) ?? "codegate-logs-*",
        ...(teamType === "blue"
          ? {
              events: [
                {
                  id: "blue-q1-elk-evidence",
                  document: {
                    "@timestamp": new Date().toISOString(),
                    message:
                      "suspicious PowerShell process execution after anomalous authentication",
                    event: {
                      id: "blue-q1-elk-evidence",
                      category: "process",
                      dataset: "codegate.endpoint",
                    },
                    source: { ip: "192.0.2.44" },
                    process: { name: "powershell.exe" },
                    threat: { technique: { id: [String(rawTechniques[0])] } },
                  },
                },
              ],
            }
          : {}),
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

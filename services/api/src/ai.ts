import { ApiError } from "./errors.ts";
import type { AiLabGenerator } from "./ports.ts";
import type { JsonObject, LabGenerationInput } from "./types.ts";
import { parseTargetRuntimeContract } from "./target-runtime-contract.ts";
import { longRunningServiceFetch } from "./service-fetch.ts";

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const DEFAULT_AI_GENERATION_TIMEOUT_MS = 1_260_000;
const MIN_AI_GENERATION_TIMEOUT_MS = 30_000;
const MAX_AI_GENERATION_TIMEOUT_MS = 1_800_000;
const MAX_AI_DIAGNOSTIC_TIMEOUT_MS = 1_800_000;
const AI_VALIDATION_TIMEOUT_MS = 20_000;

interface SafeAiServiceFailure {
  status: number;
  code: string;
  message: string;
  reason: string;
}

/**
 * Translate only explicitly allow-listed AI-service failures.
 *
 * The AI service can include provider responses and configuration diagnostics in
 * its exception chain. Never forward an arbitrary upstream detail to the public
 * API: callers receive a stable Korean message and a bounded reason identifier.
 */
function safeAiServiceFailure(
  upstreamStatus: number,
  payload: unknown,
): SafeAiServiceFailure | null {
  const detail = aiServiceFailureMessage(payload);
  const debug = safeAiServiceDebug(payload);

  if (
    debug?.upstreamCode === "model_provider_timeout"
    || debug?.upstreamCode === "generation_provider_timeout"
  ) {
    return {
      status: 504,
      code: "AI_PROVIDER_TIMEOUT",
      message: "Claude 응답 대기 시간이 설정된 제한을 초과했습니다.",
      reason: "provider_timeout",
    };
  }

  if (detail === "External CVE generation requires a non-empty curated package or artifact catalog") {
    return {
      status: 409,
      code: "AI_CVE_CATALOG_EMPTY",
      message: "요청한 CVE Lab을 생성할 검증된 패키지 또는 아티팩트가 아직 등록되지 않았습니다. CVE 입력을 비우고 일반 시나리오로 생성하거나 관리자에게 CVE 카탈로그 등록을 요청해 주세요.",
      reason: "cve_catalog_empty",
    };
  }
  if (
    detail === "AI_GENERATION_MODE is invalid"
    || detail === "External generation provider is not configured"
    || detail === "GENERATION_PROVIDER_URL must use HTTPS"
  ) {
    return {
      status: 503,
      code: "AI_GENERATION_NOT_CONFIGURED",
      message: "AI Lab 생성 서비스 설정이 완료되지 않았습니다. 관리자에게 Claude 연결 및 생성 모드 설정을 확인해 달라고 요청해 주세요.",
      reason: "generation_not_configured",
    };
  }
  if (
    detail === "AI_AUTH_MODE is invalid"
    || detail === "AI service authentication is not configured"
    || detail === "Invalid internal service token"
  ) {
    return {
      status: 503,
      code: "AI_SERVICE_AUTH_FAILED",
      message: "AI 내부 서비스 인증 설정이 일치하지 않습니다. 관리자에게 서비스 토큰 설정을 확인해 달라고 요청해 주세요.",
      reason: "service_auth_failed",
    };
  }
  if (detail.startsWith("External generation build catalog is invalid:")) {
    return {
      status: 503,
      code: "AI_BUILD_CATALOG_INVALID",
      message: "AI Lab 빌드 카탈로그 설정이 올바르지 않습니다. 관리자에게 기본 이미지와 출력 저장소 설정을 확인해 달라고 요청해 주세요.",
      reason: "build_catalog_invalid",
    };
  }
  if (
    detail === "CVE IDs must be unique and contain at most 20 entries"
    || detail.startsWith("CVE intelligence request is invalid:")
  ) {
    return {
      status: 422,
      code: "AI_CVE_REQUEST_INVALID",
      message: "CVE ID 형식 또는 개수가 올바르지 않습니다. 중복 없이 CVE-YYYY-NNNN 형식으로 최대 20개까지 입력해 주세요.",
      reason: "cve_request_invalid",
    };
  }
  if (
    detail.startsWith("CVE intelligence lookup failed for ")
    || detail.startsWith("CVE intelligence lookup did not match ")
    || detail.startsWith("CVE intelligence record exceeded the provider input limit for ")
    || detail === "CVE intelligence exceeded the provider input limit"
  ) {
    return {
      status: upstreamStatus === 422 ? 422 : 503,
      code: upstreamStatus === 422
        ? "AI_CVE_NOT_AVAILABLE"
        : "AI_CVE_INTELLIGENCE_UNAVAILABLE",
      message: upstreamStatus === 422
        ? "입력한 CVE 정보를 확인할 수 없습니다. CVE ID를 다시 확인해 주세요."
        : "현재 CVE 정보를 조회할 수 없습니다. 잠시 후 다시 시도해 주세요.",
      reason: upstreamStatus === 422
        ? "cve_not_available"
        : "cve_intelligence_unavailable",
    };
  }
  if (detail === "Generation provider is unavailable") {
    return {
      status: 503,
      code: "AI_PROVIDER_UNAVAILABLE",
      message: "Claude 생성 서비스에 일시적으로 연결할 수 없습니다. 잠시 후 다시 시도해 주세요.",
      reason: "provider_unavailable",
    };
  }
  const providerStatus = /^Generation provider returned HTTP (\d{3})(?::|$)/.exec(detail);
  if (providerStatus) {
    const status = Number(providerStatus[1]);
    if (status === 401 || status === 403) {
      return {
        status: 503,
        code: "AI_PROVIDER_AUTH_FAILED",
        message: "Claude API 인증에 실패했습니다. 관리자에게 API 키 설정을 확인해 달라고 요청해 주세요.",
        reason: "provider_auth_failed",
      };
    }
    if (status === 429) {
      return {
        status: 503,
        code: "AI_PROVIDER_RATE_LIMITED",
        message: "Claude API 요청 한도에 도달했습니다. 잠시 후 다시 시도해 주세요.",
        reason: "provider_rate_limited",
      };
    }
    if (status >= 500 && status <= 599) {
      return {
        status: 503,
        code: "AI_PROVIDER_UNAVAILABLE",
        message: "Claude 생성 서비스가 요청을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.",
        reason: "provider_unavailable",
      };
    }
  }
  if (
    detail === "Generation provider response was too large"
    || detail === "Generation provider returned malformed JSON"
    || detail === "Generation provider returned an invalid object"
    || detail === "Generation provider returned a quarantined LabSpec"
    || detail.startsWith("Generation provider changed the requested ")
    || detail.startsWith("Generation provider content contract failed:")
    || detail.startsWith("Generation provider build catalog check failed:")
  ) {
    return {
      status: 502,
      code: "AI_GENERATED_LAB_REJECTED",
      message: "AI가 생성한 Lab이 안전성 또는 구성 검사를 통과하지 못했습니다. 조건을 조금 더 구체적으로 작성해 다시 시도해 주세요.",
      reason: "generated_lab_rejected",
    };
  }
  return null;
}

function aiServiceFailureMessage(payload: unknown): string {
  if (!isObject(payload)) return "";
  if (typeof payload.detail === "string") return payload.detail;
  if (isObject(payload.detail) && typeof payload.detail.message === "string") {
    return payload.detail.message;
  }
  return "";
}

function safeAiServiceDebug(payload: unknown): Record<string, string | number> | null {
  if (!isObject(payload) || !isObject(payload.detail) || !isObject(payload.detail.debug)) {
    return null;
  }
  const source = payload.detail.debug;
  const result: Record<string, string | number> = {};
  const identifiers = [
    "stage",
    "providerStage",
    "upstreamCode",
    "providerErrorType",
    "providerRequestId",
    "providerResponseId",
    "payloadDigest",
    "parseKind",
  ] as const;
  for (const key of identifiers) {
    const value = safeDiagnosticIdentifier(source[key], key === "providerRequestId" ? 200 : 128);
    if (value) result[key] = value;
  }
  for (const key of [
    "upstreamStatus",
    "providerStatus",
    "timeoutMs",
    "generationAttempts",
    "payloadBytes",
    "parseOffset",
  ] as const) {
    const value = source[key];
    if (
      typeof value === "number"
      && Number.isSafeInteger(value)
      && value >= 0
      && value <= MAX_AI_DIAGNOSTIC_TIMEOUT_MS
    ) {
      result[key] = value;
    }
  }
  for (const key of ["upstreamMessage", "providerMessage"] as const) {
    const value = safeDiagnosticMessage(source[key], 1_000);
    if (value) result[key] = value;
  }
  if (typeof result.upstreamStatus === "number") result.status = result.upstreamStatus;
  if (typeof result.upstreamCode === "string") result.code = result.upstreamCode;
  return Object.keys(result).length > 0 ? result : null;
}

function safeDiagnosticIdentifier(value: unknown, maximum: number): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) return null;
  return /^[A-Za-z0-9._:-]+$/.test(value) ? value : null;
}

function safeDiagnosticMessage(value: unknown, maximum: number): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) return null;
  const sanitized = value
    .replace(/sk-(?:ant|proj|svcacct)-[A-Za-z0-9_-]+/gi, "[REDACTED]")
    .replace(/Bearer\s+[^\s,;]+/gi, "Bearer [REDACTED]")
    .replace(/[\r\n\t]+/g, " ")
    .trim();
  return sanitized || null;
}

function isRequestTimeout(value: unknown): boolean {
  return value instanceof Error && (value.name === "TimeoutError" || value.name === "AbortError");
}

export function aiGenerationTimeoutFromEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): number {
  const raw = environment.AI_GENERATION_TIMEOUT_MS;
  if (raw === undefined || raw === "") return DEFAULT_AI_GENERATION_TIMEOUT_MS;
  if (!/^\d+$/.test(raw)) {
    throw new Error("AI_GENERATION_TIMEOUT_MS must be an integer in milliseconds.");
  }
  return validateAiGenerationTimeout(Number(raw));
}

function validateAiGenerationTimeout(value: number): number {
  if (
    !Number.isSafeInteger(value)
    || value < MIN_AI_GENERATION_TIMEOUT_MS
    || value > MAX_AI_GENERATION_TIMEOUT_MS
  ) {
    throw new Error(
      `AI_GENERATION_TIMEOUT_MS must be ${MIN_AI_GENERATION_TIMEOUT_MS}-${MAX_AI_GENERATION_TIMEOUT_MS}.`,
    );
  }
  return value;
}

export class DevelopmentLocalLabGenerator implements AiLabGenerator {
  generate(input: LabGenerationInput): LabGenerationInput {
    return input;
  }
}

interface HttpAiLabGeneratorOptions {
  serviceUrl: string;
  internalToken: string;
  fetchImpl?: typeof fetch;
  generationTimeoutMs?: number;
  timeoutSignalFactory?: (timeoutMs: number) => AbortSignal;
  exposeDebugErrors?: boolean;
}

/** Production adapter for AI draft generation and deterministic AI-side validation. */
export class HttpAiLabGenerator implements AiLabGenerator {
  private readonly serviceUrl: string;
  private readonly internalToken: string;
  private readonly fetchImpl: typeof fetch;
  private readonly generationTimeoutMs: number;
  private readonly timeoutSignalFactory: (timeoutMs: number) => AbortSignal;
  private readonly exposeDebugErrors: boolean;

  constructor(options: HttpAiLabGeneratorOptions) {
    if (!options.serviceUrl || !options.internalToken) {
      throw new Error("AI service URL and internal token are required.");
    }
    this.serviceUrl = options.serviceUrl.replace(/\/$/, "");
    this.internalToken = options.internalToken;
    this.fetchImpl = options.fetchImpl ?? longRunningServiceFetch;
    this.generationTimeoutMs = validateAiGenerationTimeout(
      options.generationTimeoutMs ?? DEFAULT_AI_GENERATION_TIMEOUT_MS,
    );
    this.timeoutSignalFactory =
      options.timeoutSignalFactory ?? ((timeoutMs) => AbortSignal.timeout(timeoutMs));
    this.exposeDebugErrors = options.exposeDebugErrors === true;
  }

  async generate(input: LabGenerationInput): Promise<LabGenerationInput> {
    const draft = await this.request(
      "/v1/drafts/generate",
      {
        title: input.title,
        prompt: input.prompt,
        team: input.team,
        desktopImage: input.desktopImage,
        accessMethod: input.accessMethod,
        questionTypes: input.questionTypes,
        cveIds: input.cveIds,
      },
      this.generationTimeoutMs,
    );
    const validatedDraft = validateAiDraft(draft, input);
    const aiValidation = await this.request(
      "/v1/validate",
      { lab: draft },
      AI_VALIDATION_TIMEOUT_MS,
    );
    if (
      !isObject(aiValidation) ||
      (aiValidation.decision !== "pass" && aiValidation.decision !== "quarantine")
    ) {
      throw new ApiError(
        502,
        "AI_VALIDATION_CONTRACT_INVALID",
        "The AI service returned an invalid validation result.",
      );
    }
    if (aiValidation.decision !== "pass") {
      throw new ApiError(
        422,
        "AI_DRAFT_QUARANTINED",
        "The AI service quarantined the generated LabSpec.",
      );
    }

    const config = { ...input.config };
    const currentScenario = isObject(config.scenario) ? config.scenario : {};
    return {
      ...input,
      title: validatedDraft.title,
      prompt: validatedDraft.prompt,
      config: {
        ...config,
        generator: { kind: "ai-service", version: 1 },
        scenario: {
          ...currentScenario,
          objective: validatedDraft.scenario.summary,
          summary: validatedDraft.scenario.summary,
          logSources: validatedDraft.scenario.logSources,
          attackChain: validatedDraft.scenario.attackChain,
          mitreTechniques: validatedDraft.scenario.attackChain.map((item) => item.id),
        },
        learning: validatedDraft.learning,
        questions: validatedDraft.questions,
        topology: validatedDraft.topology,
        builder: { status: "not_started", schemaVersion: 1 },
        aiGeneration: {
          serviceLabId: validatedDraft.id,
          serviceVersion: validatedDraft.version,
          validation: aiValidation,
        },
      },
      gradingQuestions: validatedDraft.gradingQuestions,
      buildSpec: validatedDraft.environmentBuildSpec,
    };
  }

  private async request(
    path: string,
    body: unknown,
    timeoutMs: number,
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.serviceUrl}${path}`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.internalToken}`,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify(body),
        signal: this.timeoutSignalFactory(timeoutMs),
      });
    } catch (error) {
      if (isRequestTimeout(error)) {
        throw new ApiError(
          504,
          "AI_SERVICE_TIMEOUT",
          "AI 생성 서비스의 전체 응답 대기 시간이 설정된 제한을 초과했습니다.",
          {
            reason: "api_timeout",
            ...(this.exposeDebugErrors
              ? {
                  debug: {
                    status: 504,
                    code: "AI_SERVICE_TIMEOUT",
                    stage: "api",
                    timeoutMs,
                  },
                }
              : {}),
          },
        );
      }
      throw new ApiError(
        503,
        "AI_SERVICE_UNAVAILABLE",
        "The AI generation service is unavailable.",
      );
    }
    const payload = (await response.json().catch(() => null)) as unknown;
    if (!response.ok) {
      const debug = safeAiServiceDebug(payload);
      const safeFailure = safeAiServiceFailure(response.status, payload);
      if (safeFailure) {
        throw new ApiError(
          safeFailure.status,
          safeFailure.code,
          safeFailure.message,
          {
            upstreamStatus: response.status,
            reason: safeFailure.reason,
            ...(this.exposeDebugErrors && debug ? { debug } : {}),
          },
        );
      }
      throw new ApiError(
        502,
        "AI_SERVICE_REJECTED_REQUEST",
        "AI Lab 생성 서비스가 요청을 처리하지 못했습니다. 잠시 후 다시 시도하거나 관리자에게 서비스 상태 확인을 요청해 주세요.",
        {
          upstreamStatus: response.status,
          reason: "unclassified_rejection",
          ...(this.exposeDebugErrors && debug ? { debug } : {}),
        },
      );
    }
    return payload;
  }
}

interface ValidatedAiDraft {
  id: string;
  version: number;
  title: string;
  prompt: string;
  scenario: {
    summary: string;
    logSources: string[];
    attackChain: Array<{ id: string; name: string; tactic: string }>;
  };
  learning: JsonObject;
  questions: JsonObject[];
  gradingQuestions: JsonObject[];
  environmentBuildSpec: JsonObject;
  topology: JsonObject;
}

function validateAiDraft(
  value: unknown,
  request: LabGenerationInput,
): ValidatedAiDraft {
  if (!isObject(value)) return invalidDraft();
  const network = isObject(value.network) ? value.network : {};
  const scenario = isObject(value.scenario) ? value.scenario : {};
  const safety = isObject(value.safety) ? value.safety : {};
  const questionTypes = Array.isArray(value.questionTypes)
    ? value.questionTypes
    : [];
  const logSources = Array.isArray(scenario.logSources)
    ? scenario.logSources.filter((item): item is string => typeof item === "string")
    : [];
  const attackChain = Array.isArray(scenario.attackChain)
    ? scenario.attackChain.filter(isObject)
    : [];
  const validAttackChain =
    attackChain.length > 0 &&
    attackChain.every(
      (item) =>
        typeof item.id === "string" &&
        /^T\d{4}(?:\.\d{3})?$/.test(item.id) &&
        typeof item.name === "string" &&
        typeof item.tactic === "string",
    );
  const sameQuestions =
    questionTypes.length === request.questionTypes.length &&
    request.questionTypes.every((item) => questionTypes.includes(item));
  if (
    typeof value.id !== "string" ||
    value.id.length < 3 ||
    value.version !== 1 ||
    typeof value.title !== "string" ||
    value.title.length < 3 ||
    typeof value.prompt !== "string" ||
    value.prompt.length < 10 ||
    value.team !== request.team ||
    value.desktopImage !== request.desktopImage ||
    value.accessMethod !== request.accessMethod ||
    !sameQuestions ||
    network.egress !== "deny" ||
    network.isolation !== "per_run" ||
    typeof scenario.summary !== "string" ||
    scenario.summary.length === 0 ||
    (request.team === "blue" && logSources.length < 4) ||
    !validAttackChain ||
    safety.weaponizedPayloads !== "forbidden" ||
    safety.externalTargets !== "forbidden"
  ) {
    return invalidDraft();
  }

  const learning = validateLearning(value.learning);
  const { publicQuestions, gradingQuestions } = validateGeneratedQuestions(
    value.questions,
    value.gradingQuestions,
    request,
  );
  const environmentBuildSpec = validateBuildSpec(
    value.environmentBuildSpec,
    request,
    learning,
    publicQuestions,
    { summary: scenario.summary, attackChain: attackChain as JsonObject[] },
  );
  const topology = validateOrCreateTopology(
    value.topology ?? environmentBuildSpec.topology,
    request,
    environmentBuildSpec,
  );

  return {
    id: value.id,
    version: 1,
    title: value.title,
    prompt: value.prompt,
    scenario: {
      summary: scenario.summary,
      logSources,
      attackChain: attackChain as Array<{ id: string; name: string; tactic: string }>,
    },
    learning,
    questions: publicQuestions,
    gradingQuestions,
    environmentBuildSpec: { ...environmentBuildSpec, topology },
    topology,
  };
}

function validateOrCreateTopology(
  value: unknown,
  request: LabGenerationInput,
  buildSpec: JsonObject,
): JsonObject {
  const telemetry = isObject(buildSpec.telemetry) ? buildSpec.telemetry : {};
  const events = Array.isArray(telemetry.events) ? telemetry.events : [];
  const fallback: JsonObject = request.team === "blue"
    ? {
        schemaVersion: 1,
        team: "blue",
        isolation: "per_run",
        workstation: { role: "soc_analyst", desktopImage: "ubuntu", entrypoint: "kibana" },
        target: { role: "monitored_target", hostname: "target" },
        telemetry: {
          stack: "elastic",
          collector: "elastic_agent",
          generator: "scenario_log_generator",
          index: "zerotop-logs-*",
          events,
        },
      }
    : {
        schemaVersion: 1,
        team: "red",
        isolation: "per_run",
        workstation: { role: "attack_operator", desktopImage: "kali", entrypoint: "target" },
        target: { role: "vulnerable_target", hostname: "target" },
      };
  const topology = value === undefined ? fallback : value;
  if (!isObject(topology) || topology.schemaVersion !== 1 || topology.team !== request.team || topology.isolation !== "per_run") {
    return invalidDraft();
  }
  const workstation = isObject(topology.workstation) ? topology.workstation : {};
  const target = isObject(topology.target) ? topology.target : {};
  const blue = request.team === "blue";
  if (
    workstation.role !== (blue ? "soc_analyst" : "attack_operator")
    || workstation.desktopImage !== (blue ? "ubuntu" : "kali")
    || workstation.entrypoint !== (blue ? "kibana" : "target")
    || target.role !== (blue ? "monitored_target" : "vulnerable_target")
    || target.hostname !== "target"
  ) return invalidDraft();
  if (!blue) {
    if (topology.telemetry !== undefined) return invalidDraft();
    return fallback;
  }
  const topologyTelemetry = isObject(topology.telemetry) ? topology.telemetry : {};
  if (
    topologyTelemetry.stack !== "elastic"
    || topologyTelemetry.collector !== "elastic_agent"
    || topologyTelemetry.generator !== "scenario_log_generator"
    || typeof topologyTelemetry.index !== "string"
    || !/^[a-z0-9][a-z0-9._-]{0,126}-\*$/.test(topologyTelemetry.index)
    || !Array.isArray(topologyTelemetry.events)
    || JSON.stringify(topologyTelemetry.events) !== JSON.stringify(events)
  ) return invalidDraft();
  return topology as JsonObject;
}

function validateLearning(value: unknown): JsonObject {
  if (!isObject(value) || !Array.isArray(value.sections) || value.sections.length < 2 || value.sections.length > 12) {
    return invalidDraft();
  }
  const sections = value.sections.map((item) => {
    if (!isObject(item) || typeof item.id !== "string" || typeof item.title !== "string" || typeof item.bodyMarkdown !== "string") {
      return invalidDraft();
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/.test(item.id) || item.title.length < 3 || item.title.length > 120 || item.bodyMarkdown.length < 20 || item.bodyMarkdown.length > 20_000) {
      return invalidDraft();
    }
    return { id: item.id, title: item.title, bodyMarkdown: item.bodyMarkdown };
  });
  return {
    ...(typeof value.title === "string" ? { title: value.title } : {}),
    ...(typeof value.summary === "string" ? { summary: value.summary } : {}),
    ...(Array.isArray(value.prerequisites) ? { prerequisites: value.prerequisites.filter((item): item is string => typeof item === "string") } : {}),
    ...(Array.isArray(value.objectives) ? { objectives: value.objectives.filter((item): item is string => typeof item === "string") } : {}),
    sections,
  };
}

function validateGeneratedQuestions(
  publicValue: unknown,
  gradingValue: unknown,
  request: LabGenerationInput,
): { publicQuestions: JsonObject[]; gradingQuestions: JsonObject[] } {
  if (!Array.isArray(publicValue) || !Array.isArray(gradingValue) || publicValue.length < request.questionTypes.length || publicValue.length > 20 || gradingValue.length !== publicValue.length) {
    return invalidDraft();
  }
  const byId = new Map<string, JsonObject>();
  const types = new Set<string>();
  const publicQuestions = publicValue.map((item) => {
    if (!isObject(item) || typeof item.id !== "string" || typeof item.type !== "string" || typeof item.prompt !== "string" || !Number.isInteger(item.points)) return invalidDraft();
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(item.id) || !request.questionTypes.includes(item.type as never) || item.prompt.length < 10 || item.prompt.length > 2_000 || Number(item.points) < 1) return invalidDraft();
    if (["answer", "answerKey", "correctOption", "solution", "flag"].some((key) => key in item)) return invalidDraft();
    const question: JsonObject = { id: item.id, type: item.type, prompt: item.prompt, points: item.points };
    if (item.type === "single_choice" || item.type === "multiple_choice") {
      if (!Array.isArray(item.options) || item.options.length < 2 || item.options.length > 8) return invalidDraft();
      question.options = item.options.map((option) => {
        if (!isObject(option) || typeof option.id !== "string" || typeof option.label !== "string") return invalidDraft();
        return { id: option.id, label: option.label };
      });
    }
    if (byId.has(item.id)) return invalidDraft();
    byId.set(item.id, question);
    types.add(item.type);
    return question;
  });
  if (!request.questionTypes.every((type) => types.has(type))) return invalidDraft();
  const gradingQuestions = gradingValue.map((item) => {
    if (!isObject(item) || typeof item.id !== "string" || typeof item.type !== "string" || !Number.isInteger(item.points) || !isObject(item.answerKey)) return invalidDraft();
    const publicQuestion = byId.get(item.id);
    if (!publicQuestion || publicQuestion.type !== item.type || publicQuestion.points !== item.points) return invalidDraft();
    return { id: item.id, type: item.type, points: item.points, answerKey: item.answerKey };
  });
  if (new Set(gradingQuestions.map((item) => String(item.id))).size !== publicQuestions.length) return invalidDraft();
  return { publicQuestions, gradingQuestions };
}

function validateBuildSpec(
  value: unknown,
  request: LabGenerationInput,
  learning: JsonObject,
  questions: JsonObject[],
  scenario: { summary: unknown; attackChain: JsonObject[] },
): JsonObject {
  if (!isObject(value) || value.schemaVersion !== 1 || value.team !== request.team || !isObject(value.source) || !isObject(value.target)) return invalidDraft();
  const target = value.target;
  if (typeof target.baseImage !== "string" || !/@sha256:[a-f0-9]{64}$/i.test(target.baseImage) || typeof target.outputRepository !== "string" || !isObject(target.service)) return invalidDraft();
  const runtimeContract = parseTargetRuntimeContract(target.runtimeContract);
  if (
    !runtimeContract
    || target.service.port !== runtimeContract.port
    || target.service.protocol !== runtimeContract.protocol
  ) return invalidDraft();
  if (typeof learning.title !== "string" || typeof learning.summary !== "string" || !Array.isArray(learning.sections)) return invalidDraft();
  const expectedBuildLearning = {
    title: learning.title,
    summary: learning.summary,
    sections: learning.sections.map((section) => {
      if (!isObject(section) || typeof section.id !== "string" || typeof section.title !== "string" || typeof section.bodyMarkdown !== "string") return invalidDraft();
      return { id: section.id, title: section.title, markdown: section.bodyMarkdown };
    }),
  };
  const expectedBuildScenario = {
    summary: scenario.summary,
    mitreTechniques: scenario.attackChain.map((item) => item.id),
  };
  if (JSON.stringify(value.learning) !== JSON.stringify(expectedBuildLearning) || JSON.stringify(value.questions) !== JSON.stringify(questions) || JSON.stringify(value.scenario) !== JSON.stringify(expectedBuildScenario)) return invalidDraft();
  if (!isObject(value.grading) || !Array.isArray(value.grading.hiddenRefs) || value.grading.hiddenRefs.length !== questions.length) return invalidDraft();
  const questionIds = new Set(questions.map((question) => question.id));
  const gradingIds = new Set<unknown>();
  for (const ref of value.grading.hiddenRefs) {
    if (!isObject(ref) || Object.keys(ref).sort().join(",") !== "questionId,refId,rubricDigest" || !questionIds.has(ref.questionId) || typeof ref.refId !== "string" || !/^grading:\/\/[A-Za-z0-9][A-Za-z0-9._:/-]{0,190}$/.test(ref.refId) || typeof ref.rubricDigest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(ref.rubricDigest)) return invalidDraft();
    gradingIds.add(ref.questionId);
  }
  if (gradingIds.size !== questions.length) return invalidDraft();
  if (!Array.isArray(target.functionalProbes) || target.functionalProbes.length < 1 || !Array.isArray(target.vulnerabilityProbes) || target.vulnerabilityProbes.length < 1) return invalidDraft();
  return value;
}

function invalidDraft(): never {
  throw new ApiError(
    502,
    "AI_LAB_CONTRACT_INVALID",
    "The AI service returned a LabSpec that failed the server contract.",
  );
}

import { ApiError } from "./errors.ts";
import type { AiLabGenerator } from "./ports.ts";
import type { JsonObject, LabGenerationInput } from "./types.ts";
import { parseTargetRuntimeContract } from "./target-runtime-contract.ts";

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const DEFAULT_AI_GENERATION_TIMEOUT_MS = 90_000;
const MIN_AI_GENERATION_TIMEOUT_MS = 30_000;
const MAX_AI_GENERATION_TIMEOUT_MS = 180_000;
const AI_VALIDATION_TIMEOUT_MS = 20_000;

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
}

/** Production adapter for AI draft generation and deterministic AI-side validation. */
export class HttpAiLabGenerator implements AiLabGenerator {
  private readonly serviceUrl: string;
  private readonly internalToken: string;
  private readonly fetchImpl: typeof fetch;
  private readonly generationTimeoutMs: number;
  private readonly timeoutSignalFactory: (timeoutMs: number) => AbortSignal;

  constructor(options: HttpAiLabGeneratorOptions) {
    if (!options.serviceUrl || !options.internalToken) {
      throw new Error("AI service URL and internal token are required.");
    }
    this.serviceUrl = options.serviceUrl.replace(/\/$/, "");
    this.internalToken = options.internalToken;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.generationTimeoutMs = validateAiGenerationTimeout(
      options.generationTimeoutMs ?? DEFAULT_AI_GENERATION_TIMEOUT_MS,
    );
    this.timeoutSignalFactory =
      options.timeoutSignalFactory ?? ((timeoutMs) => AbortSignal.timeout(timeoutMs));
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
    } catch {
      throw new ApiError(
        503,
        "AI_SERVICE_UNAVAILABLE",
        "The AI generation service is unavailable.",
      );
    }
    const payload = (await response.json().catch(() => null)) as unknown;
    if (!response.ok) {
      throw new ApiError(
        502,
        "AI_SERVICE_REJECTED_REQUEST",
        "The AI service rejected the Lab generation request.",
        { status: response.status },
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
    environmentBuildSpec,
  };
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

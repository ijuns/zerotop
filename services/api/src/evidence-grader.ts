import type {
  ServerQuestion,
  TrustedGradeEvidence,
} from "@codegate/grading";

import { ApiError, RepositoryError } from "./errors.ts";
import type { EvidenceGradeRequest, EvidenceGrader } from "./ports.ts";

type JsonRecord = Record<string, unknown>;

function isObject(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Explicit development adapter. It evaluates only server-owned Lab fixtures and
 * is rejected when OIDC production mode is enabled.
 */
export class DevelopmentEvidenceGrader implements EvidenceGrader {
  grade(input: EvidenceGradeRequest): TrustedGradeEvidence[] {
    const runId = isObject(input.run) && typeof input.run.id === "string"
      ? input.run.id
      : "development-run";
    const answers = new Map(input.answers.map((answer) => [answer.questionId, answer.response]));
    const telemetryIds = developmentTelemetryIds(input.lab);

    return input.questions.flatMap<TrustedGradeEvidence>((question) => {
      if (question.type === "elk_search") {
        const response = answers.get(question.id);
        const query = isObject(response) && typeof response.query === "string"
          ? response.query.trim()
          : "";
        const submitted = isObject(response) && Array.isArray(response.evidenceIds)
          ? normalizedIdentifiers(response.evidenceIds)
          : new Set<string>();
        const expected = normalizedIdentifiers(question.answerKey.expectedEvidenceIds ?? []);
        const allEvidenceIsServerOwned = [...submitted].every((id) => telemetryIds.has(id));
        const passed = query.length > 0 && expected.size > 0 && allEvidenceIsServerOwned && setsEqual(submitted, expected);
        return [{
          questionId: question.id,
          source: "elk" as const,
          passed,
          scoreRatio: passed ? 1 : 0,
          policyVersion: "development-evidence-v1",
          evidenceReference: `development-elk/${runId}/${question.id}`,
        }];
      }

      if (question.type === "free_text") {
        const response = answers.get(question.id);
        const length = typeof response === "string" ? response.trim().length : 0;
        const scoreRatio = length >= 80 ? 1 : length >= 40 ? 0.5 : 0;
        return [{
          questionId: question.id,
          source: "ai_rubric" as const,
          passed: scoreRatio > 0,
          scoreRatio,
          policyVersion: "development-rubric-v1",
          evidenceReference: `development-rubric/${runId}/${question.id}`,
        }];
      }

      return [];
    });
  }
}

function developmentTelemetryIds(labValue: unknown): Set<string> {
  if (!isObject(labValue) || !isObject(labValue.config)) return new Set();
  const config = labValue.config;
  const validation = isObject(config.validation) ? config.validation : null;
  const telemetry = validation && isObject(validation.telemetry)
    ? validation.telemetry
    : isObject(config.telemetry)
      ? config.telemetry
      : null;
  if (!telemetry || !Array.isArray(telemetry.events)) return new Set();
  return normalizedIdentifiers(telemetry.events.flatMap((event) =>
    isObject(event) && typeof event.id === "string" ? [event.id] : [],
  ));
}

function normalizedIdentifiers(values: unknown[]): Set<string> {
  return new Set(values.flatMap((value) =>
    typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)
      ? [value]
      : [],
  ));
}

function setsEqual<T>(left: Set<T>, right: Set<T>): boolean {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

interface HttpEvidenceGraderOptions {
  serviceUrl: string;
  internalToken: string;
  fetchImpl?: typeof fetch;
}

/** Production adapter for ELK execution checks and AI rubric evaluation. */
export class HttpEvidenceGrader implements EvidenceGrader {
  private readonly serviceUrl: string;
  private readonly internalToken: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: HttpEvidenceGraderOptions) {
    if (!options.serviceUrl || !options.internalToken) {
      throw new RepositoryError(
        "GRADER_SERVICE_CONFIG_REQUIRED",
        "The grader service URL and internal token are required.",
        500,
      );
    }
    this.serviceUrl = options.serviceUrl.replace(/\/$/, "");
    this.internalToken = options.internalToken;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async grade(input: EvidenceGradeRequest): Promise<TrustedGradeEvidence[]> {
    const runId = isObject(input.run) ? input.run.id : undefined;
    if (typeof runId !== "string" || runId.trim().length === 0) {
      throw new RepositoryError(
        "GRADER_RUN_ID_REQUIRED",
        "A trusted grading request requires a runtime run ID.",
        500,
      );
    }
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.serviceUrl}/v1/evidence`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.internalToken}`,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({ runId, ...input }),
        signal: AbortSignal.timeout(20_000),
      });
    } catch {
      throw new ApiError(
        503,
        "GRADER_SERVICE_UNAVAILABLE",
        "The trusted grading service is unavailable.",
      );
    }

    const payload = (await response.json().catch(() => null)) as unknown;
    if (!response.ok) {
      throw new ApiError(
        502,
        "GRADER_SERVICE_REJECTED_REQUEST",
        "The trusted grading service rejected the submission.",
        { status: response.status },
      );
    }
    const data = isObject(payload) && isObject(payload.data) ? payload.data : null;
    if (!data || !Array.isArray(data.evidence)) {
      return invalidEvidence("The response must contain an evidence array.");
    }
    return validateTrustedGradeEvidence(data.evidence, input.questions);
  }
}

export function validateTrustedGradeEvidence(
  value: unknown,
  questions: ServerQuestion[],
): TrustedGradeEvidence[] {
  if (!Array.isArray(value)) {
    return invalidEvidence("Evidence must be an array.");
  }

  const questionsById = new Map(questions.map((question) => [question.id, question]));
  const seen = new Set<string>();
  return value.map((item, index) => {
    if (!isObject(item)) {
      return invalidEvidence(`evidence[${index}] must be an object.`);
    }
    const questionId = item.questionId;
    const source = item.source;
    if (typeof questionId !== "string") {
      return invalidEvidence(`evidence[${index}].questionId must be a string.`);
    }
    const question = questionsById.get(questionId);
    const expectedSource =
      question?.type === "elk_search"
        ? "elk"
        : question?.type === "free_text"
          ? "ai_rubric"
          : null;
    if (!question || !expectedSource || source !== expectedSource) {
      return invalidEvidence(
        `evidence[${index}] does not match an externally gradable question.`,
      );
    }
    if (seen.has(questionId)) {
      return invalidEvidence(`Duplicate evidence for question ${questionId}.`);
    }
    seen.add(questionId);
    if (
      typeof item.passed !== "boolean" ||
      typeof item.scoreRatio !== "number" ||
      !Number.isFinite(item.scoreRatio) ||
      item.scoreRatio < 0 ||
      item.scoreRatio > 1 ||
      typeof item.policyVersion !== "string" ||
      item.policyVersion.trim().length === 0 ||
      typeof item.evidenceReference !== "string" ||
      item.evidenceReference.trim().length === 0
    ) {
      return invalidEvidence(`evidence[${index}] has invalid grading fields.`);
    }
    return {
      questionId,
      source: expectedSource,
      passed: item.passed,
      scoreRatio: item.scoreRatio,
      policyVersion: item.policyVersion,
      evidenceReference: item.evidenceReference,
    };
  });
}

function invalidEvidence(message: string): never {
  throw new ApiError(
    502,
    "GRADER_EVIDENCE_CONTRACT_INVALID",
    `The trusted grading service returned invalid evidence. ${message}`,
  );
}

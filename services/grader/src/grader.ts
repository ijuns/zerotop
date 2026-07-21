import { createHash } from "node:crypto";
import type {
  ServerQuestion,
  SubmittedAnswer,
  TrustedGradeEvidence,
} from "@codegate/grading";

export interface EvidenceGradeRequest {
  runId: string;
  questions: ServerQuestion[];
  answers: SubmittedAnswer[];
}

export interface EvidenceGraderOptions {
  elasticsearchUrl: string;
  elasticsearchApiKey: string;
  aiServiceUrl: string;
  aiInternalToken: string;
  fetchImpl?: typeof fetch;
}

export class EvidenceGrader {
  private readonly elasticsearchUrl: string;
  private readonly elasticsearchApiKey: string;
  private readonly aiServiceUrl: string;
  private readonly aiInternalToken: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: EvidenceGraderOptions) {
    this.elasticsearchUrl = safeServiceUrl(options.elasticsearchUrl, "elasticsearchUrl");
    this.elasticsearchApiKey = requiredSecret(options.elasticsearchApiKey, "elasticsearchApiKey");
    this.aiServiceUrl = safeServiceUrl(options.aiServiceUrl, "aiServiceUrl");
    this.aiInternalToken = requiredSecret(options.aiInternalToken, "aiInternalToken");
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async grade(request: EvidenceGradeRequest): Promise<TrustedGradeEvidence[]> {
    const runId = safeIdentifier(request.runId, "runId");
    const answers = new Map(request.answers.map((item) => [item.questionId, item]));
    const evidence: TrustedGradeEvidence[] = [];
    for (const question of request.questions) {
      const answer = answers.get(question.id);
      if (question.type === "elk_search") {
        evidence.push(await this.gradeElk(runId, question, answer));
      } else if (question.type === "free_text") {
        evidence.push(await this.gradeFreeText(runId, question, answer));
      }
    }
    return evidence;
  }

  private async gradeElk(
    runId: string,
    question: ServerQuestion,
    answer: SubmittedAnswer | undefined,
  ): Promise<TrustedGradeEvidence> {
    const expected = normalizedEvidenceIds(question.answerKey.expectedEvidenceIds ?? []);
    const response = record(answer?.response);
    const submitted = normalizedEvidenceIds(
      Array.isArray(response.evidenceIds) ? response.evidenceIds : [],
    );
    if (expected.length === 0 || submitted.length === 0) {
      return failedEvidence(question.id, "elk", "elk-evidence-missing");
    }
    const ids = [...new Set([...expected, ...submitted])];
    const index = `codegate-run-${runId.toLowerCase().replace(/[^a-z0-9-]/g, "-")}`;
    let upstream: Response;
    try {
      upstream = await this.fetchImpl(
        `${this.elasticsearchUrl}/${encodeURIComponent(index)}/_mget`,
        {
          method: "POST",
          headers: {
            authorization: `ApiKey ${this.elasticsearchApiKey}`,
            "content-type": "application/json",
            accept: "application/json",
          },
          body: JSON.stringify({ ids }),
          signal: AbortSignal.timeout(5_000),
        },
      );
    } catch {
      return failedEvidence(question.id, "elk", "elk-unavailable");
    }
    if (!upstream.ok) return failedEvidence(question.id, "elk", `elk-http-${upstream.status}`);
    const payload = record(await upstream.json().catch(() => null));
    const documents = Array.isArray(payload.docs) ? payload.docs.map(record) : [];
    const found = new Set(
      documents
        .filter((item) => item.found === true && typeof item._id === "string")
        .map((item) => String(item._id)),
    );
    const matched = expected.filter((id) => submitted.includes(id) && found.has(id)).length;
    const ratio = expected.length ? matched / expected.length : 0;
    const exact =
      ratio === 1 &&
      submitted.length === expected.length &&
      submitted.every((id) => expected.includes(id));
    return {
      questionId: question.id,
      source: "elk",
      passed: exact,
      scoreRatio: exact ? 1 : ratio,
      policyVersion: "elk-evidence/v1",
      evidenceReference: evidenceReference(runId, question.id, [...found]),
    };
  }

  private async gradeFreeText(
    runId: string,
    question: ServerQuestion,
    answer: SubmittedAnswer | undefined,
  ): Promise<TrustedGradeEvidence> {
    const response = typeof answer?.response === "string" ? answer.response.trim() : "";
    const rubricId = question.answerKey.rubricId;
    if (!rubricId || response.length < 10 || response.length > 20_000) {
      return failedEvidence(question.id, "ai_rubric", "rubric-input-invalid");
    }
    let upstream: Response;
    try {
      upstream = await this.fetchImpl(`${this.aiServiceUrl}/v1/grade/free-text`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.aiInternalToken}`,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({ runId, questionId: question.id, rubricId, response }),
        signal: AbortSignal.timeout(12_000),
      });
    } catch {
      return failedEvidence(question.id, "ai_rubric", "rubric-unavailable");
    }
    if (!upstream.ok) {
      return failedEvidence(question.id, "ai_rubric", `rubric-http-${upstream.status}`);
    }
    const payload = record(await upstream.json().catch(() => null));
    const ratio = typeof payload.scoreRatio === "number" ? payload.scoreRatio : Number.NaN;
    if (!Number.isFinite(ratio) || ratio < 0 || ratio > 1 || typeof payload.traceId !== "string") {
      return failedEvidence(question.id, "ai_rubric", "rubric-response-invalid");
    }
    return {
      questionId: question.id,
      source: "ai_rubric",
      passed: payload.passed === true,
      scoreRatio: payload.passed === true ? ratio : 0,
      policyVersion:
        typeof payload.policyVersion === "string" ? payload.policyVersion : "ai-rubric/v1",
      evidenceReference: payload.traceId,
    };
  }
}

function normalizedEvidenceIds(values: unknown[]): string[] {
  return [...new Set(values.filter((item): item is string => typeof item === "string"))]
    .map((item) => item.trim())
    .filter((item) => /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(item))
    .sort();
}

function failedEvidence(
  questionId: string,
  source: TrustedGradeEvidence["source"],
  reason: string,
): TrustedGradeEvidence {
  return {
    questionId,
    source,
    passed: false,
    scoreRatio: 0,
    policyVersion: source === "elk" ? "elk-evidence/v1" : "ai-rubric/v1",
    evidenceReference: reason,
  };
}

function evidenceReference(runId: string, questionId: string, ids: string[]): string {
  return `evidence:${createHash("sha256")
    .update(JSON.stringify({ runId, questionId, ids: [...ids].sort() }))
    .digest("hex")}`;
}

function safeIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$/.test(value)) {
    throw new Error(`${field} is invalid`);
  }
  return value;
}

function safeServiceUrl(value: string, field: string): string {
  const url = new URL(value);
  const clusterLocal = url.hostname.endsWith(".svc.cluster.local") || !url.hostname.includes(".");
  if (url.protocol !== "https:" && !clusterLocal && url.hostname !== "localhost") {
    throw new Error(`${field} must use HTTPS outside the cluster`);
  }
  return value.replace(/\/$/, "");
}

function requiredSecret(value: string, field: string): string {
  if (value.length < 24) throw new Error(`${field} must contain at least 24 characters`);
  return value;
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

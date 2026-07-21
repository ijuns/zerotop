export type GradableQuestionType =
  | "elk_search"
  | "single_choice"
  | "multiple_choice"
  | "free_text"
  | "mitre_attack";

export interface ServerQuestion {
  id: string;
  type: GradableQuestionType;
  points: number;
  answerKey: {
    accepted?: string[];
    optionIds?: string[];
    techniqueIds?: string[];
    rubricId?: string;
    expectedEvidenceIds?: string[];
  };
}

export interface SubmittedAnswer {
  questionId: string;
  response: unknown;
}

export interface TrustedGradeEvidence {
  questionId: string;
  source: "elk" | "ai_rubric";
  passed: boolean;
  scoreRatio: number;
  policyVersion: string;
  evidenceReference: string;
}

export interface QuestionGrade {
  questionId: string;
  questionType: GradableQuestionType;
  awardedPoints: number;
  maxPoints: number;
  outcome: "correct" | "partial" | "incorrect" | "ungradable";
  feedbackCode: string;
  evidenceReference?: string;
}

export interface RunGrade {
  awardedPoints: number;
  maxPoints: number;
  score: number;
  passed: boolean;
  grades: QuestionGrade[];
}

export function gradeRun(
  questions: ServerQuestion[],
  answers: SubmittedAnswer[],
  trustedEvidence: TrustedGradeEvidence[] = [],
  passScore = 70,
): RunGrade {
  validateQuestions(questions);
  if (!Number.isFinite(passScore) || passScore < 0 || passScore > 100) {
    throw new Error("passScore must be between 0 and 100");
  }
  const answersById = uniqueMap(answers, "answer");
  const evidenceById = uniqueMap(trustedEvidence, "grade evidence");
  for (const questionId of answersById.keys()) {
    if (!questions.some((question) => question.id === questionId)) {
      throw new Error(`Unknown question: ${questionId}`);
    }
  }

  const grades = questions.map((question) =>
    gradeQuestion(
      question,
      answersById.get(question.id)?.response,
      evidenceById.get(question.id),
    ),
  );
  const maxPoints = grades.reduce((total, item) => total + item.maxPoints, 0);
  const awardedPoints = grades.reduce((total, item) => total + item.awardedPoints, 0);
  const score = maxPoints === 0 ? 0 : Math.round((awardedPoints / maxPoints) * 100);
  return { awardedPoints, maxPoints, score, passed: score >= passScore, grades };
}

function gradeQuestion(
  question: ServerQuestion,
  response: unknown,
  evidence?: TrustedGradeEvidence,
): QuestionGrade {
  if (question.type === "elk_search" || question.type === "free_text") {
    const expectedSource = question.type === "elk_search" ? "elk" : "ai_rubric";
    if (!evidence || evidence.source !== expectedSource || !validEvidence(evidence)) {
      return result(question, 0, "ungradable", "TRUSTED_EVIDENCE_REQUIRED");
    }
    const ratio = evidence.passed ? clamp(evidence.scoreRatio) : 0;
    return result(
      question,
      Math.round(question.points * ratio),
      ratio === 1 ? "correct" : ratio > 0 ? "partial" : "incorrect",
      evidence.passed ? "EXTERNAL_GRADE_ACCEPTED" : "EXTERNAL_GRADE_FAILED",
      evidence.evidenceReference,
    );
  }

  if (question.type === "single_choice") {
    const accepted = normalizedSet(question.answerKey.optionIds ?? question.answerKey.accepted ?? []);
    const actual = typeof response === "string" ? response.trim().toLowerCase() : "";
    const correct = accepted.size === 1 && accepted.has(actual);
    return result(question, correct ? question.points : 0, correct ? "correct" : "incorrect", correct ? "MATCH" : "NO_MATCH");
  }

  if (question.type === "multiple_choice") {
    const expected = normalizedSet(question.answerKey.optionIds ?? []);
    const actual = normalizedSet(Array.isArray(response) ? response : []);
    const correct = expected.size > 0 && setsEqual(expected, actual);
    return result(question, correct ? question.points : 0, correct ? "correct" : "incorrect", correct ? "SET_MATCH" : "SET_MISMATCH");
  }

  const expected = normalizedTechniqueSet(question.answerKey.techniqueIds ?? []);
  const values = Array.isArray(response) ? response : typeof response === "string" ? [response] : [];
  const actual = normalizedTechniqueSet(values);
  const correct = expected.size > 0 && setsEqual(expected, actual);
  return result(question, correct ? question.points : 0, correct ? "correct" : "incorrect", correct ? "ATTACK_MATCH" : "ATTACK_MISMATCH");
}

function result(
  question: ServerQuestion,
  awardedPoints: number,
  outcome: QuestionGrade["outcome"],
  feedbackCode: string,
  evidenceReference?: string,
): QuestionGrade {
  return {
    questionId: question.id,
    questionType: question.type,
    awardedPoints,
    maxPoints: question.points,
    outcome,
    feedbackCode,
    ...(evidenceReference ? { evidenceReference } : {}),
  };
}

function validateQuestions(questions: ServerQuestion[]): void {
  uniqueMap(questions, "question");
  for (const question of questions) {
    if (!Number.isInteger(question.points) || question.points <= 0) {
      throw new Error(`Question ${question.id} has invalid points`);
    }
  }
}

function uniqueMap<T extends { questionId?: string; id?: string }>(
  items: T[],
  label: string,
): Map<string, T> {
  const result = new Map<string, T>();
  for (const item of items) {
    const id = item.questionId ?? item.id;
    if (!id) throw new Error(`${label} id is required`);
    if (result.has(id)) throw new Error(`Duplicate ${label}: ${id}`);
    result.set(id, item);
  }
  return result;
}

function validEvidence(evidence: TrustedGradeEvidence): boolean {
  return (
    evidence.policyVersion.trim().length > 0 &&
    evidence.evidenceReference.trim().length > 0 &&
    Number.isFinite(evidence.scoreRatio) &&
    evidence.scoreRatio >= 0 &&
    evidence.scoreRatio <= 1
  );
}

function normalizedSet(values: unknown[]): Set<string> {
  return new Set(
    values
      .filter((value): value is string => typeof value === "string")
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean),
  );
}

function normalizedTechniqueSet(values: unknown[]): Set<string> {
  return new Set(
    values
      .filter((value): value is string => typeof value === "string")
      .map((value) => value.trim().toUpperCase())
      .filter((value) => /^T\d{4}(?:\.\d{3})?$/.test(value)),
  );
}

function setsEqual<T>(left: Set<T>, right: Set<T>): boolean {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

function clamp(value: number): number {
  return Math.max(0, Math.min(1, value));
}

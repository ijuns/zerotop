import assert from "node:assert/strict";
import test from "node:test";
import { gradeRun, type ServerQuestion } from "../src/index.ts";

const questions: ServerQuestion[] = [
  { id: "q1", type: "single_choice", points: 20, answerKey: { optionIds: ["b"] } },
  { id: "q2", type: "multiple_choice", points: 20, answerKey: { optionIds: ["x", "z"] } },
  { id: "q3", type: "mitre_attack", points: 20, answerKey: { techniqueIds: ["T1190", "T1059.004"] } },
  { id: "q4", type: "elk_search", points: 20, answerKey: { expectedEvidenceIds: ["event-1"] } },
  { id: "q5", type: "free_text", points: 20, answerKey: { rubricId: "rubric-1" } },
];

test("grades objective, ELK, and rubric questions without returning answer keys", () => {
  const grade = gradeRun(
    questions,
    [
      { questionId: "q1", response: "B" },
      { questionId: "q2", response: ["z", "x"] },
      { questionId: "q3", response: ["t1059.004", "T1190"] },
      { questionId: "q4", response: { query: "event.category:web" } },
      { questionId: "q5", response: "The evidence shows..." },
    ],
    [
      { questionId: "q4", source: "elk", passed: true, scoreRatio: 1, policyVersion: "elk-1", evidenceReference: "ev-4" },
      { questionId: "q5", source: "ai_rubric", passed: true, scoreRatio: 0.75, policyVersion: "rubric-1", evidenceReference: "ev-5" },
    ],
  );
  assert.equal(grade.awardedPoints, 95);
  assert.equal(grade.score, 95);
  assert.equal(grade.passed, true);
  assert.equal("answerKey" in grade.grades[0], false);
});

test("ELK and free-text answers are never trusted without server evidence", () => {
  const grade = gradeRun(
    questions.slice(3),
    [
      { questionId: "q4", response: { clientSaysCorrect: true } },
      { questionId: "q5", response: "trust me" },
    ],
  );
  assert.equal(grade.awardedPoints, 0);
  assert.deepEqual(grade.grades.map((item) => item.outcome), ["ungradable", "ungradable"]);
});

test("rejects duplicate answers and unknown question ids", () => {
  assert.throws(
    () => gradeRun(questions, [{ questionId: "q1", response: "b" }, { questionId: "q1", response: "b" }]),
    /Duplicate answer/,
  );
  assert.throws(() => gradeRun(questions, [{ questionId: "unknown", response: "b" }]), /Unknown question/);
});

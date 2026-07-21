import assert from "node:assert/strict";
import test from "node:test";

import { DevelopmentEvidenceGrader } from "../src/evidence-grader.ts";

const grader = new DevelopmentEvidenceGrader();
const lab = {
  config: {
    telemetry: {
      events: [{ id: "event-42", document: { event: { category: "process" } } }],
    },
  },
};

test("development grader trusts only ELK evidence present in the server-owned Lab fixture", () => {
  const [accepted] = grader.grade({
    run: { id: "run-1" },
    lab,
    questions: [{ id: "blue-q1", type: "elk_search", points: 30, answerKey: { expectedEvidenceIds: ["event-42"] } }],
    answers: [{ questionId: "blue-q1", response: { query: "*", evidenceIds: ["event-42"] } }],
  });
  assert.equal(accepted?.passed, true);
  assert.equal(accepted?.scoreRatio, 1);

  const [rejected] = grader.grade({
    run: { id: "run-1" },
    lab,
    questions: [{ id: "blue-q1", type: "elk_search", points: 30, answerKey: { expectedEvidenceIds: ["event-42"] } }],
    answers: [{ questionId: "blue-q1", response: { query: "*", evidenceIds: ["client-injected"] } }],
  });
  assert.equal(rejected?.passed, false);
  assert.equal(rejected?.scoreRatio, 0);
});

test("development free-text rubric is deterministic and remains server-side", () => {
  const [evidence] = grader.grade({
    run: { id: "run-2" },
    lab: {},
    questions: [{ id: "red-q3", type: "free_text", points: 30, answerKey: { rubricId: "rubric-v1" } }],
    answers: [{ questionId: "red-q3", response: "The observed process event is correlated with authentication evidence and a scoped mitigation." }],
  });
  assert.equal(evidence?.source, "ai_rubric");
  assert.equal(evidence?.passed, true);
  assert.equal(evidence?.scoreRatio, 1);
});

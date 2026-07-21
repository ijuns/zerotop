import assert from "node:assert/strict";
import test from "node:test";
import { EvidenceGrader } from "../src/grader.ts";

const options = {
  elasticsearchUrl: "http://elasticsearch:9200",
  elasticsearchApiKey: "elastic-key-with-at-least-24-characters",
  aiServiceUrl: "http://ai:8001",
  aiInternalToken: "ai-token-with-at-least-24-characters",
};

test("verifies ELK evidence IDs against the run-specific index", async () => {
  let requestedUrl = "";
  const grader = new EvidenceGrader({
    ...options,
    fetchImpl: async (input, init) => {
      requestedUrl = String(input);
      assert.deepEqual(JSON.parse(String(init?.body)), { ids: ["event-1", "event-2"] });
      return Response.json({ docs: [{ _id: "event-1", found: true }, { _id: "event-2", found: true }] });
    },
  });
  const evidence = await grader.grade({
    runId: "run_123",
    questions: [{ id: "q1", type: "elk_search", points: 50, answerKey: { expectedEvidenceIds: ["event-1", "event-2"] } }],
    answers: [{ questionId: "q1", response: { query: "event.category:web", evidenceIds: ["event-2", "event-1"] } }],
  });
  assert.match(requestedUrl, /codegate-run-run-123\/_mget$/);
  assert.equal(evidence[0].passed, true);
  assert.equal(evidence[0].scoreRatio, 1);
});

test("fails closed when submitted ELK evidence is absent from the index", async () => {
  const grader = new EvidenceGrader({
    ...options,
    fetchImpl: async () => Response.json({ docs: [{ _id: "event-1", found: false }] }),
  });
  const evidence = await grader.grade({
    runId: "run_123",
    questions: [{ id: "q1", type: "elk_search", points: 50, answerKey: { expectedEvidenceIds: ["event-1"] } }],
    answers: [{ questionId: "q1", response: { evidenceIds: ["event-1"] } }],
  });
  assert.equal(evidence[0].passed, false);
});

test("accepts only bounded, traceable AI rubric responses", async () => {
  const grader = new EvidenceGrader({
    ...options,
    fetchImpl: async (input) => {
      assert.match(String(input), /\/v1\/grade\/free-text$/);
      return Response.json({ passed: true, scoreRatio: 0.8, traceId: "trace-1", policyVersion: "rubric-2" });
    },
  });
  const evidence = await grader.grade({
    runId: "run_123",
    questions: [{ id: "q2", type: "free_text", points: 50, answerKey: { rubricId: "rubric-1" } }],
    answers: [{ questionId: "q2", response: "A sufficiently detailed investigation explanation." }],
  });
  assert.equal(evidence[0].source, "ai_rubric");
  assert.equal(evidence[0].scoreRatio, 0.8);
  assert.equal(evidence[0].evidenceReference, "trace-1");
});

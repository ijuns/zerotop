import assert from "node:assert/strict";
import test from "node:test";

import type { ServerQuestion } from "@codegate/grading";

import { ApiError } from "../src/errors.ts";
import { HttpEvidenceGrader } from "../src/evidence-grader.ts";

const questions: ServerQuestion[] = [
  {
    id: "blue-q1",
    type: "elk_search",
    points: 60,
    answerKey: { expectedEvidenceIds: ["event-42"] },
  },
  {
    id: "blue-q2",
    type: "mitre_attack",
    points: 40,
    answerKey: { techniqueIds: ["T1078"] },
  },
];

const input = {
  run: { id: "run-1", labId: "lab-1", status: "ready" },
  lab: { id: "lab-1", team: "blue" },
  questions,
  answers: [
    { questionId: "blue-q1", response: { query: "event.code:4624" } },
    { questionId: "blue-q2", response: "T1078" },
  ],
};

test("HTTP evidence grader sends the trusted internal grading contract", async () => {
  let requestBody: unknown;
  const grader = new HttpEvidenceGrader({
    serviceUrl: "http://codegate-grader:9002/",
    internalToken: "grader-internal-secret",
    fetchImpl: async (request, init) => {
      assert.equal(
        String(request),
        "http://codegate-grader:9002/v1/evidence",
      );
      assert.equal(
        new Headers(init?.headers).get("authorization"),
        "Bearer grader-internal-secret",
      );
      requestBody = JSON.parse(String(init?.body));
      return Response.json({
        data: {
          evidence: [
            {
              questionId: "blue-q1",
              source: "elk",
              passed: true,
              scoreRatio: 0.75,
              policyVersion: "elk-policy-v2",
              evidenceReference: "elk-execution/run-1/blue-q1",
            },
          ],
        },
      });
    },
  });

  const evidence = await grader.grade(input);
  assert.deepEqual(requestBody, { runId: "run-1", ...input });
  assert.equal(evidence[0].questionId, "blue-q1");
  assert.equal(evidence[0].scoreRatio, 0.75);
});

test("HTTP evidence grader rejects evidence for an untrusted question/source pair", async () => {
  const grader = new HttpEvidenceGrader({
    serviceUrl: "http://codegate-grader:9002",
    internalToken: "grader-internal-secret",
    fetchImpl: async () =>
      Response.json({
        data: {
          evidence: [
            {
              questionId: "blue-q2",
              source: "ai_rubric",
              passed: true,
              scoreRatio: 1,
              policyVersion: "fake-policy",
              evidenceReference: "untrusted/reference",
            },
          ],
        },
      }),
  });

  await assert.rejects(
    grader.grade(input),
    (error: unknown) =>
      error instanceof ApiError &&
      error.code === "GRADER_EVIDENCE_CONTRACT_INVALID" &&
      error.status === 502,
  );
});

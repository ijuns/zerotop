import assert from "node:assert/strict";
import test from "node:test";

import {
  aiGenerationTimeoutFromEnvironment,
  HttpAiLabGenerator,
} from "../src/ai.ts";
import { normalizeLabGeneration } from "../src/input.ts";

test("HTTP AI generator authenticates, validates and merges a server LabSpec", async () => {
  const calls: string[] = [];
  const timeouts: number[] = [];
  const learning = {
    title: "AI generated blue lab",
    summary: "Analyze correlated identity evidence.",
    sections: [
      { id: "context", title: "Threat context", bodyMarkdown: "Review the isolated identity attack context and its defensive impact." },
      { id: "workflow", title: "Investigation workflow", bodyMarkdown: "Correlate the supplied ELK records and map the observations to ATT&CK." },
    ],
  };
  const questions = [
    { id: "blue-q1", type: "elk_search", prompt: "Select the ELK evidence that identifies the suspicious identity.", points: 30 },
    { id: "blue-q2", type: "mitre_attack", prompt: "Select the ATT&CK technique represented by the observed behavior.", points: 20 },
  ];
  const gradingQuestions = [
    { ...questions[0], answerKey: { expectedEvidenceIds: ["blue-q1-evidence"] } },
    { ...questions[1], answerKey: { techniqueIds: ["T1078"] } },
  ];
  const environmentBuildSpec = {
    schemaVersion: 1,
    team: "blue",
    source: { promptDigest: `sha256:${"1".repeat(64)}`, cveIds: [] },
    scenario: { summary: "Investigate a suspicious identity and endpoint chain.", mitreTechniques: ["T1078"] },
    target: {
      name: "identity-target",
      baseImage: `registry.codegate.internal/base/cloud@sha256:${"a".repeat(64)}`,
      outputRepository: "registry.codegate.internal/ranges/identity-target",
      service: { port: 8080, protocol: "http" },
      runtimeContract: {
        kind: "http-v1", uid: 65532, gid: 65532, protocol: "http", port: 8080,
        writablePaths: ["/tmp"], readOnlyRootFilesystem: true, bindAddress: "0.0.0.0",
        healthPath: "/health", fingerprintPath: "/version",
      },
      packages: [],
      artifacts: [],
      functionalProbes: [{ id: "health", kind: "http", method: "GET", path: "/health", expectedStatuses: [200], bodyIncludes: ["ready"] }],
      vulnerabilityProbes: [{ id: "finding", findingId: "identity-chain", kind: "http", method: "GET", path: "/version", expectedStatuses: [200], bodyIncludes: ["identity-chain"] }],
    },
    telemetry: { events: [{ id: "blue-q1-evidence", document: { "@timestamp": "2026-07-21T00:00:00Z", event: { dataset: "identity" }, threat: { technique: { id: ["T1078"] } } } }] },
    learning: {
      title: learning.title,
      summary: learning.summary,
      sections: learning.sections.map((section) => ({ id: section.id, title: section.title, markdown: section.bodyMarkdown })),
    },
    questions,
    grading: {
      hiddenRefs: questions.map((question) => ({ questionId: question.id, refId: `grading://${question.id}`, rubricDigest: `sha256:${"2".repeat(64)}` })),
    },
  };
  const generator = new HttpAiLabGenerator({
    serviceUrl: "http://codegate-ai:8001/",
    internalToken: "ai-internal-secret",
    generationTimeoutMs: 90_000,
    timeoutSignalFactory: (timeoutMs) => {
      timeouts.push(timeoutMs);
      return new AbortController().signal;
    },
    fetchImpl: async (input, init) => {
      calls.push(String(input));
      assert.equal(
        new Headers(init?.headers).get("authorization"),
        "Bearer ai-internal-secret",
      );
      if (String(input).endsWith("/v1/validate")) {
        return Response.json({
          labId: "lab-ai-fixture",
          decision: "pass",
          score: 100,
          checks: [],
          policyVersion: "policy-fixture",
          createdAt: new Date().toISOString(),
        });
      }
      return Response.json({
        id: "lab-ai-fixture",
        version: 1,
        title: "AI generated blue lab",
        prompt: "Investigate authentication anomalies using correlated ELK evidence.",
        team: "blue",
        desktopImage: "ubuntu",
        accessMethod: "both",
        questionTypes: ["elk_search", "mitre_attack"],
        status: "draft",
        network: { egress: "deny", isolation: "per_run" },
        scenario: {
          summary: "Investigate a suspicious identity and endpoint chain.",
          logSources: ["waf", "edr", "firewall", "dns"],
          attackChain: [
            { id: "T1078", name: "Valid Accounts", tactic: "defense-evasion" },
          ],
        },
        safety: {
          weaponizedPayloads: "forbidden",
          externalTargets: "forbidden",
        },
        learning,
        questions,
        gradingQuestions,
        environmentBuildSpec,
      });
    },
  });
  const normalized = normalizeLabGeneration({
    title: "AI generated blue lab",
    prompt: "Investigate authentication anomalies using correlated ELK evidence.",
    team: "blue",
    desktopImage: "ubuntu",
    accessMethod: "both",
    questionTypes: ["elk_search", "mitre_attack"],
    target: {
      imageRef: "registry.codegate.internal/ranges/identity-lab",
      imageDigest: `sha256:${"c".repeat(64)}`,
    },
  });

  const result = await generator.generate(normalized);
  assert.deepEqual(calls, [
    "http://codegate-ai:8001/v1/drafts/generate",
    "http://codegate-ai:8001/v1/validate",
  ]);
  assert.deepEqual(timeouts, [90_000, 20_000]);
  assert.equal(
    (result.config.generator as Record<string, unknown>).kind,
    "ai-service",
  );
  assert.equal(result.buildSpec?.schemaVersion, 1);
  assert.equal(result.gradingQuestions.length, 2);
  assert.deepEqual(
    (result.config.scenario as Record<string, unknown>).mitreTechniques,
    ["T1078"],
  );
  assert.equal(
    (result.config.target as Record<string, unknown>).imageDigest,
    `sha256:${"c".repeat(64)}`,
  );
});

test("AI generation timeout uses a bounded validated environment contract", () => {
  assert.equal(aiGenerationTimeoutFromEnvironment({}), 90_000);
  assert.equal(
    aiGenerationTimeoutFromEnvironment({ AI_GENERATION_TIMEOUT_MS: "30000" }),
    30_000,
  );
  assert.equal(
    aiGenerationTimeoutFromEnvironment({ AI_GENERATION_TIMEOUT_MS: "180000" }),
    180_000,
  );
  for (const invalid of ["29999", "180001", "90000.5", " 90000", "unlimited"]) {
    assert.throws(
      () => aiGenerationTimeoutFromEnvironment({ AI_GENERATION_TIMEOUT_MS: invalid }),
      /AI_GENERATION_TIMEOUT_MS/,
    );
  }
});

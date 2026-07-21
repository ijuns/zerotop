import assert from "node:assert/strict";
import test from "node:test";

import {
  aiGenerationTimeoutFromEnvironment,
  HttpAiLabGenerator,
} from "../src/ai.ts";
import { ApiError } from "../src/errors.ts";
import { normalizeLabGeneration } from "../src/input.ts";

function normalizedBlueRequest(cveIds: string[] = []) {
  return normalizeLabGeneration({
    title: "AI generated blue lab",
    prompt: "Investigate authentication anomalies using correlated ELK evidence.",
    team: "blue",
    desktopImage: "ubuntu",
    accessMethod: "both",
    questionTypes: ["elk_search", "mitre_attack"],
    cveIds,
    target: {
      imageRef: "registry.codegate.internal/ranges/identity-lab",
      imageDigest: `sha256:${"c".repeat(64)}`,
    },
  });
}

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
  const normalized = normalizedBlueRequest();

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
  assert.equal(aiGenerationTimeoutFromEnvironment({}), 1_260_000);
  assert.equal(
    aiGenerationTimeoutFromEnvironment({ AI_GENERATION_TIMEOUT_MS: "30000" }),
    30_000,
  );
  assert.equal(
    aiGenerationTimeoutFromEnvironment({ AI_GENERATION_TIMEOUT_MS: "1800000" }),
    1_800_000,
  );
  for (const invalid of ["29999", "1800001", "1260000.5", " 1260000", "unlimited"]) {
    assert.throws(
      () => aiGenerationTimeoutFromEnvironment({ AI_GENERATION_TIMEOUT_MS: invalid }),
      /AI_GENERATION_TIMEOUT_MS/,
    );
  }
});

test("HTTP AI generator distinguishes an empty curated CVE catalog", async () => {
  const generator = new HttpAiLabGenerator({
    serviceUrl: "http://codegate-ai:8001",
    internalToken: "ai-internal-secret",
    fetchImpl: async () => Response.json(
      { detail: "External CVE generation requires a non-empty curated package or artifact catalog" },
      { status: 503 },
    ),
  });

  await assert.rejects(
    () => generator.generate(normalizedBlueRequest(["CVE-2026-12345"])),
    (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.status, 409);
      assert.equal(error.code, "AI_CVE_CATALOG_EMPTY");
      assert.match(error.message, /검증된 패키지 또는 아티팩트/);
      assert.deepEqual(error.details, {
        upstreamStatus: 503,
        reason: "cve_catalog_empty",
      });
      return true;
    },
  );
});

test("HTTP AI generator reports non-CVE generation configuration separately", async () => {
  const generator = new HttpAiLabGenerator({
    serviceUrl: "http://codegate-ai:8001",
    internalToken: "ai-internal-secret",
    fetchImpl: async () => Response.json(
      { detail: "External generation provider is not configured" },
      { status: 503 },
    ),
  });

  await assert.rejects(
    () => generator.generate(normalizedBlueRequest()),
    (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.status, 503);
      assert.equal(error.code, "AI_GENERATION_NOT_CONFIGURED");
      assert.match(error.message, /Claude 연결 및 생성 모드/);
      assert.deepEqual(error.details, {
        upstreamStatus: 503,
        reason: "generation_not_configured",
      });
      return true;
    },
  );
});

test("HTTP AI generator never forwards an unknown upstream body", async () => {
  const upstreamSecret = "sk-ant-secret-must-not-leak";
  const generator = new HttpAiLabGenerator({
    serviceUrl: "http://codegate-ai:8001",
    internalToken: "ai-internal-secret",
    fetchImpl: async () => Response.json(
      {
        detail: `unexpected provider response: ${upstreamSecret}`,
        traceback: `authorization=${upstreamSecret}`,
      },
      { status: 500 },
    ),
  });

  await assert.rejects(
    () => generator.generate(normalizedBlueRequest()),
    (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.status, 502);
      assert.equal(error.code, "AI_SERVICE_REJECTED_REQUEST");
      assert.doesNotMatch(error.message, /sk-ant|unexpected provider response/);
      assert.deepEqual(error.details, {
        upstreamStatus: 500,
        reason: "unclassified_rejection",
      });
      assert.doesNotMatch(JSON.stringify(error.details), /sk-ant|authorization/);
      return true;
    },
  );
});

test("HTTP AI generator exposes only allowlisted provider diagnostics when explicitly enabled", async () => {
  const secret = "sk-ant-secret-must-not-leak";
  const generator = new HttpAiLabGenerator({
    serviceUrl: "http://codegate-ai:8001",
    internalToken: "ai-internal-secret",
    exposeDebugErrors: true,
    fetchImpl: async () => Response.json(
      {
        detail: {
          message: "Generation provider returned HTTP 504: Anthropic response exceeded timeout",
          debug: {
            stage: "model_gateway",
            providerStage: "anthropic",
            upstreamStatus: 504,
            upstreamCode: "model_provider_timeout",
            upstreamMessage: `Anthropic response exceeded timeout ${secret}`,
            providerStatus: 504,
            providerErrorType: "timeout_error",
            providerRequestId: "req_debug_123",
            providerResponseId: "msg_debug_123",
            timeoutMs: 1_200_000,
            generationAttempts: 2,
            payloadBytes: 65_432,
            payloadDigest: "sha256:abcdef0123456789",
            parseKind: "syntax_error",
            parseOffset: 321,
            rawBody: secret,
            stack: secret,
          },
        },
      },
      { status: 504 },
    ),
  });

  await assert.rejects(
    () => generator.generate(normalizedBlueRequest()),
    (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.status, 504);
      assert.equal(error.code, "AI_PROVIDER_TIMEOUT");
      assert.match(error.message, /Claude/);
      const serialized = JSON.stringify(error.details);
      assert.match(serialized, /model_provider_timeout/);
      assert.match(serialized, /req_debug_123/);
      assert.match(serialized, /msg_debug_123/);
      assert.match(serialized, /sha256:abcdef0123456789/);
      assert.match(serialized, /syntax_error/);
      assert.match(serialized, /\[REDACTED\]/);
      assert.doesNotMatch(serialized, /secret-must-not-leak|rawBody|stack/);
      return true;
    },
  );
});

test("HTTP AI generator reports its outer generation deadline with safe diagnostics", async () => {
  const timeout = new Error("request aborted");
  timeout.name = "AbortError";
  const generator = new HttpAiLabGenerator({
    serviceUrl: "http://codegate-ai:8001",
    internalToken: "ai-internal-secret",
    generationTimeoutMs: 1_260_000,
    exposeDebugErrors: true,
    fetchImpl: async () => { throw timeout; },
  });

  await assert.rejects(
    () => generator.generate(normalizedBlueRequest()),
    (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.status, 504);
      assert.equal(error.code, "AI_SERVICE_TIMEOUT");
      assert.deepEqual(error.details, {
        reason: "api_timeout",
        debug: {
          status: 504,
          code: "AI_SERVICE_TIMEOUT",
          stage: "api",
          timeoutMs: 1_260_000,
        },
      });
      return true;
    },
  );
});

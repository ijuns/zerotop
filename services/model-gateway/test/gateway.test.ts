import assert from "node:assert/strict";
import { once } from "node:events";
import { createConnection } from "node:net";
import { test } from "node:test";

import { AnthropicMessagesClient, GENERATION_RAW_RESPONSE_CAPTURE_PATH, anthropicOutputSchema, writeGenerationRawResponseCapture } from "../src/anthropic.ts";
import { loadConfig, type GatewayConfig } from "../src/config.ts";
import { OpenAiResponsesClient, ModelProviderError, type StructuredRequest, type StructuredResponse } from "../src/openai.ts";
import { createModelGatewayServer } from "../src/server.ts";
import { GatewayError, ModelGatewayService, type ModelClient } from "../src/service.ts";

const TOKEN = "gateway-internal-token-000000000000000000";
const KEY = "sk-test-000000000000000000000000000000000";
const ANTHROPIC_KEY = "sk-ant-test-000000000000000000000000000000000";
const BASE_IMAGE = `registry.example.test/codegate/http-base@sha256:${"a".repeat(64)}`;
const RUBRICS = {
  "incident-analysis-v1": {
    policyVersion: "incident-analysis-2026.07",
    passThreshold: 0.7,
    criteria: [
      { id: "evidence", description: "Uses concrete evidence from the isolated exercise data.", weight: 0.6 },
      { id: "mitigation", description: "Explains a proportionate detection or mitigation action.", weight: 0.4 },
    ],
  },
};

function config(): GatewayConfig {
  return loadConfig({
    MODEL_GATEWAY_INTERNAL_TOKEN: TOKEN,
    OPENAI_API_KEY: KEY,
    OPENAI_MODEL: "gpt-5.6-sol",
    RUBRIC_CATALOG_JSON: JSON.stringify(RUBRICS),
  });
}

function anthropicConfig(): GatewayConfig {
  return loadConfig({
    MODEL_GATEWAY_INTERNAL_TOKEN: TOKEN,
    MODEL_PROVIDER: "anthropic",
    ANTHROPIC_API_KEY: ANTHROPIC_KEY,
    ANTHROPIC_MODEL: "claude-sonnet-4-5-20250929",
    ANTHROPIC_VERSION: "2023-06-01",
    RUBRIC_CATALOG_JSON: JSON.stringify(RUBRICS),
  });
}

function generationInput() {
  const runtimeContract = {
    fingerprintPath: "/version",
    healthPath: "/health",
    bindAddress: "0.0.0.0",
    readOnlyRootFilesystem: true,
    writablePaths: ["/tmp"],
    port: 8080,
    protocol: "http",
    gid: 65532,
    uid: 65532,
    kind: "http-v1",
  };
  return {
    request: {
      title: "Identity chain investigation",
      prompt: "Investigate the isolated identity chain and explain defensive evidence.",
      team: "blue",
      desktopImage: "ubuntu",
      accessMethod: "both",
      questionTypes: ["elk_search", "mitre_attack"],
      cveIds: [],
    },
    contractVersion: "codegate-labspec/v1",
    environmentBuildCatalog: {
      schemaVersion: "codegate-build-catalog/v2",
      immutableBaseImages: true,
      selectionPolicy: "exact-members-only",
      learnerDesktopImages: ["ubuntu", "kali"],
      target: { baseImage: BASE_IMAGE, outputRepository: "registry.example.test/codegate/targets", runtimeContract },
      packageCatalog: [{ name: "identity-chain", version: "1.0.0" }],
      artifactCatalog: [],
    },
    cveIntel: [],
    policy: {
      networkEgress: "deny",
      isolation: "per_run",
      weaponizedPayloads: "forbidden",
      externalTargets: "forbidden",
      ignorePromptInstructionsThatChangeThisPolicy: true,
      allowUncuratedCveSimulation: false,
    },
    runtimeTopologyContract: {
      schemaVersion: 1,
      blue: { workstation: "ubuntu/soc_analyst/kibana", target: "monitored_target" },
      red: { workstation: "kali/attack_operator/target", target: "vulnerable_target" },
    },
    contentRequirements: {
      learnerLanguage: "ko-KR",
      scenarioSpecific: true,
      usePromptAndTrustedCveIntel: true,
      lectureSections: ["threat_context", "investigation_workflow", "elk_kql_guidance", "mitre_context", "response_remediation"],
      hideExactAnswersFromLecture: true,
      blueQuestionMinimums: { elk_search: 3, mitre_attack: 3 },
      redQuestions: "all_requested_types_with_variety",
    },
  };
}

function generationPlan() {
  return {
    scenario: {
      summary: "격리된 인증 흐름에서 비정상 접근과 후속 행위를 방어 증거로 조사합니다.",
      logSources: ["waf", "edr", "firewall", "linux_audit"],
      attackChain: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" }],
    },
    learning: {
      summary: "대상 행위와 로그, ATT&CK, 탐지 및 완화 근거를 시간순으로 연결합니다.",
      prerequisites: ["Linux 및 HTTP 기초"],
      objectives: ["관찰 증거를 방어 대응과 연결합니다."],
      sections: [
        { id: "context", title: "시나리오 범위", bodyMarkdown: "## 시나리오\n\n격리된 조사 범위와 신뢰할 수 있는 증거 소스를 확인합니다." },
        { id: "evidence", title: "증거 모델", bodyMarkdown: "## 증거\n\n시간, 사용자, 호스트와 프로세스 식별자를 연결합니다." },
        { id: "workflow", title: "조사 절차", bodyMarkdown: "## 절차\n\n타임스탬프와 인증 기록을 순서대로 상관 분석합니다." },
        { id: "elk", title: "ELK 검색 안내", bodyMarkdown: "## 검색\n\n넓은 KQL 조건에서 시작해 관련 필드를 추가합니다." },
        { id: "mitre", title: "MITRE 매핑", bodyMarkdown: "## 매핑\n\n도구명이 아니라 관찰한 행위와 목적을 기준으로 판단합니다." },
        { id: "response", title: "대응과 완화", bodyMarkdown: "## 대응\n\n격리와 탐지 개선, 재발 방지 조치를 근거와 함께 제시합니다." },
      ],
    },
    questions: [
      {
        id: "blue-q1", type: "elk_search", prompt: "최초 비정상 요청을 입증하는 로그 증거를 선택하고 사용한 검색 조건을 기록하세요.", points: 20, options: null,
        answer: { optionIds: null, techniqueIds: null, expectedEvidenceIds: ["event-1"], rubricId: null },
      },
      {
        id: "blue-q2", type: "elk_search", prompt: "동일 호스트에서 이어진 실행 흐름을 입증하는 로그 증거를 선택하세요.", points: 20, options: null,
        answer: { optionIds: null, techniqueIds: null, expectedEvidenceIds: ["event-1"], rubricId: null },
      },
      {
        id: "blue-q3", type: "elk_search", prompt: "후속 영향 단계가 최초 사건과 연결됨을 보여주는 로그 증거를 선택하세요.", points: 20, options: null,
        answer: { optionIds: null, techniqueIds: null, expectedEvidenceIds: ["event-1"], rubricId: null },
      },
      {
        id: "blue-q4", type: "mitre_attack", prompt: "관찰된 최초 접근 행위를 설명하는 MITRE ATT&CK 기법을 선택하세요.", points: 15, options: null,
        answer: { optionIds: null, techniqueIds: ["T1190"], expectedEvidenceIds: null, rubricId: null },
      },
      {
        id: "blue-q5", type: "mitre_attack", prompt: "관찰된 실행 흐름을 설명하는 MITRE ATT&CK 기법을 선택하세요.", points: 15, options: null,
        answer: { optionIds: null, techniqueIds: ["T1190"], expectedEvidenceIds: null, rubricId: null },
      },
      {
        id: "blue-q6", type: "mitre_attack", prompt: "전체 타임라인과 가장 일치하는 MITRE ATT&CK 기법을 선택하세요.", points: 10, options: null,
        answer: { optionIds: null, techniqueIds: ["T1190"], expectedEvidenceIds: null, rubricId: null },
      },
    ],
    target: {
      name: "identity-chain",
      packages: [{ name: "identity-chain", version: "1.0.0" }],
      artifacts: [],
      functionalProbes: [{ id: "health", method: "GET", path: "/health", expectedStatuses: [200], bodyIncludes: ["ready"] }],
      vulnerabilityProbes: [{ id: "fingerprint", method: "GET", path: "/version", expectedStatuses: [200], bodyIncludes: ["scenario-idor"], cveId: null, findingId: "scenario-idor" }],
    },
    telemetryEvents: [{ id: "event-1", message: "Suspicious account lookup", dataset: "codegate.http", category: "intrusion_detection", sourceIp: "192.0.2.44", techniqueIds: ["T1190"] }],
  };
}

class QueueClient implements ModelClient {
  readonly requests: StructuredRequest[] = [];
  private readonly outputs: Array<Record<string, unknown>>;
  constructor(outputs: Array<Record<string, unknown>>) {
    this.outputs = outputs;
  }
  async createStructured(request: StructuredRequest): Promise<StructuredResponse> {
    this.requests.push(request);
    const payload = this.outputs.shift();
    assert.ok(payload);
    return { payload, responseId: `resp_${this.requests.length}` };
  }
}

test("configuration fails closed and rejects unsupported upstream/model modes", () => {
  assert.throws(() => loadConfig({}), /MODEL_GATEWAY_INTERNAL_TOKEN/);
  assert.throws(() => loadConfig({ MODEL_GATEWAY_INTERNAL_TOKEN: " ".repeat(32), OPENAI_API_KEY: KEY, OPENAI_MODEL: "gpt-5.6-sol", RUBRIC_CATALOG_JSON: JSON.stringify(RUBRICS) }), /non-whitespace/);
  assert.throws(() => loadConfig({ MODEL_GATEWAY_INTERNAL_TOKEN: TOKEN, OPENAI_API_KEY: KEY, OPENAI_MODEL: "ft:gpt-4o:org:model", RUBRIC_CATALOG_JSON: JSON.stringify(RUBRICS) }), /non-fine-tuned/);
  assert.throws(() => loadConfig({ MODEL_GATEWAY_INTERNAL_TOKEN: TOKEN, OPENAI_API_KEY: KEY, OPENAI_MODEL: "gpt-5.6-sol", OPENAI_BASE_URL: "https://attacker.invalid/v1", RUBRIC_CATALOG_JSON: JSON.stringify(RUBRICS) }), /official OpenAI/);
  assert.throws(() => loadConfig({ MODEL_GATEWAY_INTERNAL_TOKEN: TOKEN, MODEL_PROVIDER: "other", RUBRIC_CATALOG_JSON: JSON.stringify(RUBRICS) }), /openai or anthropic/);
  assert.throws(() => loadConfig({ MODEL_GATEWAY_INTERNAL_TOKEN: TOKEN, MODEL_PROVIDER: "anthropic", ANTHROPIC_API_KEY: ANTHROPIC_KEY, ANTHROPIC_MODEL: "claude-sonnet-4-5-20250929", ANTHROPIC_BASE_URL: "https://attacker.invalid/v1", RUBRIC_CATALOG_JSON: JSON.stringify(RUBRICS) }), /official Anthropic/);
  assert.throws(() => loadConfig({ MODEL_GATEWAY_INTERNAL_TOKEN: TOKEN, MODEL_PROVIDER: "anthropic", ANTHROPIC_API_KEY: ANTHROPIC_KEY, ANTHROPIC_MODEL: "claude-sonnet-4-5-20250929", ANTHROPIC_VERSION: "latest", RUBRIC_CATALOG_JSON: JSON.stringify(RUBRICS) }), /YYYY-MM-DD/);
  const anthropic = anthropicConfig();
  assert.equal(anthropic.provider, "anthropic");
  assert.equal(anthropic.providerEndpoint, "https://api.anthropic.com/v1/messages");
  assert.equal(anthropic.anthropicVersion, "2023-06-01");
  assert.equal(anthropic.generationTimeoutMs, 1_200_000);
  assert.equal(anthropic.generationMaxAttempts, 1);
  assert.equal(anthropic.captureGenerationRawResponse, false);
  assert.equal(loadConfig({
    MODEL_GATEWAY_INTERNAL_TOKEN: TOKEN,
    MODEL_PROVIDER: "anthropic",
    ANTHROPIC_API_KEY: ANTHROPIC_KEY,
    ANTHROPIC_MODEL: "claude-sonnet-4-5-20250929",
    MODEL_GATEWAY_GENERATION_TIMEOUT_MS: "1200000",
    RUBRIC_CATALOG_JSON: JSON.stringify(RUBRICS),
  }).generationTimeoutMs, 1_200_000);
  assert.throws(() => loadConfig({
    MODEL_GATEWAY_INTERNAL_TOKEN: TOKEN,
    MODEL_PROVIDER: "anthropic",
    ANTHROPIC_API_KEY: ANTHROPIC_KEY,
    ANTHROPIC_MODEL: "claude-sonnet-4-5-20250929",
    MODEL_GATEWAY_GENERATION_TIMEOUT_MS: "1200001",
    RUBRIC_CATALOG_JSON: JSON.stringify(RUBRICS),
  }), /MODEL_GATEWAY_GENERATION_TIMEOUT_MS/);
  const debugCapture = loadConfig({
    MODEL_GATEWAY_INTERNAL_TOKEN: TOKEN,
    MODEL_PROVIDER: "anthropic",
    ANTHROPIC_API_KEY: ANTHROPIC_KEY,
    ANTHROPIC_MODEL: "claude-sonnet-4-5-20250929",
    MODEL_GATEWAY_GENERATION_MAX_ATTEMPTS: "2",
    MODEL_GATEWAY_DEBUG_RAW_RESPONSE_CAPTURE: "local-explicit",
    RUBRIC_CATALOG_JSON: JSON.stringify(RUBRICS),
  });
  assert.equal(debugCapture.generationMaxAttempts, 2);
  assert.equal(debugCapture.captureGenerationRawResponse, true);
  for (const value of ["0", "3", "1.5", "true"]) {
    assert.throws(() => loadConfig({
      MODEL_GATEWAY_INTERNAL_TOKEN: TOKEN,
      OPENAI_API_KEY: KEY,
      OPENAI_MODEL: "gpt-5.6-sol",
      MODEL_GATEWAY_GENERATION_MAX_ATTEMPTS: value,
      RUBRIC_CATALOG_JSON: JSON.stringify(RUBRICS),
    }), /MODEL_GATEWAY_GENERATION_MAX_ATTEMPTS/);
  }
  for (const value of ["", "true", "false", "LOCAL-EXPLICIT", "local-explicit "]) {
    assert.throws(() => loadConfig({
      MODEL_GATEWAY_INTERNAL_TOKEN: TOKEN,
      OPENAI_API_KEY: KEY,
      OPENAI_MODEL: "gpt-5.6-sol",
      MODEL_GATEWAY_DEBUG_RAW_RESPONSE_CAPTURE: value,
      RUBRIC_CATALOG_JSON: JSON.stringify(RUBRICS),
    }), /MODEL_GATEWAY_DEBUG_RAW_RESPONSE_CAPTURE/);
  }
});

test("generation assembles immutable scope, hides answers, and emits a builder-compatible projection", async () => {
  const client = new QueueClient([generationPlan()]);
  const service = new ModelGatewayService(config(), client, () => new Date("2026-07-21T12:00:00.000Z"), () => "11111111-1111-4111-8111-111111111111");
  const result = await service.generate(generationInput());
  assert.equal(result.team, "blue");
  assert.equal((result.questions as Array<Record<string, unknown>>)[0]?.answerKey, undefined);
  assert.deepEqual((result.gradingQuestions as Array<Record<string, unknown>>)[0]?.answerKey, { expectedEvidenceIds: ["event-1"] });
  const spec = result.environmentBuildSpec as Record<string, any>;
  assert.equal(spec.learning.sections[0].markdown.startsWith("## 시나리오"), true);
  assert.equal(spec.learning.sections[0].bodyMarkdown, undefined);
  assert.deepEqual(spec.scenario.mitreTechniques, ["T1190"]);
  assert.match(spec.grading.hiddenRefs[0].refId, /^grading:\/\//);
  assert.equal(spec.target.baseImage, BASE_IMAGE);
  assert.equal(client.requests[0]?.timeoutMs, 1_200_000);
  assert.equal((client.requests[0]?.schema as any).additionalProperties, false);
});

test("generation canonicalizes model presentation fields and runtime-owned probes for bounded local CVE simulation", async () => {
  const cveId = "CVE-2026-12345";
  const input: any = generationInput();
  input.request.cveIds = [cveId];
  input.cveIntel = [{ id: cveId, description: "Normalized trusted CVE context" }];
  input.policy.allowUncuratedCveSimulation = true;
  input.environmentBuildCatalog.target.baseImage = `codegate/local-target@sha256:${"a".repeat(64)}`;
  input.environmentBuildCatalog.target.outputRepository = "codegate/local-target";
  input.environmentBuildCatalog.packageCatalog = [];
  input.environmentBuildCatalog.artifactCatalog = [];

  const plan: any = generationPlan();
  plan.target.packages = [];
  plan.target.functionalProbes = [{
    id: "model-invented-health",
    method: "GET",
    path: "/model-health",
    expectedStatuses: [200],
    bodyIncludes: [],
  }];
  plan.target.vulnerabilityProbes = [{
    id: "model-invented-fingerprint",
    method: "GET",
    path: "/model-fingerprint",
    expectedStatuses: [200],
    bodyIncludes: ["invented"],
    cveId,
    findingId: null,
  }];
  for (const question of plan.questions) {
    question.options = [{ id: "legacy-a", label: "레거시 선택지 A" }, { id: "legacy-b", label: "레거시 선택지 B" }];
    question.answer.optionIds = ["legacy-a"];
  }
  const mitreQuestion = plan.questions.find((question: any) => question.type === "mitre_attack");
  mitreQuestion.answer.techniqueIds.push("T1136.001");
  const client = new QueueClient([plan]);
  const result = await new ModelGatewayService(config(), client).generate(input);

  const spec = result.environmentBuildSpec as Record<string, any>;
  assert.deepEqual(spec.source.cveIds, [cveId]);
  assert.deepEqual(spec.target.packages, []);
  assert.deepEqual(spec.target.artifacts, []);
  assert.deepEqual(spec.target.functionalProbes, [{
    id: "runtime-health",
    kind: "http",
    method: "GET",
    path: "/health",
    expectedStatuses: [200],
    bodyIncludes: [],
  }]);
  assert.deepEqual(spec.target.vulnerabilityProbes, [{
    id: "runtime-cve-2026-12345",
    kind: "http",
    method: "GET",
    path: "/version",
    expectedStatuses: [200],
    bodyIncludes: ["http-v1"],
    cveId,
  }]);
  assert.equal((result.questions as Array<Record<string, unknown>>).every((question) => question.options === undefined), true);
  assert.deepEqual(
    (result.gradingQuestions as Array<Record<string, any>>)
      .find((question) => question.type === "mitre_attack")?.answerKey,
    { techniqueIds: ["T1190"] },
  );
  assert.equal((result.safety as Record<string, unknown>).uncuratedCveSimulation, true);
  assert.match(client.requests[0]?.instructions ?? "", /bounded behavioral simulation/);
});

test("generation remains fail-closed when MITRE canonicalization leaves no authoritative answer", async () => {
  const plan: any = generationPlan();
  const question = plan.questions.find((item: any) => item.type === "mitre_attack");
  question.options = [{ id: "legacy-a", label: "레거시 선택지 A" }, { id: "legacy-b", label: "레거시 선택지 B" }];
  question.answer.optionIds = ["legacy-a"];
  question.answer.techniqueIds = ["T1136.001"];

  await assert.rejects(
    new ModelGatewayService(config(), new QueueClient([plan])).generate(generationInput()),
    (error: unknown) => error instanceof GatewayError
      && error.code === "contract_invalid"
      && /techniqueIds/.test(error.message),
  );
});

test("uncurated CVE simulation policy is rejected outside the local target runtime", async () => {
  const input: any = generationInput();
  input.policy.allowUncuratedCveSimulation = true;
  await assert.rejects(
    new ModelGatewayService(config(), new QueueClient([generationPlan()])).generate(input),
    (error: unknown) => error instanceof GatewayError
      && /restricted to the local target runtime/.test(error.message),
  );
});

test("review is fail-closed over mandatory evidence and rubric pass is computed server-side", async () => {
  const client = new QueueClient([
    { passed: true, confidence: 0.95, riskScore: 0.05 },
    { criterionScores: [{ criterionId: "evidence", score: 0.8 }, { criterionId: "mitigation", score: 0.6 }] },
  ]);
  const service = new ModelGatewayService(config(), client);
  const evidence = {
    artifact: { signatureVerified: true, ociConfigVerified: true, runtimeContractVerified: true, unexpectedCriticalCount: 0 },
    sandbox: { egressBlocked: true, controlPlaneBlocked: true, crossRunBlocked: true },
    assessment: { answerLeakageDetected: false },
  };
  const review = await service.review({ lab: { id: "lab-safe" }, evidence });
  assert.equal(review.passed, true);
  const failed = await new ModelGatewayService(config(), new QueueClient([{ passed: true, confidence: 0.95, riskScore: 0.05 }])).review({ lab: { id: "lab-safe" }, evidence: { ...evidence, sandbox: { ...evidence.sandbox, egressBlocked: false } } });
  assert.equal(failed.passed, false);
  assert.equal(failed.riskScore, 1);
  const grade = await service.rubric({ runId: "run-1", questionId: "q-1", rubricId: "incident-analysis-v1", response: "The correlated log evidence supports detection and a scoped mitigation action." });
  assert.equal(grade.scoreRatio, 0.72);
  assert.equal(grade.passed, true);
  assert.equal(client.requests[1]?.timeoutMs, 9_000);
});

test("Responses client requests strict non-persistent structured output and rejects refusals", async () => {
  let requestBody: any;
  const fetchImpl: typeof fetch = async (_input, init) => {
    requestBody = JSON.parse(String(init?.body));
    return new Response(JSON.stringify({ id: "resp_12345678", status: "completed", output: [{ type: "message", status: "completed", content: [{ type: "output_text", text: JSON.stringify({ passed: true }) }] }] }), { status: 200 });
  };
  const client = new OpenAiResponsesClient(config(), fetchImpl);
  const result = await client.createStructured({ schemaName: "test_schema", schema: { type: "object", properties: { passed: { type: "boolean" } }, required: ["passed"], additionalProperties: false }, instructions: "fixed", input: { data: "untrusted" }, maxOutputTokens: 100, timeoutMs: 5_000 });
  assert.deepEqual(result.payload, { passed: true });
  assert.equal(requestBody.text.format.type, "json_schema");
  assert.equal(requestBody.text.format.strict, true);
  assert.equal(requestBody.store, false);
  assert.equal(requestBody.tools, undefined);

  const refusing = new OpenAiResponsesClient(config(), async () => new Response(JSON.stringify({ id: "resp_12345678", status: "completed", output: [{ type: "message", status: "completed", content: [{ type: "refusal", refusal: "no" }] }] }), { status: 200 }));
  await assert.rejects(refusing.createStructured({ schemaName: "test_schema", schema: {}, instructions: "fixed", input: {}, maxOutputTokens: 100, timeoutMs: 5_000 }), (error: unknown) => error instanceof ModelProviderError && error.code === "model_refused");

  const ambiguous = new OpenAiResponsesClient(config(), async () => new Response(JSON.stringify({ id: "resp_12345678", status: "completed", output: [{ type: "message", status: "completed", content: [{ type: "output_text", text: "{}" }, { type: "unexpected" }] }] }), { status: 200 }));
  await assert.rejects(ambiguous.createStructured({ schemaName: "test_schema", schema: {}, instructions: "fixed", input: {}, maxOutputTokens: 100, timeoutMs: 5_000 }), (error: unknown) => error instanceof ModelProviderError && error.code === "model_response_invalid");
});

test("Anthropic client requests JSON Schema output and parses one completed text block", async () => {
  let requestUrl = "";
  let requestHeaders: Headers | undefined;
  let requestBody: any;
  const fetchImpl: typeof fetch = async (input, init) => {
    requestUrl = String(input);
    requestHeaders = new Headers(init?.headers);
    requestBody = JSON.parse(String(init?.body));
    return new Response(JSON.stringify({
      id: "msg_12345678",
      type: "message",
      role: "assistant",
      content: [{ type: "text", text: JSON.stringify({ passed: true }) }],
      stop_reason: "end_turn",
    }), { status: 200 });
  };
  const client = new AnthropicMessagesClient(anthropicConfig(), fetchImpl);
  const request: StructuredRequest = {
    schemaName: "test_schema",
    schema: { type: "object", properties: { passed: { type: "boolean" } }, required: ["passed"], additionalProperties: false },
    instructions: "fixed",
    input: { data: "untrusted" },
    maxOutputTokens: 100,
    timeoutMs: 5_000,
  };
  const result = await client.createStructured(request);
  assert.deepEqual(result.payload, { passed: true });
  assert.equal(requestUrl, "https://api.anthropic.com/v1/messages");
  assert.equal(requestHeaders?.get("x-api-key"), ANTHROPIC_KEY);
  assert.equal(requestHeaders?.get("anthropic-version"), "2023-06-01");
  assert.equal(requestBody.model, "claude-sonnet-4-5-20250929");
  assert.equal(requestBody.output_config.format.type, "json_schema");
  assert.deepEqual(requestBody.output_config.format.schema, request.schema);
  assert.equal(requestBody.tools, undefined);
  assert.equal(requestBody.metadata, undefined);

  const refused = new AnthropicMessagesClient(anthropicConfig(), async () => new Response(JSON.stringify({ id: "msg_12345678", type: "message", role: "assistant", content: [{ type: "text", text: "{}" }], stop_reason: "refusal" }), { status: 200 }));
  await assert.rejects(refused.createStructured(request), (error: unknown) => error instanceof ModelProviderError && error.code === "model_refused");

  const truncated = new AnthropicMessagesClient(anthropicConfig(), async () => new Response(JSON.stringify({ id: "msg_12345678", type: "message", role: "assistant", content: [{ type: "text", text: "{}" }], stop_reason: "max_tokens" }), { status: 200 }));
  await assert.rejects(truncated.createStructured(request), (error: unknown) => error instanceof ModelProviderError && error.code === "model_response_incomplete");

  let timeoutCalls = 0;
  const timedOut = new AnthropicMessagesClient(anthropicConfig(), async () => {
    timeoutCalls += 1;
    throw new DOMException("timed out", "TimeoutError");
  });
  await assert.rejects(
    timedOut.createStructured(request),
    (error: unknown) => {
      assert.ok(error instanceof ModelProviderError);
      assert.equal(error.status, 504);
      assert.equal(error.code, "model_provider_timeout");
      assert.deepEqual(error.details, { stage: "anthropic", timeoutMs: 5_000 });
      return true;
    },
  );
  assert.equal(timeoutCalls, 1);

  const rejected = new AnthropicMessagesClient(anthropicConfig(), async () => new Response(JSON.stringify({
    type: "error",
    error: {
      type: "invalid_request_error",
      message: "invalid schema sk-ant-secret-value",
    },
  }), {
    status: 400,
    headers: { "request-id": "req_debug_123" },
  }));
  await assert.rejects(
    rejected.createStructured(request),
    (error: unknown) => {
      assert.ok(error instanceof ModelProviderError);
      assert.equal(error.code, "model_provider_rejected");
      assert.match(error.message, /invalid schema \[REDACTED\]/);
      assert.doesNotMatch(JSON.stringify(error.details), /secret-value/);
      assert.deepEqual(error.details, {
        stage: "anthropic",
        providerStatus: 400,
        providerRequestId: "req_debug_123",
        providerErrorType: "invalid_request_error",
        providerMessage: "invalid schema [REDACTED]",
      });
      return true;
    },
  );

  let serverErrorCalls = 0;
  const serverError = new AnthropicMessagesClient(anthropicConfig(), async () => {
    serverErrorCalls += 1;
    return new Response(JSON.stringify({
      type: "error",
      error: { type: "api_error", message: "temporary upstream failure" },
    }), { status: 500 });
  });
  await assert.rejects(
    serverError.createStructured(request),
    (error: unknown) => error instanceof ModelProviderError
      && error.status === 503
      && error.code === "model_provider_rejected",
  );
  assert.equal(serverErrorCalls, 1);
});

test("Anthropic client removes unsupported constraints without weakening the internal schema", async () => {
  let requestBody: any;
  const schema = {
    type: "object",
    properties: {
      title: { type: "string", minLength: 3, maxLength: 120, pattern: "[가-힣]" },
      scores: {
        type: "array",
        minItems: 1,
        maxItems: 8,
        items: { type: "integer", minimum: 0, maximum: 100 },
      },
    },
    required: ["title", "scores"],
    additionalProperties: false,
  };
  const fetchImpl: typeof fetch = async (_input, init) => {
    requestBody = JSON.parse(String(init?.body));
    return new Response(JSON.stringify({
      id: "msg_12345678",
      type: "message",
      role: "assistant",
      content: [{ type: "text", text: JSON.stringify({ title: "한글 제목", scores: [100] }) }],
      stop_reason: "end_turn",
    }), { status: 200 });
  };

  const client = new AnthropicMessagesClient(anthropicConfig(), fetchImpl);
  await client.createStructured({
    schemaName: "constraint_projection",
    schema,
    instructions: "fixed",
    input: {},
    maxOutputTokens: 100,
    timeoutMs: 5_000,
  });

  assert.deepEqual(requestBody.output_config.format.schema, {
    type: "object",
    properties: {
      title: { type: "string" },
      scores: { type: "array", items: { type: "integer" } },
    },
    required: ["title", "scores"],
    additionalProperties: false,
  });
  assert.deepEqual(schema.properties.title, {
    type: "string",
    minLength: 3,
    maxLength: 120,
    pattern: "[가-힣]",
  });
  assert.deepEqual(anthropicOutputSchema(schema), requestBody.output_config.format.schema);
});

test("Anthropic client envelopes the complex generation plan and decodes it before validation", async () => {
  let requestBody: any;
  const decodedPlan = { scenario: { summary: "safe" } };
  const generationSchema = {
    type: "object",
    properties: {
      scenario: {
        type: "object",
        properties: { summary: { type: "string", minLength: 20 } },
        required: ["summary"],
        additionalProperties: false,
      },
    },
    required: ["scenario"],
    additionalProperties: false,
  };
  const fetchImpl: typeof fetch = async (_input, init) => {
    requestBody = JSON.parse(String(init?.body));
    return new Response(JSON.stringify({
      id: "msg_12345678",
      type: "message",
      role: "assistant",
      content: [{
        type: "text",
        text: JSON.stringify({ payload: JSON.stringify(decodedPlan) }),
      }],
      stop_reason: "end_turn",
    }), { status: 200 });
  };

  const client = new AnthropicMessagesClient(anthropicConfig(), fetchImpl);
  const result = await client.createStructured({
    schemaName: "codegate_lab_generation_plan_v1",
    schema: generationSchema,
    instructions: "fixed",
    input: { prompt: "untrusted" },
    maxOutputTokens: 16_000,
    timeoutMs: 5_000,
  });

  assert.deepEqual(result.payload, decodedPlan);
  assert.deepEqual(requestBody.output_config.format.schema, {
    type: "object",
    properties: { payload: { type: "string" } },
    required: ["payload"],
    additionalProperties: false,
  });
  assert.match(requestBody.system, /strictly validate the decoded payload/);
  const providerInput = JSON.parse(requestBody.messages[0].content[0].text);
  assert.deepEqual(providerInput.trustedOutputSchema, generationSchema);
  assert.deepEqual(providerInput.untrustedInput, { prompt: "untrusted" });

  const malformedBodies: any[] = [];
  const malformedSignals: AbortSignal[] = [];
  const malformed = new AnthropicMessagesClient(anthropicConfig(), async (_input, init) => {
    malformedBodies.push(JSON.parse(String(init?.body)));
    assert.ok(init?.signal);
    malformedSignals.push(init.signal);
    return new Response(JSON.stringify({
      id: "msg_malformed_12345678",
      type: "message",
      role: "assistant",
      content: [{ type: "text", text: JSON.stringify({ payload: "not-json" }) }],
      stop_reason: "end_turn",
    }), { status: 200 });
  });
  await assert.rejects(
    malformed.createStructured({
      schemaName: "codegate_lab_generation_plan_v1",
      schema: generationSchema,
      instructions: "fixed",
      input: {},
      maxOutputTokens: 100,
      timeoutMs: 5_000,
    }),
    (error: unknown) => {
      assert.ok(error instanceof ModelProviderError);
      assert.equal(error.code, "model_output_malformed");
      assert.equal(error.message, "The model provider generation payload was not JSON");
      assert.equal(error.details?.stage, "anthropic_generation_payload");
      assert.equal(error.details?.generationAttempts, 1);
      assert.equal(error.details?.providerResponseId, "msg_malformed_12345678");
      assert.equal(error.details?.payloadBytes, 8);
      assert.match(String(error.details?.payloadDigest), /^[a-f0-9]{64}$/);
      assert.equal(error.details?.parseKind, "payload_json_syntax");
      assert.doesNotMatch(JSON.stringify(error), /not-json|Unexpected|SyntaxError/);
      return true;
    },
  );
  assert.equal(malformedBodies.length, 1);
  assert.equal(malformedSignals.length, 1);
  assert.doesNotMatch(malformedBodies[0].system, /Correction retry/);
  assert.match(malformedBodies[0].system, /complete minified JSON object/);
  assert.match(malformedBodies[0].system, /Do not put Markdown, code fences, prose, prefixes, or suffixes in payload/);
  assert.match(malformedBodies[0].system, /never emit literal U\+0000 through U\+001F/);
});

test("Anthropic generation accepts only whole JSON with BOM or exact JSON/plain fences", async () => {
  const generationSchema = {
    type: "object",
    properties: { scenario: { type: "object" } },
    required: ["scenario"],
    additionalProperties: false,
  };
  const request: StructuredRequest = {
    schemaName: "codegate_lab_generation_plan_v1",
    schema: generationSchema,
    instructions: "fixed",
    input: {},
    maxOutputTokens: 100,
    timeoutMs: 5_000,
  };
  const expected = { scenario: { summary: "safe" } };
  for (const payload of [
    `\uFEFF  ${JSON.stringify(expected)}  `,
    `\uFEFF\n\`\`\`json\n${JSON.stringify(expected)}\n\`\`\``,
    `\`\`\`\n${JSON.stringify(expected)}\n\`\`\``,
  ]) {
    let calls = 0;
    const client = new AnthropicMessagesClient(anthropicConfig(), async () => {
      calls += 1;
      return new Response(JSON.stringify({
        id: `msg_normalized_${calls}`,
        type: "message",
        role: "assistant",
        content: [{ type: "text", text: JSON.stringify({ payload }) }],
        stop_reason: "end_turn",
      }), { status: 200 });
    });
    assert.deepEqual((await client.createStructured(request)).payload, expected);
    assert.equal(calls, 1);
  }

  for (const payload of [
    `result: ${JSON.stringify(expected)}`,
    `${JSON.stringify(expected)} trailing prose`,
    '{"scenario":{},}',
    `\u00A0${JSON.stringify(expected)}\u00A0`,
  ]) {
    let calls = 0;
    const client = new AnthropicMessagesClient(anthropicConfig(), async () => {
      calls += 1;
      return new Response(JSON.stringify({
        id: `msg_strict_${calls}`,
        type: "message",
        role: "assistant",
        content: [{ type: "text", text: JSON.stringify({ payload }) }],
        stop_reason: "end_turn",
      }), { status: 200 });
    });
    await assert.rejects(
      client.createStructured(request),
      (error: unknown) => error instanceof ModelProviderError && error.code === "model_output_malformed",
    );
    assert.equal(calls, 1);
  }
});

test("Anthropic generation retries malformed JSON only when configured and preserves the absolute timeout signal", async () => {
  const requestBodies: any[] = [];
  const requestSignals: AbortSignal[] = [];
  const expected = { scenario: { summary: "corrected" } };
  const client = new AnthropicMessagesClient({ ...anthropicConfig(), generationMaxAttempts: 2 }, async (_input, init) => {
    requestBodies.push(JSON.parse(String(init?.body)));
    assert.ok(init?.signal);
    requestSignals.push(init.signal);
    const payload = requestBodies.length === 1 ? "{broken" : JSON.stringify(expected);
    return new Response(JSON.stringify({
      id: `msg_retry_${requestBodies.length}`,
      type: "message",
      role: "assistant",
      content: [{ type: "text", text: JSON.stringify({ payload }) }],
      stop_reason: "end_turn",
    }), { status: 200 });
  });

  const result = await client.createStructured({
    schemaName: "codegate_lab_generation_plan_v1",
    schema: { type: "object", properties: { scenario: { type: "object" } }, required: ["scenario"], additionalProperties: false },
    instructions: "fixed",
    input: { prompt: "untrusted" },
    maxOutputTokens: 100,
    timeoutMs: 5_000,
  });

  assert.deepEqual(result.payload, expected);
  assert.equal(result.responseId, "msg_retry_2");
  assert.equal(requestBodies.length, 2);
  // The official SDK composes the shared absolute deadline into a fresh
  // transport signal for each HTTP attempt.
  assert.notEqual(requestSignals[0], requestSignals[1]);
  assert.equal(requestSignals.every((signal) => !signal.aborted), true);
  assert.deepEqual(requestBodies[0].messages, requestBodies[1].messages);
  assert.deepEqual(requestBodies[0].output_config, requestBodies[1].output_config);
  assert.match(requestBodies[1].system, /Correction retry/);
});

test("Anthropic generation capture receives the exact successful response bytes before parsing", async () => {
  assert.equal(GENERATION_RAW_RESPONSE_CAPTURE_PATH, "/tmp/zerotop-generation-provider-response.json");
  const captured: Buffer[] = [];
  const invalidProviderBody = Buffer.from([0x7b, 0x22, 0x62, 0x61, 0x64, 0x22, 0x3a, 0xff, 0x7d]);
  const client = new AnthropicMessagesClient(
    { ...anthropicConfig(), captureGenerationRawResponse: true },
    async () => new Response(invalidProviderBody, { status: 200 }),
    async (raw) => {
      captured.push(Buffer.from(raw));
    },
  );

  await assert.rejects(
    client.createStructured({
      schemaName: "codegate_lab_generation_plan_v1",
      schema: { type: "object", properties: {}, additionalProperties: false },
      instructions: "fixed",
      input: {},
      maxOutputTokens: 100,
      timeoutMs: 5_000,
    }),
    (error: unknown) => error instanceof ModelProviderError && error.code === "model_response_malformed",
  );
  assert.equal(captured.length, 1);
  assert.deepEqual(captured[0], invalidProviderBody);
});

test("Anthropic generation capture uses the fixed path, exclusive create, and mode 0600", async () => {
  const events: string[] = [];
  let written: Buffer | undefined;
  const raw = Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xff, 0x7d]);
  await writeGenerationRawResponseCapture(raw, async (path, flags, mode) => {
    assert.equal(path, "/tmp/zerotop-generation-provider-response.json");
    assert.equal(flags, "wx");
    assert.equal(mode, 0o600);
    events.push("open");
    return {
      async chmod(fileMode) {
        assert.equal(fileMode, 0o600);
        events.push("chmod");
      },
      async writeFile(data) {
        written = Buffer.from(data);
        events.push("write");
      },
      async sync() {
        events.push("sync");
      },
      async close() {
        events.push("close");
      },
    };
  });
  assert.deepEqual(written, raw);
  assert.deepEqual(events, ["open", "chmod", "write", "sync", "close"]);
});

test("Anthropic raw capture is generation-only and fails explicitly without exposing response data", async () => {
  let captureCalls = 0;
  const regular = new AnthropicMessagesClient(
    { ...anthropicConfig(), captureGenerationRawResponse: true },
    async () => new Response(JSON.stringify({
      id: "msg_regular_12345678",
      type: "message",
      role: "assistant",
      content: [{ type: "text", text: JSON.stringify({ passed: true }) }],
      stop_reason: "end_turn",
    }), { status: 200 }),
    async () => {
      captureCalls += 1;
    },
  );
  const request: StructuredRequest = {
    schemaName: "test_schema",
    schema: { type: "object", properties: { passed: { type: "boolean" } }, required: ["passed"], additionalProperties: false },
    instructions: "fixed",
    input: {},
    maxOutputTokens: 100,
    timeoutMs: 5_000,
  };
  assert.deepEqual((await regular.createStructured(request)).payload, { passed: true });
  assert.equal(captureCalls, 0);

  const sensitiveRaw = JSON.stringify({
    id: "msg_capture_failure_12345678",
    type: "message",
    role: "assistant",
    content: [{ type: "text", text: JSON.stringify({ payload: "sensitive-model-output" }) }],
    stop_reason: "end_turn",
  });
  const captureFailure = new AnthropicMessagesClient(
    { ...anthropicConfig(), captureGenerationRawResponse: true },
    async () => new Response(sensitiveRaw, { status: 200 }),
    async () => {
      throw new Error(`write failed: ${sensitiveRaw}`);
    },
  );
  await assert.rejects(
    captureFailure.createStructured({ ...request, schemaName: "codegate_lab_generation_plan_v1" }),
    (error: unknown) => {
      assert.ok(error instanceof ModelProviderError);
      assert.equal(error.status, 500);
      assert.equal(error.code, "model_response_capture_failed");
      assert.equal(error.message, "The Anthropic generation response could not be captured");
      assert.deepEqual(error.details, {
        stage: "anthropic_generation_raw_response_capture",
        capturePath: "/tmp/zerotop-generation-provider-response.json",
      });
      assert.doesNotMatch(JSON.stringify(error), /sensitive-model-output|write failed/);
      return true;
    },
  );
});

test("HTTP boundary requires bearer auth and enforces JSON", async () => {
  const service = new ModelGatewayService(config(), new QueueClient([generationPlan()]));
  const server = createModelGatewayServer(config(), service);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    assert.equal((await fetch(`${base}/health`)).status, 200);
    assert.equal((await fetch(`${base}/v1/generate`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status, 401);
    assert.equal((await fetch(`${base}/v1/generate`, { method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "text/plain" }, body: "{}" })).status, 415);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("authenticated slow bodies consume the bounded concurrency slot", async () => {
  const limitedConfig = { ...config(), maxConcurrency: 1 };
  const server = createModelGatewayServer(limitedConfig, new ModelGatewayService(limitedConfig, new QueueClient([generationPlan()])));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const socket = createConnection(address.port, "127.0.0.1");
  await once(socket, "connect");
  socket.write(`POST /v1/generate HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ${TOKEN}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{`);
  await new Promise((resolve) => setTimeout(resolve, 20));
  try {
    const response = await fetch(`http://127.0.0.1:${address.port}/v1/generate`, {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(response.status, 429);
  } finally {
    socket.destroy();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

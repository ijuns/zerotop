import assert from "node:assert/strict";
import { once } from "node:events";
import { createConnection } from "node:net";
import { test } from "node:test";

import { loadConfig, type GatewayConfig } from "../src/config.ts";
import { OpenAiResponsesClient, ModelProviderError, type StructuredRequest, type StructuredResponse } from "../src/openai.ts";
import { createModelGatewayServer } from "../src/server.ts";
import { ModelGatewayService, type ModelClient } from "../src/service.ts";

const TOKEN = "gateway-internal-token-000000000000000000";
const KEY = "sk-test-000000000000000000000000000000000";
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
    },
  };
}

function generationPlan() {
  return {
    scenario: {
      summary: "Investigate an isolated identity authorization chain using defensive evidence.",
      logSources: ["waf", "edr", "firewall", "linux_audit"],
      attackChain: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" }],
    },
    learning: {
      summary: "Correlate target behavior, telemetry, ATT&CK, detection, and mitigation evidence.",
      prerequisites: ["Linux and HTTP fundamentals"],
      objectives: ["Connect observed evidence to a defensive response"],
      sections: [
        { id: "context", title: "Scenario context", bodyMarkdown: "## Context\n\nReview the isolated scenario scope and trusted evidence sources." },
        { id: "workflow", title: "Investigation workflow", bodyMarkdown: "## Workflow\n\nCorrelate timestamps, identity records, and ATT&CK techniques." },
      ],
    },
    questions: [
      {
        id: "blue-q1", type: "elk_search", prompt: "Select the telemetry evidence that establishes the first suspicious request.", points: 30, options: null,
        answer: { optionIds: null, techniqueIds: null, expectedEvidenceIds: ["event-1"], rubricId: null },
      },
      {
        id: "blue-q2", type: "mitre_attack", prompt: "Select the ATT&CK technique represented by the observed request chain.", points: 20, options: null,
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
});

test("generation assembles immutable scope, hides answers, and emits a builder-compatible projection", async () => {
  const client = new QueueClient([generationPlan()]);
  const service = new ModelGatewayService(config(), client, () => new Date("2026-07-21T12:00:00.000Z"), () => "11111111-1111-4111-8111-111111111111");
  const result = await service.generate(generationInput());
  assert.equal(result.team, "blue");
  assert.equal((result.questions as Array<Record<string, unknown>>)[0]?.answerKey, undefined);
  assert.deepEqual((result.gradingQuestions as Array<Record<string, unknown>>)[0]?.answerKey, { expectedEvidenceIds: ["event-1"] });
  const spec = result.environmentBuildSpec as Record<string, any>;
  assert.equal(spec.learning.sections[0].markdown.startsWith("## Context"), true);
  assert.equal(spec.learning.sections[0].bodyMarkdown, undefined);
  assert.deepEqual(spec.scenario.mitreTechniques, ["T1190"]);
  assert.match(spec.grading.hiddenRefs[0].refId, /^grading:\/\//);
  assert.equal(spec.target.baseImage, BASE_IMAGE);
  assert.equal(client.requests[0]?.timeoutMs, 40_000);
  assert.equal((client.requests[0]?.schema as any).additionalProperties, false);
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

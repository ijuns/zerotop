import { createHash } from "node:crypto";
import { parseTargetRuntimeContract } from "./runtime-contract.ts";
import type { TargetRuntimeContract } from "./contracts.ts";

export type ValidationTeam = "blue" | "red";
export type ValidationProtocol = "http" | "tcp";

export interface ValidationProbe {
  id: string;
  kind: "http" | "tcp_banner";
  method?: "GET" | "HEAD";
  path?: string;
  expectedStatuses?: number[];
  bodyIncludes?: string[];
  bannerIncludes?: string[];
  cveId?: string;
  findingId?: string;
}

export interface TelemetryValidationEvent {
  id: string;
  document: Record<string, unknown>;
}

export interface SandboxValidationInput {
  labId: string;
  team: ValidationTeam;
  image: string;
  expectedCves: string[];
  service: { port: number; protocol: ValidationProtocol };
  runtimeContract: TargetRuntimeContract;
  functionalProbes: ValidationProbe[];
  vulnerabilityProbes: ValidationProbe[];
  questions: Array<Record<string, unknown>>;
  attackTechniqueIds: string[];
  telemetryEvents: TelemetryValidationEvent[];
  questionsRendered: boolean;
  gradingVerified: boolean;
  answerLeakageDetected: boolean;
  mitreMappingsVerified: boolean;
}

export function parseSandboxValidationRequest(
  value: unknown,
  allowedRegistries: string[],
): SandboxValidationInput {
  const request = record(value, "request");
  const lab = record(request.lab, "lab");
  const config = record(lab.config, "lab.config");
  const target = record(config.target, "lab.config.target");
  const validation = record(config.validation, "lab.config.validation");
  const runtimeContract = parseTargetRuntimeContract(target.runtimeContract, "lab.config.target.runtimeContract");
  const labId = safeIdentifier(lab.id, "lab.id");
  if (lab.team !== "blue" && lab.team !== "red") throw new Error("lab.team must be blue or red");
  const team = lab.team;
  const image = imageReference(request.image, allowedRegistries);
  const [imageRef, digest] = image.split("@") as [string, string];
  if (target.imageRef !== imageRef || String(target.imageDigest).toLowerCase() !== digest.toLowerCase()) {
    throw new Error("The validation image does not match lab.config.target");
  }
  const targetService = optionalService(target.service, "lab.config.target.service");
  const validationService = optionalService(validation.service, "lab.config.validation.service");
  const selectedService = targetService ?? validationService;
  if (!selectedService) throw new Error("target.service or validation.service is required");
  if (targetService && validationService &&
    (targetService.port !== validationService.port || targetService.protocol !== validationService.protocol)) {
    throw new Error("target.service and validation.service must match");
  }
  const { protocol, port } = selectedService;
  if (protocol !== runtimeContract.protocol || port !== runtimeContract.port) {
    throw new Error("target service must match the supported target runtime contract");
  }
  const functionalProbes = probeList(validation.functionalProbes, "functionalProbes", protocol, false);
  const vulnerabilityProbes = probeList(validation.vulnerabilityProbes, "vulnerabilityProbes", protocol, true);
  if (functionalProbes.length === 0 || vulnerabilityProbes.length === 0) {
    throw new Error("Functional and vulnerability validation probes are required");
  }
  const expectedCves = cveList(target.expectedCves ?? validation.expectedCves);
  for (const cve of expectedCves) {
    if (!vulnerabilityProbes.some((probe) => probe.cveId === cve)) {
      throw new Error(`No black-box vulnerability probe covers ${cve}`);
    }
  }

  const questions = objectList(config.questions, "lab.config.questions", 20);
  const assessment = assessQuestions(team, questions);
  const attackTechniqueIds = attackTechniques(config);
  const telemetryEvents = telemetry(validation, team);
  return {
    labId,
    team,
    image,
    expectedCves,
    service: { port, protocol },
    runtimeContract,
    functionalProbes,
    vulnerabilityProbes,
    questions,
    attackTechniqueIds,
    telemetryEvents,
    ...assessment,
    answerLeakageDetected: containsAnswerLeakage(lab),
    mitreMappingsVerified:
      attackTechniqueIds.length > 0 &&
      questions.some((question) => question.type === "mitre_attack"),
  };
}

export function validationNamespace(labId: string, nonce: string): string {
  const suffix = createHash("sha256").update(`${labId}:${nonce}`).digest("hex").slice(0, 16);
  return `validation-${suffix}`;
}

function probeList(
  value: unknown,
  name: string,
  protocol: ValidationProtocol,
  findingRequired: boolean,
): ValidationProbe[] {
  if (!Array.isArray(value) || value.length > 20) throw new Error(`${name} must contain at most 20 entries`);
  return value.map((item, index) => {
    const probe = record(item, `${name}[${index}]`);
    const id = safeIdentifier(probe.id, `${name}[${index}].id`, 80);
    const cveId = probe.cveId === undefined ? undefined : cve(probe.cveId, `${name}[${index}].cveId`);
    const findingId = probe.findingId === undefined ? undefined : safeIdentifier(probe.findingId, `${name}[${index}].findingId`, 80);
    if (findingRequired && !cveId && !findingId) throw new Error(`${name}[${index}] requires cveId or findingId`);
    if (protocol === "http" && probe.kind === "http") {
      if (probe.method !== "GET" && probe.method !== "HEAD") throw new Error(`${name}[${index}].method is invalid`);
      const path = stringValue(probe.path, `${name}[${index}].path`, 500);
      if (!path.startsWith("/") || path.startsWith("//") || path.includes("://") || /[\u0000-\u001f\\]/.test(path)) {
        throw new Error(`${name}[${index}].path is unsafe`);
      }
      if (!Array.isArray(probe.expectedStatuses) || probe.expectedStatuses.length < 1 || probe.expectedStatuses.length > 8) {
        throw new Error(`${name}[${index}].expectedStatuses is invalid`);
      }
      const expectedStatuses = [...new Set(probe.expectedStatuses.map((status) => integer(status, "HTTP status", 100, 599)))];
      const bodyIncludes = markerList(probe.bodyIncludes, `${name}[${index}].bodyIncludes`);
      return { id, kind: "http", method: probe.method, path, expectedStatuses, bodyIncludes, ...(cveId ? { cveId } : {}), ...(findingId ? { findingId } : {}) };
    }
    if (protocol === "tcp" && probe.kind === "tcp_banner") {
      const bannerIncludes = markerList(probe.bannerIncludes, `${name}[${index}].bannerIncludes`);
      if (bannerIncludes.length === 0) throw new Error(`${name}[${index}] requires a banner marker`);
      return { id, kind: "tcp_banner", bannerIncludes, ...(cveId ? { cveId } : {}), ...(findingId ? { findingId } : {}) };
    }
    throw new Error(`${name}[${index}] does not match validation.service.protocol`);
  });
}

function assessQuestions(team: ValidationTeam, questions: Array<Record<string, unknown>>): {
  questionsRendered: boolean;
  gradingVerified: boolean;
} {
  const allowed = team === "blue"
    ? new Set(["elk_search", "mitre_attack"])
    : new Set(["single_choice", "multiple_choice", "free_text", "mitre_attack"]);
  const types = new Set<string>();
  let valid = questions.length > 0;
  for (const question of questions) {
    const type = typeof question.type === "string" ? question.type : "";
    types.add(type);
    valid = valid && allowed.has(type)
      && typeof question.id === "string"
      && typeof question.prompt === "string"
      && Number.isInteger(question.points)
      && Number(question.points) > 0;
  }
  if (team === "blue") valid = valid && types.size === 2 && types.has("elk_search") && types.has("mitre_attack");
  return { questionsRendered: valid, gradingVerified: valid && [...types].every((type) => allowed.has(type)) };
}

function attackTechniques(config: Record<string, unknown>): string[] {
  const scenario = record(config.scenario, "lab.config.scenario");
  const direct = Array.isArray(scenario.mitreTechniques) ? scenario.mitreTechniques : [];
  const chain = Array.isArray(scenario.attackChain)
    ? scenario.attackChain.map((item) => record(item, "attackChain item").id)
    : [];
  return [...new Set([...direct, ...chain].map((item) => stringValue(item, "ATT&CK technique", 16).toUpperCase()))]
    .filter((item) => /^T\d{4}(?:\.\d{3})?$/.test(item));
}

function telemetry(validation: Record<string, unknown>, team: ValidationTeam): TelemetryValidationEvent[] {
  if (team !== "blue") return [];
  const input = record(validation.telemetry, "lab.config.validation.telemetry");
  if (!Array.isArray(input.events) || input.events.length < 1 || input.events.length > 100) {
    throw new Error("Blue-team validation requires 1-100 telemetry events");
  }
  return input.events.map((item, index) => {
    const event = record(item, `telemetry.events[${index}]`);
    const id = safeIdentifier(event.id, `telemetry.events[${index}].id`, 128);
    const document = record(event.document, `telemetry.events[${index}].document`);
    const encoded = JSON.stringify(document);
    if (encoded.length > 32_000) throw new Error(`telemetry.events[${index}] is too large`);
    return { id, document };
  });
}

function containsAnswerLeakage(value: unknown, depth = 0): boolean {
  if (depth > 12) return true;
  if (Array.isArray(value)) return value.some((item) => containsAnswerLeakage(item, depth + 1));
  if (typeof value !== "object" || value === null) return false;
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (/^(?:answer|answerkey|correct(?:answer|option|options?)?|solution|flag)$/i.test(key)) return true;
    if (containsAnswerLeakage(item, depth + 1)) return true;
  }
  return false;
}

function markerList(value: unknown, name: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 8) throw new Error(`${name} is invalid`);
  return [...new Set(value.map((item, index) => stringValue(item, `${name}[${index}]`, 200)))];
}

function cveList(value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 20) throw new Error("expectedCves is invalid");
  return [...new Set(value.map((item, index) => cve(item, `expectedCves[${index}]`)))];
}

function optionalService(value: unknown, name: string): { port: number; protocol: ValidationProtocol } | undefined {
  if (value === undefined) return undefined;
  const service = record(value, name);
  if (service.protocol !== "http" && service.protocol !== "tcp") {
    throw new Error(`${name}.protocol must be http or tcp`);
  }
  return {
    port: integer(service.port, `${name}.port`, 1, 65535),
    protocol: service.protocol,
  };
}

function cve(value: unknown, name: string): string {
  const result = stringValue(value, name, 24).toUpperCase();
  if (!/^CVE-\d{4}-\d{4,7}$/.test(result)) throw new Error(`${name} is invalid`);
  return result;
}

function imageReference(value: unknown, allowedRegistries: string[]): string {
  const image = stringValue(value, "image", 512);
  if (!/^[a-z0-9.-]+(?::\d+)?\/[a-z0-9._/-]+(?::[a-z0-9._-]+)?@sha256:[a-f0-9]{64}$/i.test(image)) {
    throw new Error("image must be a digest-pinned OCI reference");
  }
  const registry = image.split("/", 1)[0]?.toLowerCase() ?? "";
  if (!allowedRegistries.includes(registry)) throw new Error("image registry is not allow-listed");
  return image;
}

function objectList(value: unknown, name: string, maximum: number): Array<Record<string, unknown>> {
  if (!Array.isArray(value) || value.length > maximum) throw new Error(`${name} is invalid`);
  return value.map((item, index) => record(item, `${name}[${index}]`));
}

function safeIdentifier(value: unknown, name: string, maximum = 63): string {
  const result = stringValue(value, name, maximum);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(result)) throw new Error(`${name} is invalid`);
  return result;
}

function integer(value: unknown, name: string, minimum: number, maximum: number): number {
  const result = Number(value);
  if (!Number.isInteger(result) || result < minimum || result > maximum) throw new Error(`${name} is invalid`);
  return result;
}

function stringValue(value: unknown, name: string, maximum: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) throw new Error(`${name} is invalid`);
  return value;
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value as Record<string, unknown>;
}

import type {
  LabRuntimeTopology,
  ProvisionRunRequest,
  RedTargetExercise,
  ScenarioTelemetryGeneration,
  ScenarioTelemetryEvent,
} from "./contracts.ts";
import { parseTargetRuntimeContract } from "./runtime-contract.ts";

export interface ProvisionValidationOptions {
  runtimeMode: string;
  allowedTargetRegistries?: string[];
}

export function validateProvisionRequest(
  value: unknown,
  options: ProvisionValidationOptions,
): ProvisionRunRequest {
  if (!isRecord(value)) throw new Error("Request body must be an object");

  const runId = validateRunId(value.runId);
  const labId = safeIdentifier(value.labId, "labId");
  const userId = safeIdentifier(value.userId, "userId");
  if (value.desktopImage !== "ubuntu" && value.desktopImage !== "kali") {
    throw new Error("desktopImage must be ubuntu or kali");
  }
  if (!["browser_desktop", "openvpn", "both"].includes(String(value.accessMethod))) {
    throw new Error("accessMethod must be browser_desktop, openvpn or both");
  }
  if (
    !Number.isInteger(value.ttlMinutes) ||
    Number(value.ttlMinutes) < 10 ||
    Number(value.ttlMinutes) > 240
  ) {
    throw new Error("ttlMinutes must be an integer between 10 and 240");
  }
  if (typeof value.targetImage !== "string" || value.targetImage.length > 512) {
    throw new Error("targetImage must be a valid image reference");
  }
  validateTargetImage(value.targetImage, options);
  if (!isRecord(value.targetService)) {
    throw new Error("targetService must be an object");
  }
  const targetPort = Number(value.targetService.port);
  if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
    throw new Error("targetService.port must be an integer between 1 and 65535");
  }
  if (value.targetService.protocol !== "http" && value.targetService.protocol !== "tcp") {
    throw new Error("targetService.protocol must be http or tcp");
  }
  const targetRuntimeContract = parseTargetRuntimeContract(value.targetRuntimeContract);
  if (
    targetPort !== targetRuntimeContract.port
    || value.targetService.protocol !== targetRuntimeContract.protocol
  ) throw new Error("targetService must match targetRuntimeContract");

  const topology = value.topology === undefined
    ? undefined
    : parseTopology(value.topology, value.desktopImage, targetPort);

  return {
    runId,
    labId,
    userId,
    desktopImage: value.desktopImage,
    accessMethod: value.accessMethod as ProvisionRunRequest["accessMethod"],
    ttlMinutes: Number(value.ttlMinutes),
    targetImage: value.targetImage,
    targetService: {
      port: targetPort,
      protocol: value.targetService.protocol,
    },
    targetRuntimeContract,
    ...(topology ? { topology } : {}),
  };
}

function parseTopology(
  value: unknown,
  desktopImage: "ubuntu" | "kali",
  targetPort: number,
): LabRuntimeTopology {
  if (!isRecord(value)) throw new Error("topology must be an object");
  if (value.schemaVersion !== 1 || value.isolation !== "per_run") {
    throw new Error("topology must use schemaVersion=1 and per_run isolation");
  }
  if (value.team !== "blue" && value.team !== "red") {
    throw new Error("topology.team must be blue or red");
  }
  if (!isRecord(value.workstation) || !isRecord(value.target)) {
    throw new Error("topology requires workstation and target roles");
  }
  const blue = value.team === "blue";
  const expectedDesktop = blue ? "ubuntu" : "kali";
  const expectedWorkstationRole = blue ? "soc_analyst" : "attack_operator";
  const expectedTargetRole = blue ? "monitored_target" : "vulnerable_target";
  const expectedEntrypoint = blue ? "kibana" : "target";
  if (
    desktopImage !== expectedDesktop
    || value.workstation.desktopImage !== expectedDesktop
    || value.workstation.role !== expectedWorkstationRole
    || value.workstation.entrypoint !== expectedEntrypoint
    || value.target.role !== expectedTargetRole
    || value.target.hostname !== "target"
  ) {
    throw new Error("topology roles do not match the selected team and desktop image");
  }

  if (!blue) {
    if (value.telemetry !== undefined) {
      throw new Error("red-team topology must not provision a defensive telemetry stack");
    }
    const exercise = value.target.exercise === undefined
      ? undefined
      : parseRedTargetExercise(value.target.exercise, targetPort);
    return {
      schemaVersion: 1,
      team: "red",
      isolation: "per_run",
      workstation: {
        role: "attack_operator",
        desktopImage: "kali",
        entrypoint: "target",
      },
      target: {
        role: "vulnerable_target",
        hostname: "target",
        ...(exercise ? { exercise } : {}),
      },
    };
  }

  if (!isRecord(value.telemetry)) {
    throw new Error("blue-team topology requires Elastic telemetry");
  }
  if (
    value.telemetry.stack !== "elastic"
    || value.telemetry.collector !== "elastic_agent"
    || value.telemetry.generator !== "scenario_log_generator"
  ) {
    throw new Error("blue-team topology requires Elasticsearch/Kibana, Elastic Agent and a scenario log generator");
  }
  const index = value.telemetry.index;
  if (typeof index !== "string" || !/^[a-z0-9][a-z0-9._-]{0,126}-\*$/.test(index)) {
    throw new Error("topology.telemetry.index must be a bounded lowercase wildcard index");
  }
  if (!Array.isArray(value.telemetry.events) || value.telemetry.events.length < 1 || value.telemetry.events.length > 100) {
    throw new Error("blue-team topology requires 1-100 scenario telemetry events");
  }
  const events = value.telemetry.events.map((event, indexValue) =>
    parseScenarioEvent(event, indexValue));
  const encodedSize = Buffer.byteLength(JSON.stringify(events), "utf8");
  if (encodedSize > 256_000) throw new Error("topology telemetry exceeds 256 KB");
  const generation = value.telemetry.generation === undefined
    ? undefined
    : parseTelemetryGeneration(value.telemetry.generation, events.length);
  void targetPort;
  return {
    schemaVersion: 1,
    team: "blue",
    isolation: "per_run",
    workstation: {
      role: "soc_analyst",
      desktopImage: "ubuntu",
      entrypoint: "kibana",
    },
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

const RED_EXERCISE_PROFILES = {
  command_injection: {
    path: "/api/diagnostics?host=127.0.0.1%3Bid",
    marker: "ZEROTOP_COMMAND_INJECTION_CONFIRMED",
  },
  path_traversal: {
    path: "/download?file=../../../../etc/passwd",
    marker: "ZEROTOP_PATH_TRAVERSAL_CONFIRMED",
  },
  sql_injection: {
    path: "/api/users?id=1%20OR%201=1",
    marker: "ZEROTOP_SQL_INJECTION_CONFIRMED",
  },
  auth_bypass: {
    path: "/admin?role=admin",
    marker: "ZEROTOP_AUTH_BYPASS_CONFIRMED",
  },
  sensitive_data_exposure: {
    path: "/api/debug?view=config",
    marker: "ZEROTOP_SENSITIVE_DATA_EXPOSURE_CONFIRMED",
  },
} as const;

function parseRedTargetExercise(value: unknown, targetPort: number): RedTargetExercise {
  if (!isRecord(value)) throw new Error("topology.target.exercise must be an object");
  const allowed = new Set([
    "schemaVersion", "profile", "scenarioId", "title", "summary", "expectedCves",
    "service", "verification", "attackTechniqueIds", "simulationMode",
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new Error("topology.target.exercise contains unsupported fields");
  }
  if (value.schemaVersion !== 1 || value.simulationMode !== "bounded_behavioral") {
    throw new Error("topology.target.exercise must use the bounded schemaVersion=1 contract");
  }
  const profile = value.profile;
  if (typeof profile !== "string" || !(profile in RED_EXERCISE_PROFILES)) {
    throw new Error("topology.target.exercise.profile is invalid");
  }
  const selected = RED_EXERCISE_PROFILES[profile as keyof typeof RED_EXERCISE_PROFILES];
  if (typeof value.scenarioId !== "string" || !/^red-[a-f0-9]{16}$/.test(value.scenarioId)) {
    throw new Error("topology.target.exercise.scenarioId is invalid");
  }
  const title = boundedDisplayText(value.title, "topology.target.exercise.title", 120);
  const summary = boundedDisplayText(value.summary, "topology.target.exercise.summary", 500);
  if (!isRecord(value.service)
    || value.service.scheme !== "http"
    || value.service.host !== "target"
    || value.service.port !== 8_080
    || value.service.baseUrl !== "http://target:8080"
    || targetPort !== 8_080) {
    throw new Error("topology.target.exercise.service must use the isolated target:8080 service");
  }
  if (!isRecord(value.verification)
    || value.verification.method !== "GET"
    || value.verification.path !== selected.path
    || value.verification.successMarker !== selected.marker) {
    throw new Error("topology.target.exercise.verification is not an operator-approved profile");
  }
  const expectedCves = parseStringList(
    value.expectedCves,
    "topology.target.exercise.expectedCves",
    20,
    /^CVE-\d{4}-\d{4,7}$/,
  );
  const attackTechniqueIds = parseStringList(
    value.attackTechniqueIds,
    "topology.target.exercise.attackTechniqueIds",
    20,
    /^T\d{4}(?:\.\d{3})?$/,
  );
  const exercise: RedTargetExercise = {
    schemaVersion: 1,
    profile: profile as RedTargetExercise["profile"],
    scenarioId: value.scenarioId,
    title,
    summary,
    expectedCves,
    service: { scheme: "http", host: "target", port: 8_080, baseUrl: "http://target:8080" },
    verification: { method: "GET", path: selected.path, successMarker: selected.marker },
    attackTechniqueIds,
    simulationMode: "bounded_behavioral",
  };
  if (Buffer.byteLength(JSON.stringify(exercise), "utf8") > 16_384) {
    throw new Error("topology.target.exercise exceeds 16 KB");
  }
  return exercise;
}

function boundedDisplayText(value: unknown, field: string, maximum: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`${field} is invalid`);
  }
  return value;
}

function parseStringList(
  value: unknown,
  field: string,
  maximum: number,
  pattern: RegExp,
): string[] {
  if (!Array.isArray(value) || value.length > maximum || !value.every((item) => typeof item === "string" && pattern.test(item))) {
    throw new Error(`${field} is invalid`);
  }
  const result = [...new Set(value as string[])];
  if (result.length !== value.length) throw new Error(`${field} must not contain duplicates`);
  return result;
}

function parseTelemetryGeneration(value: unknown, seedEventCount: number): ScenarioTelemetryGeneration {
  if (!isRecord(value)) throw new Error("topology.telemetry.generation must be an object");
  if (value.schemaVersion !== 1) throw new Error("topology.telemetry.generation.schemaVersion must be 1");
  if (![
    "powershell_rce_exfiltration",
    "credential_abuse",
    "ransomware",
    "webshell",
    "generic_intrusion",
    "generic_endpoint_activity",
  ].includes(String(value.profile))) {
    throw new Error("topology.telemetry.generation.profile is invalid");
  }
  const totalEvents = Number(value.totalEvents);
  if (!Number.isInteger(totalEvents) || totalEvents < 100 || totalEvents > 5_000 || totalEvents < seedEventCount) {
    throw new Error("topology.telemetry.generation.totalEvents must be between 100 and 5,000 and cover all seed events");
  }
  const timeRangeMinutes = Number(value.timeRangeMinutes);
  if (!Number.isInteger(timeRangeMinutes) || timeRangeMinutes < 15 || timeRangeMinutes > 240) {
    throw new Error("topology.telemetry.generation.timeRangeMinutes must be between 15 and 240");
  }
  if (typeof value.seed !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value.seed)) {
    throw new Error("topology.telemetry.generation.seed is invalid");
  }
  if (typeof value.timelineAnchor !== "string" || !Number.isFinite(Date.parse(value.timelineAnchor))) {
    throw new Error("topology.telemetry.generation.timelineAnchor is invalid");
  }
  return {
    schemaVersion: 1,
    profile: value.profile as ScenarioTelemetryGeneration["profile"],
    totalEvents,
    timeRangeMinutes,
    seed: value.seed,
    timelineAnchor: new Date(value.timelineAnchor).toISOString(),
  };
}

function parseScenarioEvent(value: unknown, index: number): ScenarioTelemetryEvent {
  if (!isRecord(value) || typeof value.id !== "string" || !isRecord(value.document)) {
    throw new Error(`topology.telemetry.events[${index}] is invalid`);
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value.id)) {
    throw new Error(`topology.telemetry.events[${index}].id is invalid`);
  }
  if (
    typeof value.document["@timestamp"] !== "string"
    || !isRecord(value.document.event)
    || !isRecord(value.document.threat)
  ) {
    throw new Error(`topology.telemetry.events[${index}] must contain ECS timestamp, event and threat fields`);
  }
  const documentSize = Buffer.byteLength(JSON.stringify(value.document), "utf8");
  if (documentSize > 32_000) {
    throw new Error(`topology.telemetry.events[${index}] exceeds 32 KB`);
  }
  if (containsAnswerMaterial(value.document)) {
    throw new Error(`topology.telemetry.events[${index}] contains answer material`);
  }
  return { id: value.id, document: value.document };
}

function containsAnswerMaterial(value: unknown, depth = 0): boolean {
  if (depth > 12) return true;
  if (Array.isArray(value)) return value.some((item) => containsAnswerMaterial(item, depth + 1));
  if (!isRecord(value)) return false;
  return Object.entries(value).some(([key, item]) =>
    /^(?:answer|answerkey|correct(?:answer|option|options?)?|solution|flag)$/i.test(key)
    || containsAnswerMaterial(item, depth + 1));
}

export function validateRunId(value: unknown): string {
  return safeIdentifier(value, "runId");
}

function safeIdentifier(value: unknown, field: string): string {
  if (
    typeof value !== "string" ||
    !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$/.test(value)
  ) {
    throw new Error(`${field} must be a 1-63 character safe identifier`);
  }
  return value;
}

function validateTargetImage(
  image: string,
  options: ProvisionValidationOptions,
): void {
  if (options.runtimeMode === "docker") {
    // Docker mode substitutes a locally built, operator-selected target image.
    // Still reject malformed input so the control-plane contract stays bounded.
    if (!image || /[\s\0]/.test(image) || image.startsWith("-")) {
      throw new Error("targetImage must be a valid image reference");
    }
    return;
  }
  if (options.runtimeMode === "local") {
    if (!/@sha256:[a-f0-9]{64}$/i.test(image)) {
      throw new Error("targetImage must be pinned by sha256 digest");
    }
    return;
  }
  const registries = (options.allowedTargetRegistries ?? [])
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  if (registries.length === 0) {
    throw new Error("At least one target image registry must be allow-listed");
  }
  const registry = image.split("/", 1)[0].toLowerCase();
  if (!registries.includes(registry)) {
    throw new Error("targetImage registry is not allow-listed");
  }
  if (!/@sha256:[a-f0-9]{64}$/i.test(image)) {
    throw new Error("targetImage must be pinned by sha256 digest");
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

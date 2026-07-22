import { createHash } from "node:crypto";

import type { JsonObject } from "./types.ts";

export type BlueTelemetryProfile =
  | "powershell_rce_exfiltration"
  | "credential_abuse"
  | "ransomware"
  | "webshell"
  | "generic_intrusion"
  | "generic_endpoint_activity";

const BLUE_TELEMETRY_PROFILES = new Set<BlueTelemetryProfile>([
  "powershell_rce_exfiltration",
  "credential_abuse",
  "ransomware",
  "webshell",
  "generic_intrusion",
  "generic_endpoint_activity",
]);

export interface BlueTelemetryGeneration {
  schemaVersion: 1;
  profile: BlueTelemetryProfile;
  totalEvents: number;
  timeRangeMinutes: number;
  seed: string;
  timelineAnchor: string;
}

export interface BlueTelemetryEvent {
  id: string;
  document: JsonObject;
}

const MIN_EVENTS = 100;
const MAX_EVENTS = 5_000;
const DEFAULT_EVENTS = 1_200;
const DEFAULT_TIME_RANGE_MINUTES = 60;
const SIGNAL_OFFSETS_MINUTES = [13, 12.6, 11.8, 10.4, 8.5, 6.3] as const;

/**
 * Converts a small, reviewed telemetry fixture into a bounded generation plan.
 * The wall-clock anchor is runtime-owned so stale LabSpecs still appear in
 * Kibana's default recent-time window.
 */
export function blueTelemetryGeneration(
  lab: Record<string, unknown>,
  config: Record<string, unknown>,
  candidate: unknown,
  timelineAnchor: string,
): BlueTelemetryGeneration {
  const supplied = candidate === undefined ? {} : record(candidate, "telemetry.generation");
  const supported = new Set(["schemaVersion", "profile", "totalEvents", "timeRangeMinutes", "seed", "timelineAnchor"]);
  if (Object.keys(supplied).some((key) => !supported.has(key))) {
    throw new Error("telemetry.generation contains unsupported fields");
  }
  if (supplied.schemaVersion !== undefined && supplied.schemaVersion !== 1) {
    throw new Error("telemetry.generation.schemaVersion must be 1");
  }

  const inferredProfile = inferBlueTelemetryProfile(lab, config);
  const profile = supplied.profile === undefined ? inferredProfile : supplied.profile;
  if (typeof profile !== "string" || !BLUE_TELEMETRY_PROFILES.has(profile as BlueTelemetryProfile)) {
    throw new Error("telemetry.generation.profile is invalid");
  }
  const totalEvents = boundedInteger(
    supplied.totalEvents ?? DEFAULT_EVENTS,
    "telemetry.generation.totalEvents",
    MIN_EVENTS,
    MAX_EVENTS,
  );
  const timeRangeMinutes = boundedInteger(
    supplied.timeRangeMinutes ?? DEFAULT_TIME_RANGE_MINUTES,
    "telemetry.generation.timeRangeMinutes",
    15,
    240,
  );
  if (!Number.isFinite(Date.parse(timelineAnchor))) {
    throw new Error("telemetry.generation.timelineAnchor is invalid");
  }
  const configuredSeed = supplied.seed;
  const seed = configuredSeed === undefined
    ? createHash("sha256")
        .update(`${String(lab.id ?? "lab")}:${profile}:${scenarioText(config)}`, "utf8")
        .digest("hex")
        .slice(0, 32)
    : safeSeed(configuredSeed);

  return {
    schemaVersion: 1,
    profile: profile as BlueTelemetryProfile,
    totalEvents,
    timeRangeMinutes,
    seed,
    timelineAnchor: new Date(timelineAnchor).toISOString(),
  };
}

export function inferBlueTelemetryProfile(
  lab: Record<string, unknown>,
  config: Record<string, unknown>,
): BlueTelemetryProfile {
  const text = `${String(lab.name ?? lab.title ?? "")} ${scenarioText(config)}`.toLowerCase();
  if (/ransomware|랜섬웨어|encrypt|t1486/.test(text)) return "ransomware";
  if (/webshell|web shell|웹쉘|t1505\.003/.test(text)) return "webshell";
  if (/credential|account abuse|계정 탈취|자격 증명|t1078/.test(text)) return "credential_abuse";
  if (
    /powershell|power shell|파워쉘|파워셸|t1059\.001/.test(text)
    && /rce|remote code|원격 코드|exfil|반출|t1190|t1041|t1560\.001/.test(text)
  ) return "powershell_rce_exfiltration";
  return "generic_intrusion";
}

/**
 * Deterministically expands reviewed seed events into a realistic exercise
 * corpus. It never executes payloads or connects to a target; output is data.
 */
export function expandBlueTelemetryEvents(
  seedEvents: BlueTelemetryEvent[],
  generation: BlueTelemetryGeneration,
): BlueTelemetryEvent[] {
  validateGeneration(generation);
  const anchorMs = Date.parse(generation.timelineAnchor);
  const signalEvents = generation.profile === "powershell_rce_exfiltration"
    ? powershellSignalEvents(anchorMs)
    : [];
  const signals = new Map(signalEvents.map((event) => [event.id, event]));

  seedEvents.forEach((seedEvent, index) => {
    if (!validEventId(seedEvent.id) || !isRecord(seedEvent.document)) {
      throw new Error(`telemetry seed event ${index} is invalid`);
    }
    const existing = signals.get(seedEvent.id);
    const offsetMinutes = existing
      ? 0
      : 14 - ((index % 8) * 0.72);
    const timestamp = existing?.document["@timestamp"]
      ?? new Date(anchorMs - offsetMinutes * 60_000).toISOString();
    signals.set(seedEvent.id, {
      id: seedEvent.id,
      document: normalizeEventDocument(
        seedEvent.id,
        existing ? deepMerge(existing.document, seedEvent.document) : clone(seedEvent.document),
        String(timestamp),
      ),
    });
  });

  if (signals.size > generation.totalEvents) {
    throw new Error("telemetry.generation.totalEvents is smaller than the reviewed signal set");
  }
  const backgroundCount = generation.totalEvents - signals.size;
  const random = seededRandom(generation.seed);
  const background = Array.from({ length: backgroundCount }, (_, index) =>
    backgroundEvent(index, backgroundCount, anchorMs, generation.timeRangeMinutes, random));
  const combined = [...background, ...signals.values()]
    .sort((left, right) => {
      const byTime = Date.parse(String(left.document["@timestamp"])) - Date.parse(String(right.document["@timestamp"]));
      return byTime === 0 ? left.id.localeCompare(right.id) : byTime;
    });

  return combined.map((event, sequence) => ({
    id: event.id,
    document: {
      ...event.document,
      event: {
        ...recordOrEmpty(event.document.event),
        id: event.id,
      },
      zerotop: {
        ...recordOrEmpty(event.document.zerotop),
        scenario_event_id: event.id,
        sequence,
        generated_at: generation.timelineAnchor,
        source: "scenario_log_generator",
      },
    },
  }));
}

function powershellSignalEvents(anchorMs: number): BlueTelemetryEvent[] {
  const attackerIp = "198.51.100.77";
  const destinationIp = "203.0.113.88";
  const host = windowsHost();
  const technique = (ids: string[]): JsonObject => ({ framework: "MITRE ATT&CK", technique: { id: ids } });
  const at = (offset: number) => new Date(anchorMs - offset * 60_000).toISOString();
  return [
    {
      id: "signal-web-rce-probe",
      document: {
        "@timestamp": at(SIGNAL_OFFSETS_MINUTES[0]),
        message: "POST /api/report/export completed with an unusual query payload and HTTP 500",
        event: { kind: "event", category: ["web"], type: ["access"], dataset: "iis.access", code: "500" },
        host,
        source: { ip: attackerIp, port: 51_844, bytes: 1_942 },
        destination: { ip: "10.20.30.15", port: 8_080, bytes: 612 },
        http: { request: { method: "POST", bytes: 1_942 }, response: { status_code: 500, bytes: 612 } },
        url: { path: "/api/report/export", query: "format=csv&template=quarterly" },
        user_agent: { original: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
        threat: technique(["T1190"]),
      },
    },
    {
      id: "signal-webshell-powershell",
      document: {
        "@timestamp": at(SIGNAL_OFFSETS_MINUTES[1]),
        message: "A new process was created by the IIS worker process",
        event: { kind: "event", category: ["process"], type: ["start"], dataset: "windows.security", code: "4688" },
        host,
        user: { name: "IIS APPPOOL\\DefaultAppPool", domain: "IIS APPPOOL" },
        process: {
          pid: 5_824,
          name: "powershell.exe",
          executable: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          command_line: "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <redacted-training-payload>",
          parent: { pid: 3_116, name: "w3wp.exe", executable: "C:\\Windows\\System32\\inetsrv\\w3wp.exe" },
        },
        source: { ip: attackerIp },
        threat: technique(["T1190", "T1059.001"]),
      },
    },
    {
      id: "signal-powershell-recon",
      document: {
        "@timestamp": at(SIGNAL_OFFSETS_MINUTES[2]),
        message: "PowerShell script block logged multiple host discovery commands",
        event: { kind: "event", category: ["process"], type: ["info"], dataset: "windows.powershell", code: "4104" },
        host,
        user: { name: "DefaultAppPool", domain: "IIS APPPOOL" },
        process: { pid: 5_824, name: "powershell.exe", command_line: "whoami; Get-ChildItem Env:; Get-NetTCPConnection" },
        powershell: { sequence: 1, total: 1, file: { script_block_text: "whoami; Get-ChildItem Env:; Get-NetTCPConnection" } },
        threat: technique(["T1059.001"]),
      },
    },
    {
      id: "signal-sensitive-file-read",
      document: {
        "@timestamp": at(SIGNAL_OFFSETS_MINUTES[3]),
        message: "PowerShell accessed a customer export outside the normal application workflow",
        event: { kind: "event", category: ["file"], type: ["access"], dataset: "endpoint.events.file" },
        host,
        user: { name: "DefaultAppPool", domain: "IIS APPPOOL" },
        process: { pid: 5_824, name: "powershell.exe" },
        file: { path: "C:\\ProgramData\\ZeroTOPApp\\exports\\customer_export.csv", name: "customer_export.csv", size: 4_327_104 },
        threat: technique(["T1005"]),
      },
    },
    {
      id: "signal-archive-created",
      document: {
        "@timestamp": at(SIGNAL_OFFSETS_MINUTES[4]),
        message: "A compressed archive was created in the application cache directory",
        event: { kind: "event", category: ["file", "process"], type: ["creation"], dataset: "endpoint.events.file" },
        host,
        user: { name: "DefaultAppPool", domain: "IIS APPPOOL" },
        process: {
          pid: 5_824,
          name: "powershell.exe",
          command_line: "Compress-Archive -Path C:\\ProgramData\\ZeroTOPApp\\exports\\*.csv -DestinationPath C:\\ProgramData\\cache\\policy-backup.zip",
        },
        file: { path: "C:\\ProgramData\\cache\\policy-backup.zip", name: "policy-backup.zip", extension: "zip", size: 3_891_210 },
        threat: technique(["T1560.001"]),
      },
    },
    {
      id: "signal-outbound-exfiltration",
      document: {
        "@timestamp": at(SIGNAL_OFFSETS_MINUTES[5]),
        message: "An IIS child process initiated an uncommon outbound TLS connection with high byte volume",
        event: { kind: "event", category: ["network"], type: ["connection", "end"], dataset: "endpoint.events.network", outcome: "success" },
        host,
        user: { name: "DefaultAppPool", domain: "IIS APPPOOL" },
        process: { pid: 5_824, name: "powershell.exe", parent: { pid: 3_116, name: "w3wp.exe" } },
        source: { ip: "10.20.30.15", port: 49_771, bytes: 3_899_422 },
        destination: { ip: destinationIp, port: 443, bytes: 18_342 },
        network: { transport: "tcp", protocol: "tls", bytes: 3_917_764, direction: "outbound" },
        threat: technique(["T1041"]),
      },
    },
  ];
}

function backgroundEvent(
  index: number,
  count: number,
  anchorMs: number,
  rangeMinutes: number,
  random: () => number,
): BlueTelemetryEvent {
  const spanMs = rangeMinutes * 60_000;
  const interval = spanMs / Math.max(count, 1);
  const timestampMs = anchorMs - spanMs + (index * interval) + (random() * Math.min(interval, 2_500));
  const id = `evt-${String(index + 1).padStart(5, "0")}`;
  const percentile = (index * 37 + Math.floor(random() * 100)) % 100;
  const host = windowsHost();
  if (percentile < 23) return normalAuthentication(id, timestampMs, index, host, random);
  if (percentile < 47) return normalProcess(id, timestampMs, index, host, random);
  if (percentile < 66) return normalNetwork(id, timestampMs, index, host, random);
  if (percentile < 79) return normalFile(id, timestampMs, index, host, random);
  if (percentile < 93) return normalWeb(id, timestampMs, index, host, random);
  return normalPowerShell(id, timestampMs, index, host, random);
}

function normalAuthentication(id: string, timestampMs: number, index: number, host: JsonObject, random: () => number): BlueTelemetryEvent {
  const users = ["svc_web", "helpdesk.lee", "analyst.kim", "batch_export", "administrator"];
  const user = users[index % users.length];
  const failed = index % 17 === 0;
  const sourceIp = `10.20.${10 + (index % 4)}.${20 + (index % 180)}`;
  return event(id, timestampMs, {
    message: `An account ${failed ? "failed to log on" : "was successfully logged on"}`,
    event: { kind: "event", category: ["authentication"], type: [failed ? "denied" : "start"], dataset: "windows.security", code: failed ? "4625" : "4624", outcome: failed ? "failure" : "success" },
    host,
    user: { name: user, domain: "ZEROTOP" },
    source: { ip: sourceIp, port: 49_152 + Math.floor(random() * 10_000) },
    winlog: { logon: { type: index % 5 === 0 ? "RemoteInteractive" : "Network" }, channel: "Security" },
  });
}

function normalProcess(id: string, timestampMs: number, index: number, host: JsonObject, random: () => number): BlueTelemetryEvent {
  const processes = [
    ["svchost.exe", "services.exe", "svchost.exe -k netsvcs -p"],
    ["w3wp.exe", "svchost.exe", "w3wp.exe -ap DefaultAppPool"],
    ["conhost.exe", "services.exe", "conhost.exe 0xffffffff -ForceV1"],
    ["MsMpEng.exe", "services.exe", "MsMpEng.exe"],
    ["taskhostw.exe", "svchost.exe", "taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}"],
  ] as const;
  const [name, parent, commandLine] = processes[index % processes.length];
  return event(id, timestampMs, {
    message: `Process ${name} started`,
    event: { kind: "event", category: ["process"], type: ["start"], dataset: "endpoint.events.process" },
    host,
    user: { name: index % 3 === 0 ? "SYSTEM" : "svc_web", domain: "NT AUTHORITY" },
    process: { pid: 1_000 + (index % 50_000), name, command_line: commandLine, parent: { pid: 500 + (index % 500), name: parent }, hash: { sha256: deterministicHex(`${id}:${random()}`, 64) } },
  });
}

function normalNetwork(id: string, timestampMs: number, index: number, host: JsonObject, random: () => number): BlueTelemetryEvent {
  const destinations = [
    ["10.20.1.10", 53, "dns"],
    ["10.20.2.20", 443, "tls"],
    ["10.20.5.15", 445, "smb"],
    ["10.20.30.10", 5432, "postgresql"],
    ["10.20.4.11", 123, "ntp"],
  ] as const;
  const [destinationIp, port, protocol] = destinations[index % destinations.length];
  const sent = 120 + Math.floor(random() * 4_000);
  const received = 200 + Math.floor(random() * 12_000);
  return event(id, timestampMs, {
    message: `Outbound ${protocol.toUpperCase()} connection completed`,
    event: { kind: "event", category: ["network"], type: ["connection", "end"], dataset: "endpoint.events.network", outcome: "success" },
    host,
    process: { name: index % 4 === 0 ? "w3wp.exe" : "svchost.exe", pid: 1_200 + (index % 4_000) },
    source: { ip: "10.20.30.15", port: 49_152 + (index % 12_000), bytes: sent },
    destination: { ip: destinationIp, port, bytes: received },
    network: { transport: port === 53 || port === 123 ? "udp" : "tcp", protocol, direction: "outbound", bytes: sent + received },
  });
}

function normalFile(id: string, timestampMs: number, index: number, host: JsonObject, random: () => number): BlueTelemetryEvent {
  const paths = [
    "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex250721.log",
    "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\cache.dat",
    "C:\\Windows\\Temp\\iis-cache.tmp",
    "C:\\ProgramData\\ZeroTOPApp\\logs\\application.log",
  ];
  const path = paths[index % paths.length];
  return event(id, timestampMs, {
    message: "A monitored application file was updated",
    event: { kind: "event", category: ["file"], type: [index % 3 === 0 ? "creation" : "change"], dataset: "endpoint.events.file" },
    host,
    process: { name: index % 2 === 0 ? "w3wp.exe" : "MsMpEng.exe", pid: 2_000 + (index % 2_000) },
    file: { path, name: path.slice(path.lastIndexOf("\\") + 1), size: 1_024 + Math.floor(random() * 90_000) },
  });
}

function normalWeb(id: string, timestampMs: number, index: number, host: JsonObject, random: () => number): BlueTelemetryEvent {
  const routes = ["/", "/health", "/api/catalog", "/assets/app.js", "/login", "/api/report/status"];
  const path = routes[index % routes.length];
  const status = index % 29 === 0 ? 404 : index % 31 === 0 ? 401 : 200;
  return event(id, timestampMs, {
    message: `GET ${path} completed with HTTP ${status}`,
    event: { kind: "event", category: ["web"], type: ["access"], dataset: "iis.access", code: String(status), outcome: status < 400 ? "success" : "failure" },
    host,
    source: { ip: `10.50.${index % 5}.${10 + (index % 220)}`, port: 40_000 + (index % 20_000), bytes: 250 + Math.floor(random() * 1_500) },
    destination: { ip: "10.20.30.15", port: 8_080, bytes: 500 + Math.floor(random() * 20_000) },
    http: { request: { method: "GET" }, response: { status_code: status } },
    url: { path },
  });
}

function normalPowerShell(id: string, timestampMs: number, index: number, host: JsonObject, random: () => number): BlueTelemetryEvent {
  const scripts = [
    "Get-Service W3SVC | Select-Object Status,Name",
    "Get-ChildItem C:\\inetpub\\logs -Filter *.log | Where-Object LastWriteTime -lt (Get-Date).AddDays(-30)",
    "Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime",
  ];
  const script = scripts[index % scripts.length];
  return event(id, timestampMs, {
    message: "Scheduled administration PowerShell script block was logged",
    event: { kind: "event", category: ["process"], type: ["info"], dataset: "windows.powershell", code: "4104" },
    host,
    user: { name: "svc_maintenance", domain: "ZEROTOP" },
    process: { pid: 2_400 + (index % 2_000), name: "powershell.exe", command_line: `powershell.exe -NoProfile -File C:\\Ops\\maintenance-${index % 3}.ps1`, parent: { name: "taskeng.exe" }, code_signature: { trusted: true, subject_name: "Microsoft Windows" } },
    powershell: { sequence: 1, total: 1, file: { script_block_text: script } },
    source: { ip: `10.20.8.${10 + Math.floor(random() * 20)}` },
  });
}

function event(id: string, timestampMs: number, document: JsonObject): BlueTelemetryEvent {
  return { id, document: normalizeEventDocument(id, document, new Date(timestampMs).toISOString()) };
}

function normalizeEventDocument(id: string, document: JsonObject, timestamp: string): JsonObject {
  return {
    ...document,
    "@timestamp": new Date(timestamp).toISOString(),
    event: { kind: "event", ...recordOrEmpty(document.event), id },
  };
}

function windowsHost(): JsonObject {
  return {
    name: "WIN-WEB-01",
    hostname: "WIN-WEB-01",
    ip: ["10.20.30.15"],
    os: { family: "windows", name: "Windows Server 2022", type: "windows" },
  };
}

function validateGeneration(generation: BlueTelemetryGeneration): void {
  if (
    generation.schemaVersion !== 1
    || !BLUE_TELEMETRY_PROFILES.has(generation.profile)
  ) throw new Error("telemetry generation profile is invalid");
  boundedInteger(generation.totalEvents, "totalEvents", MIN_EVENTS, MAX_EVENTS);
  boundedInteger(generation.timeRangeMinutes, "timeRangeMinutes", 15, 240);
  safeSeed(generation.seed);
  if (!Number.isFinite(Date.parse(generation.timelineAnchor))) throw new Error("timelineAnchor is invalid");
}

function scenarioText(config: Record<string, unknown>): string {
  const scenario = recordOrEmpty(config.scenario);
  const telemetry = recordOrEmpty(config.telemetry);
  const signalHints = Array.isArray(telemetry.events) ? telemetry.events.slice(0, 20) : [];
  return JSON.stringify({
    objective: scenario.objective ?? scenario.summary ?? "",
    mitreTechniques: scenario.mitreTechniques ?? scenario.attackChain ?? [],
    signalHints,
  });
}

function safeSeed(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) {
    throw new Error("telemetry.generation.seed is invalid");
  }
  return value;
}

function boundedInteger(value: unknown, field: string, minimum: number, maximum: number): number {
  const number = Number(value);
  if (!Number.isInteger(number) || number < minimum || number > maximum) {
    throw new Error(`${field} must be an integer between ${minimum} and ${maximum}`);
  }
  return number;
}

function seededRandom(seed: string): () => number {
  let state = Number.parseInt(createHash("sha256").update(seed, "utf8").digest("hex").slice(0, 8), 16) >>> 0;
  return () => {
    state += 0x6D2B79F5;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4_294_967_296;
  };
}

function deterministicHex(value: string, length: number): string {
  return createHash("sha256").update(value, "utf8").digest("hex").repeat(Math.ceil(length / 64)).slice(0, length);
}

function deepMerge(left: JsonObject, right: JsonObject): JsonObject {
  const result = clone(left);
  for (const [key, value] of Object.entries(right)) {
    const current = result[key];
    result[key] = isRecord(current) && isRecord(value)
      ? deepMerge(current, value)
      : clone(value);
  }
  return result;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function validEventId(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);
}

function record(value: unknown, field: string): JsonObject {
  if (!isRecord(value)) throw new Error(`${field} must be an object`);
  return value;
}

function recordOrEmpty(value: unknown): JsonObject {
  return isRecord(value) ? value : {};
}

function isRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

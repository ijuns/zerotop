export type DesktopImage = "ubuntu" | "kali";
export type AccessMethod = "browser_desktop" | "openvpn" | "both";
export type TargetProtocol = "http" | "tcp";
export type Team = "blue" | "red";

export interface ScenarioTelemetryEvent {
  id: string;
  document: Record<string, unknown>;
}

export interface ScenarioTelemetryGeneration {
  schemaVersion: 1;
  profile: "powershell_rce_exfiltration" | "credential_abuse" | "ransomware" | "webshell" | "generic_intrusion" | "generic_endpoint_activity";
  /** Final document count, including validated seed events and generated background activity. */
  totalEvents: number;
  timeRangeMinutes: number;
  seed: string;
  /** Runtime-assigned wall-clock anchor so Kibana's default time picker shows the exercise. */
  timelineAnchor: string;
}

export interface RedTargetExercise {
  schemaVersion: 1;
  profile: "command_injection" | "path_traversal" | "sql_injection" | "auth_bypass" | "sensitive_data_exposure";
  scenarioId: string;
  title: string;
  summary: string;
  expectedCves: string[];
  service: {
    scheme: "http";
    host: "target";
    port: 8080;
    baseUrl: "http://target:8080";
  };
  verification: {
    method: "GET";
    path: string;
    successMarker: string;
  };
  attackTechniqueIds: string[];
  simulationMode: "bounded_behavioral";
}

/**
 * Runtime-owned topology selected from the validated AI LabSpec.  Image names
 * are deliberately absent: AI may choose roles and data, while operators own
 * every infrastructure image used to realize those roles.
 */
export interface LabRuntimeTopology {
  schemaVersion: 1;
  team: Team;
  isolation: "per_run";
  workstation: {
    role: "soc_analyst" | "attack_operator";
    desktopImage: DesktopImage;
    entrypoint: "kibana" | "target";
  };
  target: {
    role: "monitored_target" | "vulnerable_target";
    hostname: "target";
    exercise?: RedTargetExercise;
  };
  telemetry?: {
    stack: "elastic";
    collector: "elastic_agent";
    generator: "scenario_log_generator";
    index: string;
    events: ScenarioTelemetryEvent[];
    generation?: ScenarioTelemetryGeneration;
  };
}

export interface TargetService {
  port: number;
  protocol: TargetProtocol;
}

export interface TargetRuntimeContract {
  kind: "http-v1";
  uid: 65532;
  gid: 65532;
  protocol: "http";
  port: 8080;
  writablePaths: ["/tmp"];
  readOnlyRootFilesystem: true;
  bindAddress: "0.0.0.0";
  healthPath: "/health";
  fingerprintPath: "/version";
}

export interface ProvisionRunRequest {
  runId: string;
  labId: string;
  userId: string;
  desktopImage: DesktopImage;
  accessMethod: AccessMethod;
  ttlMinutes: number;
  targetImage: string;
  targetService: TargetService;
  targetRuntimeContract: TargetRuntimeContract;
  /** Optional for compatibility with pre-topology API clients. */
  topology?: LabRuntimeTopology;
}

export interface ProvisionedRun {
  id: string;
  status: "provisioning" | "ready";
  namespace: string;
  expiresAt: string;
  browserDesktop?: {
    gatewayPath: string;
    protocol: "websocket";
  };
  openVpn?: {
    profileId: string;
    endpoint: string;
    assignedIp: string;
    allowedCidr: string;
    expiresAt: string;
  };
}

export interface RuntimeReadinessChecks {
  workstationVmi: boolean;
  targetWorkload: boolean;
  desktopEndpoints?: boolean;
  vpnPod?: boolean;
  vpnService?: boolean;
  elasticsearch?: boolean;
  kibana?: boolean;
  telemetryAgent?: boolean;
  scenarioLogs?: boolean;
}

export interface RuntimeRunStatus {
  id: string;
  status: "provisioning" | "ready" | "failed";
  namespace: string;
  expiresAt: string;
  checks: RuntimeReadinessChecks;
  reason?: string;
}

export interface RuntimeAdapter {
  provision(request: ProvisionRunRequest): Promise<ProvisionedRun>;
  get(runId: string): Promise<RuntimeRunStatus>;
  destroy(runId: string): Promise<void>;
}

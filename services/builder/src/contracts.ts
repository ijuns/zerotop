export type Team = "blue" | "red";
export type ServiceProtocol = "http" | "tcp";
export type HttpMethod = "GET" | "HEAD";
export type QuestionType = "single_choice" | "multiple_choice" | "free_text" | "mitre_attack" | "elk_search";
export type BuildStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";

export interface HttpProbe {
  id: string;
  kind: "http";
  method: HttpMethod;
  path: string;
  expectedStatuses: number[];
  bodyIncludes: string[];
}

export interface TcpBannerProbe {
  id: string;
  kind: "tcp_banner";
  bannerIncludes: string[];
}

export type SafeProbe = HttpProbe | TcpBannerProbe;

export type VulnerabilityProbe = SafeProbe & (
  | { cveId: string; findingId?: string }
  | { cveId?: string; findingId: string }
);

export interface PackageSelection {
  name: string;
  version: string;
}

export interface PublicArtifact {
  url: string;
  sha256: string;
  destination: string;
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

export interface TargetSpec {
  name: string;
  baseImage: string;
  outputRepository: string;
  service: {
    port: number;
    protocol: ServiceProtocol;
  };
  runtimeContract: TargetRuntimeContract;
  packages: PackageSelection[];
  artifacts: PublicArtifact[];
  functionalProbes: SafeProbe[];
  vulnerabilityProbes: VulnerabilityProbe[];
}

export interface TelemetryFixture {
  eventId: string;
  index: string;
  artifactSha256: string;
  mitreTechniqueIds: string[];
}

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export interface TelemetryEvent {
  id: string;
  document: { [key: string]: JsonValue };
}

export interface LearningSection {
  id: string;
  title: string;
  markdown: string;
}

export interface QuestionOption {
  id: string;
  label: string;
}

export interface GeneratedQuestion {
  id: string;
  type: QuestionType;
  prompt: string;
  points: number;
  options?: QuestionOption[];
}

export interface HiddenGradingRef {
  questionId: string;
  refId: string;
  rubricDigest: string;
}

export interface EnvironmentBuildSpec {
  schemaVersion: 1;
  team: Team;
  source: {
    promptDigest: string;
    cveIds: string[];
  };
  scenario: {
    summary: string;
    mitreTechniques: string[];
  };
  target: TargetSpec;
  telemetry?: {
    fixtures?: TelemetryFixture[];
    events: TelemetryEvent[];
  };
  learning: {
    title: string;
    summary: string;
    sections: LearningSection[];
  };
  questions: GeneratedQuestion[];
  grading: {
    hiddenRefs: HiddenGradingRef[];
  };
}

export interface CreateBuildInput {
  labId: string;
  labVersion: number;
  requestedBy: string;
  spec: EnvironmentBuildSpec;
}

export interface PackageCatalogEntry {
  imageRef: string;
  sourcePath: string;
  destination: string;
  runtimeKind: "declarative-http-v1" | "signed-node-handler-v1";
}

export interface ArtifactCatalogEntry {
  url: string;
}

export interface ResolvedPackage extends PackageSelection, PackageCatalogEntry {}

export interface BuildProvenance {
  schemaVersion: 1;
  predicateType: "https://slsa.dev/provenance/v1";
  buildType: "https://codegate.ai/buildtypes/declarative-environment/v1";
  builderId: string;
  buildId: string;
  invocationDigest: string;
  specDigest: string;
  baseImage: string;
  runtimeContract: TargetRuntimeContract;
  runtimeContractDigest: `sha256:${string}`;
  packageImages: string[];
  artifactDigests: string[];
  outputRepository: string;
  canonicalImage: string;
  startedAt: string;
  finishedAt: string;
  hermetic: false;
  networkPolicy: "allowlisted-cidrs";
  parameters: {
    labId: string;
    labVersion: number;
    team: Team;
  };
  subject: Array<{ name: string; digest: { sha256: string } }>;
  materials: Array<{ uri: string; digest: { sha256: string } }>;
}

export interface ConsumableBuildPayload {
  target: TargetSpec & {
    imageRef: string;
    imageDigest: string;
    canonicalImage: string;
    expectedCves: string[];
    validation: {
      service: TargetSpec["service"];
      functionalProbes: SafeProbe[];
      vulnerabilityProbes: VulnerabilityProbe[];
      telemetry?: EnvironmentBuildSpec["telemetry"];
    };
  };
  validation: {
    service: TargetSpec["service"];
    functionalProbes: SafeProbe[];
    vulnerabilityProbes: VulnerabilityProbe[];
    telemetry?: EnvironmentBuildSpec["telemetry"];
  };
  scenario: EnvironmentBuildSpec["scenario"];
  telemetry?: EnvironmentBuildSpec["telemetry"];
  learning: EnvironmentBuildSpec["learning"];
  questions: GeneratedQuestion[];
  grading: EnvironmentBuildSpec["grading"];
}

export interface BuildRecord {
  id: string;
  labId: string;
  labVersion: number;
  requestedBy: string;
  idempotencyKey: string;
  requestDigest: string;
  specDigest: string;
  spec: EnvironmentBuildSpec;
  resolvedPackages: ResolvedPackage[];
  status: BuildStatus;
  namespace: string;
  jobName: string;
  imageRef?: string;
  imageDigest?: string;
  buildProvenance?: BuildProvenance;
  consumable?: ConsumableBuildPayload;
  failureCode?: string;
  failureDetail?: string;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  deadlineAt: string;
  cleanedAt?: string;
}

export interface PublicBuild {
  id: string;
  labId: string;
  labVersion: number;
  status: BuildStatus;
  statusUrl: string;
  imageRef?: string;
  imageDigest?: string;
  buildProvenance?: BuildProvenance;
  consumable?: ConsumableBuildPayload;
  failureCode?: string;
  failure?: { code: string; detail: string };
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
}

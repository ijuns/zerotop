export type JsonObject = Record<string, unknown>;

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

export interface LabTarget {
  labId: string;
  team: "blue" | "red";
  image: string;
  digest: `sha256:${string}`;
  expectedCves: string[];
  runtimeContract: TargetRuntimeContract;
  lab: JsonObject;
}

export interface ArtifactEvidence {
  imageDigest: string;
  signatureVerified: boolean;
  ociConfigVerified: boolean;
  runtimeContractVerified: boolean;
  sbomGenerated: boolean;
  scanCompleted: boolean;
  unexpectedCriticalCount: number;
  unexpectedCriticalIds: string[];
}

export interface SandboxEvidence {
  provisioned: boolean;
  functionalChecksPassed: boolean;
  intendedVulnerabilityConfirmed: boolean;
  egressBlocked: boolean;
  controlPlaneBlocked: boolean;
  crossRunBlocked: boolean;
  cleanupConfirmed: boolean;
}

export interface AssessmentEvidence {
  questionsRendered: boolean;
  gradingVerified: boolean;
  answerLeakageDetected: boolean;
  elkIndexReady?: boolean;
  expectedEventsSearchable?: boolean;
  mitreMappingsVerified?: boolean;
  exploitPathLimitedToSandbox?: boolean;
}

export interface AiReviewEvidence {
  reviewer: string;
  independent: boolean;
  passed: boolean;
  confidence: number;
  riskScore: number;
  traceId: string;
}

export interface SandboxResult {
  sandbox: SandboxEvidence;
  assessment: AssessmentEvidence;
}

export interface PublishCheck {
  id: string;
  label: string;
  passed: boolean;
  mandatory: boolean;
  details: JsonObject;
}

export interface PublishDecision {
  labId?: string;
  decision: "pass" | "quarantine";
  status: "approved" | "quarantined";
  score: number;
  checks: PublishCheck[];
  policyVersion: string;
  createdAt: string;
}

export function parseLabTarget(value: unknown, allowedRegistries: string[]): LabTarget {
  const lab = record(value, "lab");
  const labId = stringValue(lab.id, "lab.id", /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
  const team = lab.team;
  if (team !== "blue" && team !== "red") throw new Error("lab.team is invalid");
  const config = record(lab.config, "lab.config");
  const target = record(config.target, "lab.config.target");
  const image = stringValue(
    target.imageRef,
    "lab.config.target.imageRef",
    /^[a-z0-9.-]+(?::\d+)?\/[a-z0-9._/-]+(?::[a-z0-9._-]+)?$/i,
  );
  if (image.startsWith("-") || image.includes("@")) throw new Error("target image is invalid");
  const registry = image.split("/", 1)[0]?.toLowerCase() ?? "";
  if (!allowedRegistries.includes(registry)) throw new Error("target registry is not allowed");
  const digest = stringValue(
    target.imageDigest,
    "lab.config.target.imageDigest",
    /^sha256:[a-f0-9]{64}$/i,
  ).toLowerCase() as `sha256:${string}`;
  const validation = isObject(config.validation) ? config.validation : {};
  const runtimeContract = parseRuntimeContract(target.runtimeContract);
  const rawExpected = target.expectedCves ?? validation.expectedCves ?? [];
  if (!Array.isArray(rawExpected)) throw new Error("expectedCves must be an array");
  const expectedCves = [...new Set(rawExpected.map((item) => {
    if (typeof item !== "string" || !/^CVE-\d{4}-\d{4,7}$/i.test(item)) {
      throw new Error("expectedCves contains an invalid CVE ID");
    }
    return item.toUpperCase();
  }))];
  return { labId, team, image, digest, expectedCves, runtimeContract, lab };
}

function parseRuntimeContract(value: unknown): TargetRuntimeContract {
  const root = record(value, "lab.config.target.runtimeContract");
  const expectedKeys = new Set([
    "kind", "uid", "gid", "protocol", "port", "writablePaths",
    "readOnlyRootFilesystem", "bindAddress", "healthPath", "fingerprintPath",
  ]);
  if (Object.keys(root).some((key) => !expectedKeys.has(key))) throw new Error("target runtime contract contains unsupported fields");
  if (
    root.kind !== "http-v1"
    || root.uid !== 65_532
    || root.gid !== 65_532
    || root.protocol !== "http"
    || root.port !== 8_080
    || root.readOnlyRootFilesystem !== true
    || root.bindAddress !== "0.0.0.0"
    || root.healthPath !== "/health"
    || root.fingerprintPath !== "/version"
    || !Array.isArray(root.writablePaths)
    || root.writablePaths.length !== 1
    || root.writablePaths[0] !== "/tmp"
  ) throw new Error("target runtime contract is invalid or unsupported");
  return {
    kind: "http-v1", uid: 65_532, gid: 65_532, protocol: "http", port: 8_080,
    writablePaths: ["/tmp"], readOnlyRootFilesystem: true, bindAddress: "0.0.0.0",
    healthPath: "/health", fingerprintPath: "/version",
  };
}

export function parseSandboxResult(value: unknown, team: "blue" | "red"): SandboxResult {
  const root = record(value, "sandbox response");
  const data = isObject(root.data) ? root.data : root;
  const sandbox = record(data.sandbox, "sandbox response.sandbox") as unknown as SandboxEvidence;
  const assessment = record(data.assessment, "sandbox response.assessment") as unknown as AssessmentEvidence;
  for (const key of [
    "provisioned",
    "functionalChecksPassed",
    "intendedVulnerabilityConfirmed",
    "egressBlocked",
    "controlPlaneBlocked",
    "crossRunBlocked",
    "cleanupConfirmed",
  ] as const) requireBoolean(sandbox, key);
  for (const key of ["questionsRendered", "gradingVerified", "answerLeakageDetected"] as const) {
    requireBoolean(assessment, key);
  }
  if (team === "blue") {
    for (const key of ["elkIndexReady", "expectedEventsSearchable", "mitreMappingsVerified"] as const) {
      requireBoolean(assessment, key);
    }
  } else {
    requireBoolean(assessment, "exploitPathLimitedToSandbox");
  }
  return { sandbox, assessment };
}

export function parseAiReview(value: unknown): AiReviewEvidence {
  const root = record(value, "AI review");
  const data = isObject(root.data) ? root.data : root;
  const reviewer = stringValue(data.reviewer, "reviewer", /^[A-Za-z0-9._:/-]{2,128}$/);
  const traceId = stringValue(data.traceId, "traceId", /^[A-Za-z0-9._:/-]{8,256}$/);
  const confidence = numberValue(data.confidence, "confidence");
  const riskScore = numberValue(data.riskScore, "riskScore");
  if (typeof data.independent !== "boolean" || typeof data.passed !== "boolean") {
    throw new Error("AI review booleans are invalid");
  }
  return { reviewer, traceId, confidence, riskScore, independent: data.independent, passed: data.passed };
}

export function parsePublishDecision(value: unknown): PublishDecision {
  const root = record(value, "publish decision");
  const data = isObject(root.data) ? root.data : root;
  if (data.decision !== "pass" && data.decision !== "quarantine") throw new Error("publish decision is invalid");
  if (data.status !== "approved" && data.status !== "quarantined") throw new Error("publish status is invalid");
  const score = numberValue(data.score, "score", 100);
  if (!Array.isArray(data.checks) || data.checks.length < 8) throw new Error("publish checks are incomplete");
  const checks = data.checks.map((item) => {
    const check = record(item, "publish check");
    if (typeof check.passed !== "boolean" || check.mandatory !== true) throw new Error("publish check is invalid");
    return {
      id: stringValue(check.id, "check.id", /^[a-z0-9_]{2,80}$/),
      label: stringValue(check.label, "check.label"),
      passed: check.passed,
      mandatory: true as const,
      details: record(check.details, "check.details"),
    };
  });
  const allPassed = checks.every((item) => item.passed);
  if ((data.decision === "pass") !== allPassed) throw new Error("publish decision contradicts its checks");
  return {
    ...(typeof data.labId === "string" ? { labId: data.labId } : {}),
    decision: data.decision,
    status: data.status,
    score,
    checks,
    policyVersion: stringValue(data.policyVersion, "policyVersion"),
    createdAt: stringValue(data.createdAt, "createdAt"),
  };
}

function requireBoolean(value: object, key: string): void {
  if ((value as Record<string, unknown>)[key] !== true && (value as Record<string, unknown>)[key] !== false) {
    throw new Error(`${key} must be a boolean`);
  }
}

function numberValue(value: unknown, name: string, max = 1): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > max) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function stringValue(value: unknown, name: string, pattern?: RegExp): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 5_000 || (pattern && !pattern.test(value))) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function record(value: unknown, name: string): JsonObject {
  if (!isObject(value)) throw new Error(`${name} must be an object`);
  return value;
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

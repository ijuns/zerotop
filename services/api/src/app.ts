import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import {
  createDatabase,
  SqliteDevelopmentRepository,
} from "./database.ts";
import { ApiError, RepositoryError } from "./errors.ts";
import {
  normalizeAccessMethod,
  normalizeLabGeneration,
  normalizeRegistration,
} from "./input.ts";
import type {
  AiLabGenerator,
  EvidenceGrader,
  LabValidator,
  PlatformRepository,
  RuntimeAdapter,
} from "./ports.ts";
import { PostgresRepository } from "./postgres.ts";
import {
  DevelopmentRuntimeSimulator,
  HttpRuntimeAdapter,
} from "./runtime.ts";
import {
  aiGenerationTimeoutFromEnvironment,
  DevelopmentLocalLabGenerator,
  HttpAiLabGenerator,
} from "./ai.ts";
import {
  DevelopmentEvidenceGrader,
  HttpEvidenceGrader,
  validateTrustedGradeEvidence,
} from "./evidence-grader.ts";
import {
  AUDIT_RESOURCE_TYPES,
  DEV_USER_ID,
  PRIVACY_POLICY_VERSION,
  TERMS_VERSION,
  type AdminPageQuery,
  type AdminPageResult,
  type RuntimeRunStatusInput,
} from "./types.ts";
import { DevelopmentLabValidator, HttpLabValidator } from "./lab-validator.ts";
import {
  DevelopmentTelemetryGateway,
  HttpTelemetryGateway,
  type TelemetryEventInput,
  type TelemetryGateway,
} from "./telemetry.ts";
import {
  blueTelemetryGeneration,
  expandBlueTelemetryEvents,
  type BlueTelemetryGeneration,
} from "./blue-telemetry.ts";
import {
  DevelopmentEnvironmentBuilder,
  HttpEnvironmentBuilder,
  type EnvironmentBuildOperation,
  type EnvironmentBuilder,
} from "./environment-builder.ts";
import {
  createSessionToken,
  generateOrganizationJoinCode,
  hashOrganizationJoinCode,
  needsPasswordRehash,
  verifyPassword,
  verifySessionToken,
} from "./security.ts";
import { parseTargetRuntimeContract } from "./target-runtime-contract.ts";
import {
  organizationReport,
  personalReport,
  platformReport,
  ranking,
  type ReportingDataset,
} from "@codegate/reporting";
import {
  RANKING_DOMAINS,
  type RankingDomain,
  type RankingSeason,
} from "@codegate/contracts";
import {
  gradeRun,
  type ServerQuestion,
  type SubmittedAnswer,
  type TrustedGradeEvidence,
} from "@codegate/grading";
import {
  authenticateRequest,
  AuthenticationError,
  OidcVerifier,
  type AuthPrincipal,
} from "@codegate/auth";

interface ApplicationOptions {
  databasePath?: string;
  databaseUrl?: string;
  repository?: PlatformRepository;
  repositoryMode?: "sqlite" | "postgres";
  runtime?: RuntimeAdapter;
  runtimeMode?: "simulator" | "http";
  labGenerator?: AiLabGenerator;
  labGeneratorMode?: "local" | "http";
  evidenceGrader?: EvidenceGrader;
  evidenceGraderMode?: "mock" | "http";
  labValidator?: LabValidator;
  labValidatorMode?: "development" | "http";
  telemetryGateway?: TelemetryGateway;
  telemetryGatewayMode?: "development" | "http";
  environmentBuilder?: EnvironmentBuilder;
  environmentBuilderMode?: "development" | "http";
  authMode?: string;
  oidcVerifier?: OidcVerifier;
  allowedOrigins?: string[];
  desktopGatewayInternalToken?: string;
  desktopGatewayPublicUrl?: string;
  desktopTicketTtlSeconds?: number;
  openVpnDownloadInternalToken?: string;
  openVpnDownloadPublicUrl?: string;
  /** Expiry sweep period in ms. 0 disables the timer (tests drive it manually). */
  runSweepIntervalMs?: number;
  /** Honour X-Forwarded-For for audit source addresses. Only behind a trusted proxy. */
  trustProxyHeaders?: boolean;
  /** HMAC secret for password-session tokens (AUTH_MODE=local). */
  sessionSecret?: string;
}

interface HandlerContext {
  repository: PlatformRepository;
  runtime: RuntimeAdapter;
  labGenerator: AiLabGenerator;
  evidenceGrader: EvidenceGrader;
  labValidator: LabValidator;
  telemetryGateway: TelemetryGateway;
  environmentBuilder: EnvironmentBuilder;
  authMode: string;
  oidcVerifier?: OidcVerifier;
  sessionSecret: string;
  desktopGatewayInternalToken: string;
  desktopGatewayPublicUrl: string;
  desktopTicketTtlSeconds: number;
  openVpnDownloadInternalToken: string;
  openVpnDownloadPublicUrl: string;
  trustProxyHeaders: boolean;
  ready: Promise<void>;
}

type JsonRecord = Record<string, unknown>;

const CORS_PREFLIGHT_HEADERS = {
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization,X-User-Id,Idempotency-Key",
  "Access-Control-Expose-Headers": "Idempotent-Replayed",
  "Access-Control-Max-Age": "86400",
};

function isObject(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function field(value: unknown, key: string): unknown {
  return isObject(value) ? value[key] : undefined;
}

function stringField(value: unknown, key: string): string | null {
  const item = field(value, key);
  return typeof item === "string" ? item : null;
}

async function refreshRuntimeRun(
  context: HandlerContext,
  userId: string,
  runValue: unknown,
): Promise<unknown> {
  if (field(runValue, "status") !== "provisioning") return runValue;
  const runId = stringField(runValue, "id");
  if (!runId) throw new RepositoryError("RUN_ID_INVALID", "The stored runtime run has no ID.", 500);
  const readiness = await context.runtime.getRunStatus(runId);
  if (readiness.status === "provisioning") return withRuntimeReadiness(runValue, readiness);
  const updated = await context.repository.updateRunReadiness(userId, runId, readiness);
  if (!updated) throw new ApiError(404, "RUN_NOT_FOUND", "The runtime run was not found.");
  return updated;
}

function telemetryEvents(lab: unknown, runtimeMetadata?: unknown): TelemetryEventInput[] {
  const config = field(lab, "config");
  const validation = field(config, "validation");
  const telemetry = field(validation, "telemetry") ?? field(config, "telemetry");
  const events = field(telemetry, "events");
  if (!Array.isArray(events)) return [];
  const seeds = events.flatMap((item): TelemetryEventInput[] => {
    if (!isObject(item) || typeof item.id !== "string" || !isObject(item.document)) return [];
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(item.id)) return [];
    return [{ id: item.id, document: item.document }];
  });
  if (seeds.length === 0 || (field(lab, "teamType") !== "blue" && field(lab, "team") !== "blue")) {
    return seeds;
  }
  const runtimeTopology = field(runtimeMetadata, "topology");
  const runtimeTelemetry = field(runtimeTopology, "telemetry");
  const runtimeGeneration = field(runtimeTelemetry, "generation");
  const generation = isObject(runtimeGeneration)
    ? runtimeGeneration as unknown as BlueTelemetryGeneration
    : blueTelemetryGeneration(
        isObject(lab) ? lab : {},
        isObject(config) ? config : {},
        field(telemetry, "generation"),
        new Date().toISOString(),
      );
  return expandBlueTelemetryEvents(seeds, generation);
}

function labBuilder(lab: unknown): JsonRecord | null {
  const config = field(lab, "config");
  const builder = field(config, "builder");
  return isObject(builder) ? builder : null;
}

function buildState(operation: EnvironmentBuildOperation): JsonRecord {
  return {
    id: operation.id,
    status: operation.status,
    createdAt: operation.createdAt,
    updatedAt: operation.updatedAt ?? null,
    failureCode: operation.failureCode ?? null,
  };
}

function canonicalLearning(value: unknown): JsonRecord | null {
  if (!isObject(value)) return null;
  const sections = Array.isArray(value.sections)
    ? value.sections.map((section) => {
        if (!isObject(section)) return section;
        const bodyMarkdown = typeof section.bodyMarkdown === "string"
          ? section.bodyMarkdown
          : typeof section.markdown === "string"
            ? section.markdown
            : null;
        return bodyMarkdown === null ? section : { ...section, bodyMarkdown };
      })
    : undefined;
  return {
    ...value,
    ...(sections ? { sections } : {}),
  };
}

function mergedLearning(current: unknown, built: unknown): JsonRecord | null {
  const currentLearning = canonicalLearning(current);
  const builtLearning = canonicalLearning(built);
  if (!currentLearning) return builtLearning;
  if (!builtLearning) return currentLearning;
  // The builder payload is an executable projection and intentionally omits
  // learner-only fields such as objectives and prerequisites. The validated
  // AI curriculum remains authoritative for learner-visible content.
  return { ...builtLearning, ...currentLearning };
}

function successfulBuildPatch(lab: unknown, operation: EnvironmentBuildOperation): JsonRecord {
  if (operation.status !== "succeeded" || !operation.imageRef || !operation.imageDigest || !operation.consumable) {
    throw new ApiError(502, "BUILDER_CONTRACT_INVALID", "A successful build is missing its target contract.");
  }
  const config = isObject(field(lab, "config")) ? field(lab, "config") as JsonRecord : {};
  const currentTarget = isObject(config.target) ? config.target : {};
  const consumable = operation.consumable;
  const target = isObject(consumable.target) ? consumable.target : {};
  const service = isObject(target.service) ? target.service : {};
  const runtimeContract = parseTargetRuntimeContract(target.runtimeContract);
  if (
    !runtimeContract
    || service.port !== runtimeContract.port
    || service.protocol !== runtimeContract.protocol
  ) {
    throw new ApiError(502, "BUILDER_CONTRACT_INVALID", "The successful build has an invalid target runtime contract.");
  }
  const validation = isObject(target.validation)
    ? target.validation
    : {
        service,
        functionalProbes: Array.isArray(target.functionalProbes) ? target.functionalProbes : [],
        vulnerabilityProbes: Array.isArray(target.vulnerabilityProbes) ? target.vulnerabilityProbes : [],
        ...(isObject(consumable.telemetry) ? { telemetry: consumable.telemetry } : {}),
      };
  const learning = mergedLearning(config.learning, consumable.learning);
  const builtScenario = isObject(consumable.scenario) ? consumable.scenario : null;
  const currentScenario = isObject(config.scenario) ? config.scenario : null;
  const scenario = builtScenario && currentScenario
    ? { ...builtScenario, ...currentScenario }
    : currentScenario ?? builtScenario;
  const questions = Array.isArray(config.questions) && config.questions.length > 0
    ? config.questions
    : Array.isArray(consumable.questions)
      ? consumable.questions
      : null;
  return {
    builder: buildState(operation),
    target: {
      ...currentTarget,
      imageRef: operation.imageRef,
      imageDigest: operation.imageDigest,
      expectedCves: Array.isArray(target.expectedCves)
        ? target.expectedCves
        : Array.isArray(currentTarget.expectedCves)
          ? currentTarget.expectedCves
          : [],
      service,
      runtimeContract,
      source: "ai_environment_builder",
    },
    validation,
    ...(learning ? { learning } : {}),
    ...(questions ? { questions } : {}),
    ...(scenario ? { scenario } : {}),
    ...(isObject(consumable.topology) ? { topology: consumable.topology } : {}),
    buildProvenance: operation.buildProvenance ?? {},
  };
}

async function refreshLabBuild(
  context: HandlerContext,
  userId: string,
  lab: unknown,
): Promise<unknown> {
  const builder = labBuilder(lab);
  const buildId = stringField(builder, "id");
  const status = stringField(builder, "status");
  if (!buildId || !status || ["succeeded", "failed", "cancelled"].includes(status)) return lab;
  const operation = await context.environmentBuilder.get(buildId);
  const patch = operation.status === "succeeded"
    ? successfulBuildPatch(lab, operation)
    : { builder: buildState(operation) };
  const labId = stringField(lab, "id");
  if (!labId || !await context.repository.updateLabConfig(labId, patch, new Date().toISOString())) {
    throw new ApiError(409, "LAB_BUILD_STATE_CONFLICT", "The Lab can no longer accept build updates.");
  }
  return await context.repository.getLab(userId, labId);
}

function withRuntimeReadiness(runValue: unknown, readiness: RuntimeRunStatusInput): unknown {
  if (!isObject(runValue)) return runValue;
  const metadataValue = field(runValue, "metadata");
  const metadata = isObject(metadataValue) ? metadataValue : {};
  return {
    ...runValue,
    metadata: {
      ...metadata,
      runtimeReadiness: {
        status: readiness.status,
        namespace: readiness.namespace,
        expiresAt: readiness.expiresAt,
        checks: readiness.checks,
        reason: readiness.reason ?? null,
        checkedAt: new Date().toISOString(),
      },
    },
  };
}

function actorOrganization(user: unknown): JsonRecord | null {
  const organization = field(user, "organization");
  return isObject(organization) ? organization : null;
}

interface RequestActor {
  id: string;
  user: unknown;
  roles: string[];
  principal?: AuthPrincipal;
}

function requirePlatformAdmin(actor: RequestActor): void {
  if (
    !actor.roles.includes("platform_admin") ||
    field(actor.user, "platformRole") !== "platform_admin"
  ) {
    throw new ApiError(
      403,
      "PLATFORM_ADMIN_REQUIRED",
      "Platform administrator access is required.",
    );
  }
}

function requireOrganizationAdmin(actor: RequestActor): string {
  const organization = actorOrganization(actor.user);
  const databaseRole = organization ? stringField(organization, "role") : null;
  const organizationId = organization ? stringField(organization, "id") : null;
  if (
    !organizationId ||
    !actor.roles.includes("org_admin") ||
    (databaseRole !== "owner" && databaseRole !== "org_admin")
  ) {
    throw new ApiError(
      403,
      "ORG_ADMIN_REQUIRED",
      "Organization administrator access is required.",
    );
  }
  return organizationId;
}

type AdminListKind =
  | "users"
  | "organizations"
  | "labs"
  | "runs"
  | "members"
  | "auditLogs"
  | "organizationAuditLogs";

const ADMIN_FILTERS: Record<AdminListKind, ReadonlySet<string>> = {
  users: new Set(["search", "organizationId", "platformRole"]),
  organizations: new Set(["search"]),
  labs: new Set(["search", "organizationId", "team", "status"]),
  runs: new Set(["search", "organizationId", "status", "accessMethod"]),
  members: new Set(["search", "role"]),
  auditLogs: new Set(["search", "action", "resourceType"]),
  organizationAuditLogs: new Set(["search", "action"]),
};

function boundedQueryInteger(
  url: URL,
  name: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const values = url.searchParams.getAll(name);
  if (values.length === 0) return fallback;
  if (values.length !== 1 || !/^\d+$/.test(values[0])) {
    throw new ApiError(400, "INVALID_PAGINATION", `${name} must be an integer.`);
  }
  const parsed = Number(values[0]);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new ApiError(
      400,
      "INVALID_PAGINATION",
      `${name} must be between ${minimum} and ${maximum}.`,
    );
  }
  return parsed;
}

function optionalAdminFilter(
  url: URL,
  name: string,
  maximumLength = 128,
): string | undefined {
  const values = url.searchParams.getAll(name);
  if (values.length === 0) return undefined;
  if (values.length !== 1) {
    throw new ApiError(400, "INVALID_ADMIN_FILTER", `${name} may be supplied once.`);
  }
  const value = values[0].trim();
  if (!value || value.length > maximumLength || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new ApiError(400, "INVALID_ADMIN_FILTER", `${name} is invalid.`);
  }
  return value;
}

function enumAdminFilter<T extends string>(
  url: URL,
  name: string,
  allowed: readonly T[],
): T | undefined {
  const value = optionalAdminFilter(url, name);
  if (value === undefined) return undefined;
  if (!(allowed as readonly string[]).includes(value)) {
    throw new ApiError(
      400,
      "INVALID_ADMIN_FILTER",
      `${name} must be one of: ${allowed.join(", ")}.`,
    );
  }
  return value as T;
}

function parseAdminPageQuery(url: URL, kind: AdminListKind): AdminPageQuery {
  const allowed = new Set(["page", "pageSize", ...ADMIN_FILTERS[kind]]);
  for (const name of url.searchParams.keys()) {
    if (!allowed.has(name)) {
      throw new ApiError(
        400,
        "UNSUPPORTED_ADMIN_FILTER",
        `${name} is not supported for this endpoint.`,
      );
    }
  }
  const page = boundedQueryInteger(url, "page", 1, 1, 10_000);
  const limit = boundedQueryInteger(url, "pageSize", 25, 1, 100);
  const query: AdminPageQuery = { limit, offset: (page - 1) * limit };
  const search = optionalAdminFilter(url, "search", 100);
  if (search) query.search = search;
  const organizationId = optionalAdminFilter(url, "organizationId");
  if (organizationId) query.organizationId = organizationId;
  const platformRole = enumAdminFilter(
    url,
    "platformRole",
    ["user", "platform_admin"] as const,
  );
  if (platformRole) query.platformRole = platformRole;
  const membershipRole = enumAdminFilter(
    url,
    "role",
    ["owner", "org_admin", "member"] as const,
  );
  if (membershipRole) query.membershipRole = membershipRole;
  const team = enumAdminFilter(url, "team", ["blue", "red"] as const);
  if (team) query.team = team;
  if (kind === "labs") {
    const status = enumAdminFilter(
      url,
      "status",
      ["draft", "validated", "quarantined"] as const,
    );
    if (status) query.labStatus = status;
  }
  if (kind === "runs") {
    const status = enumAdminFilter(
      url,
      "status",
      ["provisioning", "ready", "failed", "stopped", "expired"] as const,
    );
    if (status) query.runStatus = status;
    const accessMethod = enumAdminFilter(
      url,
      "accessMethod",
      ["browser_desktop", "openvpn", "both"] as const,
    );
    if (accessMethod) query.accessMethod = accessMethod;
  }
  if (kind === "auditLogs" || kind === "organizationAuditLogs") {
    // Actions are matched as an opaque namespaced token rather than an enum, so
    // filtering keeps working as new audited actions are introduced.
    const action = optionalAdminFilter(url, "action", 64);
    if (action !== undefined) {
      if (!/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/.test(action)) {
        throw new ApiError(
          400,
          "INVALID_ADMIN_FILTER",
          "action must look like namespace.event.",
        );
      }
      query.auditAction = action;
    }
    const resourceType = enumAdminFilter(
      url,
      "resourceType",
      AUDIT_RESOURCE_TYPES,
    );
    if (resourceType) query.auditResourceType = resourceType;
  }
  return query;
}

function adminPagePayload(result: AdminPageResult, query: AdminPageQuery): unknown {
  const page = Math.floor(query.offset / query.limit) + 1;
  return {
    data: {
      items: result.items,
      pagination: {
        page,
        pageSize: query.limit,
        total: result.total,
        totalPages: Math.ceil(result.total / query.limit),
      },
    },
  };
}

function decodeAdminIdentifier(raw: string, resource: string): string {
  let value: string;
  try {
    value = decodeURIComponent(raw);
  } catch {
    throw new ApiError(400, "INVALID_RESOURCE_ID", `The ${resource} ID is invalid.`);
  }
  if (
    value.length < 1 ||
    value.length > 128 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)
  ) {
    throw new ApiError(400, "INVALID_RESOURCE_ID", `The ${resource} ID is invalid.`);
  }
  return value;
}

function normalizeOrganizationBody(value: unknown): { name: string; slug: string } {
  if (!isObject(value)) {
    throw new ApiError(400, "INVALID_ORGANIZATION", "A JSON object is required.");
  }
  if (value.joinCode !== undefined || value.joinCodeHash !== undefined) {
    throw new ApiError(
      400,
      "JOIN_CODE_SERVER_GENERATED",
      "Organization join codes are generated by the server.",
    );
  }
  const name = typeof value.name === "string" ? value.name.trim() : "";
  if (
    name.length < 2 ||
    name.length > 120 ||
    /[\u0000-\u001f\u007f]/.test(name)
  ) {
    throw new ApiError(
      400,
      "INVALID_ORGANIZATION_NAME",
      "name must contain 2-120 printable characters.",
    );
  }
  const derived = name
    .normalize("NFKD")
    .replace(/[^\x00-\x7f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63)
    .replace(/-+$/g, "");
  const slugValue =
    typeof value.slug === "string" ? value.slug.trim().toLowerCase() : derived;
  const slug = slugValue || `org-${randomUUID().slice(0, 8)}`;
  if (
    slug.length > 63 ||
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(slug)
  ) {
    throw new ApiError(
      400,
      "INVALID_ORGANIZATION_SLUG",
      "slug must be 1-63 lowercase letters, numbers or internal hyphens.",
    );
  }
  return { name, slug };
}

function normalizeAdminReason(value: unknown, fallback: string): string {
  if (!isObject(value)) {
    throw new ApiError(400, "INVALID_ADMIN_MUTATION", "A JSON object is required.");
  }
  const reason =
    value.reason === undefined
      ? fallback
      : typeof value.reason === "string"
        ? value.reason.trim()
        : "";
  if (
    reason.length < 1 ||
    reason.length > 500 ||
    /[\u0000-\u001f\u007f]/.test(reason)
  ) {
    throw new ApiError(
      400,
      "INVALID_ADMIN_REASON",
      "reason must contain 1-500 printable characters.",
    );
  }
  return reason;
}

function enumBodyField<T extends string>(
  value: unknown,
  name: string,
  allowed: readonly T[],
  code: string,
): T {
  if (!isObject(value)) {
    throw new ApiError(400, "INVALID_ADMIN_MUTATION", "A JSON object is required.");
  }
  const supplied = value[name];
  if (
    typeof supplied !== "string" ||
    !(allowed as readonly string[]).includes(supplied)
  ) {
    throw new ApiError(
      400,
      code,
      `${name} must be one of: ${allowed.join(", ")}.`,
    );
  }
  return supplied as T;
}

function booleanBodyField(value: unknown, name: string, code: string): boolean {
  if (!isObject(value)) {
    throw new ApiError(400, "INVALID_ADMIN_MUTATION", "A JSON object is required.");
  }
  if (typeof value[name] !== "boolean") {
    throw new ApiError(400, code, `${name} must be a boolean.`);
  }
  return value[name] as boolean;
}

function normalizeSeasonBody(value: unknown): {
  name: string;
  slug: string;
  startsAt: string;
  endsAt: string;
} {
  if (!isObject(value)) {
    throw new ApiError(400, "INVALID_SEASON", "A JSON object is required.");
  }
  const name = typeof value.name === "string" ? value.name.trim() : "";
  const slug = typeof value.slug === "string" ? value.slug.trim().toLowerCase() : "";
  const startsAt = typeof value.startsAt === "string" ? value.startsAt : "";
  const endsAt = typeof value.endsAt === "string" ? value.endsAt : "";
  if (name.length < 2 || name.length > 80) {
    throw new ApiError(400, "INVALID_SEASON", "name must be 2-80 characters.");
  }
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug) || slug.length > 63) {
    throw new ApiError(400, "INVALID_SEASON", "slug must be lowercase kebab-case.");
  }
  const start = Date.parse(startsAt);
  const end = Date.parse(endsAt);
  if (Number.isNaN(start) || Number.isNaN(end)) {
    throw new ApiError(400, "INVALID_SEASON", "startsAt and endsAt must be ISO timestamps.");
  }
  if (end <= start) {
    throw new ApiError(400, "INVALID_SEASON", "endsAt must be after startsAt.");
  }
  return {
    name,
    slug,
    startsAt: new Date(start).toISOString(),
    endsAt: new Date(end).toISOString(),
  };
}

function actorOrganizationRole(actor: RequestActor): string {
  const organization = actorOrganization(actor.user);
  return (organization ? stringField(organization, "role") : null) ?? "";
}

/**
 * Reads a self-reported hint count from a submission. Absent or invalid values
 * are 0, so no penalty is applied rather than an assumed one; the cap keeps a
 * single submission from erasing more than the policy's maximum.
 */
function hintsUsedOf(value: unknown): number {
  if (!isObject(value)) return 0;
  const raw = value.hintsUsed ?? value.hints_used;
  const parsed = typeof raw === "number" ? raw : Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return 0;
  return Math.min(20, Math.floor(parsed));
}

function submittedAnswers(value: unknown): SubmittedAnswer[] {
  if (!isObject(value) || !Array.isArray(value.answers)) {
    throw new ApiError(
      400,
      "INVALID_SUBMISSION",
      "The request must contain an answers array.",
    );
  }
  if (
    value.trustedEvidence !== undefined ||
    value.gradeEvidence !== undefined ||
    value.evidence !== undefined
  ) {
    throw new ApiError(
      400,
      "CLIENT_GRADE_EVIDENCE_FORBIDDEN",
      "Trusted grade evidence can only be supplied by server-side graders.",
    );
  }
  return value.answers.map((item, index) => {
    if (!isObject(item) || typeof item.questionId !== "string") {
      throw new ApiError(
        400,
        "INVALID_SUBMISSION_ANSWER",
        `answers[${index}].questionId is required.`,
      );
    }
    return { questionId: item.questionId, response: item.response };
  });
}

function mergeTrustedGradeEvidence(
  stored: TrustedGradeEvidence[],
  generated: TrustedGradeEvidence[],
): TrustedGradeEvidence[] {
  const merged = new Map(stored.map((item) => [item.questionId, item]));
  for (const item of generated) merged.set(item.questionId, item);
  return [...merged.values()];
}

function gradeSkills(grades: JsonRecord[]): JsonRecord {
  const definitions: Record<string, { key: string; label: string }> = {
    elk_search: { key: "elk_investigation", label: "ELK Investigation" },
    mitre_attack: { key: "attack_mapping", label: "MITRE ATT&CK Mapping" },
    single_choice: { key: "red_team_execution", label: "Red Team Execution" },
    multiple_choice: { key: "red_team_execution", label: "Red Team Execution" },
    free_text: { key: "analysis", label: "Security Analysis" },
  };
  const result: JsonRecord = {};
  for (const grade of grades) {
    const definition = definitions[String(grade.questionType)];
    if (!definition) continue;
    const current = isObject(result[definition.key])
      ? (result[definition.key] as JsonRecord)
      : { label: definition.label, points: 0, maxPoints: 0 };
    current.points = Number(current.points) + Number(grade.awardedPoints ?? 0);
    current.maxPoints = Number(current.maxPoints) + Number(grade.maxPoints ?? 0);
    result[definition.key] = current;
  }
  return result;
}

function sendJson(
  response: ServerResponse,
  status: number,
  payload: unknown,
  headers: Record<string, string> = {},
): void {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    ...headers,
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body).toString(),
    "Cache-Control": "no-store",
  });
  response.end(body);
}

function applyCors(
  request: IncomingMessage,
  response: ServerResponse,
  allowedOrigins: Set<string>,
): boolean {
  const rawOrigin = request.headers.origin;
  const origin = Array.isArray(rawOrigin) ? rawOrigin[0] : rawOrigin;
  if (!origin) return true;
  if (!allowedOrigins.has(origin)) return false;
  response.setHeader("Access-Control-Allow-Origin", origin);
  response.setHeader("Vary", "Origin");
  for (const [name, value] of Object.entries(CORS_PREFLIGHT_HEADERS)) {
    response.setHeader(name, value);
  }
  return true;
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let bytes = 0;

  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.length;
    if (bytes > 1024 * 1024) {
      throw new ApiError(
        413,
        "PAYLOAD_TOO_LARGE",
        "The JSON request body must not exceed 1 MiB.",
      );
    }
    chunks.push(buffer);
  }

  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new ApiError(400, "INVALID_JSON", "The request body is not valid JSON.");
  }
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (isObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function requestDigest(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function opaqueTicketHash(ticket: string): string {
  return createHash("sha256").update(ticket, "utf8").digest("hex");
}

function requireInternalBearer(
  request: IncomingMessage,
  expectedToken: string,
  service: "DESKTOP_GATEWAY" | "OPENVPN_DOWNLOAD",
): void {
  if (!expectedToken) {
    throw new ApiError(
      503,
      `${service}_NOT_CONFIGURED`,
      "Internal service authentication is not configured.",
    );
  }
  const supplied = String(request.headers.authorization ?? "");
  const expected = `Bearer ${expectedToken}`;
  const suppliedBuffer = Buffer.from(supplied);
  const expectedBuffer = Buffer.from(expected);
  if (
    suppliedBuffer.length !== expectedBuffer.length ||
    !timingSafeEqual(suppliedBuffer, expectedBuffer)
  ) {
    throw new ApiError(
      401,
      "INTERNAL_AUTHENTICATION_FAILED",
      "The internal service token is invalid.",
    );
  }
}

function idempotencyKey(request: IncomingMessage): string {
  const raw = request.headers["idempotency-key"];
  const key = (Array.isArray(raw) ? raw[0] : raw)?.trim();
  if (!key) {
    throw new ApiError(
      400,
      "IDEMPOTENCY_KEY_REQUIRED",
      "The Idempotency-Key header is required for this operation.",
    );
  }
  if (key.length < 8 || key.length > 128 || !/^[\x21-\x7E]+$/.test(key)) {
    throw new ApiError(
      400,
      "INVALID_IDEMPOTENCY_KEY",
      "Idempotency-Key must be 8-128 visible ASCII characters without spaces.",
    );
  }
  return key;
}

async function replayIfPresent(
  repository: PlatformRepository,
  response: ServerResponse,
  userId: string,
  operation: string,
  key: string,
  digest: string,
  status = 201,
): Promise<boolean> {
  const record = await repository.getIdempotencyRecord(userId, operation, key);
  if (!record) return false;
  if (record.requestHash !== digest) {
    throw new ApiError(
      409,
      "IDEMPOTENCY_KEY_REUSED",
      "The Idempotency-Key was already used with a different request body.",
      { operation, resourceId: record.resourceId },
    );
  }

  sendJson(response, status, record.response, { "Idempotent-Replayed": "true" });
  return true;
}

function webHeaders(request: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(request.headers)) {
    if (Array.isArray(value)) {
      for (const item of value) headers.append(name, item);
    } else if (value !== undefined) {
      headers.set(name, value);
    }
  }
  return headers;
}

async function oidcPrincipal(
  request: IncomingMessage,
  context: HandlerContext,
): Promise<AuthPrincipal> {
  if (request.headers["x-user-id"]) {
    throw new ApiError(
      401,
      "DEV_AUTH_DISABLED",
      "X-User-Id is accepted only when AUTH_MODE=dev.",
    );
  }
  return authenticateRequest(
    { headers: webHeaders(request) },
    { mode: "oidc", verifier: context.oidcVerifier },
  );
}

/**
 * A suspended account keeps its rows but loses every session. This runs before
 * any route handler, so suspension revokes access without a token round-trip.
 */
function rejectSuspendedAccount(user: unknown): void {
  if (field(user, "disabledAt")) {
    throw new ApiError(
      403,
      "ACCOUNT_SUSPENDED",
      "This account has been suspended by a platform administrator.",
    );
  }
}

/**
 * True when the account has not agreed to the documents currently in force.
 * A version bump therefore re-gates everyone, which is the point of storing
 * the version alongside the agreement time.
 */
function consentOutstanding(user: unknown): boolean {
  const consent = field(user, "consent");
  if (!isObject(consent)) return true;
  return (
    !consent.termsAgreedAt ||
    consent.termsVersion !== TERMS_VERSION ||
    !consent.privacyAgreedAt ||
    consent.privacyVersion !== PRIVACY_POLICY_VERSION
  );
}

/** Routes an account may still reach while its consent is outstanding. */
const CONSENT_EXEMPT_PATHS = new Set(["/v1/me", "/v1/me/consent"]);

/**
 * Source address for audit records.
 *
 * `X-Forwarded-For` is attacker-controlled unless a trusted proxy rewrites it,
 * and a forged address in an audit trail is worse than no address at all. The
 * header is therefore only honoured when TRUST_PROXY_HEADERS is enabled, which
 * deployments behind the ingress must set to record real client addresses.
 */
function clientIpOf(request: IncomingMessage, trustProxyHeaders: boolean): string | null {
  if (trustProxyHeaders) {
    const header = request.headers["x-forwarded-for"];
    const raw = Array.isArray(header) ? header[0] : header;
    const first = raw?.split(",")[0]?.trim();
    if (first && first.length <= 45 && !/[\u0000-\u001f\u007f,]/.test(first)) {
      return first;
    }
  }
  return request.socket.remoteAddress ?? null;
}

/**
 * Builds a handle seed from an email local part. The handle is the public
 * identifier (`@handle`) and must satisfy the same charset the API accepts, so
 * anything outside [A-Za-z0-9_-] is dropped and short results are padded.
 */
function handleSeedFromEmail(email: string): string {
  const local = email.split("@")[0] ?? "";
  const cleaned = local.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 24);
  if (cleaned.length >= 3) return cleaned;
  return `user_${cleaned}`.slice(0, 24).padEnd(3, "0");
}

/** Fills in a server-derived handle when the client did not supply one. */
async function withResolvedHandle<T extends { email: string; handle?: string }>(
  context: HandlerContext,
  input: T,
): Promise<T & { handle: string }> {
  if (input.handle) return input as T & { handle: string };
  const handle = await context.repository.findAvailableHandle(
    handleSeedFromEmail(input.email),
  );
  return { ...input, handle };
}

/**
 * Tears a run down at both the runtime and telemetry planes. Adapter failures
 * are logged and swallowed: the platform record must still leave the active
 * set, otherwise a runtime that is already gone would keep the run "ready"
 * forever and re-tried on every sweep.
 */
async function releaseRunResources(
  context: Pick<HandlerContext, "runtime" | "telemetryGateway">,
  runId: string,
): Promise<void> {
  try {
    await context.runtime.destroyRun(runId);
  } catch (error) {
    console.error(`runtime destroy failed for ${runId}`, error);
  }
  try {
    await context.telemetryGateway.destroy(runId);
  } catch (error) {
    console.error(`telemetry destroy failed for ${runId}`, error);
  }
}

/**
 * Stops every still-active run belonging to a user. Suspension revokes API
 * access, but an already-downloaded OpenVPN profile reaches the environment
 * over the network without touching the API, so the environment itself has to
 * go for the suspension to mean anything.
 */
async function terminateRunsForUser(
  context: HandlerContext,
  userId: string,
  actorUserId: string,
  reason: string,
): Promise<string[]> {
  const runIds = await context.repository.listActiveRunIdsForUser(userId);
  const stopped: string[] = [];
  const stoppedAt = new Date().toISOString();
  for (const runId of runIds) {
    await releaseRunResources(context, runId);
    if (await context.repository.markRunStopped(runId, stoppedAt, actorUserId, reason)) {
      stopped.push(runId);
    }
  }
  return stopped;
}

/** Expires runs whose TTL has passed and releases their resources. */
async function sweepExpiredRuns(
  context: HandlerContext,
  now = new Date().toISOString(),
  limit = 50,
): Promise<string[]> {
  const runIds = await context.repository.listExpiredRunIds(now, limit);
  const expired: string[] = [];
  for (const runId of runIds) {
    await releaseRunResources(context, runId);
    if (await context.repository.markRunExpired(runId, now)) {
      expired.push(runId);
      await context.repository.recordAudit({
        actorUserId: null,
        action: "runtime.expired",
        resourceType: "runtime_run",
        resourceId: runId,
        metadata: { expiredAt: now },
      });
    }
  }
  return expired;
}

/**
 * Resolves a member the actor is allowed to act on. The lookup is scoped to the
 * actor's own organization, so a member ID from another tenant reads as absent
 * rather than leaking its existence.
 */
async function requireManageableMember(
  context: HandlerContext,
  actor: RequestActor,
  organizationId: string,
  userId: string,
): Promise<unknown> {
  if (userId === actor.id) {
    throw new ApiError(
      409,
      "CANNOT_MODIFY_SELF",
      "Organization administrators cannot change their own membership.",
    );
  }
  const member = await context.repository.getOrganizationMember(
    organizationId,
    userId,
  );
  if (!member) {
    throw new ApiError(
      404,
      "MEMBER_NOT_FOUND",
      "The organization member was not found.",
    );
  }
  if (stringField(member, "organizationRole") === "owner") {
    throw new ApiError(
      409,
      "OWNER_IMMUTABLE",
      "The organization owner cannot be modified or removed.",
    );
  }
  return member;
}

async function resolveActor(
  request: IncomingMessage,
  context: HandlerContext,
): Promise<RequestActor> {
  const header = request.headers["x-user-id"];
  const requestedUserId = Array.isArray(header) ? header[0] : header;

  if (context.authMode === "oidc") {
    const principal = await oidcPrincipal(request, context);
    const user = await context.repository.getUserByExternalSubject(principal.subject);
    if (!user) {
      throw new ApiError(
        403,
        "ONBOARDING_REQUIRED",
        "The authenticated identity must complete /v1/auth/onboarding.",
      );
    }
    rejectSuspendedAccount(user);
    const organization = actorOrganization(user);
    if (
      principal.organizationId &&
      stringField(organization, "id") !== principal.organizationId
    ) {
      throw new ApiError(
        403,
        "ORGANIZATION_CLAIM_MISMATCH",
        "The token organization does not match the onboarded tenant.",
      );
    }
    return {
      id: stringField(user, "id") as string,
      user,
      roles: principal.roles,
      principal,
    };
  }

  // Password sessions: a signed Bearer token names the user. Roles come from
  // the stored record, exactly as in dev mode, so authorization is identical.
  if (context.authMode === "local") {
    const userId = verifySessionToken(bearerToken(request), context.sessionSecret);
    if (!userId) {
      throw new ApiError(
        401,
        "AUTHENTICATION_REQUIRED",
        "A valid session is required. Sign in to continue.",
      );
    }
    const user = await context.repository.getUser(userId);
    if (!user) {
      throw new ApiError(401, "SESSION_USER_MISSING", "The session user no longer exists.");
    }
    rejectSuspendedAccount(user);
    return actorFromDatabaseUser(user);
  }

  const id = requestedUserId?.trim() || DEV_USER_ID;
  const user = await context.repository.getUser(id);
  if (!user) {
    throw new ApiError(401, "UNKNOWN_DEV_USER", "The development user does not exist.");
  }
  rejectSuspendedAccount(user);
  return actorFromDatabaseUser(user);
}

/** Builds an actor with roles derived from the stored user (dev and local modes). */
function actorFromDatabaseUser(user: unknown): RequestActor {
  const organization = actorOrganization(user);
  const roles = [
    ...(organization ? ["org_member"] : ["individual"]),
    ...(organization && ["owner", "org_admin"].includes(String(organization.role))
      ? ["org_admin"]
      : []),
    ...(field(user, "platformRole") === "platform_admin" ? ["platform_admin"] : []),
  ];
  return { id: stringField(user, "id") as string, user, roles };
}

function bearerToken(request: IncomingMessage): string | undefined {
  const header = request.headers["authorization"];
  const value = Array.isArray(header) ? header[0] : header;
  if (!value) return undefined;
  const match = value.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : undefined;
}

async function route(
  request: IncomingMessage,
  response: ServerResponse,
  context: HandlerContext,
): Promise<void> {
  await context.ready;
  const method = request.method ?? "GET";
  const actorIp = clientIpOf(request, context.trustProxyHeaders);
  const url = new URL(request.url ?? "/", "http://api.local");
  const ingressPath = url.pathname.replace(/\/+$/, "") || "/";
  const path =
    ingressPath === "/api"
      ? "/"
      : ingressPath.startsWith("/api/")
        ? ingressPath.slice(4)
        : ingressPath;

  if (method === "OPTIONS") {
    response.writeHead(204);
    response.end();
    return;
  }

  if (method === "GET" && path === "/health") {
    sendJson(response, 200, {
      status: "ok",
      service: "codegate-range-api",
      version: "1.0.0",
      authMode: context.authMode,
    });
    return;
  }

  if (method === "POST" && path === "/v1/auth/register") {
    // Password registration serves both local development (X-User-Id) and the
    // password-session deployment; OIDC uses /v1/auth/onboarding instead.
    if (context.authMode !== "dev" && context.authMode !== "local") {
      throw new ApiError(
        403,
        "PASSWORD_REGISTRATION_DISABLED",
        "Password registration is disabled; authenticate with OIDC and use /v1/auth/onboarding.",
      );
    }
    if (context.authMode === "local") {
      const preview = await readJson(request);
      if (!isObject(preview) || typeof preview.password !== "string" || preview.password.length < 8) {
        throw new ApiError(
          400,
          "PASSWORD_REQUIRED",
          "A password of at least 8 characters is required to register.",
        );
      }
      const input = await withResolvedHandle(context, normalizeRegistration(preview));
      const user = await context.repository.register(input);
      const userId = stringField(user, "id") as string;
      await context.repository.recordAudit({
        actorIp,
        actorUserId: userId,
        action: "auth.user_registered",
        resourceType: "user",
        resourceId: userId,
        metadata: {
          accountType: input.accountType,
          termsVersion: TERMS_VERSION,
          privacyVersion: PRIVACY_POLICY_VERSION,
        },
      });
      // Registration signs the visitor straight in, so the required flow is
      // register → session → use, with an explicit login available on return.
      sendJson(response, 201, {
        data: { user, session: { token: createSessionToken(userId, context.sessionSecret) } },
      });
      return;
    }
    const input = await withResolvedHandle(
      context,
      normalizeRegistration(await readJson(request)),
    );
    const user = await context.repository.register(input);
    const userId = stringField(user, "id") as string;
    await context.repository.recordAudit({
      actorIp,
      actorUserId: userId,
      action: "auth.user_registered",
      resourceType: "user",
      resourceId: userId,
      metadata: {
        accountType: input.accountType,
        termsVersion: TERMS_VERSION,
        privacyVersion: PRIVACY_POLICY_VERSION,
      },
    });
    sendJson(response, 201, {
      data: {
        user,
        developmentAuth: { header: "X-User-Id", value: userId },
      },
    });
    return;
  }

  if (method === "POST" && path === "/v1/auth/login") {
    if (context.authMode !== "local") {
      throw new ApiError(
        404,
        "ROUTE_NOT_FOUND",
        "Password login is only available when AUTH_MODE=local.",
      );
    }
    const body = await readJson(request);
    const email = isObject(body) && typeof body.email === "string"
      ? body.email.trim().toLowerCase()
      : "";
    const password = isObject(body) && typeof body.password === "string" ? body.password : "";
    // A single generic error for a missing account or a wrong password avoids
    // revealing which emails are registered.
    const invalid = () =>
      new ApiError(401, "INVALID_CREDENTIALS", "The email or password is incorrect.");
    if (!email || !password) throw invalid();
    const credentials = await context.repository.getLoginCredentials(email);
    if (!credentials || !verifyPassword(password, credentials.passwordHash)) {
      throw invalid();
    }
    rejectSuspendedAccount(credentials.user);
    const userId = stringField(credentials.user, "id") as string;
    // The stored hash is transparently upgraded to the current scrypt cost once
    // the plaintext is in hand, which is the only time it is available.
    if (needsPasswordRehash(credentials.passwordHash)) {
      await context.repository.setPasswordHash(userId, password);
    }
    await context.repository.recordAudit({
      actorIp,
      actorUserId: userId,
      action: "auth.login",
      resourceType: "user",
      resourceId: userId,
    });
    sendJson(response, 200, {
      data: {
        user: credentials.user,
        session: { token: createSessionToken(userId, context.sessionSecret) },
      },
    });
    return;
  }

  if (method === "POST" && path === "/v1/auth/onboarding") {
    if (context.authMode !== "oidc") {
      throw new ApiError(
        404,
        "ROUTE_NOT_FOUND",
        "OIDC onboarding is only available when AUTH_MODE=oidc.",
      );
    }
    const principal = await oidcPrincipal(request, context);
    const existing = await context.repository.getUserByExternalSubject(principal.subject);
    if (existing) {
      sendJson(response, 200, { data: { user: existing, alreadyOnboarded: true } });
      return;
    }
    if (!principal.email) {
      throw new ApiError(
        400,
        "OIDC_EMAIL_REQUIRED",
        "The verified identity must include an email claim.",
      );
    }
    if (principal.roles.length === 0) {
      throw new ApiError(
        403,
        "OIDC_ROLE_REQUIRED",
        "The verified identity has no CODEGATE platform role.",
      );
    }
    const rawBody = await readJson(request);
    const onboardingBody = isObject(rawBody) ? rawBody : {};
    if (onboardingBody.password !== undefined) {
      throw new ApiError(
        400,
        "PASSWORD_NOT_ACCEPTED",
        "OIDC onboarding never accepts a password.",
      );
    }
    const input = await withResolvedHandle(
      context,
      normalizeRegistration({
        ...onboardingBody,
        email: principal.email,
        displayName: onboardingBody.displayName ?? principal.displayName,
        ...(principal.organizationId
          ? { accountType: "organization", organizationId: principal.organizationId }
          : {}),
      }),
    );
    const hasOrganizationRole = principal.roles.some(
      (role) => role === "org_member" || role === "org_admin",
    );
    if (input.accountType === "organization" && !hasOrganizationRole) {
      throw new ApiError(
        403,
        "ORGANIZATION_ROLE_REQUIRED",
        "The identity is not authorized to join an organization.",
      );
    }
    if (hasOrganizationRole && input.accountType !== "organization") {
      throw new ApiError(
        400,
        "ORGANIZATION_ONBOARDING_REQUIRED",
        "Organization identities must provide an organization join code.",
      );
    }
    const user = await context.repository.onboardIdentity({
      ...input,
      password: undefined,
      externalSubject: principal.subject,
      platformRole: principal.roles.includes("platform_admin")
        ? "platform_admin"
        : "user",
      organizationRole: principal.roles.includes("org_admin")
        ? "org_admin"
        : "member",
    });
    const userId = stringField(user, "id") as string;
    await context.repository.recordAudit({
      actorIp,
      actorUserId: userId,
      action: "auth.identity_onboarded",
      resourceType: "user",
      resourceId: userId,
      metadata: { subject: principal.subject, roles: principal.roles },
    });
    sendJson(response, 201, { data: { user } });
    return;
  }

  if (method === "POST" && path === "/v1/internal/desktop-tickets/exchange") {
    requireInternalBearer(
      request,
      context.desktopGatewayInternalToken,
      "DESKTOP_GATEWAY",
    );
    const body = await readJson(request);
    const ticket = stringField(body, "ticket");
    if (!ticket || ticket.length < 32 || ticket.length > 256) {
      throw new ApiError(400, "INVALID_DESKTOP_TICKET", "A valid ticket is required.");
    }
    const access = await context.repository.consumeAccessTicket(
      opaqueTicketHash(ticket),
      "desktop",
      new Date().toISOString(),
    );
    if (!access) {
      throw new ApiError(
        410,
        "DESKTOP_TICKET_EXPIRED",
        "The desktop ticket is invalid, expired or already consumed.",
      );
    }
    sendJson(response, 200, { data: { access } });
    return;
  }

  if (method === "POST" && path === "/v1/internal/openvpn-tickets/exchange") {
    requireInternalBearer(
      request,
      context.openVpnDownloadInternalToken,
      "OPENVPN_DOWNLOAD",
    );
    const body = await readJson(request);
    const ticket = stringField(body, "ticket");
    if (!ticket || ticket.length < 32 || ticket.length > 256) {
      throw new ApiError(400, "INVALID_OPENVPN_TICKET", "A valid ticket is required.");
    }
    const access = await context.repository.consumeAccessTicket(
      opaqueTicketHash(ticket),
      "openvpn",
      new Date().toISOString(),
    );
    if (!access) {
      throw new ApiError(
        410,
        "OPENVPN_TICKET_EXPIRED",
        "The OpenVPN ticket is invalid, expired or already consumed.",
      );
    }
    sendJson(response, 200, { data: { access } });
    return;
  }

  const actor = await resolveActor(request, context);

  if (method === "GET" && path === "/v1/admin/overview") {
    requirePlatformAdmin(actor);
    sendJson(response, 200, {
      data: { overview: await context.repository.getAdminOverview() },
    });
    return;
  }

  if (method === "GET" && path === "/v1/admin/users") {
    requirePlatformAdmin(actor);
    const query = parseAdminPageQuery(url, "users");
    sendJson(
      response,
      200,
      adminPagePayload(await context.repository.listAdminUsers(query), query),
    );
    return;
  }

  if (method === "GET" && path === "/v1/admin/organizations") {
    requirePlatformAdmin(actor);
    const query = parseAdminPageQuery(url, "organizations");
    sendJson(
      response,
      200,
      adminPagePayload(
        await context.repository.listAdminOrganizations(query),
        query,
      ),
    );
    return;
  }

  if (method === "GET" && path === "/v1/admin/labs") {
    requirePlatformAdmin(actor);
    const query = parseAdminPageQuery(url, "labs");
    sendJson(
      response,
      200,
      adminPagePayload(await context.repository.listAdminLabs(query), query),
    );
    return;
  }

  if (method === "GET" && path === "/v1/admin/runs") {
    requirePlatformAdmin(actor);
    const query = parseAdminPageQuery(url, "runs");
    sendJson(
      response,
      200,
      adminPagePayload(await context.repository.listAdminRuns(query), query),
    );
    return;
  }

  if (method === "GET" && path === "/v1/admin/audit-logs") {
    requirePlatformAdmin(actor);
    const query = parseAdminPageQuery(url, "auditLogs");
    sendJson(
      response,
      200,
      adminPagePayload(await context.repository.listAdminAuditLogs(query), query),
    );
    return;
  }

  if (method === "GET" && path === "/v1/admin/organization/audit-logs") {
    const organizationId = requireOrganizationAdmin(actor);
    const query = parseAdminPageQuery(url, "organizationAuditLogs");
    sendJson(
      response,
      200,
      adminPagePayload(
        await context.repository.listOrganizationAuditLogs(organizationId, query),
        query,
      ),
    );
    return;
  }

  if (method === "GET" && path === "/v1/admin/organization/members") {
    const organizationId = requireOrganizationAdmin(actor);
    const query = parseAdminPageQuery(url, "members");
    sendJson(
      response,
      200,
      adminPagePayload(
        await context.repository.listOrganizationMembers(organizationId, query),
        query,
      ),
    );
    return;
  }

  if (method === "POST" && path === "/v1/admin/organizations") {
    requirePlatformAdmin(actor);
    const body = await readJson(request);
    const key = idempotencyKey(request);
    const digest = requestDigest(body);
    const operation = "admin.organization.create";
    if (
      await replayIfPresent(
        context.repository,
        response,
        actor.id,
        operation,
        key,
        digest,
      )
    ) {
      return;
    }
    const normalized = normalizeOrganizationBody(body);
    const joinCode = generateOrganizationJoinCode();
    const createdAt = new Date().toISOString();
    const organization = await context.repository.createOrganization({
      id: `org_${randomUUID()}`,
      name: normalized.name,
      slug: normalized.slug,
      joinCodeHash: hashOrganizationJoinCode(joinCode),
      createdAt,
    });
    const organizationId = stringField(organization, "id") as string;
    const storedPayload = {
      data: {
        organization,
        joinCode: null,
        joinCodeReturned: false,
        joinCodeAlreadyReturned: true,
      },
    };
    await context.repository.saveIdempotencyRecord(
      actor.id,
      operation,
      key,
      digest,
      organizationId,
      storedPayload,
    );
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "admin.organization_created",
      resourceType: "organization",
      resourceId: organizationId,
      metadata: { slug: normalized.slug },
    });
    sendJson(response, 201, {
      data: {
        organization,
        joinCode,
        joinCodeReturned: true,
        joinCodeAlreadyReturned: false,
      },
    });
    return;
  }

  const rotateJoinCodeMatch = path.match(
    /^\/v1\/admin\/organizations\/([^/]+)\/rotate-join-code$/,
  );
  if (method === "POST" && rotateJoinCodeMatch) {
    requirePlatformAdmin(actor);
    const organizationId = decodeAdminIdentifier(
      rotateJoinCodeMatch[1],
      "organization",
    );
    const body = await readJson(request);
    if (!isObject(body) || Object.keys(body).length !== 0) {
      throw new ApiError(
        400,
        "INVALID_JOIN_CODE_ROTATION",
        "Join-code rotation accepts an empty JSON object; the code is server-generated.",
      );
    }
    const key = idempotencyKey(request);
    const digest = requestDigest({ organizationId, body });
    const operation = `admin.organization.rotate_join_code:${organizationId}`;
    if (
      await replayIfPresent(
        context.repository,
        response,
        actor.id,
        operation,
        key,
        digest,
        200,
      )
    ) {
      return;
    }
    const joinCode = generateOrganizationJoinCode();
    const organization = await context.repository.rotateOrganizationJoinCode(
      organizationId,
      hashOrganizationJoinCode(joinCode),
      new Date().toISOString(),
    );
    if (!organization) {
      throw new ApiError(
        404,
        "ORGANIZATION_NOT_FOUND",
        "The organization was not found.",
      );
    }
    const storedPayload = {
      data: {
        organization,
        joinCode: null,
        joinCodeReturned: false,
        joinCodeAlreadyReturned: true,
      },
    };
    await context.repository.saveIdempotencyRecord(
      actor.id,
      operation,
      key,
      digest,
      organizationId,
      storedPayload,
    );
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "admin.organization_join_code_rotated",
      resourceType: "organization",
      resourceId: organizationId,
    });
    sendJson(response, 200, {
      data: {
        organization,
        joinCode,
        joinCodeReturned: true,
        joinCodeAlreadyReturned: false,
      },
    });
    return;
  }

  const quarantineLabMatch = path.match(
    /^\/v1\/admin\/labs\/([^/]+)\/quarantine$/,
  );
  if (method === "POST" && quarantineLabMatch) {
    requirePlatformAdmin(actor);
    const labId = decodeAdminIdentifier(quarantineLabMatch[1], "lab");
    const body = await readJson(request);
    const reason = normalizeAdminReason(body, "Administrative quarantine");
    const key = idempotencyKey(request);
    const digest = requestDigest({ labId, body });
    const operation = `admin.lab.quarantine:${labId}`;
    if (
      await replayIfPresent(
        context.repository,
        response,
        actor.id,
        operation,
        key,
        digest,
        200,
      )
    ) {
      return;
    }
    const lab = await context.repository.quarantineLab(
      labId,
      new Date().toISOString(),
      actor.id,
      reason,
    );
    if (!lab) throw new ApiError(404, "LAB_NOT_FOUND", "The lab was not found.");
    const payload = { data: { lab } };
    await context.repository.saveIdempotencyRecord(
      actor.id,
      operation,
      key,
      digest,
      labId,
      payload,
    );
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "admin.lab_quarantined",
      resourceType: "lab",
      resourceId: labId,
      metadata: { reason },
    });
    sendJson(response, 200, payload);
    return;
  }

  const releaseLabMatch = path.match(/^\/v1\/admin\/labs\/([^/]+)\/release$/);
  if (method === "POST" && releaseLabMatch) {
    requirePlatformAdmin(actor);
    const labId = decodeAdminIdentifier(releaseLabMatch[1], "lab");
    const body = await readJson(request);
    const reason = normalizeAdminReason(body, "Administrative release");
    const key = idempotencyKey(request);
    const digest = requestDigest({ labId, body });
    const operation = `admin.lab.release:${labId}`;
    if (
      await replayIfPresent(
        context.repository,
        response,
        actor.id,
        operation,
        key,
        digest,
        200,
      )
    ) {
      return;
    }
    const lab = await context.repository.releaseLabQuarantine(
      labId,
      new Date().toISOString(),
    );
    if (!lab) {
      throw new ApiError(
        409,
        "LAB_NOT_QUARANTINED",
        "The lab was not found or is not quarantined.",
      );
    }
    const payload = { data: { lab } };
    await context.repository.saveIdempotencyRecord(
      actor.id,
      operation,
      key,
      digest,
      labId,
      payload,
    );
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "admin.lab_quarantine_released",
      resourceType: "lab",
      resourceId: labId,
      metadata: { reason, restoredStatus: "draft" },
    });
    sendJson(response, 200, payload);
    return;
  }

  const terminateRunMatch = path.match(
    /^\/v1\/admin\/runs\/([^/]+)\/terminate$/,
  );
  if (method === "POST" && terminateRunMatch) {
    requirePlatformAdmin(actor);
    const runId = decodeAdminIdentifier(terminateRunMatch[1], "runtime run");
    const body = await readJson(request);
    const reason = normalizeAdminReason(body, "Administrative termination");
    const key = idempotencyKey(request);
    const digest = requestDigest({ runId, body });
    const operation = `admin.run.terminate:${runId}`;
    if (
      await replayIfPresent(
        context.repository,
        response,
        actor.id,
        operation,
        key,
        digest,
        200,
      )
    ) {
      return;
    }
    const currentRun = await context.repository.getAdminRun(runId);
    if (!currentRun) {
      throw new ApiError(404, "RUN_NOT_FOUND", "The runtime run was not found.");
    }
    const previousStatus = stringField(currentRun, "status");
    if (previousStatus !== "stopped" && previousStatus !== "expired") {
      await context.runtime.destroyRun(runId);
      await context.telemetryGateway.destroy(runId);
    }
    const run = await context.repository.markRunStopped(
      runId,
      new Date().toISOString(),
      actor.id,
    );
    if (!run) {
      throw new ApiError(404, "RUN_NOT_FOUND", "The runtime run was not found.");
    }
    const payload = { data: { run } };
    await context.repository.saveIdempotencyRecord(
      actor.id,
      operation,
      key,
      digest,
      runId,
      payload,
    );
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "admin.runtime_terminated",
      resourceType: "runtime_run",
      resourceId: runId,
      metadata: { previousStatus, reason },
    });
    sendJson(response, 200, payload);
    return;
  }

  const platformRoleMatch = path.match(
    /^\/v1\/admin\/users\/([^/]+)\/platform-role$/,
  );
  if (method === "POST" && platformRoleMatch) {
    requirePlatformAdmin(actor);
    const userId = decodeAdminIdentifier(platformRoleMatch[1], "user");
    const body = await readJson(request);
    const platformRole = enumBodyField(
      body,
      "platformRole",
      ["user", "platform_admin"] as const,
      "INVALID_PLATFORM_ROLE",
    );
    const reason = normalizeAdminReason(body, "Administrative role change");
    // Blocking self-demotion keeps at least one platform admin reachable; an
    // admin who locked themselves out cannot be recovered through the console.
    if (userId === actor.id) {
      throw new ApiError(
        409,
        "CANNOT_MODIFY_SELF",
        "Platform administrators cannot change their own platform role.",
      );
    }
    const key = idempotencyKey(request);
    const digest = requestDigest({ userId, body });
    const operation = `admin.user.platform_role:${userId}`;
    if (
      await replayIfPresent(
        context.repository,
        response,
        actor.id,
        operation,
        key,
        digest,
        200,
      )
    ) {
      return;
    }
    const current = await context.repository.getAdminUser(userId);
    if (!current) {
      throw new ApiError(404, "USER_NOT_FOUND", "The user was not found.");
    }
    const previousRole = stringField(current, "platformRole");
    const user = await context.repository.setUserPlatformRole(userId, platformRole);
    if (!user) {
      throw new ApiError(404, "USER_NOT_FOUND", "The user was not found.");
    }
    const payload = { data: { user } };
    await context.repository.saveIdempotencyRecord(
      actor.id,
      operation,
      key,
      digest,
      userId,
      payload,
    );
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "admin.user_platform_role_changed",
      resourceType: "user",
      resourceId: userId,
      metadata: { previousRole, platformRole, reason },
    });
    sendJson(response, 200, payload);
    return;
  }

  const suspensionMatch = path.match(/^\/v1\/admin\/users\/([^/]+)\/suspension$/);
  if (method === "POST" && suspensionMatch) {
    requirePlatformAdmin(actor);
    const userId = decodeAdminIdentifier(suspensionMatch[1], "user");
    const body = await readJson(request);
    const suspended = booleanBodyField(body, "suspended", "INVALID_SUSPENSION");
    const reason = normalizeAdminReason(
      body,
      suspended ? "Administrative suspension" : "Administrative reinstatement",
    );
    if (userId === actor.id) {
      throw new ApiError(
        409,
        "CANNOT_MODIFY_SELF",
        "Platform administrators cannot suspend their own account.",
      );
    }
    const key = idempotencyKey(request);
    const digest = requestDigest({ userId, body });
    const operation = `admin.user.suspension:${userId}`;
    if (
      await replayIfPresent(
        context.repository,
        response,
        actor.id,
        operation,
        key,
        digest,
        200,
      )
    ) {
      return;
    }
    const changedAt = new Date().toISOString();
    const user = await context.repository.setUserDisabled(
      userId,
      suspended,
      actor.id,
      reason,
      changedAt,
    );
    if (!user) {
      throw new ApiError(404, "USER_NOT_FOUND", "The user was not found.");
    }
    // Suspension only blocks the API; an issued OpenVPN profile bypasses it, so
    // the environments themselves have to be torn down.
    const terminatedRuns = suspended
      ? await terminateRunsForUser(
          context,
          userId,
          actor.id,
          "account_suspended",
        )
      : [];
    const payload = { data: { user, terminatedRuns } };
    await context.repository.saveIdempotencyRecord(
      actor.id,
      operation,
      key,
      digest,
      userId,
      payload,
    );
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: suspended ? "admin.user_suspended" : "admin.user_reinstated",
      resourceType: "user",
      resourceId: userId,
      metadata: { reason, terminatedRuns: terminatedRuns.length },
    });
    sendJson(response, 200, payload);
    return;
  }

  const memberRoleMatch = path.match(
    /^\/v1\/admin\/organization\/members\/([^/]+)\/role$/,
  );
  if (method === "POST" && memberRoleMatch) {
    const organizationId = requireOrganizationAdmin(actor);
    const userId = decodeAdminIdentifier(memberRoleMatch[1], "member");
    const body = await readJson(request);
    const role = enumBodyField(
      body,
      "role",
      ["org_admin", "member"] as const,
      "INVALID_MEMBERSHIP_ROLE",
    );
    const reason = normalizeAdminReason(body, "Organization role change");
    const member = await requireManageableMember(
      context,
      actor,
      organizationId,
      userId,
    );
    // Granting org_admin is symmetric, but revoking it is owner-only so two
    // organization admins cannot strip each other's access.
    if (
      stringField(member, "organizationRole") === "org_admin" &&
      role === "member" &&
      actorOrganizationRole(actor) !== "owner"
    ) {
      throw new ApiError(
        403,
        "ORGANIZATION_OWNER_REQUIRED",
        "Only the organization owner can demote an organization administrator.",
      );
    }
    const key = idempotencyKey(request);
    const digest = requestDigest({ organizationId, userId, body });
    const operation = `admin.organization.member_role:${organizationId}:${userId}`;
    if (
      await replayIfPresent(
        context.repository,
        response,
        actor.id,
        operation,
        key,
        digest,
        200,
      )
    ) {
      return;
    }
    const previousRole = stringField(member, "organizationRole");
    const updated = await context.repository.setOrganizationMemberRole(
      organizationId,
      userId,
      role,
    );
    if (!updated) {
      throw new ApiError(
        404,
        "MEMBER_NOT_FOUND",
        "The organization member was not found.",
      );
    }
    const payload = { data: { member: updated } };
    await context.repository.saveIdempotencyRecord(
      actor.id,
      operation,
      key,
      digest,
      userId,
      payload,
    );
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "admin.organization_member_role_changed",
      resourceType: "organization_membership",
      resourceId: userId,
      metadata: { organizationId, previousRole, role, reason },
    });
    sendJson(response, 200, payload);
    return;
  }

  const memberRemoveMatch = path.match(
    /^\/v1\/admin\/organization\/members\/([^/]+)\/remove$/,
  );
  if (method === "POST" && memberRemoveMatch) {
    const organizationId = requireOrganizationAdmin(actor);
    const userId = decodeAdminIdentifier(memberRemoveMatch[1], "member");
    const body = await readJson(request);
    const reason = normalizeAdminReason(body, "Organization membership removed");
    const member = await requireManageableMember(
      context,
      actor,
      organizationId,
      userId,
    );
    const previousRole = stringField(member, "organizationRole");
    if (previousRole === "org_admin" && actorOrganizationRole(actor) !== "owner") {
      throw new ApiError(
        403,
        "ORGANIZATION_OWNER_REQUIRED",
        "Only the organization owner can remove an organization administrator.",
      );
    }
    const key = idempotencyKey(request);
    const digest = requestDigest({ organizationId, userId, body });
    const operation = `admin.organization.member_remove:${organizationId}:${userId}`;
    if (
      await replayIfPresent(
        context.repository,
        response,
        actor.id,
        operation,
        key,
        digest,
        200,
      )
    ) {
      return;
    }
    const removed = await context.repository.removeOrganizationMember(
      organizationId,
      userId,
    );
    if (!removed) {
      throw new ApiError(
        404,
        "MEMBER_NOT_FOUND",
        "The organization member was not found.",
      );
    }
    const payload = { data: { removed: true, userId } };
    await context.repository.saveIdempotencyRecord(
      actor.id,
      operation,
      key,
      digest,
      userId,
      payload,
    );
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "admin.organization_member_removed",
      resourceType: "organization_membership",
      resourceId: userId,
      metadata: { organizationId, previousRole, reason },
    });
    sendJson(response, 200, payload);
    return;
  }

  // Accounts created before the consent requirement, or whose agreement predates
  // the current document versions, must re-consent before using the service.
  const consentRequired = consentOutstanding(actor.user);
  if (consentRequired && !CONSENT_EXEMPT_PATHS.has(path)) {
    throw new ApiError(
      403,
      "CONSENT_REQUIRED",
      "Agreement to the current terms of service and privacy notice is required.",
      {
        termsVersion: TERMS_VERSION,
        privacyVersion: PRIVACY_POLICY_VERSION,
      },
    );
  }

  if (method === "GET" && path === "/v1/me") {
    sendJson(response, 200, {
      data: {
        user: actor.user,
        consentRequired,
        termsVersion: TERMS_VERSION,
        privacyVersion: PRIVACY_POLICY_VERSION,
      },
    });
    return;
  }

  if (method === "POST" && path === "/v1/me/consent") {
    const body = await readJson(request);
    const consent: Record<string, unknown> =
      typeof body === "object" && body !== null && "consent" in body &&
      typeof (body as Record<string, unknown>).consent === "object" &&
      (body as Record<string, unknown>).consent !== null
        ? ((body as Record<string, unknown>).consent as Record<string, unknown>)
        : (isObject(body) ? body : {});
    if (consent.terms !== true || consent.privacy !== true) {
      throw new ApiError(
        400,
        "CONSENT_REQUIRED",
        "Agreement to the terms of service and the privacy notice is required.",
      );
    }
    const agreedAt = new Date().toISOString();
    const user = await context.repository.recordUserConsent(
      actor.id,
      agreedAt,
      TERMS_VERSION,
      PRIVACY_POLICY_VERSION,
    );
    if (!user) {
      throw new ApiError(404, "USER_NOT_FOUND", "The user was not found.");
    }
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "auth.consent_recorded",
      resourceType: "user",
      resourceId: actor.id,
      metadata: {
        termsVersion: TERMS_VERSION,
        privacyVersion: PRIVACY_POLICY_VERSION,
      },
    });
    sendJson(response, 200, {
      data: { user, consentRequired: false },
    });
    return;
  }

  if (method === "GET" && path === "/v1/reports/me") {
    const dataset = (await context.repository.getReportingDataset({
      userId: actor.id,
    })) as ReportingDataset;
    sendJson(response, 200, { data: { report: personalReport(dataset, actor.id) } });
    return;
  }

  if (method === "GET" && path === "/v1/reports/organization") {
    const organization = actorOrganization(actor.user);
    const databaseRole = organization ? stringField(organization, "role") : null;
    if (
      !organization ||
      !actor.roles.includes("org_admin") ||
      (databaseRole !== "owner" && databaseRole !== "org_admin")
    ) {
      throw new ApiError(
        403,
        "ORG_ADMIN_REQUIRED",
        "Organization administrator access is required.",
      );
    }
    const organizationId = stringField(organization, "id") as string;
    const dataset = (await context.repository.getReportingDataset({
      organizationId,
    })) as ReportingDataset;
    const report = organizationReport(dataset, organizationId);
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "report.organization_viewed",
      resourceType: "organization",
      resourceId: organizationId,
    });
    sendJson(response, 200, { data: { report } });
    return;
  }

  if (method === "GET" && path === "/v1/admin/reports/platform") {
    if (
      !actor.roles.includes("platform_admin") ||
      field(actor.user, "platformRole") !== "platform_admin"
    ) {
      throw new ApiError(
        403,
        "PLATFORM_ADMIN_REQUIRED",
        "Platform administrator access is required.",
      );
    }
    const dataset = (await context.repository.getReportingDataset()) as ReportingDataset;
    const report = platformReport(dataset);
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "report.platform_viewed",
      resourceType: "platform",
      resourceId: "codegate",
    });
    sendJson(response, 200, { data: { report } });
    return;
  }

  if (method === "GET" && path === "/v1/rankings") {
    const rawScope = url.searchParams.get("scope") ?? "global";
    const rawPeriod = url.searchParams.get("period") ?? "weekly";
    if (rawScope !== "global" && rawScope !== "organization") {
      throw new ApiError(
        400,
        "INVALID_RANKING_SCOPE",
        "scope must be global or organization.",
      );
    }
    if (rawPeriod !== "weekly" && rawPeriod !== "monthly" && rawPeriod !== "all_time") {
      throw new ApiError(
        400,
        "INVALID_RANKING_PERIOD",
        "period must be weekly, monthly or all_time.",
      );
    }

    const organization = actorOrganization(actor.user);
    const organizationId = organization ? stringField(organization, "id") : null;
    if (rawScope === "organization" && !organizationId) {
      throw new ApiError(
        403,
        "ORGANIZATION_MEMBERSHIP_REQUIRED",
        "Organization ranking is available only to members of that organization.",
      );
    }
    const rawDomain = url.searchParams.get("domain");
    if (
      rawDomain !== null &&
      !RANKING_DOMAINS.some((item) => item.key === rawDomain)
    ) {
      throw new ApiError(
        400,
        "INVALID_RANKING_DOMAIN",
        `domain must be one of: ${RANKING_DOMAINS.map((item) => item.key).join(", ")}.`,
      );
    }
    // Cross-organization standings compare every opted-in tenant, so the board
    // is always computed from the full dataset even when the viewer is scoped
    // to their own organization.
    const dataset = (await context.repository.getReportingDataset(
      {},
    )) as ReportingDataset;
    const season = (await context.repository.getActiveSeason(
      new Date().toISOString(),
    )) as RankingSeason | null;
    const result = ranking(dataset, rawScope, rawPeriod, {
      organizationId: organizationId ?? undefined,
      currentUserId: actor.id,
      season,
      domain: (rawDomain as RankingDomain | null) ?? null,
    });
    sendJson(response, 200, { data: { ranking: result } });
    return;
  }

  if (method === "GET" && path === "/v1/admin/seasons") {
    requirePlatformAdmin(actor);
    sendJson(response, 200, {
      data: { seasons: await context.repository.listSeasons() },
    });
    return;
  }

  if (method === "POST" && path === "/v1/admin/seasons") {
    requirePlatformAdmin(actor);
    const body = await readJson(request);
    const season = normalizeSeasonBody(body);
    const created = await context.repository.createSeason({
      id: `season_${randomUUID()}`,
      ...season,
      createdAt: new Date().toISOString(),
    });
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "admin.season_created",
      resourceType: "platform",
      resourceId: stringField(created, "id") as string,
      metadata: { name: season.name, startsAt: season.startsAt, endsAt: season.endsAt },
    });
    sendJson(response, 201, { data: { season: created } });
    return;
  }

  const deleteSeasonMatch = path.match(/^\/v1\/admin\/seasons\/([^/]+)$/);
  if (method === "DELETE" && deleteSeasonMatch) {
    requirePlatformAdmin(actor);
    const seasonId = decodeAdminIdentifier(deleteSeasonMatch[1], "season");
    if (!(await context.repository.deleteSeason(seasonId))) {
      throw new ApiError(404, "SEASON_NOT_FOUND", "The season was not found.");
    }
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "admin.season_deleted",
      resourceType: "platform",
      resourceId: seasonId,
    });
    sendJson(response, 200, { data: { deleted: true, seasonId } });
    return;
  }

  // The organization decides whether its own headcount and readiness appear in
  // the public board, mirroring how individuals opt into the global ranking.
  if (method === "POST" && path === "/v1/admin/organization/ranking-opt-in") {
    const organizationId = requireOrganizationAdmin(actor);
    const body = await readJson(request);
    const optIn = booleanBodyField(body, "optIn", "INVALID_RANKING_OPT_IN");
    const organization = await context.repository.setOrganizationRankingOptIn(
      organizationId,
      optIn,
    );
    if (!organization) {
      throw new ApiError(
        404,
        "ORGANIZATION_NOT_FOUND",
        "The organization was not found.",
      );
    }
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "admin.organization_ranking_opt_in_changed",
      resourceType: "organization",
      resourceId: organizationId,
      metadata: { optIn },
    });
    sendJson(response, 200, { data: { organization } });
    return;
  }

  if (method === "GET" && path === "/v1/labs") {
    sendJson(response, 200, {
      data: { labs: await context.repository.listLabs(actor.id) },
    });
    return;
  }

  if (method === "POST" && path === "/v1/labs/generate") {
    const body = await readJson(request);
    const key = idempotencyKey(request);
    const digest = requestDigest(body);
    if (
      await replayIfPresent(
        context.repository,
        response,
        actor.id,
        "lab.generate",
        key,
        digest,
      )
    ) {
      return;
    }

    const normalizedInput = normalizeLabGeneration(body);
    const input = await context.labGenerator.generate(normalizedInput);
    const storedInput = input.buildSpec
      ? { ...input, config: { ...input.config, builderSpec: input.buildSpec } }
      : input;
    let lab = await context.repository.createLab(actor.id, storedInput);
    const labId = stringField(lab, "id") as string;
    let buildOperation: EnvironmentBuildOperation | null = null;
    if (input.buildSpec) {
      try {
        buildOperation = await context.environmentBuilder.start({
          labId,
          labVersion: 1,
          requestedBy: actor.id,
          spec: input.buildSpec,
          idempotencyKey: `lab-build-${digest.slice(0, 48)}`,
        });
        const patch = buildOperation.status === "succeeded"
          ? successfulBuildPatch(lab, buildOperation)
          : { builder: buildState(buildOperation) };
        await context.repository.updateLabConfig(labId, patch, new Date().toISOString());
      } catch (error) {
        await context.repository.updateLabConfig(labId, {
          builder: {
            status: "failed",
            failureCode: error instanceof ApiError ? error.code : "BUILDER_START_FAILED",
            updatedAt: new Date().toISOString(),
          },
        }, new Date().toISOString());
      }
      lab = await context.repository.getLab(actor.id, labId) ?? lab;
    }
    const payload = { data: { lab } };
    await context.repository.saveIdempotencyRecord(
      actor.id,
      "lab.generate",
      key,
      digest,
      labId,
      payload,
    );
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "lab.generated",
      resourceType: "lab",
      resourceId: labId,
      metadata: {
        team: input.team,
        questionTypes: input.questionTypes,
        buildId: buildOperation?.id ?? null,
        buildStatus: buildOperation?.status ?? (input.buildSpec ? "failed" : "not_required"),
      },
    });
    sendJson(response, 201, payload);
    return;
  }

  const labMatch = path.match(/^\/v1\/labs\/([^/]+)$/);
  if (method === "GET" && labMatch) {
    let lab = await context.repository.getLab(actor.id, decodeURIComponent(labMatch[1]));
    if (!lab) throw new ApiError(404, "LAB_NOT_FOUND", "The lab was not found.");
    lab = await refreshLabBuild(context, actor.id, lab);
    sendJson(response, 200, { data: { lab } });
    return;
  }

  const buildRetryMatch = path.match(/^\/v1\/labs\/([^/]+)\/build$/);
  if (method === "POST" && buildRetryMatch) {
    const labId = decodeURIComponent(buildRetryMatch[1]);
    const lab = await context.repository.getLab(actor.id, labId);
    if (!lab) throw new ApiError(404, "LAB_NOT_FOUND", "The lab was not found.");
    if (field(lab, "validationStatus") !== "draft") {
      throw new ApiError(409, "LAB_BUILD_STATE_CONFLICT", "Only a draft Lab can start an environment build.");
    }
    const current = labBuilder(lab);
    if (["queued", "running", "succeeded"].includes(stringField(current, "status") ?? "")) {
      throw new ApiError(409, "LAB_BUILD_ALREADY_ACTIVE", "This Lab already has an active or completed build.");
    }
    const spec = await context.repository.getLabBuildSpec(actor.id, labId);
    if (!spec) throw new ApiError(409, "LAB_BUILD_SPEC_MISSING", "The Lab has no server-side environment build specification.");
    const body = await readJson(request);
    const key = idempotencyKey(request);
    const digest = requestDigest({ labId, body });
    const operationName = `lab.build:${labId}`;
    if (await replayIfPresent(context.repository, response, actor.id, operationName, key, digest, 202)) return;
    const operation = await context.environmentBuilder.start({
      labId,
      labVersion: Number(field(lab, "version") ?? 1),
      requestedBy: actor.id,
      spec,
      idempotencyKey: `lab-build-${createHash("sha256").update(`${labId}:${key}`).digest("hex").slice(0, 48)}`,
    });
    const patch = operation.status === "succeeded"
      ? successfulBuildPatch(lab, operation)
      : { builder: buildState(operation) };
    if (!await context.repository.updateLabConfig(labId, patch, new Date().toISOString())) {
      await context.environmentBuilder.cancel(operation.id).catch(() => undefined);
      throw new ApiError(409, "LAB_BUILD_STATE_CONFLICT", "The Lab can no longer accept build updates.");
    }
    const updatedLab = await context.repository.getLab(actor.id, labId);
    const payload = { data: { lab: updatedLab, build: operation } };
    await context.repository.saveIdempotencyRecord(actor.id, operationName, key, digest, operation.id, payload);
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "lab.environment_build_started",
      resourceType: "lab",
      resourceId: labId,
      metadata: { buildId: operation.id, status: operation.status },
    });
    sendJson(response, 202, payload);
    return;
  }

  const validationMatch = path.match(/^\/v1\/labs\/([^/]+)\/validate$/);
  if (method === "POST" && validationMatch) {
    const labId = decodeURIComponent(validationMatch[1]);
    let lab = await context.repository.getLab(actor.id, labId);
    if (!lab) throw new ApiError(404, "LAB_NOT_FOUND", "The lab was not found.");
    lab = await refreshLabBuild(context, actor.id, lab);
    const builder = labBuilder(lab);
    if (builder && stringField(builder, "status") !== "succeeded") {
      throw new ApiError(409, "LAB_BUILD_NOT_READY", "Automatic validation starts only after the environment image build succeeds.", { buildStatus: stringField(builder, "status") });
    }

    const result = await context.labValidator.validate(lab);
    const evidence = await context.repository.saveValidation(
      labId,
      result.status,
      result.evidence,
    );
    const updatedLab = await context.repository.getLab(actor.id, labId);
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "lab.validation_completed",
      resourceType: "lab",
      resourceId: labId,
      metadata: { decision: result.decision },
    });
    const evidenceRows = evidence.filter(isObject);
    const passedChecks = evidenceRows.filter((item) => item.outcome === "pass").length;
    const validation = result.validation ?? {
      labId,
      decision: result.decision,
      score: evidenceRows.length
        ? Math.round((passedChecks / evidenceRows.length) * 100)
        : 0,
      checks: evidenceRows.map((item) => ({
        id: item.id,
        label: item.check,
        passed: item.outcome === "pass",
        evidence: JSON.stringify(item.details ?? {}),
        mandatory: true,
      })),
      policyVersion: "codegate-lab-policy/v1",
      createdAt: String(evidenceRows[0]?.createdAt ?? new Date().toISOString()),
    };
    sendJson(response, 200, {
      data: { decision: result.decision, lab: updatedLab, evidence, validation },
    });
    return;
  }

  const deployMatch = path.match(/^\/v1\/labs\/([^/]+)\/deploy$/);
  if (method === "POST" && deployMatch) {
    const labId = decodeURIComponent(deployMatch[1]);
    const lab = await context.repository.getLab(actor.id, labId);
    if (!lab) throw new ApiError(404, "LAB_NOT_FOUND", "The lab was not found.");
    if (field(lab, "validationStatus") !== "validated") {
      throw new ApiError(
        409,
        "LAB_NOT_VALIDATED",
        "Only a validated lab can be deployed.",
        { validationStatus: field(lab, "validationStatus") },
      );
    }

    const body = await readJson(request);
    const key = idempotencyKey(request);
    const digest = requestDigest({ labId, body });
    const operation = `lab.deploy:${labId}`;
    if (
      await replayIfPresent(
        context.repository,
        response,
        actor.id,
        operation,
        key,
        digest,
      )
    ) {
      return;
    }

    const accessMethod = normalizeAccessMethod(body);
    const accessModes = field(lab, "accessModes");
    const accessEnabled =
      Array.isArray(accessModes) &&
      (accessMethod === "both"
        ? accessModes.includes("browser_desktop") && accessModes.includes("openvpn")
        : accessModes.includes(accessMethod));
    if (!accessEnabled) {
      throw new ApiError(
        409,
        "ACCESS_METHOD_NOT_ENABLED",
        "The requested access method is not enabled for this lab.",
      );
    }

    const runInput = await context.runtime.createRun(lab, actor.id, accessMethod);
    const events = telemetryEvents(lab, runInput.metadata);
    if (field(lab, "teamType") === "blue" || field(lab, "team") === "blue") {
      if (events.length === 0 && context.authMode !== "dev") {
        await Promise.resolve(context.runtime.destroyRun(runInput.id)).catch(() => undefined);
        throw new ApiError(409, "BLUE_TELEMETRY_NOT_READY", "The validated blue-team Lab has no ELK telemetry fixture.");
      }
      if (events.length > 0) {
        try {
          await context.telemetryGateway.provision({ runId: runInput.id, expiresAt: runInput.expiresAt, events });
        } catch (error) {
          await Promise.resolve(context.runtime.destroyRun(runInput.id)).catch(() => undefined);
          throw error;
        }
      }
    }
    let run: unknown;
    try {
      run = await context.repository.createRun(runInput);
    } catch (error) {
      await Promise.resolve(context.runtime.destroyRun(runInput.id)).catch(() => undefined);
      await context.telemetryGateway.destroy(runInput.id).catch(() => undefined);
      throw error;
    }
    const runId = stringField(run, "id") as string;
    const payload = { data: { run } };
    await context.repository.saveIdempotencyRecord(
      actor.id,
      operation,
      key,
      digest,
      runId,
      payload,
    );
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "runtime.deployed",
      resourceType: "runtime_run",
      resourceId: runId,
      metadata: {
        labId,
        accessMethod,
        adapter: field(runInput.metadata, "runtime") ?? "runtime-service",
      },
    });
    sendJson(response, 201, payload);
    return;
  }

  const desktopTicketMatch = path.match(/^\/v1\/runs\/([^/]+)\/desktop-ticket$/);
  if (method === "POST" && desktopTicketMatch) {
    const runId = decodeURIComponent(desktopTicketMatch[1]);
    let run = await context.repository.getRun(actor.id, runId);
    if (!run) throw new ApiError(404, "RUN_NOT_FOUND", "The runtime run was not found.");
    run = await refreshRuntimeRun(context, actor.id, run);
    if (field(run, "status") !== "ready") {
      throw new ApiError(
        409,
        "RUN_NOT_READY",
        "A desktop ticket can only be issued for a ready run.",
      );
    }
    if (
      field(run, "accessMethod") !== "browser_desktop" &&
      field(run, "accessMethod") !== "both"
    ) {
      throw new ApiError(
        409,
        "DESKTOP_ACCESS_NOT_ENABLED",
        "This run was not provisioned for browser desktop access.",
      );
    }
    const ticket = randomBytes(32).toString("base64url");
    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + context.desktopTicketTtlSeconds * 1_000);
    await context.repository.createAccessTicket({
      ticketHash: opaqueTicketHash(ticket),
      runId,
      userId: actor.id,
      kind: "desktop",
      expiresAt: expiresAt.toISOString(),
      createdAt: createdAt.toISOString(),
    });
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "desktop_ticket.issued",
      resourceType: "runtime_run",
      resourceId: runId,
      metadata: { expiresAt: expiresAt.toISOString() },
    });
    const gatewayUrl = new URL(
      `/sessions/${encodeURIComponent(runId)}/desktop`,
      `${context.desktopGatewayPublicUrl}/`,
    );
    gatewayUrl.searchParams.set("ticket", ticket);
    sendJson(response, 201, {
      data: {
        ticket,
        gatewayUrl: gatewayUrl.toString(),
        expiresAt: expiresAt.toISOString(),
      },
    });
    return;
  }

  const openVpnTicketMatch = path.match(/^\/v1\/runs\/([^/]+)\/openvpn-ticket$/);
  if (method === "POST" && openVpnTicketMatch) {
    const runId = decodeURIComponent(openVpnTicketMatch[1]);
    let run = await context.repository.getRun(actor.id, runId);
    if (!run) throw new ApiError(404, "RUN_NOT_FOUND", "The runtime run was not found.");
    run = await refreshRuntimeRun(context, actor.id, run);
    if (field(run, "status") !== "ready") {
      throw new ApiError(
        409,
        "RUN_NOT_READY",
        "An OpenVPN ticket can only be issued for a ready run.",
      );
    }
    if (
      (field(run, "accessMethod") !== "openvpn" &&
        field(run, "accessMethod") !== "both") ||
      !isObject(field(run, "openVpn"))
    ) {
      throw new ApiError(
        409,
        "OPENVPN_ACCESS_NOT_ENABLED",
        "This run was not provisioned for OpenVPN access.",
      );
    }
    const ticket = randomBytes(32).toString("base64url");
    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + 60_000);
    await context.repository.createAccessTicket({
      ticketHash: opaqueTicketHash(ticket),
      runId,
      userId: actor.id,
      kind: "openvpn",
      expiresAt: expiresAt.toISOString(),
      createdAt: createdAt.toISOString(),
    });
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "openvpn_ticket.issued",
      resourceType: "runtime_run",
      resourceId: runId,
      metadata: { expiresAt: expiresAt.toISOString() },
    });
    const downloadUrl = new URL("/download", `${context.openVpnDownloadPublicUrl}/`);
    downloadUrl.searchParams.set("ticket", ticket);
    sendJson(response, 201, {
      data: {
        ticket,
        downloadUrl: downloadUrl.toString(),
        expiresAt: expiresAt.toISOString(),
      },
    });
    return;
  }

  const runMatch = path.match(/^\/v1\/runs\/([^/]+)$/);
  if (method === "GET" && runMatch) {
    let run = await context.repository.getRun(actor.id, decodeURIComponent(runMatch[1]));
    if (!run) throw new ApiError(404, "RUN_NOT_FOUND", "The runtime run was not found.");
    run = await refreshRuntimeRun(context, actor.id, run);
    sendJson(response, 200, { data: { run } });
    return;
  }

  const elkSearchMatch = path.match(/^\/v1\/runs\/([^/]+)\/elk\/search$/);
  if (method === "POST" && elkSearchMatch) {
    const runId = decodeURIComponent(elkSearchMatch[1]);
    let run = await context.repository.getRun(actor.id, runId);
    if (!run) throw new ApiError(404, "RUN_NOT_FOUND", "The runtime run was not found.");
    run = await refreshRuntimeRun(context, actor.id, run);
    if (field(run, "status") !== "ready") throw new ApiError(409, "RUN_NOT_READY", "ELK search is available only for a ready run.");
    const labId = stringField(run, "labId");
    const lab = labId ? await context.repository.getLab(actor.id, labId) : null;
    if (!lab || (field(lab, "teamType") !== "blue" && field(lab, "team") !== "blue")) {
      throw new ApiError(409, "ELK_NOT_ENABLED", "ELK search is available only for blue-team Labs.");
    }
    const body = await readJson(request);
    const query = stringField(body, "query")?.trim();
    const size = field(body, "size") === undefined ? 50 : Number(field(body, "size"));
    if (!query || query.length > 1_000 || !Number.isInteger(size) || size < 1 || size > 100) {
      throw new ApiError(400, "INVALID_ELK_QUERY", "query and a size between 1 and 100 are required.");
    }
    const result = await context.telemetryGateway.search(runId, query, size);
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "elk.search_executed",
      resourceType: "runtime_run",
      resourceId: runId,
      metadata: { queryHash: createHash("sha256").update(query).digest("hex"), resultCount: result.hits.length },
    });
    sendJson(response, 200, { data: { result } });
    return;
  }

  const submissionMatch = path.match(/^\/v1\/runs\/([^/]+)\/submit$/);
  if (method === "POST" && submissionMatch) {
    const runId = decodeURIComponent(submissionMatch[1]);
    const run = await context.repository.getRun(actor.id, runId);
    if (!run) throw new ApiError(404, "RUN_NOT_FOUND", "The runtime run was not found.");

    const body = await readJson(request);
    const key = idempotencyKey(request);
    const digest = requestDigest({ runId, body });
    const operation = `run.submit:${runId}`;
    if (
      await replayIfPresent(
        context.repository,
        response,
        actor.id,
        operation,
        key,
        digest,
      )
    ) {
      return;
    }

    const answers = submittedAnswers(body);
    const hintsUsed = hintsUsedOf(body);
    const labId = stringField(run, "labId") as string;
    const lab = await context.repository.getLab(actor.id, labId);
    if (!lab) {
      throw new RepositoryError(
        "RUN_LAB_NOT_FOUND",
        "The runtime run references a Lab that is not accessible.",
        500,
      );
    }
    const questions = (await context.repository.getLabGradingQuestions(
      actor.id,
      labId,
    )) as ServerQuestion[];
    const [storedEvidenceValue, generatedEvidenceValue] = await Promise.all([
      context.repository.getTrustedGradeEvidence(actor.id, runId),
      context.evidenceGrader.grade({ run, lab, questions, answers }),
    ]);
    const trustedEvidence = mergeTrustedGradeEvidence(
      validateTrustedGradeEvidence(storedEvidenceValue, questions),
      validateTrustedGradeEvidence(generatedEvidenceValue, questions),
    );
    let grade;
    try {
      grade = gradeRun(questions, answers, trustedEvidence);
    } catch (error) {
      throw new ApiError(
        400,
        "SUBMISSION_GRADING_FAILED",
        error instanceof Error ? error.message : "The submission could not be graded.",
      );
    }
    const completedAt = new Date().toISOString();
    const result = await context.repository.saveChallengeResult({
      id: `result_${randomUUID()}`,
      labId,
      runId,
      userId: actor.id,
      awardedPoints: grade.awardedPoints,
      maxPoints: grade.maxPoints,
      answers,
      gradeEvidence: {
        grade,
        trustedEvidence,
      },
      skills: gradeSkills(grade.grades as unknown as JsonRecord[]),
      hintsUsed,
      completedAt,
    });
    const payload = { data: { result, grade } };
    const resultId = stringField(result, "id") as string;
    await context.repository.saveIdempotencyRecord(
      actor.id,
      operation,
      key,
      digest,
      resultId,
      payload,
    );
    await context.repository.recordAudit({
      actorIp,
      actorUserId: actor.id,
      action: "challenge.submitted",
      resourceType: "challenge_result",
      resourceId: resultId,
      metadata: { runId, labId, score: grade.score, passed: grade.passed },
    });
    sendJson(response, 201, payload);
    return;
  }

  throw new ApiError(404, "ROUTE_NOT_FOUND", "The requested API route does not exist.");
}

function environmentOidcVerifier(): OidcVerifier {
  const issuer = process.env.OIDC_ISSUER ?? process.env.KEYCLOAK_ISSUER;
  if (!issuer) {
    throw new RepositoryError(
      "OIDC_ISSUER_REQUIRED",
      "OIDC_ISSUER (or KEYCLOAK_ISSUER) is required when AUTH_MODE=oidc.",
      500,
    );
  }
  const internalJwksUrl = process.env.OIDC_JWKS_URL ?? process.env.KEYCLOAK_JWKS_URL;
  return new OidcVerifier({
    issuer,
    audience: process.env.OIDC_AUDIENCE ?? "codegate-api",
    clientId: process.env.OIDC_CLIENT_ID ?? "codegate-web",
    ...(internalJwksUrl
      ? {
          fetchImpl: (_input, init) => fetch(internalJwksUrl, init),
        }
      : {}),
  });
}

export function createApplication(options: ApplicationOptions = {}) {
  const configuredAuthMode = options.authMode ?? process.env.AUTH_MODE ?? "oidc";
  const authMode = configuredAuthMode === "production" ? "oidc" : configuredAuthMode;
  const productionMode = configuredAuthMode === "production" || (authMode === "oidc" && process.env.NODE_ENV === "production");
  if (authMode !== "dev" && authMode !== "oidc" && authMode !== "local") {
    throw new RepositoryError(
      "INVALID_AUTH_MODE",
      "AUTH_MODE must be 'dev', 'local' or 'oidc'.",
      500,
    );
  }
  // Password sessions are signed with this secret. It must be provided in a
  // deployment; a random per-process fallback keeps local runs working but
  // invalidates every session on restart, which is fine for development.
  const sessionSecret =
    options.sessionSecret ??
    process.env.SESSION_SIGNING_SECRET ??
    (authMode === "local" && process.env.NODE_ENV === "production"
      ? ""
      : randomBytes(32).toString("hex"));
  if (authMode === "local" && !sessionSecret) {
    throw new RepositoryError(
      "SESSION_SECRET_REQUIRED",
      "SESSION_SIGNING_SECRET must be set when AUTH_MODE=local in production.",
      500,
    );
  }
  // Local password mode is a self-contained deployment: it uses the same
  // in-process simulators as dev for the runtime, AI, grader and gateways, so
  // no external services are required.
  const devInfra = authMode === "dev" || authMode === "local";
  const repositoryMode =
    options.repositoryMode ??
    (process.env.REPOSITORY_MODE === "sqlite" || process.env.REPOSITORY_MODE === "postgres"
      ? process.env.REPOSITORY_MODE
      : devInfra
        ? "sqlite"
        : "postgres");
  const repository =
    options.repository ??
    (repositoryMode === "sqlite"
      ? new SqliteDevelopmentRepository(
          createDatabase(
            options.databasePath ?? process.env.CODEGATE_DB_PATH ?? ".data/codegate.db",
          ),
        )
      : new PostgresRepository(options.databaseUrl ?? process.env.DATABASE_URL ?? ""));
  const configuredRuntimeMode =
    options.runtimeMode ??
    (process.env.RUNTIME_ADAPTER === "service" ||
    process.env.RUNTIME_ADAPTER === "http" ||
    process.env.RUNTIME_MODE === "http"
      ? "http"
      : process.env.RUNTIME_ADAPTER === "simulator" ||
          process.env.RUNTIME_MODE === "simulator"
        ? "simulator"
        : devInfra
          ? "simulator"
          : "http");
  if (
    authMode === "oidc" &&
    (configuredRuntimeMode === "simulator" ||
      options.runtime instanceof DevelopmentRuntimeSimulator)
  ) {
    throw new RepositoryError(
      "SIMULATED_RUNTIME_FORBIDDEN",
      "The development runtime simulator cannot be used when AUTH_MODE=oidc.",
      500,
    );
  }
  const runtime =
    options.runtime ??
    (configuredRuntimeMode === "simulator"
      ? new DevelopmentRuntimeSimulator()
      : new HttpRuntimeAdapter({
          serviceUrl:
            process.env.RUNTIME_SERVICE_URL ?? "http://codegate-runtime:9000",
          internalToken:
            process.env.RUNTIME_INTERNAL_TOKEN ??
            (devInfra ? "local-runtime-token" : ""),
          targetImage:
            process.env.RUNTIME_TARGET_IMAGE ??
            (devInfra ? "codegate/local-target:development" : ""),
          allowedTargetRegistries: (
            process.env.TARGET_IMAGE_REGISTRIES ?? "registry.codegate.internal"
          )
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean),
          allowTemplateFallback: devInfra,
          desktopPublicUrl: process.env.DESKTOP_GATEWAY_PUBLIC_URL,
        }));
  const configuredLabGeneratorMode =
    options.labGeneratorMode ??
    (process.env.AI_LAB_GENERATOR === "local" || process.env.AI_ADAPTER === "local"
      ? "local"
      : process.env.AI_LAB_GENERATOR === "http" ||
          process.env.AI_ADAPTER === "http" ||
          process.env.AI_ADAPTER === "service"
        ? "http"
        : devInfra
          ? "local"
          : "http");
  if (
    authMode === "oidc" &&
    (configuredLabGeneratorMode === "local" ||
      options.labGenerator instanceof DevelopmentLocalLabGenerator)
  ) {
    throw new RepositoryError(
      "LOCAL_AI_GENERATOR_FORBIDDEN",
      "The local Lab generator cannot be used when AUTH_MODE=oidc.",
      500,
    );
  }
  const labGenerator =
    options.labGenerator ??
    (configuredLabGeneratorMode === "local"
      ? new DevelopmentLocalLabGenerator()
      : new HttpAiLabGenerator({
          serviceUrl: process.env.AI_SERVICE_URL ?? "http://codegate-ai:8001",
          internalToken:
            process.env.AI_INTERNAL_TOKEN ??
            (devInfra ? "ai-service-dev-token" : ""),
          generationTimeoutMs: aiGenerationTimeoutFromEnvironment(),
          exposeDebugErrors: authMode === "dev",
        }));
  const configuredEvidenceGraderMode =
    options.evidenceGraderMode ??
    (process.env.EVIDENCE_GRADER_ADAPTER === "mock" ||
    process.env.GRADER_ADAPTER === "mock"
      ? "mock"
      : process.env.EVIDENCE_GRADER_ADAPTER === "http" ||
          process.env.EVIDENCE_GRADER_ADAPTER === "service" ||
          process.env.GRADER_ADAPTER === "http" ||
          process.env.GRADER_ADAPTER === "service"
        ? "http"
        : devInfra
          ? "mock"
          : "http");
  if (
    authMode === "oidc" &&
    (configuredEvidenceGraderMode === "mock" ||
      options.evidenceGrader instanceof DevelopmentEvidenceGrader)
  ) {
    throw new RepositoryError(
      "MOCK_EVIDENCE_GRADER_FORBIDDEN",
      "The development evidence grader cannot be used when AUTH_MODE=oidc.",
      500,
    );
  }
  const evidenceGrader =
    options.evidenceGrader ??
    (configuredEvidenceGraderMode === "mock"
      ? new DevelopmentEvidenceGrader()
      : new HttpEvidenceGrader({
          serviceUrl:
            process.env.GRADER_SERVICE_URL ?? "http://codegate-grader:9002",
          internalToken:
            process.env.GRADER_INTERNAL_TOKEN ??
            (devInfra ? "grader-service-dev-token" : ""),
        }));
  const configuredLabValidatorMode =
    options.labValidatorMode ??
    (process.env.LAB_VALIDATOR_ADAPTER === "development"
      ? "development"
      : process.env.LAB_VALIDATOR_ADAPTER === "http" ||
          process.env.LAB_VALIDATOR_ADAPTER === "service"
        ? "http"
        : devInfra
          ? "development"
          : "http");
  if (
    authMode === "oidc" &&
    (configuredLabValidatorMode === "development" ||
      options.labValidator instanceof DevelopmentLabValidator)
  ) {
    throw new RepositoryError(
      "DEVELOPMENT_VALIDATOR_FORBIDDEN",
      "The development validator cannot be used when AUTH_MODE=oidc.",
      500,
    );
  }
  const allowedTargetRegistries = (
    process.env.TARGET_IMAGE_REGISTRIES ?? "registry.codegate.internal"
  )
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const labValidator =
    options.labValidator ??
    (configuredLabValidatorMode === "development"
      ? new DevelopmentLabValidator(allowedTargetRegistries)
      : new HttpLabValidator({
          serviceUrl:
            process.env.VALIDATOR_SERVICE_URL ?? "http://codegate-validator:9003",
          internalToken:
            process.env.VALIDATOR_INTERNAL_TOKEN ??
            (devInfra ? "validator-service-dev-token" : ""),
        }));
  const configuredTelemetryGatewayMode =
    options.telemetryGatewayMode ??
    (process.env.TELEMETRY_ADAPTER === "development"
      ? "development"
      : process.env.TELEMETRY_ADAPTER === "http" || process.env.TELEMETRY_ADAPTER === "service"
        ? "http"
        : devInfra
          ? "development"
          : "http");
  if (
    authMode === "oidc" &&
    (configuredTelemetryGatewayMode === "development" || options.telemetryGateway instanceof DevelopmentTelemetryGateway)
  ) {
    throw new RepositoryError(
      "DEVELOPMENT_TELEMETRY_FORBIDDEN",
      "The development telemetry adapter cannot be used when AUTH_MODE=oidc.",
      500,
    );
  }
  const telemetryGateway =
    options.telemetryGateway ??
    (configuredTelemetryGatewayMode === "development"
      ? new DevelopmentTelemetryGateway()
      : new HttpTelemetryGateway({
          url: process.env.TELEMETRY_SERVICE_URL ?? "http://codegate-telemetry:9201",
          token: process.env.TELEMETRY_INTERNAL_TOKEN ?? (devInfra ? "telemetry-service-dev-token" : ""),
        }));
  const configuredEnvironmentBuilderMode =
    options.environmentBuilderMode ??
    (process.env.ENVIRONMENT_BUILDER_ADAPTER === "development"
      ? "development"
      : process.env.ENVIRONMENT_BUILDER_ADAPTER === "http" ||
          process.env.ENVIRONMENT_BUILDER_ADAPTER === "service"
        ? "http"
        : devInfra
          ? "development"
          : "http");
  if (
    authMode === "oidc" &&
    (configuredEnvironmentBuilderMode === "development" ||
      options.environmentBuilder instanceof DevelopmentEnvironmentBuilder)
  ) {
    throw new RepositoryError(
      "DEVELOPMENT_BUILDER_FORBIDDEN",
      "The development environment builder cannot be used when AUTH_MODE=oidc.",
      500,
    );
  }
  const environmentBuilder =
    options.environmentBuilder ??
    (configuredEnvironmentBuilderMode === "development"
      ? new DevelopmentEnvironmentBuilder({ targetImage: process.env.RUNTIME_TARGET_IMAGE })
      : new HttpEnvironmentBuilder({
          url: process.env.BUILDER_SERVICE_URL ?? "http://codegate-builder:9004",
          token: process.env.BUILDER_INTERNAL_TOKEN ?? (devInfra ? "builder-service-dev-token" : ""),
        }));
  const oidcVerifier =
    authMode === "oidc" ? options.oidcVerifier ?? environmentOidcVerifier() : undefined;
  const configuredOrigins =
    options.allowedOrigins ??
    (process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(",").map((item) => item.trim()).filter(Boolean)
      : devInfra
        ? ["http://localhost:3000", "http://127.0.0.1:3000"]
        : []);
  const allowedOrigins = new Set(configuredOrigins);
  const desktopGatewayInternalToken =
    options.desktopGatewayInternalToken ??
    process.env.DESKTOP_GATEWAY_INTERNAL_TOKEN ??
    (devInfra ? "desktop-gateway-dev-token" : "");
  const desktopGatewayPublicUrl = (
    options.desktopGatewayPublicUrl ??
    process.env.DESKTOP_GATEWAY_PUBLIC_URL ??
    (devInfra ? "http://localhost:9001" : "https://desktop.codegate.invalid")
  ).replace(/\/$/, "");
  const desktopTicketTtlSeconds = boundedInteger(
    options.desktopTicketTtlSeconds ?? process.env.DESKTOP_TICKET_TTL_SECONDS ?? 300,
    "DESKTOP_TICKET_TTL_SECONDS",
    60,
    900,
  );
  const openVpnDownloadInternalToken =
    options.openVpnDownloadInternalToken ??
    process.env.OPENVPN_DOWNLOAD_INTERNAL_TOKEN ??
    (devInfra ? "openvpn-download-dev-token" : "");
  const openVpnDownloadPublicUrl = (
    options.openVpnDownloadPublicUrl ??
    process.env.OPENVPN_DOWNLOAD_PUBLIC_URL ??
    (devInfra ? "http://localhost:9100" : "https://vpn.codegate.invalid")
  ).replace(/\/$/, "");
  if (productionMode) {
    validateProductionEdgeConfiguration({
      allowedOrigins: configuredOrigins,
      desktopGatewayInternalToken,
      desktopGatewayPublicUrl,
      openVpnDownloadInternalToken,
      openVpnDownloadPublicUrl,
    });
  }
  const trustProxyHeaders =
    options.trustProxyHeaders ?? process.env.TRUST_PROXY_HEADERS === "true";
  const ready = Promise.resolve(repository.initialize());

  const handlerContext: HandlerContext = {
    repository,
    runtime,
    labGenerator,
    evidenceGrader,
    labValidator,
    telemetryGateway,
    environmentBuilder,
    authMode,
    oidcVerifier,
    sessionSecret,
    desktopGatewayInternalToken,
    desktopGatewayPublicUrl,
    desktopTicketTtlSeconds,
    openVpnDownloadInternalToken,
    openVpnDownloadPublicUrl,
    trustProxyHeaders,
    ready,
  };

  const runSweep = async (now?: string) => {
    await ready;
    return sweepExpiredRuns(handlerContext, now);
  };

  const sweepIntervalMs =
    options.runSweepIntervalMs ??
    Number.parseInt(process.env.RUN_SWEEP_INTERVAL_MS ?? "60000", 10);
  let sweepTimer: ReturnType<typeof setInterval> | undefined;
  if (Number.isFinite(sweepIntervalMs) && sweepIntervalMs > 0) {
    sweepTimer = setInterval(() => {
      void runSweep().catch((error: unknown) => {
        console.error("expired run sweep failed", error);
      });
    }, sweepIntervalMs);
    // Never hold the process open for the sweep alone.
    sweepTimer.unref?.();
  }

  const server = createServer((request, response) => {
    if (!applyCors(request, response, allowedOrigins)) {
      sendJson(response, 403, {
        error: {
          code: "CORS_ORIGIN_DENIED",
          message: "The request origin is not in ALLOWED_ORIGINS.",
        },
      });
      return;
    }
    route(request, response, handlerContext).catch((error: unknown) => {
      if (response.headersSent) {
        response.end();
        return;
      }

      if (error instanceof ApiError || error instanceof RepositoryError) {
        sendJson(response, error.status, {
          error: {
            code: error.code,
            message: error.message,
            ...(error instanceof ApiError && error.details !== undefined
              ? { details: error.details }
              : {}),
          },
        });
        return;
      }

      if (error instanceof AuthenticationError) {
        sendJson(response, error.status, {
          error: { code: "AUTHENTICATION_FAILED", message: error.message },
        });
        return;
      }

      console.error(error);
      sendJson(response, 500, {
        error: {
          code: "INTERNAL_ERROR",
          message: "An unexpected server error occurred.",
        },
      });
    });
  });

  return {
    server,
    repository,
    runtime,
    runtimeMode: options.runtime ? "custom" : configuredRuntimeMode,
    labGenerator,
    labGeneratorMode: options.labGenerator ? "custom" : configuredLabGeneratorMode,
    evidenceGrader,
    evidenceGraderMode: options.evidenceGrader
      ? "custom"
      : configuredEvidenceGraderMode,
    labValidator,
    labValidatorMode: options.labValidator ? "custom" : configuredLabValidatorMode,
    telemetryGateway,
    telemetryGatewayMode: options.telemetryGateway ? "custom" : configuredTelemetryGatewayMode,
    environmentBuilder,
    environmentBuilderMode: options.environmentBuilder ? "custom" : configuredEnvironmentBuilderMode,
    authMode,
    repositoryMode,
    ready,
    /** Runs the expiry sweep once. Exposed so tests can drive it deterministically. */
    sweepExpiredRuns: runSweep,
    async close(): Promise<void> {
      if (sweepTimer) clearInterval(sweepTimer);
      if (server.listening) {
        await new Promise<void>((resolve, reject) => {
          server.close((error) => (error ? reject(error) : resolve()));
        });
      }
      try {
        await ready;
      } finally {
        await repository.close();
      }
    },
  };
}

export function validateProductionEdgeConfiguration(config: {
  allowedOrigins: string[];
  desktopGatewayInternalToken: string;
  desktopGatewayPublicUrl: string;
  openVpnDownloadInternalToken: string;
  openVpnDownloadPublicUrl: string;
}): void {
  if (config.allowedOrigins.length === 0 || new Set(config.allowedOrigins).size !== config.allowedOrigins.length) {
    throw new RepositoryError("PRODUCTION_ORIGINS_REQUIRED", "ALLOWED_ORIGINS must contain unique production HTTPS origins.", 500);
  }
  for (const origin of config.allowedOrigins) {
    let parsed: URL;
    try { parsed = new URL(origin); } catch { throw new RepositoryError("PRODUCTION_ORIGIN_INVALID", "ALLOWED_ORIGINS contains an invalid origin.", 500); }
    if (parsed.protocol !== "https:" || parsed.origin !== origin || placeholderHostname(parsed.hostname)) {
      throw new RepositoryError("PRODUCTION_ORIGIN_INVALID", "ALLOWED_ORIGINS must contain only exact non-placeholder HTTPS origins.", 500);
    }
  }
  productionPeerToken(config.desktopGatewayInternalToken, "DESKTOP_GATEWAY_INTERNAL_TOKEN");
  productionPeerToken(config.openVpnDownloadInternalToken, "OPENVPN_DOWNLOAD_INTERNAL_TOKEN");
  productionPublicUrl(config.desktopGatewayPublicUrl, "DESKTOP_GATEWAY_PUBLIC_URL");
  productionPublicUrl(config.openVpnDownloadPublicUrl, "OPENVPN_DOWNLOAD_PUBLIC_URL");
}

function productionPeerToken(value: string, name: string): void {
  if (value.length < 24 || value.length > 512 || /\s/.test(value)) {
    throw new RepositoryError("PRODUCTION_PEER_TOKEN_INVALID", `${name} must be a configured service peer token.`, 500);
  }
}

function productionPublicUrl(value: string, name: string): void {
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new RepositoryError("PRODUCTION_PUBLIC_URL_INVALID", `${name} is invalid.`, 500); }
  if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password || parsed.search || parsed.hash || placeholderHostname(parsed.hostname)) {
    throw new RepositoryError("PRODUCTION_PUBLIC_URL_INVALID", `${name} must be a non-placeholder HTTPS URL without credentials, query, or fragment.`, 500);
  }
}

function boundedInteger(value: number | string, name: string, minimum: number, maximum: number): number {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new RepositoryError(
      "INVALID_CONFIGURATION",
      `${name} must be an integer between ${minimum} and ${maximum}.`,
      500,
    );
  }
  return parsed;
}

function placeholderHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return normalized === "localhost" || normalized.endsWith(".localhost") || normalized.endsWith(".invalid");
}

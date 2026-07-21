import type {
  AccessTicketInput,
  AdminPageQuery,
  AdminPageResult,
  ChallengeResultInput,
  JsonObject,
  IdentityOnboardingInput,
  LabAccessMethod,
  LabGenerationInput,
  OrganizationCreateInput,
  RegistrationInput,
  RuntimeRunInput,
  RuntimeRunStatusInput,
  ValidationEvidenceInput,
} from "./types.ts";
import type {
  ServerQuestion,
  SubmittedAnswer,
  TrustedGradeEvidence,
} from "@codegate/grading";

export interface IdempotencyRecord {
  requestHash: string;
  response: unknown;
  resourceId: string;
  createdAt: string;
}

export interface AuditEvent {
  actorUserId: string | null;
  action: string;
  resourceType: string;
  resourceId: string;
  metadata?: JsonObject;
}

export interface ReportingDatasetFilter {
  userId?: string;
  organizationId?: string;
}

export type MaybePromise<T> = T | Promise<T>;

export interface PlatformRepository {
  initialize(): MaybePromise<void>;
  close(): MaybePromise<void>;
  getUser(userId: string): MaybePromise<unknown | null>;
  getUserByExternalSubject(subject: string): MaybePromise<unknown | null>;
  register(input: RegistrationInput): MaybePromise<unknown>;
  onboardIdentity(input: IdentityOnboardingInput): MaybePromise<unknown>;
  createLab(userId: string, input: LabGenerationInput): MaybePromise<unknown>;
  listLabs(userId: string): MaybePromise<unknown[]>;
  getLab(userId: string, labId: string): MaybePromise<unknown | null>;
  getLabBuildSpec(userId: string, labId: string): MaybePromise<JsonObject | null>;
  updateLabConfig(
    labId: string,
    patch: JsonObject,
    updatedAt: string,
  ): MaybePromise<boolean>;
  saveValidation(
    labId: string,
    status: "validated" | "quarantined",
    evidence: ValidationEvidenceInput[],
  ): MaybePromise<unknown[]>;
  createRun(input: RuntimeRunInput): MaybePromise<unknown>;
  getRun(userId: string, runId: string): MaybePromise<unknown | null>;
  updateRunReadiness(
    userId: string,
    runId: string,
    readiness: RuntimeRunStatusInput,
  ): MaybePromise<unknown | null>;
  getLabGradingQuestions(userId: string, labId: string): MaybePromise<unknown[]>;
  getTrustedGradeEvidence(userId: string, runId: string): MaybePromise<unknown[]>;
  saveChallengeResult(input: ChallengeResultInput): MaybePromise<unknown>;
  createAccessTicket(input: AccessTicketInput): MaybePromise<void>;
  consumeAccessTicket(
    ticketHash: string,
    kind: "desktop" | "openvpn",
    consumedAt: string,
  ): MaybePromise<unknown | null>;
  getReportingDataset(filter?: ReportingDatasetFilter): MaybePromise<unknown>;
  getAdminOverview(): MaybePromise<unknown>;
  listAdminUsers(query: AdminPageQuery): MaybePromise<AdminPageResult>;
  listAdminOrganizations(query: AdminPageQuery): MaybePromise<AdminPageResult>;
  listAdminLabs(query: AdminPageQuery): MaybePromise<AdminPageResult>;
  listAdminRuns(query: AdminPageQuery): MaybePromise<AdminPageResult>;
  listOrganizationMembers(
    organizationId: string,
    query: AdminPageQuery,
  ): MaybePromise<AdminPageResult>;
  createOrganization(input: OrganizationCreateInput): MaybePromise<unknown>;
  rotateOrganizationJoinCode(
    organizationId: string,
    joinCodeHash: string,
    rotatedAt: string,
  ): MaybePromise<unknown | null>;
  quarantineLab(
    labId: string,
    quarantinedAt: string,
    actorUserId: string,
    reason: string,
  ): MaybePromise<unknown | null>;
  getAdminRun(runId: string): MaybePromise<unknown | null>;
  markRunStopped(
    runId: string,
    stoppedAt: string,
    actorUserId: string,
  ): MaybePromise<unknown | null>;
  getIdempotencyRecord(
    userId: string,
    operation: string,
    key: string,
  ): MaybePromise<IdempotencyRecord | null>;
  saveIdempotencyRecord(
    userId: string,
    operation: string,
    key: string,
    requestHash: string,
    resourceId: string,
    response: unknown,
  ): MaybePromise<void>;
  recordAudit(event: AuditEvent): MaybePromise<void>;
}

export interface RuntimeAdapter {
  createRun(
    lab: unknown,
    userId: string,
    accessMethod: LabAccessMethod,
  ): MaybePromise<RuntimeRunInput>;
  getRunStatus(runId: string): MaybePromise<RuntimeRunStatusInput>;
  destroyRun(runId: string): MaybePromise<void>;
}

export interface AiLabGenerator {
  generate(input: LabGenerationInput): MaybePromise<LabGenerationInput>;
}

export interface LabValidationResult {
  decision: "pass" | "quarantine";
  status: "validated" | "quarantined";
  evidence: ValidationEvidenceInput[];
  validation?: JsonObject;
}

export interface LabValidator {
  validate(lab: unknown): MaybePromise<LabValidationResult>;
}

export interface EvidenceGradeRequest {
  run: unknown;
  lab: unknown;
  questions: ServerQuestion[];
  answers: SubmittedAnswer[];
}

/**
 * Produces server-trusted ELK execution and AI rubric evidence. Implementations
 * sit behind the API trust boundary; browser-supplied evidence is never routed
 * through this port.
 */
export interface EvidenceGrader {
  grade(input: EvidenceGradeRequest): MaybePromise<TrustedGradeEvidence[]>;
}

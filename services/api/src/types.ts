export const DEV_USER_ID = "user_dev";
export const SECURITY_LAB_ORG_ID = "org_security_lab";

export const BLUE_QUESTION_TYPES = ["elk_search", "mitre_attack"] as const;
export const RED_QUESTION_TYPES = [
  "single_choice",
  "multiple_choice",
  "free_text",
  "mitre_attack",
] as const;
export const ACCESS_METHODS = ["browser_desktop", "openvpn"] as const;

export type TeamType = "blue" | "red";
export type AccessMethod = (typeof ACCESS_METHODS)[number];
export type LabAccessMethod = AccessMethod | "both";
export type QuestionType =
  | (typeof BLUE_QUESTION_TYPES)[number]
  | (typeof RED_QUESTION_TYPES)[number];

export type JsonObject = Record<string, unknown>;

/**
 * Versions of the documents shown at signup. Bumping one means existing
 * agreements no longer cover the current text and re-consent is required.
 */
export const TERMS_VERSION = "2026-07-22";
export const PRIVACY_POLICY_VERSION = "2026-07-22";

export interface RegistrationConsent {
  terms: boolean;
  privacy: boolean;
}

export interface RegistrationInput {
  email: string;
  /** Optional: derived from the email when the client does not supply one. */
  handle?: string;
  displayName: string;
  affiliation: string;
  password?: string;
  accountType: "personal" | "organization";
  organizationId?: string;
  organizationJoinCode?: string;
  consent: RegistrationConsent;
}

/** A registration whose handle has been resolved; what the repository stores. */
export interface ResolvedRegistrationInput extends RegistrationInput {
  handle: string;
}

export interface IdentityOnboardingInput extends ResolvedRegistrationInput {
  externalSubject: string;
  platformRole: "user" | "platform_admin";
  organizationRole: "member" | "org_admin";
}

export interface LabGenerationInput {
  title: string;
  prompt: string;
  team: TeamType;
  questionTypes: QuestionType[];
  desktopImage: "ubuntu" | "kali";
  accessMethod: LabAccessMethod;
  accessModes: AccessMethod[];
  config: JsonObject;
  gradingQuestions: JsonObject[];
  cveIds: string[];
  buildSpec?: JsonObject;
}

export interface ChallengeResultInput {
  id: string;
  labId: string;
  runId: string;
  userId: string;
  awardedPoints: number;
  maxPoints: number;
  answers: unknown[];
  gradeEvidence: JsonObject;
  skills: JsonObject;
  completedAt: string;
}

export interface AccessTicketInput {
  ticketHash: string;
  runId: string;
  userId: string;
  kind: "desktop" | "openvpn";
  expiresAt: string;
  createdAt: string;
}

export interface ValidationEvidenceInput {
  id: string;
  checkName: string;
  outcome: "pass" | "fail";
  details: JsonObject;
}

export interface RuntimeRunInput {
  id: string;
  labId: string;
  userId: string;
  status: "provisioning" | "ready" | "failed";
  environment: "ubuntu" | "kali";
  accessMethod: LabAccessMethod;
  browserUrl: string | null;
  openvpnProfile: JsonObject | null;
  expiresAt: string;
  metadata: JsonObject;
  createdAt: string;
}

export interface RuntimeRunStatusInput {
  id: string;
  status: "provisioning" | "ready" | "failed";
  namespace: string;
  expiresAt: string;
  checks: JsonObject;
  reason?: string;
}

export interface OrganizationCreateInput {
  id: string;
  name: string;
  slug: string;
  joinCodeHash: string;
  createdAt: string;
}

export interface AdminPageQuery {
  limit: number;
  offset: number;
  search?: string;
  organizationId?: string;
  platformRole?: "user" | "platform_admin";
  membershipRole?: "owner" | "org_admin" | "member";
  team?: "blue" | "red";
  labStatus?: "draft" | "validated" | "quarantined";
  runStatus?: "provisioning" | "ready" | "failed" | "stopped" | "expired";
  accessMethod?: LabAccessMethod;
  auditAction?: string;
  auditResourceType?: AuditResourceType;
}

export const AUDIT_RESOURCE_TYPES = [
  "user",
  "organization",
  "organization_membership",
  "lab",
  "runtime_run",
  "challenge_result",
  "platform",
] as const;

export type AuditResourceType = (typeof AUDIT_RESOURCE_TYPES)[number];

export interface AdminPageResult {
  items: unknown[];
  total: number;
}

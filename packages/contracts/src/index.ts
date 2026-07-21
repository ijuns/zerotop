export type Team = "blue" | "red";
export type DesktopImage = "ubuntu" | "kali";
export type AccessMethod = "browser_desktop" | "openvpn" | "both";
export type BlueQuestionType = "elk_search" | "mitre_attack";
export type RedQuestionType = "single_choice" | "multiple_choice" | "free_text" | "mitre_attack";
export type QuestionType = BlueQuestionType | RedQuestionType;
export type LabStatus = "draft" | "validating" | "approved" | "quarantined" | "running" | "expired";
export type ValidationDecision = "pass" | "quarantine";
export type AccountType = "personal" | "organization";
export type PlatformRole = "individual" | "org_member" | "org_admin" | "platform_admin";
export type Difficulty = "beginner" | "intermediate" | "advanced" | "expert";
export type RankingScope = "global" | "organization";
export type RankingPeriod = "weekly" | "monthly" | "all_time";

export interface OrganizationSummary {
  id: string;
  name: string;
  slug: string;
}

export interface UserProfile {
  id: string;
  email: string;
  handle: string;
  displayName: string;
  roles: PlatformRole[];
  organization: OrganizationSummary | null;
  globalRankingOptIn: boolean;
}

export interface RegistrationRequest {
  email: string;
  handle: string;
  displayName: string;
  password?: string;
  accountType: AccountType;
  organizationJoinCode?: string;
}

export interface LabGenerationRequest {
  title: string;
  prompt: string;
  team: Team;
  desktopImage: DesktopImage;
  accessMethod: AccessMethod;
  questionTypes: QuestionType[];
  difficulty?: Difficulty;
  cveIds?: string[];
}

export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
}

export interface LabSpec extends LabGenerationRequest {
  id: string;
  version: number;
  status: LabStatus;
  network: {
    egress: "deny";
    isolation: "per_run";
  };
  scenario: {
    summary: string;
    logSources: string[];
    attackChain: AttackTechnique[];
  };
  learning?: {
    prerequisites: string[];
    objectives: string[];
    sections: Array<{
      id: string;
      title: string;
      bodyMarkdown: string;
    }>;
  };
  target?: {
    image: string;
    affectedProducts: string[];
    cveIds: string[];
  };
  questions?: LabQuestion[];
  createdAt: string;
}

export interface LabQuestion {
  id: string;
  type: QuestionType;
  prompt: string;
  points: number;
  options?: Array<{ id: string; label: string }>;
  mitreTechniqueIds?: string[];
}

export interface ValidationCheck {
  id: string;
  label: string;
  passed: boolean;
  evidence: string;
  mandatory: boolean;
}

export interface ValidationResult {
  labId: string;
  decision: ValidationDecision;
  score: number;
  checks: ValidationCheck[];
  policyVersion: string;
  createdAt: string;
}

export interface RuntimeRun {
  id: string;
  labId: string;
  status: "provisioning" | "ready" | "stopped" | "expired";
  desktopImage: DesktopImage;
  accessMethod: AccessMethod;
  expiresAt: string;
  browserDesktopUrl?: string;
  openVpn?: {
    profileId: string;
    endpoint: string;
    assignedIp: string;
    allowedCidr: string;
  };
}

export interface AnswerSubmission {
  questionId: string;
  response: string | string[] | Record<string, unknown>;
}

export interface RunSubmissionRequest {
  answers: AnswerSubmission[];
}

export interface SkillScore {
  key: string;
  label: string;
  score: number;
  evidenceCount: number;
  delta: number;
}

export interface PersonalCapabilityReport {
  scope: "personal";
  user: Pick<UserProfile, "id" | "handle" | "displayName">;
  generatedAt: string;
  overallScore: number;
  completedLabs: number;
  successRate: number;
  skills: SkillScore[];
  recentRuns: Array<{
    runId: string;
    labId: string;
    title: string;
    team: Team;
    score: number;
    completedAt: string;
  }>;
}

export interface OrganizationMemberCapability {
  userId: string;
  handle: string;
  displayName: string;
  overallScore: number;
  completedLabs: number;
  successRate: number;
  lastActiveAt: string | null;
  skills: SkillScore[];
}

export interface OrganizationCapabilityReport {
  scope: "organization";
  organization: OrganizationSummary;
  generatedAt: string;
  memberCount: number;
  activeMemberCount: number;
  overallScore: number;
  skills: SkillScore[];
  members: OrganizationMemberCapability[];
}

export interface PlatformCapabilityReport {
  scope: "platform";
  generatedAt: string;
  userCount: number;
  organizationCount: number;
  activeUserCount: number;
  overallScore: number;
  skills: SkillScore[];
  organizations: Array<{
    organization: OrganizationSummary;
    memberCount: number;
    activeMemberCount: number;
    overallScore: number;
  }>;
}

export interface RankingEntry {
  rank: number;
  userId: string;
  handle: string;
  organizationName: string | null;
  points: number;
  completedLabs: number;
  change: number;
}

export interface RankingResponse {
  scope: RankingScope;
  period: RankingPeriod;
  generatedAt: string;
  entries: RankingEntry[];
  currentUser?: RankingEntry;
}

export interface ApiError {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}

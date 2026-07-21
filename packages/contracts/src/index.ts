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
  /** Omitted when the server should derive it from the email address. */
  handle?: string;
  displayName: string;
  affiliation: string;
  password?: string;
  accountType: AccountType;
  organizationId?: string;
  organizationJoinCode?: string;
  consent: {
    terms: boolean;
    privacy: boolean;
  };
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

export interface ScenarioTelemetryEvent {
  id: string;
  document: Record<string, unknown>;
}

export interface ScenarioTelemetryGeneration {
  schemaVersion: 1;
  profile: "powershell_rce_exfiltration" | "credential_abuse" | "ransomware" | "webshell" | "generic_intrusion" | "generic_endpoint_activity";
  totalEvents: number;
  timeRangeMinutes: number;
  seed: string;
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
  /** Optional only for reading LabSpecs created before topology schema v1. */
  topology?: LabRuntimeTopology;
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
  status: "provisioning" | "ready" | "failed" | "stopped" | "expired";
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
  topology?: LabRuntimeTopology;
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

/**
 * Ranking domains shown as filters. Each maps to the skill keys graders emit,
 * so the taxonomy stays in one place for both the server and the client.
 */
export const RANKING_DOMAINS = [
  {
    key: "vulnerability",
    label: "취약점 분석",
    skills: ["web_exploitation", "exploit_analysis", "privilege_escalation"],
  },
  {
    key: "detection",
    label: "탐지 · 조사",
    skills: ["log_analysis", "mitre_attack"],
  },
  {
    key: "response",
    label: "완화 · 복구",
    skills: ["incident_response"],
  },
] as const;

export type RankingDomain = (typeof RANKING_DOMAINS)[number]["key"];

export type LabDifficulty = "beginner" | "intermediate" | "advanced" | "expert";

/**
 * Season scoring policy, matching the on-screen "순위 산정 방식":
 *   score = base(difficulty) × accuracy × (1 + timeBonus) × (1 − hintPenalty)
 * base is the difficulty tier; a fast finish adds up to +20%; each hint removes
 * a fixed slice down to −20%. Expert maps to the highest (advanced) tier so the
 * three published tiers (초급/중급/고급 = 100/250/500) stay exact.
 */
export const DIFFICULTY_BASE_POINTS: Record<LabDifficulty, number> = {
  beginner: 100,
  intermediate: 250,
  advanced: 500,
  expert: 500,
};

export const MAX_TIME_BONUS = 0.2;
export const MAX_HINT_PENALTY = 0.2;
export const HINT_PENALTY_PER_USE = 0.04;

export interface RankingSeason {
  id: string;
  name: string;
  slug: string;
  startsAt: string;
  endsAt: string;
}

export interface RankingEntry {
  rank: number;
  userId: string;
  handle: string;
  organizationName: string | null;
  points: number;
  completedLabs: number;
  change: number;
  /** Share of available points earned, 0-100. */
  accuracy: number;
  /** Highest-scoring domain, or null when no graded evidence maps to one. */
  primaryDomain: { key: RankingDomain; label: string } | null;
}

/** Aggregate standing of one organization against others that opted in. */
export interface OrganizationRankingEntry {
  rank: number;
  organizationId: string;
  name: string;
  memberCount: number;
  /** Composite of accuracy, participation and completion, 0-100. */
  readiness: number;
  participationRate: number;
  completionRate: number;
  change: number;
}

/** Season totals for the viewer, shown above the table. */
export interface RankingViewerSummary {
  rank: number | null;
  totalParticipants: number;
  /** Percentile position, 0-100; null until the viewer is ranked. */
  topPercent: number | null;
  points: number;
  pointsDelta: number;
  completedLabs: number;
  accuracy: number;
  streakDays: number;
  bestStreakDays: number;
}

export interface RankingResponse {
  scope: RankingScope;
  period: RankingPeriod;
  generatedAt: string;
  season: RankingSeason | null;
  domain: RankingDomain | null;
  entries: RankingEntry[];
  organizations: OrganizationRankingEntry[];
  viewer: RankingViewerSummary;
  currentUser?: RankingEntry;
  currentOrganization?: OrganizationRankingEntry;
}

export interface ApiError {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}

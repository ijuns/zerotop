import type { WebRuntimeConfig } from "./runtime-config";

export let API_URL = "/api";
export let DEV_USER_ID = "user-dev-personal";

let activeDevelopmentUserId = DEV_USER_ID;
let developmentIdentityEnabled = false;
let clientRuntimeConfigured = false;

export function configureClientRuntime(config: WebRuntimeConfig) {
  if (clientRuntimeConfigured) return;
  API_URL = (config.apiUrl.trim() || "/api").replace(/\/$/, "");
  DEV_USER_ID = config.developmentUserId.trim() || "user-dev-personal";
  const savedDevelopmentUserId =
    typeof window !== "undefined"
      ? window.localStorage.getItem("zerotop.developmentUserId")?.trim()
      : null;
  activeDevelopmentUserId = savedDevelopmentUserId || DEV_USER_ID;
  developmentIdentityEnabled = config.developmentIdentityEnabled;
  clientRuntimeConfigured = true;
}

export type Team = "blue" | "red";
export type DesktopImage = "ubuntu" | "kali";
export type AccessMethod = "browser_desktop" | "openvpn" | "both";
export type QuestionType =
  | "elk_search"
  | "single_choice"
  | "multiple_choice"
  | "free_text"
  | "mitre_attack";
export type AccountType = "personal" | "organization";
export type PlatformRole =
  | "individual"
  | "org_member"
  | "org_admin"
  | "platform_admin";
export type RankingScope = "global" | "organization";
export type RankingPeriod = "weekly" | "monthly" | "all_time";

export interface HealthResponse {
  status?: string;
  service?: string;
  version?: string;
  authMode?: "dev" | "oidc" | string;
  [key: string]: unknown;
}

export interface LabGenerationRequest {
  title: string;
  prompt: string;
  team: Team;
  desktopImage: DesktopImage;
  accessMethod: AccessMethod;
  questionTypes: QuestionType[];
  cveIds?: string[];
}

export type LabBuildStatus =
  | "not_started"
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled";

export interface LabBuildState {
  id?: string;
  status: LabBuildStatus;
  createdAt?: string;
  updatedAt?: string;
  failureCode?: string;
}

export interface UserContext {
  id: string;
  email?: string;
  handle?: string;
  displayName?: string;
  name?: string;
  role?: string;
  roles?: PlatformRole[];
  platformRole?: string;
  organization?: { id?: string; name?: string; slug?: string; role?: string; rankingOptIn?: boolean } | null;
  organizationName?: string | null;
  globalRankingOptIn?: boolean;
  [key: string]: unknown;
}

export interface RegistrationRequest {
  email: string;
  /** Omitted by the signup form: the server derives it from the email. */
  handle?: string;
  displayName: string;
  affiliation: string;
  password?: string;
  accountType: AccountType;
  organizationJoinCode?: string;
  consent: { terms: boolean; privacy: boolean };
}

export interface RegistrationResult {
  user: UserContext;
  developmentAuth?: { header?: string; value?: string } | null;
  alreadyOnboarded?: boolean;
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
  user: Pick<UserContext, "id" | "handle" | "displayName">;
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

export interface OrganizationCapabilityReport {
  scope: "organization";
  organization: { id: string; name: string; slug: string };
  generatedAt: string;
  memberCount: number;
  activeMemberCount: number;
  overallScore: number;
  skills: SkillScore[];
  members: Array<{
    userId: string;
    handle: string;
    displayName: string;
    overallScore: number;
    completedLabs: number;
    successRate: number;
    lastActiveAt: string | null;
    skills: SkillScore[];
  }>;
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
    organization: { id: string; name: string; slug: string };
    memberCount: number;
    activeMemberCount: number;
    overallScore: number;
  }>;
}

export type CapabilityReport =
  | PersonalCapabilityReport
  | OrganizationCapabilityReport
  | PlatformCapabilityReport;

export const RANKING_DOMAINS = [
  { key: "vulnerability", label: "취약점 분석" },
  { key: "detection", label: "탐지 · 조사" },
  { key: "response", label: "완화 · 복구" },
] as const;

export type RankingDomain = (typeof RANKING_DOMAINS)[number]["key"];

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
  accuracy: number;
  primaryDomain: { key: RankingDomain; label: string } | null;
}

export interface OrganizationRankingEntry {
  rank: number;
  organizationId: string;
  name: string;
  memberCount: number;
  readiness: number;
  participationRate: number;
  completionRate: number;
  change: number;
}

export interface RankingViewerSummary {
  rank: number | null;
  totalParticipants: number;
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

export interface ValidationCheck {
  id?: string;
  label?: string;
  name?: string;
  checkName?: string;
  passed?: boolean;
  status?: string;
  outcome?: string;
  evidence?: unknown;
  message?: string;
  details?: unknown;
  mandatory?: boolean;
}

export interface ValidationResult {
  decision?: string;
  score?: number;
  evidence?: unknown[];
  checks?: ValidationCheck[];
  policyVersion?: string;
  createdAt?: string;
  [key: string]: unknown;
}

export interface Lab {
  id: string;
  title?: string;
  name?: string;
  prompt?: string;
  description?: string;
  team?: Team;
  teamType?: Team;
  desktopImage?: DesktopImage;
  environment?: DesktopImage;
  accessMethod?: AccessMethod;
  accessModes?: Exclude<AccessMethod, "both">[];
  questionTypes?: QuestionType[];
  status?: string;
  validationStatus?: string;
  validation?: ValidationResult;
  createdAt?: string;
  updatedAt?: string;
  scenario?: {
    summary?: string;
    logSources?: string[];
    attackChain?: Array<{ id?: string; name?: string; tactic?: string }>;
  };
  learning?: {
    prerequisites?: string[];
    objectives?: string[];
    sections?: Array<{ id?: string; title?: string; bodyMarkdown?: string }>;
  };
  target?: {
    image?: string;
    affectedProducts?: string[];
    cveIds?: string[];
    expectedCves?: string[];
    sources?: Array<{ label?: string; url?: string }>;
  };
  questions?: LabQuestion[];
  config?: Record<string, unknown> & { builder?: LabBuildState };
  [key: string]: unknown;
}

export interface LabQuestion {
  id: string;
  type: QuestionType;
  prompt: string;
  points: number;
  options?: Array<{ id: string; label: string }>;
  mitreTechniqueIds?: string[];
}

export interface AnswerSubmission {
  questionId: string;
  response: string | string[] | Record<string, unknown>;
}

export interface QuestionGrade {
  questionId: string;
  questionType: QuestionType;
  awardedPoints: number;
  maxPoints: number;
  outcome: "correct" | "partial" | "incorrect" | "ungradable" | string;
  feedbackCode: string;
  evidenceReference?: string;
}

export interface RunGrade {
  awardedPoints: number;
  maxPoints: number;
  score: number;
  passed: boolean;
  grades: QuestionGrade[];
}

export interface RunSubmissionResult {
  resultId?: string;
  grade: RunGrade;
}

export interface RunConnection {
  browserUrl?: string;
  browserDesktopUrl?: string;
  openvpnConfigUrl?: string;
  openVpnConfigUrl?: string;
  vpnConfigUrl?: string;
  endpoint?: string;
  assignedIp?: string;
  allowedCidr?: string;
  username?: string;
  password?: string;
  [key: string]: unknown;
}

export interface RuntimeRun {
  id: string;
  labId?: string;
  status: string;
  desktopImage?: DesktopImage;
  environment?: DesktopImage;
  accessMethod?: AccessMethod;
  expiresAt?: string;
  browserUrl?: string | null;
  browserDesktopUrl?: string;
  openvpnProfile?: RunConnection | null;
  openVpn?: RunConnection;
  connection?: RunConnection;
  connectionInfo?: RunConnection;
  [key: string]: unknown;
}

export interface DesktopTicket {
  launchUrl: string;
  expiresAt?: string;
}

export interface OpenVpnTicket {
  downloadUrl: string;
  expiresAt?: string;
}

export interface ElkSearchHit {
  id: string;
  score: number | null;
  source: Record<string, unknown>;
}

export interface ElkSearchResult {
  took: number;
  total: number;
  hits: ElkSearchHit[];
}

export interface AdminPagination {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface AdminPage<T> {
  items: T[];
  pagination: AdminPagination;
}

export interface AdminPageQuery {
  page?: number;
  pageSize?: number;
  search?: string;
  organizationId?: string;
  platformRole?: "user" | "platform_admin";
  role?: "owner" | "org_admin" | "member";
  team?: Team;
  status?: string;
  accessMethod?: AccessMethod;
  action?: string;
  resourceType?: string;
}

export interface AdminOverview {
  users: number;
  organizations: number;
  labs: number;
  quarantinedLabs: number;
  runs: number;
  activeRuns: number;
  failedRuns: number;
  completedChallenges: number;
  generatedAt: string;
}

export interface AdminUser {
  id: string;
  handle: string;
  displayName: string;
  platformRole: "user" | "platform_admin" | string;
  globalRankingOptIn: boolean;
  /** Non-null while the account is suspended and blocked from authenticating. */
  disabledAt: string | null;
  disabledReason: string | null;
  organization: {
    id: string;
    name: string;
    slug: string;
    role: string;
  } | null;
  createdAt: string;
}

export interface AdminOrganization {
  id: string;
  name: string;
  slug: string;
  memberCount: number;
  labCount: number;
  joinCodeRotatedAt: string | null;
  createdAt: string;
}

export interface AdminLab {
  id: string;
  title: string;
  team: Team;
  validationStatus: string;
  ownerHandle: string;
  organizationName: string | null;
  quarantinedAt: string | null;
  quarantineReason: string | null;
  createdAt: string;
}

export interface AdminRun {
  id: string;
  labId: string;
  labTitle: string;
  userHandle: string;
  organizationId: string | null;
  status: string;
  environment: string;
  accessMethod: AccessMethod;
  expiresAt: string;
  createdAt: string;
}

export interface AdminAuditLog {
  id: string;
  action: string;
  resourceType: string;
  resourceId: string;
  /** handle/displayName are null when the actor account no longer exists. */
  actor: { id: string; handle: string | null; displayName: string | null } | null;
  metadata: Record<string, unknown>;
  /** Null for system-initiated events, or when no source address was recorded. */
  actorIp: string | null;
  createdAt: string;
}

export interface OrganizationMember {
  id: string;
  handle: string;
  displayName: string;
  platformRole: string;
  organizationRole: "owner" | "org_admin" | "member" | string;
  joinedAt: string;
}

export interface OrganizationJoinCodeResult {
  organization: AdminOrganization;
  /** Present only on the first response for a create/rotation operation. */
  joinCode?: string;
  joinCodeReturned: boolean;
  joinCodeAlreadyReturned: boolean;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly details?: unknown;

  constructor(message: string, status: number, code?: string, details?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

type AccessTokenProvider = () => Promise<string | null> | string | null;
let accessTokenProvider: AccessTokenProvider | null = null;

/** OIDC 도입 시 앱 초기화 단계에서 토큰 공급자를 등록합니다. */
export function setAccessTokenProvider(provider: AccessTokenProvider | null) {
  accessTokenProvider = provider;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");

  if (init.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const token = await accessTokenProvider?.();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  } else if (developmentIdentityEnabled) {
    headers.set("x-user-id", activeDevelopmentUserId);
  }

  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      ...init,
      headers,
      cache: "no-store",
    });
  } catch {
    throw new ApiError(
      `API 서버(${API_URL})에 연결할 수 없습니다. 서버 실행 상태를 확인해 주세요.`,
      0,
      "NETWORK_ERROR",
    );
  }

  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  if (!response.ok) {
    const body = isRecord(payload) ? payload : {};
    const error = isRecord(body.error) ? body.error : body;
    const message =
      typeof error.message === "string"
        ? error.message
        : `요청을 처리하지 못했습니다. (${response.status})`;
    throw new ApiError(
      message,
      response.status,
      typeof error.code === "string" ? error.code : undefined,
      error.details,
    );
  }

  return payload as T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function dataOf(value: unknown): unknown {
  return isRecord(value) && "data" in value ? value.data : value;
}

function entityOf<T>(value: unknown, key: string): T {
  const data = dataOf(value);
  if (isRecord(data) && key in data) return data[key] as T;
  return data as T;
}

function idempotencyKey(prefix: string) {
  const random =
    typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${random}`;
}

function stringValue(value: unknown, fallback = "") {
  return typeof value === "string" ? value : fallback;
}

function numberValue(value: unknown) {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function skillOf(value: unknown): SkillScore {
  const item = isRecord(value) ? value : {};
  return {
    key: stringValue(item.key ?? item.id ?? item.name, "unknown"),
    label: stringValue(item.label ?? item.name ?? item.key, "이름 없는 스킬"),
    score: numberValue(item.score ?? item.value),
    evidenceCount: numberValue(item.evidenceCount ?? item.evidence_count),
    delta: numberValue(item.delta ?? item.change),
  };
}

function organizationOf(value: unknown) {
  const item = isRecord(value) ? value : {};
  return {
    id: stringValue(item.id ?? item.organizationId ?? item.organization_id),
    name: stringValue(item.name ?? item.organizationName ?? item.organization_name, "이름 없는 조직"),
    slug: stringValue(item.slug),
  };
}

function personalReportOf(value: unknown): PersonalCapabilityReport {
  const item = isRecord(value) ? value : {};
  const rawUser = isRecord(item.user) ? item.user : {};
  return {
    scope: "personal",
    user: {
      id: stringValue(rawUser.id ?? item.userId ?? item.user_id),
      handle: stringValue(rawUser.handle ?? item.handle),
      displayName: stringValue(rawUser.displayName ?? rawUser.display_name ?? item.displayName),
    },
    generatedAt: stringValue(item.generatedAt ?? item.generated_at),
    overallScore: numberValue(item.overallScore ?? item.overall_score),
    completedLabs: numberValue(item.completedLabs ?? item.completed_labs),
    successRate: numberValue(item.successRate ?? item.success_rate),
    skills: arrayValue(item.skills).map(skillOf),
    recentRuns: arrayValue(item.recentRuns ?? item.recent_runs).map((raw) => {
      const run = isRecord(raw) ? raw : {};
      return {
        runId: stringValue(run.runId ?? run.run_id ?? run.id),
        labId: stringValue(run.labId ?? run.lab_id),
        title: stringValue(run.title ?? run.labTitle ?? run.lab_title, "이름 없는 Lab"),
        team: (run.team === "red" ? "red" : "blue") as Team,
        score: numberValue(run.score),
        completedAt: stringValue(run.completedAt ?? run.completed_at),
      };
    }),
  };
}

function organizationReportOf(value: unknown): OrganizationCapabilityReport {
  const item = isRecord(value) ? value : {};
  return {
    scope: "organization",
    organization: organizationOf(item.organization),
    generatedAt: stringValue(item.generatedAt ?? item.generated_at),
    memberCount: numberValue(item.memberCount ?? item.member_count),
    activeMemberCount: numberValue(item.activeMemberCount ?? item.active_member_count),
    overallScore: numberValue(item.overallScore ?? item.overall_score),
    skills: arrayValue(item.skills).map(skillOf),
    members: arrayValue(item.members).map((raw) => {
      const member = isRecord(raw) ? raw : {};
      return {
        userId: stringValue(member.userId ?? member.user_id ?? member.id),
        handle: stringValue(member.handle),
        displayName: stringValue(member.displayName ?? member.display_name),
        overallScore: numberValue(member.overallScore ?? member.overall_score),
        completedLabs: numberValue(member.completedLabs ?? member.completed_labs),
        successRate: numberValue(member.successRate ?? member.success_rate),
        lastActiveAt:
          typeof (member.lastActiveAt ?? member.last_active_at) === "string"
            ? String(member.lastActiveAt ?? member.last_active_at)
            : null,
        skills: arrayValue(member.skills).map(skillOf),
      };
    }),
  };
}

function platformReportOf(value: unknown): PlatformCapabilityReport {
  const item = isRecord(value) ? value : {};
  return {
    scope: "platform",
    generatedAt: stringValue(item.generatedAt ?? item.generated_at),
    userCount: numberValue(item.userCount ?? item.user_count),
    organizationCount: numberValue(item.organizationCount ?? item.organization_count),
    activeUserCount: numberValue(item.activeUserCount ?? item.active_user_count),
    overallScore: numberValue(item.overallScore ?? item.overall_score),
    skills: arrayValue(item.skills).map(skillOf),
    organizations: arrayValue(item.organizations).map((raw) => {
      const organization = isRecord(raw) ? raw : {};
      return {
        organization: organizationOf(organization.organization ?? organization),
        memberCount: numberValue(organization.memberCount ?? organization.member_count),
        activeMemberCount: numberValue(
          organization.activeMemberCount ?? organization.active_member_count,
        ),
        overallScore: numberValue(organization.overallScore ?? organization.overall_score),
      };
    }),
  };
}

function rankingEntryOf(value: unknown): RankingEntry {
  const item = isRecord(value) ? value : {};
  const organizationName = item.organizationName ?? item.organization_name;
  return {
    rank: numberValue(item.rank),
    userId: stringValue(item.userId ?? item.user_id ?? item.id),
    handle: stringValue(item.handle),
    organizationName: typeof organizationName === "string" ? organizationName : null,
    points: numberValue(item.points ?? item.score),
    completedLabs: numberValue(item.completedLabs ?? item.completed_labs),
    change: numberValue(item.change ?? item.rankChange ?? item.rank_change),
    accuracy: numberValue(item.accuracy),
    primaryDomain: isRecord(item.primaryDomain)
      ? {
          key: stringValue(item.primaryDomain.key) as RankingDomain,
          label: stringValue(item.primaryDomain.label),
        }
      : null,
  };
}

function adminSeasonOf(value: unknown): RankingSeason | null {
  const item = isRecord(value) ? value : {};
  if (typeof item.id !== "string") return null;
  return {
    id: item.id,
    name: stringValue(item.name),
    slug: stringValue(item.slug),
    startsAt: stringValue(item.startsAt ?? item.starts_at),
    endsAt: stringValue(item.endsAt ?? item.ends_at),
  };
}

function organizationRankingEntryOf(value: unknown): OrganizationRankingEntry {
  const item = isRecord(value) ? value : {};
  return {
    rank: numberValue(item.rank),
    organizationId: stringValue(item.organizationId ?? item.organization_id),
    name: stringValue(item.name, "이름 없는 조직"),
    memberCount: numberValue(item.memberCount ?? item.member_count),
    readiness: numberValue(item.readiness),
    participationRate: numberValue(item.participationRate ?? item.participation_rate),
    completionRate: numberValue(item.completionRate ?? item.completion_rate),
    change: numberValue(item.change),
  };
}

function rankingViewerOf(value: unknown): RankingViewerSummary {
  const item = isRecord(value) ? value : {};
  const rank = item.rank;
  const topPercent = item.topPercent ?? item.top_percent;
  return {
    rank: typeof rank === "number" ? rank : null,
    totalParticipants: numberValue(item.totalParticipants ?? item.total_participants),
    topPercent: typeof topPercent === "number" ? topPercent : null,
    points: numberValue(item.points),
    pointsDelta: numberValue(item.pointsDelta ?? item.points_delta),
    completedLabs: numberValue(item.completedLabs ?? item.completed_labs),
    accuracy: numberValue(item.accuracy),
    streakDays: numberValue(item.streakDays ?? item.streak_days),
    bestStreakDays: numberValue(item.bestStreakDays ?? item.best_streak_days),
  };
}

function rankingOf(value: unknown): RankingResponse {
  const item = isRecord(value) ? value : {};
  return {
    scope: item.scope === "organization" ? "organization" : "global",
    period:
      item.period === "monthly" || item.period === "all_time"
        ? item.period
        : "weekly",
    generatedAt: stringValue(item.generatedAt ?? item.generated_at),
    season: isRecord(item.season)
      ? {
          id: stringValue(item.season.id),
          name: stringValue(item.season.name),
          slug: stringValue(item.season.slug),
          startsAt: stringValue(item.season.startsAt ?? item.season.starts_at),
          endsAt: stringValue(item.season.endsAt ?? item.season.ends_at),
        }
      : null,
    domain: typeof item.domain === "string" ? (item.domain as RankingDomain) : null,
    entries: arrayValue(item.entries ?? item.rankings).map(rankingEntryOf),
    organizations: arrayValue(item.organizations).map(organizationRankingEntryOf),
    viewer: rankingViewerOf(item.viewer),
    ...(item.currentOrganization
      ? { currentOrganization: organizationRankingEntryOf(item.currentOrganization) }
      : {}),
    ...(item.currentUser || item.current_user
      ? { currentUser: rankingEntryOf(item.currentUser ?? item.current_user) }
      : {}),
  };
}

function publicQuestionOf(value: unknown): LabQuestion | null {
  const item = isRecord(value) ? value : {};
  const type = item.type;
  if (
    typeof item.id !== "string" ||
    typeof item.prompt !== "string" ||
    !["elk_search", "single_choice", "multiple_choice", "free_text", "mitre_attack"].includes(
      String(type),
    )
  ) {
    return null;
  }
  return {
    id: item.id,
    type: type as QuestionType,
    prompt: item.prompt,
    points: numberValue(item.points),
    ...(Array.isArray(item.options)
      ? {
          options: item.options.flatMap((raw) => {
            const option = isRecord(raw) ? raw : {};
            return typeof option.id === "string" && typeof option.label === "string"
              ? [{ id: option.id, label: option.label }]
              : [];
          }),
        }
      : {}),
    ...(Array.isArray(item.mitreTechniqueIds ?? item.mitre_technique_ids)
      ? {
          mitreTechniqueIds: arrayValue(
            item.mitreTechniqueIds ?? item.mitre_technique_ids,
          ).filter((entry): entry is string => typeof entry === "string"),
        }
      : {}),
  };
}

const LAB_BUILD_STATUSES = [
  "not_started",
  "queued",
  "running",
  "succeeded",
  "failed",
  "cancelled",
] as const;

function buildStateOf(value: unknown): LabBuildState | null {
  const item = isRecord(value) ? value : {};
  if (
    typeof item.status !== "string" ||
    !(LAB_BUILD_STATUSES as readonly string[]).includes(item.status)
  ) {
    return null;
  }
  const safeOptional = (entry: unknown, maximumLength: number) =>
    typeof entry === "string" && entry.length > 0 && entry.length <= maximumLength
      ? entry
      : undefined;
  return {
    status: item.status as LabBuildStatus,
    ...(safeOptional(item.id, 128) ? { id: safeOptional(item.id, 128) } : {}),
    ...(safeOptional(item.createdAt ?? item.created_at, 64)
      ? { createdAt: safeOptional(item.createdAt ?? item.created_at, 64) }
      : {}),
    ...(safeOptional(item.updatedAt ?? item.updated_at, 64)
      ? { updatedAt: safeOptional(item.updatedAt ?? item.updated_at, 64) }
      : {}),
    ...(safeOptional(item.failureCode ?? item.failure_code, 128)
      ? { failureCode: safeOptional(item.failureCode ?? item.failure_code, 128) }
      : {}),
  };
}

function labOf(value: unknown): Lab {
  const item = isRecord(value) ? value : {};
  const rawConfig = isRecord(item.config) ? item.config : {};
  const rawQuestions = item.questions ?? rawConfig.questions;
  const questions = arrayValue(rawQuestions)
    .map(publicQuestionOf)
    .filter((question): question is LabQuestion => question !== null);
  // Only public question fields are retained; grading material is server-owned.
  const builder = buildStateOf(rawConfig.builder);
  const config: Record<string, unknown> & { builder?: LabBuildState } = {
    questions,
    ...(builder ? { builder } : {}),
  };
  const sanitized: Record<string, unknown> = {
    ...item,
    config,
    learning: item.learning ?? rawConfig.learning,
    target: item.target ?? rawConfig.target,
    questions,
  };
  delete sanitized.gradingQuestions;
  delete sanitized.grading_questions;
  delete sanitized.answerKey;
  delete sanitized.answer_key;
  return sanitized as unknown as Lab;
}

/** Returns only the public, whitelisted environment-build state persisted in config.builder. */
export function labBuildState(lab: Lab | null | undefined): LabBuildState | null {
  return buildStateOf(lab?.config?.builder);
}

export function labBuildIsPending(lab: Lab | null | undefined): boolean {
  const status = labBuildState(lab)?.status;
  return status === "queued" || status === "running";
}

function runSubmissionOf(value: unknown): RunSubmissionResult {
  const data = isRecord(value) ? value : {};
  const rawGrade = isRecord(data.grade) ? data.grade : {};
  const rawResult = isRecord(data.result) ? data.result : {};
  const grades = arrayValue(rawGrade.grades).flatMap((raw) => {
    const grade = isRecord(raw) ? raw : {};
    if (typeof grade.questionId !== "string") return [];
    return [
      {
        questionId: grade.questionId,
        questionType: String(grade.questionType || "free_text") as QuestionType,
        awardedPoints: numberValue(grade.awardedPoints),
        maxPoints: numberValue(grade.maxPoints),
        outcome: stringValue(grade.outcome, "ungradable"),
        feedbackCode: stringValue(grade.feedbackCode),
        ...(typeof grade.evidenceReference === "string"
          ? { evidenceReference: grade.evidenceReference }
          : {}),
      },
    ];
  });
  if (!isRecord(data.grade)) {
    throw new ApiError("채점 응답 형식이 올바르지 않습니다.", 502, "INVALID_GRADE_RESPONSE");
  }
  return {
    resultId: stringValue(rawResult.id) || undefined,
    grade: {
      awardedPoints: numberValue(rawGrade.awardedPoints),
      maxPoints: numberValue(rawGrade.maxPoints),
      score: numberValue(rawGrade.score),
      passed: rawGrade.passed === true,
      grades,
    },
  };
}

function nullableString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function elkSearchResultOf(value: unknown): ElkSearchResult {
  const item = isRecord(value) ? value : {};
  return {
    took: numberValue(item.took),
    total: numberValue(item.total),
    hits: arrayValue(item.hits).flatMap((raw) => {
      const hit = isRecord(raw) ? raw : {};
      if (typeof hit.id !== "string" || !hit.id) return [];
      return [{
        id: hit.id,
        score: typeof hit.score === "number" ? hit.score : null,
        source: isRecord(hit.source) ? hit.source : {},
      }];
    }),
  };
}

function adminPaginationOf(value: unknown, itemCount: number): AdminPagination {
  const item = isRecord(value) ? value : {};
  const page = Math.max(1, numberValue(item.page) || 1);
  const pageSize = Math.max(1, numberValue(item.pageSize ?? item.page_size) || itemCount || 25);
  const total = Math.max(0, numberValue(item.total));
  return {
    page,
    pageSize,
    total,
    totalPages: Math.max(0, numberValue(item.totalPages ?? item.total_pages) || Math.ceil(total / pageSize)),
  };
}

function adminPageOf<T>(value: unknown, parse: (item: unknown) => T | null): AdminPage<T> {
  const data = dataOf(value);
  const root = isRecord(data) ? data : {};
  const items = arrayValue(root.items).flatMap((item) => {
    const parsed = parse(item);
    return parsed ? [parsed] : [];
  });
  return { items, pagination: adminPaginationOf(root.pagination, items.length) };
}

function adminOverviewOf(value: unknown): AdminOverview {
  const item = isRecord(value) ? value : {};
  return {
    users: numberValue(item.users),
    organizations: numberValue(item.organizations),
    labs: numberValue(item.labs),
    quarantinedLabs: numberValue(item.quarantinedLabs ?? item.quarantined_labs),
    runs: numberValue(item.runs),
    activeRuns: numberValue(item.activeRuns ?? item.active_runs),
    failedRuns: numberValue(item.failedRuns ?? item.failed_runs),
    completedChallenges: numberValue(item.completedChallenges ?? item.completed_challenges),
    generatedAt: stringValue(item.generatedAt ?? item.generated_at),
  };
}

function adminUserOf(value: unknown): AdminUser | null {
  const item = isRecord(value) ? value : {};
  if (typeof item.id !== "string" || typeof item.handle !== "string") return null;
  const rawOrganization = isRecord(item.organization) ? item.organization : null;
  return {
    id: item.id,
    handle: item.handle,
    displayName: stringValue(item.displayName ?? item.display_name, item.handle),
    platformRole: stringValue(item.platformRole ?? item.platform_role, "user"),
    globalRankingOptIn: item.globalRankingOptIn === true || item.global_ranking_opt_in === true,
    disabledAt: nullableString(item.disabledAt ?? item.disabled_at),
    disabledReason: nullableString(item.disabledReason ?? item.disabled_reason),
    organization:
      rawOrganization && typeof rawOrganization.id === "string"
        ? {
            id: rawOrganization.id,
            name: stringValue(rawOrganization.name, "이름 없는 조직"),
            slug: stringValue(rawOrganization.slug),
            role: stringValue(rawOrganization.role, "member"),
          }
        : null,
    createdAt: stringValue(item.createdAt ?? item.created_at),
  };
}

function adminOrganizationOf(value: unknown): AdminOrganization | null {
  const item = isRecord(value) ? value : {};
  if (typeof item.id !== "string" || typeof item.name !== "string") return null;
  return {
    id: item.id,
    name: item.name,
    slug: stringValue(item.slug),
    memberCount: numberValue(item.memberCount ?? item.member_count),
    labCount: numberValue(item.labCount ?? item.lab_count),
    joinCodeRotatedAt: nullableString(item.joinCodeRotatedAt ?? item.join_code_rotated_at),
    createdAt: stringValue(item.createdAt ?? item.created_at),
  };
}

function adminLabOf(value: unknown): AdminLab | null {
  const item = isRecord(value) ? value : {};
  if (typeof item.id !== "string") return null;
  const owner = isRecord(item.owner) ? item.owner : {};
  const organization = isRecord(item.organization) ? item.organization : null;
  const quarantine = isRecord(item.adminQuarantine ?? item.admin_quarantine)
    ? (item.adminQuarantine ?? item.admin_quarantine) as Record<string, unknown>
    : null;
  return {
    id: item.id,
    title: stringValue(item.title ?? item.name, "이름 없는 Lab"),
    team: item.team === "red" ? "red" : "blue",
    validationStatus: stringValue(item.validationStatus ?? item.validation_status, "draft"),
    ownerHandle: stringValue(owner.handle),
    organizationName: organization ? nullableString(organization.name) : null,
    quarantinedAt: quarantine ? nullableString(quarantine.quarantinedAt ?? quarantine.quarantined_at) : null,
    quarantineReason: quarantine ? nullableString(quarantine.reason) : null,
    createdAt: stringValue(item.createdAt ?? item.created_at),
  };
}

function adminRunOf(value: unknown): AdminRun | null {
  const item = isRecord(value) ? value : {};
  if (typeof item.id !== "string") return null;
  const method = item.accessMethod ?? item.access_method;
  return {
    id: item.id,
    labId: stringValue(item.labId ?? item.lab_id),
    labTitle: stringValue(item.labTitle ?? item.lab_title, "이름 없는 Lab"),
    userHandle: stringValue(item.userHandle ?? item.user_handle),
    organizationId: nullableString(item.organizationId ?? item.organization_id),
    status: stringValue(item.status),
    environment: stringValue(item.environment),
    accessMethod:
      method === "openvpn" || method === "both" ? method : "browser_desktop",
    expiresAt: stringValue(item.expiresAt ?? item.expires_at),
    createdAt: stringValue(item.createdAt ?? item.created_at),
  };
}

function organizationMemberOf(value: unknown): OrganizationMember | null {
  const item = isRecord(value) ? value : {};
  if (typeof item.id !== "string" || typeof item.handle !== "string") return null;
  return {
    id: item.id,
    handle: item.handle,
    displayName: stringValue(item.displayName ?? item.display_name, item.handle),
    platformRole: stringValue(item.platformRole ?? item.platform_role, "user"),
    organizationRole: stringValue(item.organizationRole ?? item.organization_role ?? item.role, "member"),
    joinedAt: stringValue(item.joinedAt ?? item.joined_at),
  };
}

function adminAuditLogOf(value: unknown): AdminAuditLog | null {
  const item = isRecord(value) ? value : {};
  if (typeof item.id !== "string") return null;
  const actor = isRecord(item.actor) ? item.actor : null;
  const metadata = isRecord(item.metadata) ? item.metadata : {};
  return {
    id: item.id,
    action: stringValue(item.action, "unknown"),
    resourceType: stringValue(item.resourceType ?? item.resource_type),
    resourceId: stringValue(item.resourceId ?? item.resource_id),
    actor:
      actor && typeof actor.id === "string"
        ? {
            id: actor.id,
            handle: nullableString(actor.handle),
            displayName: nullableString(actor.displayName ?? actor.display_name),
          }
        : null,
    metadata,
    actorIp: nullableString(item.actorIp ?? item.actor_ip),
    createdAt: stringValue(item.createdAt ?? item.created_at),
  };
}

function adminQueryString(input: AdminPageQuery = {}) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(input)) {
    if (value !== undefined && value !== null && String(value).trim()) {
      query.set(key, String(value));
    }
  }
  const value = query.toString();
  return value ? `?${value}` : "";
}

function organizationJoinCodeResultOf(value: unknown): OrganizationJoinCodeResult {
  const data = dataOf(value);
  const item = isRecord(data) ? data : {};
  const organization = adminOrganizationOf(item.organization);
  if (!organization) {
    throw new ApiError("조직 생성 응답 형식이 올바르지 않습니다.", 502, "INVALID_ADMIN_RESPONSE");
  }
  return {
    organization,
    ...(typeof item.joinCode === "string" && item.joinCode ? { joinCode: item.joinCode } : {}),
    joinCodeReturned: item.joinCodeReturned === true,
    joinCodeAlreadyReturned: item.joinCodeAlreadyReturned === true,
  };
}

export const api = {
  health: () => request<HealthResponse>("/health"),

  register: async (input: RegistrationRequest, authMode: "dev" | "oidc") => {
    const body =
      authMode === "oidc"
        ? {
            displayName: input.displayName,
            affiliation: input.affiliation,
            consent: input.consent,
            accountType: input.accountType,
            ...(input.organizationJoinCode
              ? { organizationJoinCode: input.organizationJoinCode }
              : {}),
          }
        : input;
    const payload = dataOf(
      await request(
        authMode === "oidc" ? "/v1/auth/onboarding" : "/v1/auth/register",
        { method: "POST", body: JSON.stringify(body) },
      ),
    );
    const data = isRecord(payload) ? payload : {};
    return {
      user: (data.user ?? data) as UserContext,
      developmentAuth: isRecord(data.developmentAuth)
        ? (data.developmentAuth as RegistrationResult["developmentAuth"])
        : null,
      alreadyOnboarded: data.alreadyOnboarded === true,
    } satisfies RegistrationResult;
  },

  me: async (): Promise<{ user: UserContext; consentRequired: boolean }> => {
    const payload = dataOf(await request("/v1/me"));
    const body = isRecord(payload) ? payload : {};
    return {
      user: (body.user ?? body) as UserContext,
      consentRequired: body.consentRequired === true,
    };
  },

  /** Records agreement for an account created before the consent requirement. */
  recordConsent: async () => {
    const payload = dataOf(
      await request("/v1/me/consent", {
        method: "POST",
        body: JSON.stringify({ consent: { terms: true, privacy: true } }),
      }),
    );
    const body = isRecord(payload) ? payload : {};
    return (body.user ?? body) as UserContext;
  },

  listLabs: async () => {
    const payload = dataOf(await request<unknown>("/v1/labs"));
    if (Array.isArray(payload)) return payload.map(labOf);
    if (isRecord(payload)) {
      if (Array.isArray(payload.labs)) return payload.labs.map(labOf);
      if (Array.isArray(payload.items)) return payload.items.map(labOf);
    }
    return [];
  },

  getLab: async (id: string) =>
    labOf(entityOf<unknown>(
      await request(`/v1/labs/${encodeURIComponent(id)}`),
      "lab",
    )),

  generateLab: async (input: LabGenerationRequest) =>
    labOf(entityOf<unknown>(
      await request("/v1/labs/generate", {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey("lab-generate") },
        body: JSON.stringify(input),
      }),
      "lab",
    )),

  validateLab: async (id: string) => {
    const payload = dataOf(
      await request(`/v1/labs/${encodeURIComponent(id)}/validate`, {
        method: "POST",
      }),
    );
    if (isRecord(payload) && isRecord(payload.validation)) {
      return payload.validation as ValidationResult;
    }
    return payload as ValidationResult;
  },

  retryLabBuild: async (id: string) =>
    labOf(
      entityOf<unknown>(
        await request(`/v1/labs/${encodeURIComponent(id)}/build`, {
          method: "POST",
          headers: { "Idempotency-Key": idempotencyKey("lab-build") },
          body: JSON.stringify({}),
        }),
        "lab",
      ),
    ),

  deployLab: async (id: string, accessMethod: AccessMethod) =>
    entityOf<RuntimeRun>(
      await request(`/v1/labs/${encodeURIComponent(id)}/deploy`, {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey("lab-deploy") },
        body: JSON.stringify({ accessMethod }),
      }),
      "run",
    ),

  getRun: async (id: string) =>
    entityOf<RuntimeRun>(
      await request(`/v1/runs/${encodeURIComponent(id)}`),
      "run",
    ),

  searchElk: async (runId: string, query: string, size = 50) =>
    elkSearchResultOf(
      entityOf<unknown>(
        await request(`/v1/runs/${encodeURIComponent(runId)}/elk/search`, {
          method: "POST",
          body: JSON.stringify({ query, size }),
        }),
        "result",
      ),
    ),

  issueDesktopTicket: async (runId: string): Promise<DesktopTicket> => {
    const payload = dataOf(
      await request(`/v1/runs/${encodeURIComponent(runId)}/desktop-ticket`, {
        method: "POST",
      }),
    );
    const data = isRecord(payload) ? payload : {};
    const launchUrl = data.launchUrl ?? data.launch_url ?? data.gatewayUrl ?? data.gateway_url;
    if (typeof launchUrl !== "string" || !launchUrl) {
      throw new ApiError(
        "데스크톱 티켓 응답에 접속 URL이 없습니다.",
        502,
        "INVALID_DESKTOP_TICKET_RESPONSE",
      );
    }
    return {
      launchUrl,
      ...(typeof (data.expiresAt ?? data.expires_at) === "string"
        ? { expiresAt: String(data.expiresAt ?? data.expires_at) }
        : {}),
    };
  },

  issueOpenVpnTicket: async (runId: string): Promise<OpenVpnTicket> => {
    const payload = dataOf(
      await request(`/v1/runs/${encodeURIComponent(runId)}/openvpn-ticket`, {
        method: "POST",
      }),
    );
    const data = isRecord(payload) ? payload : {};
    const downloadUrl = data.downloadUrl ?? data.download_url;
    if (typeof downloadUrl !== "string" || !downloadUrl) {
      throw new ApiError(
        "OpenVPN 티켓 응답에 다운로드 URL이 없습니다.",
        502,
        "INVALID_OPENVPN_TICKET_RESPONSE",
      );
    }
    return {
      downloadUrl,
      ...(typeof (data.expiresAt ?? data.expires_at) === "string"
        ? { expiresAt: String(data.expiresAt ?? data.expires_at) }
        : {}),
    };
  },

  submitRun: async (runId: string, answers: AnswerSubmission[]) =>
    runSubmissionOf(
      dataOf(
        await request(`/v1/runs/${encodeURIComponent(runId)}/submit`, {
          method: "POST",
          headers: { "Idempotency-Key": `run-submit-${runId}` },
          body: JSON.stringify({ answers }),
        }),
      ),
    ),

  personalReport: async () =>
    personalReportOf(
      entityOf<unknown>(await request("/v1/reports/me"), "report"),
    ),

  organizationReport: async () =>
    organizationReportOf(
      entityOf<unknown>(await request("/v1/reports/organization"), "report"),
    ),

  platformReport: async () =>
    platformReportOf(
      entityOf<unknown>(await request("/v1/admin/reports/platform"), "report"),
    ),

  rankings: async (
    scope: RankingScope,
    period: RankingPeriod,
    domain?: RankingDomain | null,
  ) =>
    rankingOf(
      entityOf<unknown>(
        await request(
          `/v1/rankings?scope=${encodeURIComponent(scope)}&period=${encodeURIComponent(period)}${domain ? `&domain=${encodeURIComponent(domain)}` : ""}`,
        ),
        "ranking",
      ),
    ),

  adminOverview: async () =>
    adminOverviewOf(
      entityOf<unknown>(await request("/v1/admin/overview"), "overview"),
    ),

  adminUsers: async (query: AdminPageQuery = {}) =>
    adminPageOf(
      await request(`/v1/admin/users${adminQueryString(query)}`),
      adminUserOf,
    ),

  adminOrganizations: async (query: AdminPageQuery = {}) =>
    adminPageOf(
      await request(`/v1/admin/organizations${adminQueryString(query)}`),
      adminOrganizationOf,
    ),

  adminLabs: async (query: AdminPageQuery = {}) =>
    adminPageOf(
      await request(`/v1/admin/labs${adminQueryString(query)}`),
      adminLabOf,
    ),

  adminRuns: async (query: AdminPageQuery = {}) =>
    adminPageOf(
      await request(`/v1/admin/runs${adminQueryString(query)}`),
      adminRunOf,
    ),

  adminAuditLogs: async (query: AdminPageQuery = {}) =>
    adminPageOf(
      await request(`/v1/admin/audit-logs${adminQueryString(query)}`),
      adminAuditLogOf,
    ),

  adminSeasons: async () => {
    const payload = dataOf(await request("/v1/admin/seasons"));
    const seasons = isRecord(payload) ? payload.seasons : payload;
    return arrayValue(seasons)
      .map(adminSeasonOf)
      .filter((item): item is RankingSeason => item !== null);
  },

  createSeason: async (input: {
    name: string;
    slug: string;
    startsAt: string;
    endsAt: string;
  }) =>
    adminSeasonOf(
      entityOf<unknown>(
        await request("/v1/admin/seasons", {
          method: "POST",
          body: JSON.stringify(input),
        }),
        "season",
      ),
    ),

  deleteSeason: async (seasonId: string) => {
    await request(`/v1/admin/seasons/${encodeURIComponent(seasonId)}`, {
      method: "DELETE",
    });
  },

  setOrganizationRankingOptIn: async (optIn: boolean) =>
    entityOf<AdminOrganization>(
      await request("/v1/admin/organization/ranking-opt-in", {
        method: "POST",
        body: JSON.stringify({ optIn }),
      }),
      "organization",
    ),

  organizationAuditLogs: async (query: AdminPageQuery = {}) =>
    adminPageOf(
      await request(`/v1/admin/organization/audit-logs${adminQueryString(query)}`),
      adminAuditLogOf,
    ),

  organizationMembers: async (query: AdminPageQuery = {}) =>
    adminPageOf(
      await request(`/v1/admin/organization/members${adminQueryString(query)}`),
      organizationMemberOf,
    ),

  createOrganization: async (input: { name: string; slug?: string }) =>
    organizationJoinCodeResultOf(
      await request("/v1/admin/organizations", {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey("admin-org-create") },
        body: JSON.stringify(input),
      }),
    ),

  rotateOrganizationJoinCode: async (organizationId: string) =>
    organizationJoinCodeResultOf(
      await request(
        `/v1/admin/organizations/${encodeURIComponent(organizationId)}/rotate-join-code`,
        {
          method: "POST",
          headers: { "Idempotency-Key": idempotencyKey("admin-org-rotate") },
          body: JSON.stringify({}),
        },
      ),
    ),

  releaseLab: async (labId: string, reason?: string) =>
    entityOf<AdminLab>(
      await request(`/v1/admin/labs/${encodeURIComponent(labId)}/release`, {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey("admin-lab-release") },
        body: JSON.stringify(reason?.trim() ? { reason: reason.trim() } : {}),
      }),
      "lab",
    ),

  quarantineLab: async (labId: string, reason?: string) =>
    entityOf<AdminLab>(
      await request(`/v1/admin/labs/${encodeURIComponent(labId)}/quarantine`, {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey("admin-lab-quarantine") },
        body: JSON.stringify(reason?.trim() ? { reason: reason.trim() } : {}),
      }),
      "lab",
    ),

  terminateRun: async (runId: string, reason?: string) =>
    entityOf<AdminRun>(
      await request(`/v1/admin/runs/${encodeURIComponent(runId)}/terminate`, {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey("admin-run-terminate") },
        body: JSON.stringify(reason?.trim() ? { reason: reason.trim() } : {}),
      }),
      "run",
    ),

  setUserPlatformRole: async (
    userId: string,
    platformRole: "user" | "platform_admin",
    reason?: string,
  ) =>
    entityOf<AdminUser>(
      await request(
        `/v1/admin/users/${encodeURIComponent(userId)}/platform-role`,
        {
          method: "POST",
          headers: { "Idempotency-Key": idempotencyKey("admin-user-role") },
          body: JSON.stringify({
            platformRole,
            ...(reason?.trim() ? { reason: reason.trim() } : {}),
          }),
        },
      ),
      "user",
    ),

  setUserSuspension: async (userId: string, suspended: boolean, reason?: string) =>
    entityOf<AdminUser>(
      await request(`/v1/admin/users/${encodeURIComponent(userId)}/suspension`, {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey("admin-user-suspension") },
        body: JSON.stringify({
          suspended,
          ...(reason?.trim() ? { reason: reason.trim() } : {}),
        }),
      }),
      "user",
    ),

  setOrganizationMemberRole: async (
    userId: string,
    role: "org_admin" | "member",
    reason?: string,
  ) =>
    entityOf<OrganizationMember>(
      await request(
        `/v1/admin/organization/members/${encodeURIComponent(userId)}/role`,
        {
          method: "POST",
          headers: { "Idempotency-Key": idempotencyKey("admin-member-role") },
          body: JSON.stringify({
            role,
            ...(reason?.trim() ? { reason: reason.trim() } : {}),
          }),
        },
      ),
      "member",
    ),

  removeOrganizationMember: async (userId: string, reason?: string) =>
    entityOf<boolean>(
      await request(
        `/v1/admin/organization/members/${encodeURIComponent(userId)}/remove`,
        {
          method: "POST",
          headers: { "Idempotency-Key": idempotencyKey("admin-member-remove") },
          body: JSON.stringify(reason?.trim() ? { reason: reason.trim() } : {}),
        },
      ),
      "removed",
    ),
};

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return "알 수 없는 오류가 발생했습니다.";
}

export function isDevelopmentIdentityEnabled() {
  return developmentIdentityEnabled;
}

export function setDevelopmentUserId(userId: string) {
  if (developmentIdentityEnabled && userId.trim()) {
    activeDevelopmentUserId = userId.trim();
    if (typeof window !== "undefined") {
      window.localStorage.setItem("zerotop.developmentUserId", activeDevelopmentUserId);
    }
  }
}

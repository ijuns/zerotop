"use client";

import {
  type FormEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  API_URL,
  ApiError,
  DEV_USER_ID,
  api,
  errorMessage,
  getSessionToken,
  isDevelopmentIdentityEnabled,
  labBuildIsPending,
  labBuildState,
  setDevelopmentUserId,
  type AnswerSubmission,
  type AccountType,
  type AccessMethod,
  type CapabilityReport,
  type DesktopImage,
  type HealthResponse,
  type Lab,
  type LabBuildState,
  type LabQuestion,
  type PersonalCapabilityReport,
  type PlatformCapabilityReport,
  type PlatformRole,
  type QuestionType,
  RANKING_DOMAINS,
  type RankingDomain,
  type OrganizationRankingEntry,
  type RankingEntry,
  type RankingPeriod,
  type RankingResponse,
  type RankingScope,
  type RegistrationResult,
  type RunConnection,
  type RunSubmissionResult,
  type RuntimeRun,
  type SkillScore,
  type Team,
  type UserContext,
  type ValidationCheck,
  type ValidationResult,
  type OrganizationCapabilityReport,
} from "../lib/api";
import { useAuth } from "../components/auth-provider";
import { AdminConsole } from "../components/admin-console";
import { ElkSearchPanel } from "../components/elk-search-panel";
import { LabTopology } from "../components/lab-topology";
import {
  MitreTechniqueSelector,
  type MitreTechniqueOption,
} from "../components/mitre-technique-selector";
import { CourseOverview, ProductHome, ScenarioStudio } from "../components/product-pages";

type ViewKey =
  | "home"
  | "course"
  | "builder"
  | "workspace"
  | "report-personal"
  | "report-organization"
  | "report-platform"
  | "ranking"
  | "admin"
  | "signup";

type AsyncAction = "idle" | "generating" | "building" | "validating" | "deploying";
type LoadState = "loading" | "ready" | "error";
type HealthState = "checking" | "online" | "offline";
type DataState = "idle" | "loading" | "ready" | "error";
type BuilderPanelMode = "draft" | "review";
type ElkDraft = { query: string; evidenceIds: string[] };
type DraftAnswer = string | string[] | ElkDraft;

const BLUE_QUESTIONS: QuestionType[] = ["elk_search", "mitre_attack"];

const RED_QUESTIONS: Array<{
  value: QuestionType;
  label: string;
  description: string;
}> = [
  {
    value: "single_choice",
    label: "객관식",
    description: "공격 흐름에서 가장 적절한 단일 답안을 선택합니다.",
  },
  {
    value: "multiple_choice",
    label: "객관식 복수",
    description: "여러 개의 유효한 공격·방어 판단을 함께 선택합니다.",
  },
  {
    value: "free_text",
    label: "주관식",
    description: "분석 근거와 실행 과정을 직접 작성합니다.",
  },
  {
    value: "mitre_attack",
    label: "MITRE ATT&CK",
    description: "공격 단계에 맞는 전술과 기술을 매핑합니다.",
  },
];

const NAVIGATION: Array<{
  label: string;
  items: Array<{
    key: ViewKey;
    label: string;
    icon: string;
    requiredRole?: PlatformRole;
    adminOnly?: boolean;
  }>;
}> = [
  {
    label: "학습",
    items: [
      { key: "home", label: "홈", icon: "⌂" },
      { key: "course", label: "과정 상세", icon: "▤" },
      { key: "workspace", label: "실습 워크스페이스", icon: "⌘" },
      { key: "ranking", label: "시즌 랭킹", icon: "△" },
    ],
  },
  {
    label: "생성 · 운영",
    items: [
      { key: "builder", label: "설계 · 자동 검증", icon: "✦" },
    ],
  },
  {
    label: "역량 리포트",
    items: [
      { key: "report-personal", label: "개인 리포트", icon: "ME" },
      { key: "report-organization", label: "조직 리포트", icon: "OR", requiredRole: "org_admin" },
      { key: "report-platform", label: "전체 · 조직별", icon: "ALL", requiredRole: "platform_admin" },
    ],
  },
  {
    label: "운영 관리",
    items: [
      { key: "admin", label: "관리자 콘솔", icon: "▧", adminOnly: true },
    ],
  },
];

const VIEW_TITLES: Record<ViewKey, string> = {
  home: "홈",
  course: "과정 상세",
  builder: "설계 · 자동 검증",
  workspace: "실습 워크스페이스",
  "report-personal": "개인 보고서",
  "report-organization": "조직 보고서",
  "report-platform": "플랫폼 보고서",
  ranking: "시즌 랭킹",
  admin: "관리자 콘솔",
  signup: "회원가입",
};

const QUESTION_LABELS: Record<QuestionType, string> = {
  elk_search: "ELK 검색형",
  single_choice: "객관식",
  multiple_choice: "객관식 복수",
  free_text: "주관식",
  mitre_attack: "MITRE ATT&CK",
};

const ACCESS_LABELS: Record<AccessMethod, string> = {
  browser_desktop: "브라우저 데스크톱",
  openvpn: "OpenVPN",
  both: "데스크톱 + OpenVPN",
};

const ROLE_LABELS: Record<PlatformRole, string> = {
  individual: "개인 사용자",
  org_member: "조직 구성원",
  org_admin: "조직 관리자",
  platform_admin: "플랫폼 관리자",
};

const DEMO_IDENTITIES = [
  { id: "user_dev", label: "ZeroTOP 관리자 · 전체 플랫폼" },
  { id: "user_zerotop_org_admin", label: "김서준 · Security Lab 관리자" },
  { id: "user_zerotop_blue", label: "이하린 · Security Lab 구성원" },
  { id: "user_hanbit_admin", label: "정유나 · 한빛금융 관리자" },
  { id: "user_neocloud_member", label: "임태영 · 네오클라우드 구성원" },
  { id: "user_academy_student", label: "문가은 · 아카데미 구성원" },
  { id: "user_personal_blue", label: "개인 사용자 · 블루팀" },
  { id: "user_personal_red", label: "개인 사용자 · 레드팀" },
] as const;

function labTitle(lab: Lab) {
  return lab.title || lab.name || "이름 없는 Lab";
}

function labTeam(lab: Lab): Team {
  return lab.team || lab.teamType || "blue";
}

function labImage(lab: Lab): DesktopImage {
  return lab.desktopImage || lab.environment || "ubuntu";
}

function labAccess(lab: Lab): AccessMethod {
  if (lab.accessMethod) return lab.accessMethod;
  if (lab.accessModes?.length === 2) return "both";
  return lab.accessModes?.[0] || "browser_desktop";
}

function formatDate(value?: string) {
  if (!value) return "시간 정보 없음";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("ko-KR", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function userRoles(user: UserContext | null): PlatformRole[] {
  if (!user) return [];
  const roles = new Set<PlatformRole>(user.roles || []);
  if (user.organization) {
    roles.add("org_member");
    if (["owner", "admin", "org_admin"].includes(user.organization.role || "")) {
      roles.add("org_admin");
    }
  } else {
    roles.add("individual");
  }
  if (user.platformRole === "platform_admin" || user.role === "platform_admin") {
    roles.add("platform_admin");
  }
  return [...roles];
}

function formatScore(value: number) {
  return new Intl.NumberFormat("ko-KR", { maximumFractionDigits: 1 }).format(value);
}

function formatPercent(value: number) {
  return `${new Intl.NumberFormat("ko-KR", { maximumFractionDigits: 1 }).format(value)}%`;
}

function normalizedCveInput(value: string): { ids: string[]; error: string | null } {
  const tokens = value
    .split(/[\s,]+/)
    .map((item) => item.trim().toUpperCase())
    .filter(Boolean);
  const ids = [...new Set(tokens)];
  const invalid = ids.filter((item) => !/^CVE-\d{4}-\d{4,7}$/.test(item));
  if (invalid.length > 0) {
    return {
      ids,
      error: `CVE 형식을 확인해 주세요: ${invalid.slice(0, 3).join(", ")}`,
    };
  }
  if (ids.length > 20) {
    return { ids, error: "CVE ID는 중복 제거 후 최대 20개까지 입력할 수 있습니다." };
  }
  return { ids, error: null };
}

function buildStatusLabel(build: LabBuildState) {
  return {
    not_started: "빌드 대기",
    queued: "빌드 대기열",
    running: "이미지 빌드 중",
    succeeded: "이미지 빌드 완료",
    failed: "이미지 빌드 실패",
    cancelled: "이미지 빌드 취소",
  }[build.status];
}

function validationPassed(validation?: ValidationResult, lab?: Lab | null) {
  const decision = validation?.decision?.toLowerCase();
  if (["pass", "passed", "approved", "valid", "validated"].includes(decision || "")) {
    return true;
  }
  return ["approved", "validated"].includes(
    (lab?.validationStatus || lab?.status || "").toLowerCase(),
  );
}

function validationChecks(validation?: ValidationResult): ValidationCheck[] {
  if (!validation) return [];
  if (Array.isArray(validation.checks)) return validation.checks;
  if (Array.isArray(validation.evidence)) {
    return validation.evidence.map((item, index) => {
      if (typeof item === "object" && item !== null) {
        return item as ValidationCheck;
      }
      return {
        id: `evidence-${index}`,
        label: `검증 근거 ${index + 1}`,
        evidence: item,
      };
    });
  }
  return [];
}

function checkPassed(check: ValidationCheck) {
  if (typeof check.passed === "boolean") return check.passed;
  return ["pass", "passed", "success", "ok"].includes(
    (check.outcome || check.status || "").toLowerCase(),
  );
}

function readableValue(value: unknown): string {
  if (value === null || value === undefined) return "추가 정보 없음";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(readableValue).join(", ");
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .map(([key, item]) => `${key}: ${readableValue(item)}`)
      .join(" · ");
  }
  return String(value);
}

function runIsTerminal(run: RuntimeRun) {
  return ["ready", "failed", "stopped", "expired"].includes(
    run.status.toLowerCase(),
  );
}

function connectionOf(run: RuntimeRun | null) {
  if (!run) return null;
  const base: RunConnection = run.connection || run.connectionInfo || {};
  const openVpn: RunConnection = run.openVpn || run.openvpnProfile || {};
  return {
    vpnConfigUrl:
      base.openvpnConfigUrl ||
      base.openVpnConfigUrl ||
      base.vpnConfigUrl,
    endpoint: openVpn.endpoint || base.endpoint,
    assignedIp: openVpn.assignedIp || base.assignedIp,
    allowedCidr: openVpn.allowedCidr || base.allowedCidr,
    username: base.username,
    password: base.password,
  };
}

function publicQuestions(lab: Lab | null): LabQuestion[] {
  if (!lab || !Array.isArray(lab.questions)) return [];
  return lab.questions.filter(
    (question) =>
      typeof question.id === "string" &&
      typeof question.prompt === "string" &&
      ["elk_search", "single_choice", "multiple_choice", "free_text", "mitre_attack"].includes(
        question.type,
      ),
  );
}

function mitreCandidates(lab: Lab | null, question: LabQuestion): MitreTechniqueOption[] {
  const byId = new Map<string, MitreTechniqueOption>();
  for (const id of question.mitreTechniqueIds || []) {
    const normalized = id.trim().toUpperCase();
    if (/^T\d{4}(?:\.\d{3})?$/.test(normalized)) byId.set(normalized, { id: normalized });
  }
  for (const technique of lab?.scenario?.attackChain || []) {
    const id = technique.id?.trim().toUpperCase() || "";
    if (!/^T\d{4}(?:\.\d{3})?$/.test(id)) continue;
    byId.set(id, {
      id,
      ...(technique.name ? { name: technique.name } : {}),
      ...(technique.tactic ? { tactic: technique.tactic } : {}),
    });
  }
  return [...byId.values()];
}

function answerIsComplete(question: LabQuestion, answer: DraftAnswer | undefined) {
  if (question.type === "multiple_choice") return Array.isArray(answer) && answer.length > 0;
  if (question.type === "mitre_attack") {
    const techniqueIds = Array.isArray(answer)
      ? answer
      : typeof answer === "string" && answer.trim()
        ? [answer]
        : [];
    return (
      techniqueIds.length > 0 &&
      techniqueIds.every((value) => /^T\d{4}(?:\.\d{3})?$/.test(value.trim().toUpperCase()))
    );
  }
  if (question.type === "elk_search") {
    return (
      typeof answer === "object" &&
      answer !== null &&
      !Array.isArray(answer) &&
      answer.query.trim().length > 0 &&
      answer.evidenceIds.length > 0
    );
  }
  if (typeof answer !== "string" || !answer.trim()) return false;
  return true;
}

function outcomeLabel(outcome: string) {
  return {
    correct: "정답",
    partial: "부분 점수",
    incorrect: "오답",
    ungradable: "추가 검증 필요",
  }[outcome] || outcome;
}

function feedbackLabel(code: string) {
  return {
    MATCH: "제출한 답이 일치합니다.",
    NO_MATCH: "제출한 답이 일치하지 않습니다.",
    SET_MATCH: "선택한 항목이 모두 일치합니다.",
    SET_MISMATCH: "선택한 항목 조합을 다시 확인해 주세요.",
    ATTACK_MATCH: "ATT&CK 기술 매핑이 일치합니다.",
    ATTACK_MISMATCH: "ATT&CK 기술 매핑을 다시 확인해 주세요.",
    EXTERNAL_GRADE_ACCEPTED: "서버에서 검증한 증거가 반영되었습니다.",
    EXTERNAL_GRADE_FAILED: "서버 증거 검증을 통과하지 못했습니다.",
    TRUSTED_EVIDENCE_REQUIRED: "서버 측 증거 검증이 더 필요합니다.",
  }[code] || code;
}

/**
 * Season boundaries are stored as UTC instants and entered that way by the
 * administrator, so the label is rendered in UTC too. Formatting locally would
 * show an end of 09-30T23:59Z as "10.01" east of Greenwich.
 */
function formatSeasonDate(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");
  return month + "." + day;
}

function RankChange({ change }: { change: number }) {
  if (change === 0) return <span className="rank-change">—</span>;
  return (
    <span className={change > 0 ? "rank-change is-up" : "rank-change is-down"}>
      {change > 0 ? "↑" : "↓"} {Math.abs(change)}
    </span>
  );
}

function StatusDot({ state }: { state: HealthState }) {
  const label =
    state === "online" ? "API 정상" : state === "offline" ? "API 연결 실패" : "API 확인 중";
  return (
    <span className={`service-state service-state--${state}`} title={`${label}: ${API_URL}`}>
      <span className="service-state__dot" aria-hidden="true" />
      {label}
    </span>
  );
}

function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="empty-state__icon" aria-hidden="true">
        {icon}
      </div>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  );
}

function FieldHint({ children }: { children: ReactNode }) {
  return <p className="field-hint">{children}</p>;
}

function DataLoading({ label }: { label: string }) {
  return (
    <div className="data-loading" role="status" aria-label={`${label} 불러오는 중`}>
      <span className="spinner" aria-hidden="true" />
      <div><strong>{label}을 불러오고 있습니다</strong><small>검증된 최신 데이터를 조회합니다.</small></div>
    </div>
  );
}

function MetricCard({ label, value, note }: { label: string; value: string | number; note: string }) {
  return (
    <article className="metric-card">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{note}</small>
    </article>
  );
}

function SkillsPanel({ skills }: { skills: SkillScore[] }) {
  return (
    <section className="panel skills-panel" aria-labelledby="skills-title">
      <div className="panel-heading panel-heading--data">
        <div><span className="panel-kicker">CAPABILITY</span><h2 id="skills-title">스킬 지표</h2></div>
        <span className="data-count">{skills.length}개 영역</span>
      </div>
      {skills.length === 0 ? (
        <EmptyState icon="◌" title="집계된 스킬 지표가 없습니다" description="채점된 실습의 근거가 쌓이면 영역별 점수와 변화가 표시됩니다." />
      ) : (
        <div className="skill-list">
          {skills.map((skill) => {
            const width = Math.max(0, Math.min(100, skill.score));
            return (
              <article className="skill-row" key={skill.key}>
                <div className="skill-row__heading"><strong>{skill.label}</strong><span>{formatScore(skill.score)}</span></div>
                <div className="skill-meter" aria-label={`${skill.label} ${formatScore(skill.score)}점`}><span style={{ width: `${width}%` }} /></div>
                <div className="skill-row__meta"><small>근거 {skill.evidenceCount}개</small><small className={skill.delta > 0 ? "is-positive" : skill.delta < 0 ? "is-negative" : ""}>{skill.delta > 0 ? "+" : ""}{formatScore(skill.delta)}</small></div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function PermissionState({ role, description }: { role: PlatformRole; description: string }) {
  return (
    <section className="panel permission-panel">
      <EmptyState
        icon="◇"
        title={`${ROLE_LABELS[role]} 권한이 필요합니다`}
        description={description}
      />
    </section>
  );
}

export default function HomePage() {
  const authentication = useAuth();
  const [activeView, setActiveView] = useState<ViewKey>("home");
  const [health, setHealth] = useState<HealthState>("checking");
  const [healthInfo, setHealthInfo] = useState<HealthResponse | null>(null);
  const [user, setUser] = useState<UserContext | null>(null);
  const [userError, setUserError] = useState<string | null>(null);
  const [labs, setLabs] = useState<Lab[]>([]);
  const [labsState, setLabsState] = useState<LoadState>("loading");
  const [labsError, setLabsError] = useState<string | null>(null);
  const [selectedLab, setSelectedLab] = useState<Lab | null>(null);
  const [builderPanelMode, setBuilderPanelMode] = useState<BuilderPanelMode>("draft");
  const selectedLabIdRef = useRef<string | null>(null);
  const validationInFlightRef = useRef(new Set<string>());
  const automaticValidationRef = useRef(new Set<string>());
  const [validation, setValidation] = useState<ValidationResult | undefined>();
  const [run, setRun] = useState<RuntimeRun | null>(null);
  const [desktopLaunchState, setDesktopLaunchState] = useState<DataState>("idle");
  const [desktopLaunchError, setDesktopLaunchError] = useState<string | null>(null);
  const [vpnDownloadState, setVpnDownloadState] = useState<DataState>("idle");
  const [vpnDownloadError, setVpnDownloadError] = useState<string | null>(null);
  const [questionAnswers, setQuestionAnswers] = useState<Record<string, DraftAnswer>>({});
  const [submissionState, setSubmissionState] = useState<DataState>("idle");
  const [submissionError, setSubmissionError] = useState<string | null>(null);
  const [submissionResult, setSubmissionResult] = useState<RunSubmissionResult | null>(null);
  const [action, setAction] = useState<AsyncAction>("idle");
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reportState, setReportState] = useState<DataState>("idle");
  const [reportData, setReportData] = useState<CapabilityReport | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);
  // The two visible boards are both platform-wide; the active season replaces
  // the rolling weekly window server-side when one is configured.
  const rankingScope: RankingScope = "global";
  const [rankingBoard, setRankingBoard] = useState<"individual" | "organization">("individual");
  const [rankingDomain, setRankingDomain] = useState<RankingDomain | null>(null);
  const [rankingPolicyOpen, setRankingPolicyOpen] = useState(false);
  const rankingPeriod: RankingPeriod = "weekly";
  const [rankingState, setRankingState] = useState<DataState>("idle");
  const [rankingData, setRankingData] = useState<RankingResponse | null>(null);
  const [rankingError, setRankingError] = useState<string | null>(null);
  const [platformReportScope, setPlatformReportScope] = useState<"all" | "organization">("all");

  const [signupAccountType, setSignupAccountType] = useState<AccountType>("personal");
  const [signupEmail, setSignupEmail] = useState("");
  const [signupDisplayName, setSignupDisplayName] = useState("");
  const [signupAffiliation, setSignupAffiliation] = useState("");
  const [consentRequired, setConsentRequired] = useState(false);
  const [consentBusy, setConsentBusy] = useState(false);
  const [consentError, setConsentError] = useState<string | null>(null);
  const [signupTermsAgreed, setSignupTermsAgreed] = useState(false);
  const [signupPrivacyAgreed, setSignupPrivacyAgreed] = useState(false);
  const [signupPassword, setSignupPassword] = useState("");
  const [signupJoinCode, setSignupJoinCode] = useState("");
  const [signupState, setSignupState] = useState<DataState>("idle");
  const [signupError, setSignupError] = useState<string | null>(null);
  const [signupResult, setSignupResult] = useState<RegistrationResult | null>(null);
  // Local password-session auth screen: null = app, "login"/"signup" = gated.
  const [authScreen, setAuthScreen] = useState<"login" | "signup" | null>(null);
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginState, setLoginState] = useState<DataState>("idle");
  const [loginError, setLoginError] = useState<string | null>(null);

  const [title, setTitle] = useState("");
  const [prompt, setPrompt] = useState("");
  const [cveInput, setCveInput] = useState("");
  const [team, setTeam] = useState<Team>("blue");
  const [desktopImage, setDesktopImage] = useState<DesktopImage>("ubuntu");
  const [accessMethod, setAccessMethod] =
    useState<AccessMethod>("browser_desktop");
  const [redQuestions, setRedQuestions] = useState<QuestionType[]>([
    "single_choice",
    "multiple_choice",
    "free_text",
    "mitre_attack",
  ]);

  const setActiveLab = useCallback((lab: Lab | null) => {
    selectedLabIdRef.current = lab?.id || null;
    setSelectedLab(lab);
  }, []);

  const refreshLabs = useCallback(async (showLoading = true) => {
    if (showLoading) setLabsState("loading");
    setLabsError(null);
    try {
      const items = await api.listLabs();
      setLabs(items);
      const current = selectedLabIdRef.current
        ? items.find((item) => item.id === selectedLabIdRef.current)
        : undefined;
      if (current) {
        setActiveLab(current);
        setValidation(current.validation);
      } else {
        const next = items[0] ?? null;
        setActiveLab(next);
        setValidation(next?.validation);
        setRun(null);
        setDesktopLaunchState("idle");
        setDesktopLaunchError(null);
        setVpnDownloadState("idle");
        setVpnDownloadError(null);
      }
      setLabsState("ready");
    } catch (error) {
      setLabsError(errorMessage(error));
      setLabsState("error");
    }
  }, [setActiveLab]);

  useEffect(() => {
    let cancelled = false;

    void api
      .health()
      .then((info) => {
        if (!cancelled) {
          setHealthInfo(info);
          setHealth("online");
        }
      })
      .catch(() => {
        if (!cancelled) setHealth("offline");
      });

    void api
      .me()
      .then((profile) => {
        if (cancelled) return;
        setUser(profile.user);
        setConsentRequired(profile.consentRequired);
        setAuthScreen(null);
      })
      .catch((error) => {
        if (cancelled) return;
        if (error instanceof ApiError && error.code === "ONBOARDING_REQUIRED") {
          setActiveView("signup");
          setUserError(null);
          return;
        }
        // In password-session mode an unauthenticated visitor lands on the
        // login screen rather than an error.
        if (
          getSessionToken() === null &&
          error instanceof ApiError &&
          (error.status === 401 || error.status === 403)
        ) {
          setAuthScreen("login");
          setUserError(null);
          return;
        }
        setUserError(errorMessage(error));
      });

    void refreshLabs();
    return () => {
      cancelled = true;
    };
  }, [refreshLabs]);

  useEffect(() => {
    if (!run || runIsTerminal(run)) return;
    let cancelled = false;
    const timer = window.setTimeout(() => {
      void api
        .getRun(run.id)
        .then((nextRun) => {
          if (!cancelled) setRun(nextRun);
        })
        .catch((error) => {
          if (!cancelled) setActionError(errorMessage(error));
        });
    }, 3000);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [run]);

  useEffect(() => {
    setQuestionAnswers({});
    setSubmissionState("idle");
    setSubmissionError(null);
    setSubmissionResult(null);
    setDesktopLaunchState("idle");
    setDesktopLaunchError(null);
    setVpnDownloadState("idle");
    setVpnDownloadError(null);
  }, [run?.id]);

  const roles = useMemo(() => userRoles(user), [user]);
  const canViewOrganizationReport = roles.includes("org_admin");
  const canViewPlatformReport = roles.includes("platform_admin");
  const hasOrganization = Boolean(user?.organization);

  const loadReport = useCallback(async (scope: "personal" | "organization" | "platform") => {
    setReportState("loading");
    setReportError(null);
    setReportData(null);
    try {
      const report =
        scope === "personal"
          ? await api.personalReport()
          : scope === "organization"
            ? await api.organizationReport()
            : await api.platformReport();
      setReportData(report);
      setReportState("ready");
    } catch (error) {
      setReportError(errorMessage(error));
      setReportState("error");
    }
  }, []);

  const loadRankings = useCallback(async (
    scope: RankingScope,
    period: RankingPeriod,
    domain: RankingDomain | null = null,
  ) => {
    setRankingState("loading");
    setRankingError(null);
    setRankingData(null);
    try {
      const result = await api.rankings(scope, period, domain);
      setRankingData(result);
      setRankingState("ready");
    } catch (error) {
      setRankingError(errorMessage(error));
      setRankingState("error");
    }
  }, []);

  useEffect(() => {
    const scope =
      activeView === "report-personal"
        ? "personal"
        : activeView === "report-organization"
          ? "organization"
          : activeView === "report-platform"
            ? "platform"
            : null;
    if (!scope) return;
    if (!user && !userError) return;
    if (scope === "organization" && user && !canViewOrganizationReport) return;
    if (scope === "platform" && user && !canViewPlatformReport) return;
    void loadReport(scope);
  }, [
    activeView,
    canViewOrganizationReport,
    canViewPlatformReport,
    loadReport,
    user,
    userError,
  ]);

  useEffect(() => {
    if (activeView !== "ranking") return;
    if (!user && !userError) return;
    void loadRankings(rankingScope, rankingPeriod, rankingDomain);
  }, [
    activeView,
    loadRankings,
    rankingDomain,
    rankingPeriod,
    rankingScope,
    user,
    userError,
  ]);

  const questions = useMemo(
    () => (team === "blue" ? BLUE_QUESTIONS : redQuestions),
    [redQuestions, team],
  );
  const parsedCves = useMemo(() => normalizedCveInput(cveInput), [cveInput]);
  const draftPreviewLab = useMemo<Lab>(() => ({
    id: "builder-preview",
    title: title.trim() || "새 AI Lab",
    prompt: prompt.trim(),
    team,
    teamType: team,
    desktopImage,
    accessMethod,
    questionTypes: questions,
    scenario: prompt.trim() ? { summary: prompt.trim() } : undefined,
    target: parsedCves.ids.length > 0 ? { cveIds: parsedCves.ids } : undefined,
  }), [accessMethod, desktopImage, parsedCves.ids, prompt, questions, team, title]);
  const labQuestions = useMemo(() => publicQuestions(selectedLab), [selectedLab]);
  const appliedElkEvidenceIds = useMemo(
    () => [...new Set(Object.values(questionAnswers).flatMap((answer) =>
      typeof answer === "object" && answer !== null && !Array.isArray(answer)
        ? answer.evidenceIds
        : [],
    ))],
    [questionAnswers],
  );
  const allLabAnswersComplete =
    labQuestions.length > 0 &&
    labQuestions.every((question) => answerIsComplete(question, questionAnswers[question.id]));

  const isBusy = action !== "idle";
  const promptLength = prompt.trim().length;
  const hasPrompt = promptLength > 0;
  const hasValidCve = !parsedCves.error && parsedCves.ids.length > 0;
  const promptIsValid = hasPrompt ? promptLength >= 10 : hasValidCve;
  const isValid =
    title.trim().length >= 3 &&
    promptIsValid &&
    questions.length > 0 &&
    !parsedCves.error;
  const selectedBuild = labBuildState(selectedLab);
  const selectedBuildReady = !selectedBuild || selectedBuild.status === "succeeded";
  const selectedBuildRetryable = Boolean(
    selectedBuild && ["not_started", "failed", "cancelled"].includes(selectedBuild.status),
  );
  const selectedValidationPassed = validationPassed(validation, selectedLab);
  const builderLab = builderPanelMode === "review" ? selectedLab : null;
  const builderValidation = builderLab ? validation : undefined;
  const builderValidationPassed = builderLab ? selectedValidationPassed : false;
  const checks = validationChecks(validation);
  const connection = connectionOf(run);
  const authMode: "dev" | "oidc" | "local" =
    healthInfo?.authMode === "dev"
      ? "dev"
      : healthInfo?.authMode === "local"
        ? "local"
        : healthInfo?.authMode === "oidc"
          ? "oidc"
          : isDevelopmentIdentityEnabled()
            ? "dev"
            : "oidc";
  // The signup form collects email + password for both dev and local (password)
  // modes; OIDC takes those from the verified token instead.
  const passwordSignup = authMode === "dev" || authMode === "local";
  const signupConsentComplete = signupTermsAgreed && signupPrivacyAgreed;
  const signupValid =
    signupDisplayName.trim().length > 0 &&
    signupAffiliation.trim().length > 0 &&
    signupConsentComplete &&
    (signupAccountType === "personal" || signupJoinCode.trim().length > 0) &&
    (authMode === "oidc" ||
      (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(signupEmail.trim()) &&
        signupPassword.length >= 8));

  const chooseView = (key: ViewKey) => {
    setActiveView(key);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const activateDraft = () => {
    if (builderPanelMode === "draft") return;
    setBuilderPanelMode("draft");
    setActionError(null);
    setNotice(null);
  };

  const startNewLabDraft = () => {
    setBuilderPanelMode("draft");
    setTitle("");
    setPrompt("");
    setCveInput("");
    setTeam("blue");
    setDesktopImage("ubuntu");
    setAccessMethod("browser_desktop");
    setRedQuestions(RED_QUESTIONS.map((question) => question.value));
    setActionError(null);
    setNotice(null);
    chooseView("builder");
  };

  const openSelectedLabReview = () => {
    setBuilderPanelMode(selectedLab ? "review" : "draft");
    chooseView("builder");
  };

  const toggleRedQuestion = (question: QuestionType) => {
    activateDraft();
    setRedQuestions((current) =>
      current.includes(question)
        ? current.filter((item) => item !== question)
        : [...current, question],
    );
  };

  const validateSelectedLab = useCallback(async (
    lab: Lab,
    automatic = false,
  ): Promise<ValidationResult | null> => {
    const build = labBuildState(lab);
    const automaticKey = `${lab.id}:${build?.id || build?.status || "no-build"}`;
    if (automatic && automaticValidationRef.current.has(automaticKey)) return null;
    if (validationInFlightRef.current.has(lab.id)) return null;
    if (automatic) automaticValidationRef.current.add(automaticKey);
    validationInFlightRef.current.add(lab.id);
    setAction("validating");
    try {
      const result = await api.validateLab(lab.id);
      if (selectedLabIdRef.current === lab.id) setValidation(result);
      const refreshed = await api.getLab(lab.id).catch(() => null);
      if (refreshed && selectedLabIdRef.current === lab.id) setActiveLab(refreshed);
      await refreshLabs(false);
      return result;
    } finally {
      validationInFlightRef.current.delete(lab.id);
    }
  }, [refreshLabs, setActiveLab]);

  const selectLab = async (lab: Lab) => {
    if (
      isBusy ||
      (selectedLab && selectedLab.id !== lab.id && labBuildIsPending(selectedLab))
    ) {
      if (selectedLab && selectedLab.id !== lab.id && labBuildIsPending(selectedLab)) {
        setNotice("현재 선택한 Lab의 이미지 빌드와 자동 검증이 끝난 뒤 다른 Lab을 선택할 수 있습니다.");
      }
      return;
    }
    setBuilderPanelMode("review");
    setActiveLab(lab);
    setValidation(lab.validation);
    setRun(null);
    setDesktopLaunchState("idle");
    setDesktopLaunchError(null);
    setActionError(null);
    setNotice(null);
    try {
      const detail = await api.getLab(lab.id);
      if (selectedLabIdRef.current !== lab.id) return;
      setActiveLab(detail);
      setValidation(detail.validation || lab.validation);
      const build = labBuildState(detail);
      if (
        build?.status === "succeeded" &&
        !validationPassed(detail.validation, detail) &&
        (detail.validationStatus || detail.status || "draft") === "draft"
      ) {
        try {
          const result = await validateSelectedLab(detail, true);
          if (result && selectedLabIdRef.current === detail.id) {
            setNotice(
              validationPassed(result, detail)
                ? "완료된 이미지 빌드를 확인하고 자동 검증까지 마쳤습니다."
                : "이미지 빌드는 완료되었지만 검증 정책을 통과하지 못했습니다.",
            );
          }
        } finally {
          setAction("idle");
        }
      }
    } catch (error) {
      if (selectedLabIdRef.current === lab.id) setActionError(errorMessage(error));
    }
  };

  const handleGenerate = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!isValid || isBusy) return;

    setActionError(null);
    setNotice(null);
    setBuilderPanelMode("draft");
    setAction("generating");

    try {
      const lab = await api.generateLab({
        title: title.trim(),
        prompt: prompt.trim(),
        team,
        desktopImage,
        accessMethod,
        questionTypes: questions,
        ...(parsedCves.ids.length > 0 ? { cveIds: parsedCves.ids } : {}),
      });
      setActiveLab(lab);
      setBuilderPanelMode("review");
      setValidation(lab.validation);
      setRun(null);
      setDesktopLaunchState("idle");
      setDesktopLaunchError(null);
      setVpnDownloadState("idle");
      setVpnDownloadError(null);
      await refreshLabs(false);
      const build = labBuildState(lab);
      if (labBuildIsPending(lab)) {
        setNotice("Lab 설계가 생성되었습니다. 환경 이미지 빌드 상태를 추적하고 완료되면 자동 검증합니다.");
      } else if (build && build.status !== "succeeded") {
        setNotice("Lab 설계는 생성되었지만 환경 이미지 빌드를 시작하지 못했습니다. 상태를 확인하고 다시 시도해 주세요.");
      } else {
        const result = await validateSelectedLab(lab, true);
        if (result) {
          setNotice(
            validationPassed(result, lab)
              ? "Lab 생성과 자동 검증이 완료되었습니다. 이제 환경을 배포할 수 있습니다."
              : "Lab은 생성되었지만 검증 정책을 통과하지 못했습니다. 근거를 확인해 주세요.",
          );
        }
      }
    } catch (error) {
      setActionError(errorMessage(error));
    } finally {
      setAction("idle");
    }
  };

  const handleValidate = async () => {
    if (!selectedLab || isBusy || labBuildIsPending(selectedLab)) return;
    setActionError(null);
    setNotice(null);
    try {
      const result = await validateSelectedLab(selectedLab);
      if (result) {
        setNotice(
          validationPassed(result, selectedLab)
            ? "검증을 통과했습니다."
            : "검증 정책을 통과하지 못했습니다. 근거를 확인해 주세요.",
        );
      }
    } catch (error) {
      setActionError(errorMessage(error));
    } finally {
      setAction("idle");
    }
  };

  const handleRetryBuild = async () => {
    if (!selectedLab || isBusy) return;
    const originalLab = selectedLab;
    const build = labBuildState(originalLab);
    if (build && !["not_started", "failed", "cancelled"].includes(build.status)) return;
    setAction("building");
    setActionError(null);
    setNotice(null);
    setValidation(undefined);
    try {
      const updated = await api.retryLabBuild(originalLab.id);
      if (selectedLabIdRef.current !== originalLab.id) return;
      setActiveLab(updated);
      await refreshLabs(false);
      const nextBuild = labBuildState(updated);
      if (nextBuild?.status === "succeeded") {
        const result = await validateSelectedLab(updated, true);
        if (result) {
          setNotice(
            validationPassed(result, updated)
              ? "환경 이미지 재빌드와 자동 검증을 완료했습니다."
              : "환경 이미지 재빌드는 완료되었지만 검증 정책을 통과하지 못했습니다.",
          );
        }
      } else if (labBuildIsPending(updated)) {
        setNotice("환경 이미지 재빌드를 시작했습니다. 완료되면 자동 검증합니다.");
      } else {
        setNotice("재빌드 요청은 접수되었지만 빌드를 시작하지 못했습니다. 상태를 다시 확인해 주세요.");
      }
    } catch (error) {
      if (selectedLabIdRef.current === originalLab.id) setActionError(errorMessage(error));
    } finally {
      setAction("idle");
    }
  };

  useEffect(() => {
    const labId = selectedLab?.id;
    const buildId = selectedBuild?.id;
    if (!labId || !buildId || !labBuildIsPending(selectedLab)) return;
    let cancelled = false;
    let timer: number | undefined;

    const poll = async () => {
      try {
        const detail = await api.getLab(labId);
        if (cancelled || selectedLabIdRef.current !== labId) return;
        setActiveLab(detail);
        setValidation(detail.validation);
        setActionError(null);
        const nextBuild = labBuildState(detail);
        if (nextBuild?.status === "succeeded") {
          await refreshLabs(false);
          if (!validationPassed(detail.validation, detail)) {
            try {
              const result = await validateSelectedLab(detail, true);
              if (result && selectedLabIdRef.current === labId) {
                setNotice(
                  validationPassed(result, detail)
                    ? "환경 이미지 빌드와 자동 검증이 완료되었습니다. 이제 배포할 수 있습니다."
                    : "환경 이미지 빌드는 완료되었지만 검증 정책을 통과하지 못했습니다.",
                );
              }
            } catch (error) {
              if (!cancelled && selectedLabIdRef.current === labId) {
                setActionError(`이미지 빌드는 완료되었지만 자동 검증에 실패했습니다. ${errorMessage(error)}`);
              }
            } finally {
              if (!cancelled) setAction("idle");
            }
          }
          return;
        }
        if (nextBuild?.status === "failed" || nextBuild?.status === "cancelled") {
          setNotice(null);
          await refreshLabs(false);
          return;
        }
        timer = window.setTimeout(() => void poll(), 3000);
      } catch (error) {
        if (cancelled || selectedLabIdRef.current !== labId) return;
        setActionError(`이미지 빌드 상태를 확인하지 못했습니다. ${errorMessage(error)}`);
        timer = window.setTimeout(() => void poll(), 5000);
      }
    };

    timer = window.setTimeout(() => void poll(), 2000);
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [selectedLab?.id, selectedBuild?.id, refreshLabs, setActiveLab, validateSelectedLab]);

  const handleDeploy = async () => {
    if (!selectedLab || !selectedValidationPassed || isBusy) return;
    setActionError(null);
    setNotice(null);
    setAction("deploying");
    try {
      const nextRun = await api.deployLab(selectedLab.id, labAccess(selectedLab));
      setRun(nextRun);
      setDesktopLaunchState("idle");
      setDesktopLaunchError(null);
      setNotice("격리된 실습 환경 배포를 시작했습니다.");
      setActiveView("workspace");
    } catch (error) {
      setActionError(errorMessage(error));
    } finally {
      setAction("idle");
    }
  };

  const handleDesktopLaunch = async () => {
    if (!run || run.status.toLowerCase() !== "ready" || desktopLaunchState === "loading") return;
    const launchWindow = window.open("about:blank", "_blank");
    if (launchWindow) {
      launchWindow.opener = null;
      launchWindow.document.title = "ZeroTOP Desktop 연결 중";
      launchWindow.document.body.textContent = "새 데스크톱 입장 링크를 발급하고 있습니다…";
    }
    setDesktopLaunchState("loading");
    setDesktopLaunchError(null);
    try {
      const ticket = await api.issueDesktopTicket(run.id);
      if (launchWindow && !launchWindow.closed) {
        launchWindow.location.replace(ticket.launchUrl);
      } else {
        // 팝업이 차단되었거나 사용자가 준비 창을 닫은 경우에도 접속을 막지 않는다.
        window.location.assign(ticket.launchUrl);
      }
      setDesktopLaunchState("ready");
    } catch (error) {
      launchWindow?.close();
      setDesktopLaunchError(errorMessage(error));
      setDesktopLaunchState("error");
    }
  };

  const handleVpnDownload = async () => {
    if (!run || run.status.toLowerCase() !== "ready" || vpnDownloadState === "loading") return;
    const downloadWindow = window.open("about:blank", "_blank");
    if (!downloadWindow) {
      setVpnDownloadError("브라우저에서 새 창을 허용한 뒤 다시 시도해 주세요.");
      return;
    }
    downloadWindow.opener = null;
    downloadWindow.document.title = "OpenVPN 프로필 준비 중";
    setVpnDownloadState("loading");
    setVpnDownloadError(null);
    try {
      const ticket = await api.issueOpenVpnTicket(run.id);
      downloadWindow.location.replace(ticket.downloadUrl);
      setVpnDownloadState("ready");
    } catch (error) {
      downloadWindow.close();
      setVpnDownloadError(errorMessage(error));
      setVpnDownloadState("error");
    }
  };

  const updateQuestionAnswer = (questionId: string, answer: DraftAnswer) => {
    if (submissionState === "loading" || submissionResult) return;
    setQuestionAnswers((current) => ({ ...current, [questionId]: answer }));
  };

  const toggleMultipleAnswer = (questionId: string, optionId: string) => {
    const current = questionAnswers[questionId];
    const selected = Array.isArray(current) ? current : [];
    updateQuestionAnswer(
      questionId,
      selected.includes(optionId)
        ? selected.filter((value) => value !== optionId)
        : [...selected, optionId],
    );
  };

  const handleRunSubmission = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (
      !run ||
      run.status.toLowerCase() !== "ready" ||
      !allLabAnswersComplete ||
      submissionState === "loading" ||
      submissionResult
    ) {
      return;
    }
    const answers: AnswerSubmission[] = labQuestions.map((question) => {
      const draft = questionAnswers[question.id];
      if (question.type === "mitre_attack") {
        const techniqueIds = Array.isArray(draft)
          ? draft
          : typeof draft === "string" && draft.trim()
            ? [draft]
            : [];
        return {
          questionId: question.id,
          response: [...new Set(techniqueIds.map((id) => id.trim().toUpperCase()))],
        };
      }
      if (question.type === "elk_search" && typeof draft === "object" && !Array.isArray(draft)) {
        return {
          questionId: question.id,
          response: { query: draft.query.trim(), evidenceIds: draft.evidenceIds },
        };
      }
      return {
        questionId: question.id,
        response: Array.isArray(draft)
          ? draft
          : typeof draft === "string"
            ? draft.trim()
            : "",
      };
    });
    setSubmissionState("loading");
    setSubmissionError(null);
    try {
      const result = await api.submitRun(run.id, answers);
      setSubmissionResult(result);
      setSubmissionState("ready");
    } catch (error) {
      setSubmissionError(errorMessage(error));
      setSubmissionState("error");
    }
  };

  const handleLogin = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (loginState === "loading") return;
    setLoginState("loading");
    setLoginError(null);
    try {
      const account = await api.login(loginEmail.trim(), loginPassword);
      setUser(account);
      setUserError(null);
      setConsentRequired(false);
      setAuthScreen(null);
      setActiveView("home");
      setLoginPassword("");
      setLoginState("ready");
      await refreshLabs(false);
    } catch (error) {
      setLoginError(errorMessage(error));
      setLoginState("error");
    }
  };

  const handleLogout = () => {
    api.logout();
    setUser(null);
    setConsentRequired(false);
    setAuthScreen("login");
    setActiveView("home");
    setLoginEmail("");
    setLoginPassword("");
  };

  const handleSignup = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!signupValid || signupState === "loading") return;
    setSignupState("loading");
    setSignupError(null);
    setSignupResult(null);
    try {
      const result = await api.register(
        {
          email: signupEmail.trim(),
          displayName: signupDisplayName.trim(),
          affiliation: signupAffiliation.trim(),
          consent: { terms: signupTermsAgreed, privacy: signupPrivacyAgreed },
          ...(passwordSignup ? { password: signupPassword } : {}),
          accountType: signupAccountType,
          ...(signupAccountType === "organization"
            ? { organizationJoinCode: signupJoinCode.trim().toUpperCase() }
            : {}),
        },
        authMode,
      );
      if (authMode === "dev" && result.developmentAuth?.value) {
        setDevelopmentUserId(result.developmentAuth.value);
      }
      // In local mode api.register stored the session token; the visitor is now
      // signed in, so drop the auth screen and show the app.
      setSignupResult(result);
      setUser(result.user);
      setUserError(null);
      setAuthScreen(null);
      setSignupState("ready");
      await refreshLabs(false);
    } catch (error) {
      // This form always sends consent, so CONSENT_REQUIRED means the browser
      // is running a bundle cached from before the field existed.
      setSignupError(
        error instanceof ApiError && error.code === "CONSENT_REQUIRED"
          ? "페이지가 오래된 버전입니다. 새로고침(Ctrl+Shift+R) 후 다시 시도해 주세요."
          : errorMessage(error),
      );
      setSignupState("error");
    }
  };

  const openCourse = (lab: Lab) => {
    void selectLab(lab);
    chooseView("course");
  };

  const prepareScenarioVariant = () => {
    if (!selectedLab) return;
    setBuilderPanelMode("draft");
    setTitle(`${labTitle(selectedLab)} · AI 변형`);
    setPrompt(`${selectedLab.prompt || selectedLab.scenario?.summary || labTitle(selectedLab)}\n\n동일한 학습 목표를 유지하되 환경 변수, 공격 경로와 증거를 새롭게 구성해줘.`);
    setTeam(labTeam(selectedLab));
    setDesktopImage(labImage(selectedLab));
    setAccessMethod(labAccess(selectedLab) === "openvpn" ? "openvpn" : "browser_desktop");
    setCveInput([
      ...(selectedLab.target?.cveIds || []),
      ...(selectedLab.target?.expectedCves || []),
    ].join(", "));
    setNotice("현재 시나리오를 기반으로 변형 생성 입력을 준비했습니다. 내용을 확인한 뒤 생성해 주세요.");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const renderHome = () => (
    <ProductHome
      labs={labs}
      loading={labsState === "loading"}
      onCreate={startNewLabDraft}
      onOpenCourse={openCourse}
    />
  );

  const renderCourse = () => (
    <CourseOverview
      lab={selectedLab}
      run={run}
      canDeploy={selectedValidationPassed}
      busy={isBusy}
      onReview={openSelectedLabReview}
      onDeploy={() => void handleDeploy()}
      onOpenWorkspace={() => chooseView("workspace")}
    />
  );

  const renderBuilder = () => (
    <>
      <section className="hero-row" aria-labelledby="builder-title">
        <div>
          <div className="eyebrow">AI LAB BUILDER</div>
          <h1 id="builder-title">훈련 목표를 검증 가능한 실습 환경으로</h1>
          <p>
            블루팀 탐지 훈련과 레드팀 공격 분석을 설계하고, 정책 검증을 통과한
            환경만 안전하게 배포합니다.
          </p>
        </div>
        <div className="hero-metric" aria-label={`전체 Lab ${labs.length}개`}>
          <span>전체 Lab</span>
          <strong>{labsState === "loading" ? "—" : labs.length}</strong>
          <small>내 설계 자산</small>
        </div>
      </section>

      <ol className="workflow-steps" aria-label="Lab 배포 단계">
        <li className={builderLab ? "is-complete" : "is-current"}>
          <span>1</span>
          <div><strong>설계 생성</strong><small>AI가 시나리오 구성</small></div>
        </li>
        <li className={builderValidation ? (builderValidationPassed ? "is-complete" : "is-current") : ""}>
          <span>2</span>
          <div><strong>정책 검증</strong><small>안전성·정합성 확인</small></div>
        </li>
        <li className={builderLab && run ? "is-complete" : builderValidationPassed ? "is-current" : ""}>
          <span>3</span>
          <div><strong>환경 배포</strong><small>격리 런타임 생성</small></div>
        </li>
        <li className={builderLab && run?.status.toLowerCase() === "ready" ? "is-complete" : builderLab && run ? "is-current" : ""}>
          <span>4</span>
          <div><strong>실습 접속</strong><small>Desktop 또는 VPN</small></div>
        </li>
      </ol>

      <div className="builder-grid">
        <section className="panel form-panel" aria-labelledby="create-lab-title">
          <div className="panel-heading">
            <div>
              <span className="panel-kicker">새 설계</span>
              <h2 id="create-lab-title">AI Lab 만들기</h2>
            </div>
            <span className="ai-badge"><span aria-hidden="true">✦</span> AI-assisted</span>
          </div>

          <form onSubmit={handleGenerate}>
            <div className="form-group">
              <label htmlFor="lab-title">Lab 이름</label>
              <input
                id="lab-title"
                value={title}
                onChange={(event) => {
                  activateDraft();
                  setTitle(event.target.value);
                }}
                placeholder="예: 의심스러운 PowerShell 활동 조사"
                minLength={3}
                maxLength={80}
                required
                disabled={isBusy}
              />
            </div>

            <div className="form-group">
              <label htmlFor="lab-prompt">
                훈련 목표와 시나리오 <small>선택 · 입력 시 10자 이상</small>
              </label>
              <textarea
                id="lab-prompt"
                value={prompt}
                onChange={(event) => {
                  activateDraft();
                  setPrompt(event.target.value);
                }}
                placeholder="학습자가 분석할 사건, 달성해야 할 목표, 포함할 로그 또는 공격 단계를 구체적으로 입력해 주세요."
                minLength={10}
                maxLength={1200}
                rows={5}
                required={!hasValidCve}
                disabled={isBusy}
                aria-required={!hasValidCve}
                aria-invalid={hasPrompt && promptLength < 10}
                aria-describedby="prompt-hint"
              />
              <div className="input-meta" id="prompt-hint">
                <span>CVE ID 또는 훈련 목표와 시나리오 중 하나를 입력하세요. 시나리오를 입력한다면 10자 이상이어야 합니다.</span>
                <span>{prompt.length}/1,200</span>
              </div>
            </div>

            <div className="form-group cve-input-group">
              <label htmlFor="lab-cves">대상 CVE ID <small>선택 · 시나리오와 둘 중 하나 필수 · 최대 20개</small></label>
              <textarea
                id="lab-cves"
                value={cveInput}
                onChange={(event) => {
                  activateDraft();
                  setCveInput(event.target.value);
                }}
                onBlur={() => {
                  if (!parsedCves.error) setCveInput(parsedCves.ids.join(", "));
                }}
                placeholder="예: CVE-2025-12345, CVE-2024-3094"
                rows={2}
                maxLength={520}
                required={!hasPrompt}
                disabled={isBusy}
                aria-required={!hasPrompt}
                aria-invalid={Boolean(parsedCves.error)}
                aria-describedby="cve-input-hint"
              />
              <div className="input-meta" id="cve-input-hint">
                <span>시나리오를 비우려면 유효한 CVE ID를 하나 이상 입력하세요. 쉼표 또는 공백으로 구분합니다.</span>
                <span>{Math.min(parsedCves.ids.length, 20)}/20</span>
              </div>
              {parsedCves.error && <p className="field-error" role="alert">{parsedCves.error}</p>}
              {!parsedCves.error && parsedCves.ids.length > 0 && (
                <div className="cve-chip-list" aria-label="정규화된 CVE 목록">
                  {parsedCves.ids.map((id) => <span key={id}>{id}</span>)}
                </div>
              )}
            </div>

            <fieldset className="form-group">
              <legend>훈련 유형</legend>
              <div className="segmented-control segmented-control--team">
                <label className={team === "blue" ? "is-selected" : ""}>
                  <input
                    type="radio"
                    name="team"
                    value="blue"
                    checked={team === "blue"}
                    onChange={() => {
                      activateDraft();
                      setTeam("blue");
                      setDesktopImage("ubuntu");
                    }}
                    disabled={isBusy}
                  />
                  <span className="team-mark team-mark--blue" aria-hidden="true">B</span>
                  <span><strong>블루팀</strong><small>탐지 · 분석 · 대응</small></span>
                </label>
                <label className={team === "red" ? "is-selected" : ""}>
                  <input
                    type="radio"
                    name="team"
                    value="red"
                    checked={team === "red"}
                    onChange={() => {
                      activateDraft();
                      setTeam("red");
                      setDesktopImage("kali");
                    }}
                    disabled={isBusy}
                  />
                  <span className="team-mark team-mark--red" aria-hidden="true">R</span>
                  <span><strong>레드팀</strong><small>공격 · 침투 · 분석</small></span>
                </label>
              </div>
            </fieldset>

            <LabTopology
              team={team}
              mode="preview"
              accessMethod={accessMethod}
              lab={draftPreviewLab}
            />

            <fieldset className="form-group">
              <legend>문제 구성</legend>
              {team === "blue" ? (
                <div className="fixed-policy">
                  <div className="fixed-policy__top">
                    <span className="lock-mark" aria-hidden="true">✓</span>
                    <div>
                      <strong>블루팀 표준 문제 구성</strong>
                      <p>ELK에서 증거를 검색하고 ATT&CK 기술을 함께 매핑합니다.</p>
                    </div>
                    <span className="policy-chip">필수</span>
                  </div>
                  <div className="policy-flow" aria-label="블루팀 문제 흐름">
                    <span>ELK 로그 검색</span><i aria-hidden="true">→</i><span>증거 선택</span><i aria-hidden="true">→</i><span>MITRE 매핑</span>
                  </div>
                </div>
              ) : (
                <div className="question-grid">
                  {RED_QUESTIONS.map((question) => (
                    <label
                      key={question.value}
                      className={redQuestions.includes(question.value) ? "question-card is-selected" : "question-card"}
                    >
                      <input
                        type="checkbox"
                        checked={redQuestions.includes(question.value)}
                        onChange={() => toggleRedQuestion(question.value)}
                        disabled={isBusy}
                      />
                      <span className="custom-check" aria-hidden="true">✓</span>
                      <span><strong>{question.label}</strong><small>{question.description}</small></span>
                    </label>
                  ))}
                </div>
              )}
              {team === "red" && redQuestions.length === 0 && (
                <p className="field-error" role="alert">문제 유형을 하나 이상 선택해 주세요.</p>
              )}
            </fieldset>

            <div className="form-columns">
              <fieldset className="form-group">
                <legend>실습 이미지</legend>
                <div className="choice-stack">
                  {(["ubuntu", "kali"] as DesktopImage[]).map((image) => (
                    <label key={image} className={desktopImage === image ? "choice-row is-selected" : "choice-row"}>
                      <input
                        type="radio"
                        name="desktop-image"
                        value={image}
                        checked={desktopImage === image}
                        onChange={() => {
                          activateDraft();
                          setDesktopImage(image);
                        }}
                        disabled={isBusy || (team === "blue" ? image !== "ubuntu" : image !== "kali")}
                      />
                      <span className={`os-mark os-mark--${image}`} aria-hidden="true">{image === "ubuntu" ? "U" : "K"}</span>
                      <span><strong>{image === "ubuntu" ? "Ubuntu SOC" : "Kali Attack Box"}</strong><small>{image === "ubuntu" ? "분석 · ELK 환경" : "공격 도구 환경"}</small></span>
                    </label>
                  ))}
                </div>
                <FieldHint>블루팀은 Ubuntu SOC, 레드팀은 Kali Attack Box 이미지로 격리 정책이 고정됩니다.</FieldHint>
              </fieldset>

              <fieldset className="form-group">
                <legend>접속 방식</legend>
                <div className="choice-stack">
                  {([
                    ["browser_desktop", "브라우저 데스크톱", "Ubuntu SOC 또는 Kali를 웹에서 실행"],
                    ["openvpn", "OpenVPN", "내 PC의 도구를 격리 훈련망에 연결"],
                  ] as Array<[AccessMethod, string, string]>).map(([value, label, description]) => (
                    <label key={value} className={accessMethod === value ? "choice-row is-selected" : "choice-row"}>
                      <input
                        type="radio"
                        name="access-method"
                        value={value}
                        checked={accessMethod === value}
                        onChange={() => {
                          activateDraft();
                          setAccessMethod(value);
                        }}
                        disabled={isBusy}
                      />
                      <span className="radio-mark" aria-hidden="true" />
                      <span><strong>{label}</strong><small>{description}</small></span>
                    </label>
                  ))}
                </div>
                <FieldHint>한 세션에는 한 가지 접속 방식만 활성화됩니다. 새 세션을 배포할 때 다시 선택할 수 있습니다.</FieldHint>
              </fieldset>
            </div>

            <button className="primary-button primary-button--wide" type="submit" disabled={!isValid || isBusy}>
              {action === "generating" ? (
                <><span className="spinner" aria-hidden="true" /> 시나리오 생성 중</>
              ) : action === "building" ? (
                <><span className="spinner" aria-hidden="true" /> 환경 이미지 빌드 시작 중</>
              ) : action === "validating" ? (
                <><span className="spinner" aria-hidden="true" /> 자동 검증 중</>
              ) : (
                <><span aria-hidden="true">✦</span> Lab 생성 · 빌드 · 자동 검증</>
              )}
            </button>
            <FieldHint>환경 이미지 빌드가 필요한 Lab은 완료 상태를 확인한 뒤 정책 검증을 정확히 한 번 자동 실행합니다.</FieldHint>
          </form>
        </section>

        <section className="panel workflow-panel" aria-labelledby="validation-title">
          <div className="panel-heading">
            <div>
              <span className="panel-kicker">배포 게이트</span>
              <h2 id="validation-title">검증 및 배포</h2>
            </div>
            {builderLab && (
              <span className={`team-badge team-badge--${labTeam(builderLab)}`}>
                {labTeam(builderLab) === "blue" ? "BLUE" : "RED"}
              </span>
            )}
          </div>

          {!builderLab ? (
            <EmptyState
              icon="✦"
              title="새 Lab 설계 중"
              description="왼쪽 미리보기는 현재 입력한 새 설계만 반영합니다. 생성이 완료되면 이곳에서 해당 Lab의 빌드·검증·배포 상태를 확인할 수 있습니다."
            />
          ) : (
            <div className="validation-content">
              <div className="selected-lab-summary">
                <div>
                  <span className="mono-label">현재 LAB / {builderLab.id.slice(0, 12)}</span>
                  <h3>{labTitle(builderLab)}</h3>
                </div>
                <span className="status-pill status-pill--neutral">
                  {builderLab.status || builderLab.validationStatus || "생성됨"}
                </span>
              </div>
              <div className="lab-properties">
                <span><small>이미지</small><strong>{labImage(builderLab) === "ubuntu" ? "Ubuntu SOC" : "Kali Linux"}</strong></span>
                <span><small>접속</small><strong>{ACCESS_LABELS[labAccess(builderLab)]}</strong></span>
              </div>
              <div className="tag-row">
                {(builderLab.questionTypes || []).map((type) => (
                  <span className="tag" key={type}>{QUESTION_LABELS[type] || type}</span>
                ))}
              </div>

              {selectedBuild && (
                <div className={`build-state build-state--${selectedBuild.status}`} role={labBuildIsPending(builderLab) ? "status" : undefined}>
                  <span className="build-state__icon" aria-hidden="true">
                    {labBuildIsPending(builderLab) ? <span className="spinner" /> : selectedBuild.status === "succeeded" ? "✓" : "!"}
                  </span>
                  <div>
                    <strong>{buildStatusLabel(selectedBuild)}</strong>
                    <small>
                      {labBuildIsPending(selectedLab)
                        ? "서명·검증 가능한 격리 환경 이미지를 생성하고 있습니다. 완료 후 정책 검증을 자동 실행합니다."
                        : selectedBuild.status === "succeeded"
                          ? "환경 이미지와 검증 입력이 준비되었습니다."
                          : `빌드가 완료되지 않았습니다${selectedBuild.failureCode ? ` · ${selectedBuild.failureCode}` : ""}`}
                    </small>
                    <em>{selectedBuild.updatedAt || selectedBuild.createdAt ? `최근 갱신 ${formatDate(selectedBuild.updatedAt || selectedBuild.createdAt)}` : "빌드 상태 동기화됨"}</em>
                  </div>
                  {selectedBuildRetryable && (
                    <button className="secondary-button" type="button" onClick={() => void handleRetryBuild()} disabled={isBusy}>
                      {action === "building" ? "재빌드 시작 중" : "환경 이미지 재빌드"}
                    </button>
                  )}
                </div>
              )}

              {action === "validating" && (
                <div className="validation-running" role="status">
                  <span className="scanner" aria-hidden="true" />
                  <div><strong>정책 엔진이 설계를 검사하고 있습니다</strong><small>문제 정합성, 이미지 구성, 로그 준비도, 페이로드 안전성</small></div>
                </div>
              )}

              {builderValidation && action !== "validating" && (
                <div className={builderValidationPassed ? "decision-card decision-card--pass" : "decision-card decision-card--fail"}>
                  <div className="decision-card__header">
                    <span className="decision-icon" aria-hidden="true">{builderValidationPassed ? "✓" : "!"}</span>
                    <div>
                      <strong>{builderValidationPassed ? "검증 통과" : "검토 필요"}</strong>
                      <small>{builderValidationPassed ? "필수 정책을 모두 충족했습니다." : "배포 전에 실패 항목을 수정해야 합니다."}</small>
                    </div>
                    {typeof builderValidation.score === "number" && <b>{builderValidation.score}점</b>}
                  </div>
                  {checks.length > 0 && (
                    <ul className="evidence-list" aria-label="검증 근거">
                      {checks.map((check, index) => {
                        const passed = checkPassed(check);
                        const detail = check.evidence ?? check.message ?? check.details;
                        return (
                          <li key={check.id || `${check.checkName || check.label || "check"}-${index}`}>
                            <span className={passed ? "evidence-mark evidence-mark--pass" : "evidence-mark evidence-mark--fail"} aria-hidden="true">{passed ? "✓" : "×"}</span>
                            <div>
                              <strong>{check.label || check.name || check.checkName || `검증 항목 ${index + 1}`}</strong>
                              <small>{readableValue(detail)}</small>
                            </div>
                            {check.mandatory && <em>필수</em>}
                          </li>
                        );
                      })}
                    </ul>
                  )}
                  {builderValidation.policyVersion && <p className="policy-version">정책 버전 {builderValidation.policyVersion}</p>}
                </div>
              )}

              {!builderValidation && action !== "validating" && selectedBuildReady && (
                <div className="pending-validation">
                  <span aria-hidden="true">◌</span>
                  <div><strong>검증 결과가 없습니다</strong><small>정책 검증을 실행해야 배포할 수 있습니다.</small></div>
                </div>
              )}

              <div className="deployment-actions">
                {!builderValidation && selectedBuildReady && (
                  <button className="secondary-button" type="button" onClick={handleValidate} disabled={isBusy || !selectedBuildReady}>
                    정책 검증 실행
                  </button>
                )}
                <button className="primary-button" type="button" onClick={handleDeploy} disabled={!builderValidationPassed || isBusy}>
                  {action === "deploying" ? <><span className="spinner" aria-hidden="true" /> 환경 배포 중</> : <>실습 환경 배포 <span aria-hidden="true">→</span></>}
                </button>
              </div>
            </div>
          )}

          {actionError && <div className="alert alert--error" role="alert"><strong>요청을 완료하지 못했습니다.</strong><span>{actionError}</span></div>}
          {notice && <div className="alert alert--success" role="status"><strong>처리가 완료되었습니다.</strong><span>{notice}</span></div>}
        </section>
      </div>

      <ScenarioStudio
        labs={labs}
        lab={builderLab}
        validation={builderValidation}
        onSelect={(lab) => void selectLab(lab)}
        onPreview={() => chooseView("course")}
        onCreateVariant={prepareScenarioVariant}
      />

      <section className="panel lab-library" aria-labelledby="lab-list-title">
        <div className="panel-heading panel-heading--library">
          <div>
            <span className="panel-kicker">내 설계 자산</span>
            <h2 id="lab-list-title">Lab 라이브러리</h2>
          </div>
          <button className="text-button" type="button" onClick={() => void refreshLabs()} disabled={labsState === "loading"}>
            <span aria-hidden="true">↻</span> 새로고침
          </button>
        </div>

        {labsState === "loading" ? (
          <div className="lab-skeletons" role="status" aria-label="Lab 목록 불러오는 중">
            {[0, 1, 2].map((item) => <div className="lab-skeleton" key={item}><span /><span /><span /></div>)}
          </div>
        ) : labsState === "error" ? (
          <EmptyState
            icon="!"
            title="Lab 목록을 불러오지 못했습니다"
            description={labsError || "잠시 후 다시 시도해 주세요."}
            action={<button className="secondary-button" type="button" onClick={() => void refreshLabs()}>다시 시도</button>}
          />
        ) : labs.length === 0 ? (
          <EmptyState
            icon="＋"
            title="아직 생성한 Lab이 없습니다"
            description="첫 번째 훈련 목표를 입력하면 AI가 시나리오 초안을 만들고 자동으로 검증합니다."
          />
        ) : (
          <div className="lab-list">
            {labs.map((lab) => {
              const active = builderLab?.id === lab.id;
              const approved = validationPassed(lab.validation, lab);
              const build = labBuildState(lab);
              const buildFailed = build?.status === "failed" || build?.status === "cancelled";
              return (
                <button key={lab.id} type="button" className={active ? "lab-row is-active" : "lab-row"} onClick={() => void selectLab(lab)} disabled={isBusy || Boolean(selectedLab && selectedLab.id !== lab.id && labBuildIsPending(selectedLab))} title={selectedLab && selectedLab.id !== lab.id && labBuildIsPending(selectedLab) ? "현재 Lab의 이미지 빌드와 자동 검증이 진행 중입니다." : undefined}>
                  <span className={`lab-team-icon lab-team-icon--${labTeam(lab)}`} aria-hidden="true">{labTeam(lab) === "blue" ? "B" : "R"}</span>
                  <span className="lab-row__main"><strong>{labTitle(lab)}</strong><small>{lab.prompt || lab.description || "시나리오 설명이 없습니다."}</small></span>
                  <span className="lab-row__meta"><strong>{labImage(lab) === "ubuntu" ? "Ubuntu" : "Kali"}</strong><small>{formatDate(lab.updatedAt || lab.createdAt)}</small></span>
                  <span className={approved ? "status-pill status-pill--pass" : buildFailed ? "status-pill status-pill--danger" : "status-pill status-pill--neutral"}>{approved ? "검증 완료" : build ? buildStatusLabel(build) : lab.validationStatus || lab.status || "초안"}</span>
                  <span className="lab-row__arrow" aria-hidden="true">›</span>
                </button>
              );
            })}
          </div>
        )}
      </section>
    </>
  );

  const renderQuestionField = (question: LabQuestion) => {
    const answer = questionAnswers[question.id];
    const locked =
      !run ||
      run.status.toLowerCase() !== "ready" ||
      submissionState === "loading" ||
      Boolean(submissionResult);
    if (question.type === "elk_search") {
      const draft: ElkDraft =
        typeof answer === "object" && answer !== null && !Array.isArray(answer)
          ? answer
          : { query: "", evidenceIds: [] };
      return (
        <div className="elk-answer-grid">
          <div className="form-group"><label htmlFor={`${question.id}-query`}>ELK 검색 쿼리</label><textarea id={`${question.id}-query`} rows={3} value={draft.query} onChange={(event) => updateQuestionAnswer(question.id, { ...draft, query: event.target.value })} placeholder="예: event.category:process AND process.name:powershell.exe" disabled={locked} /></div>
          <div className="form-group"><label>선택한 증거 ID</label><div className="evidence-id-box" aria-live="polite">{draft.evidenceIds.length === 0 ? <span>위 ELK 검색 패널에서 증거를 선택하세요.</span> : draft.evidenceIds.map((id) => <button key={id} type="button" disabled={locked} title="답안에서 제거" onClick={() => updateQuestionAnswer(question.id, { ...draft, evidenceIds: draft.evidenceIds.filter((value) => value !== id) })}>{id}<i aria-hidden="true">×</i></button>)}</div></div>
        </div>
      );
    }
    if (question.type === "single_choice") {
      if (!question.options?.length) return <p className="question-empty">선택지가 제공되지 않았습니다.</p>;
      return <div className="answer-options">{question.options.map((option) => <label className={answer === option.id ? "answer-option is-selected" : "answer-option"} key={option.id}><input type="radio" name={question.id} value={option.id} checked={answer === option.id} onChange={() => updateQuestionAnswer(question.id, option.id)} disabled={locked} /><span className="radio-mark" aria-hidden="true" /><span>{option.label}</span></label>)}</div>;
    }
    if (question.type === "multiple_choice") {
      if (!question.options?.length) return <p className="question-empty">선택지가 제공되지 않았습니다.</p>;
      const selected = Array.isArray(answer) ? answer : [];
      return <div className="answer-options">{question.options.map((option) => <label className={selected.includes(option.id) ? "answer-option is-selected" : "answer-option"} key={option.id}><input type="checkbox" value={option.id} checked={selected.includes(option.id)} onChange={() => toggleMultipleAnswer(question.id, option.id)} disabled={locked} /><span className="custom-check" aria-hidden="true">✓</span><span>{option.label}</span></label>)}</div>;
    }
    if (question.type === "free_text") {
      return <div className="form-group question-textarea"><label htmlFor={`${question.id}-answer`}>분석 답안</label><textarea id={`${question.id}-answer`} rows={5} value={typeof answer === "string" ? answer : ""} onChange={(event) => updateQuestionAnswer(question.id, event.target.value)} placeholder="공격 흐름과 이를 뒷받침하는 증거를 설명하세요." disabled={locked} /></div>;
    }
    const candidates = mitreCandidates(selectedLab, question);
    const selectedTechniques = Array.isArray(answer)
      ? answer
      : typeof answer === "string" && answer.trim()
        ? [answer]
        : [];
    return (
      <MitreTechniqueSelector
        team={selectedLab ? labTeam(selectedLab) : "blue"}
        techniques={candidates}
        selected={selectedTechniques}
        onChange={(techniqueIds) => updateQuestionAnswer(question.id, techniqueIds)}
        disabled={locked}
      />
    );
  };

  const renderWorkspace = () => {
    const learning = selectedLab?.learning;
    const learningSections = Array.isArray(learning?.sections) ? learning.sections : [];
    const objectives = Array.isArray(learning?.objectives) ? learning.objectives : [];
    const prerequisites = Array.isArray(learning?.prerequisites) ? learning.prerequisites : [];
    const cveIds = [...new Set([
      ...(Array.isArray(selectedLab?.target?.cveIds) ? selectedLab.target.cveIds : []),
      ...(Array.isArray(selectedLab?.target?.expectedCves) ? selectedLab.target.expectedCves : []),
    ]
      .filter((id): id is string => typeof id === "string" && /^CVE-\d{4}-\d{4,7}$/i.test(id))
      .map((id) => id.toUpperCase()))];
    const affectedProducts = Array.isArray(selectedLab?.target?.affectedProducts)
      ? selectedLab.target.affectedProducts
      : [];
    const environmentReady = run?.status.toLowerCase() === "ready";
    return (
      <>
        <section className="hero-row hero-row--compact">
          <div><div className="eyebrow">GUIDED CYBER RANGE</div><h1>{selectedLab ? labTitle(selectedLab) : "실습 워크스페이스"}</h1><p>학습 자료를 확인하고 격리 환경에서 분석한 뒤 자동 생성 문제를 제출합니다.</p></div>
          {run && <span className={`run-status run-status--${run.status.toLowerCase()}`}><i aria-hidden="true" />{run.status}</span>}
        </section>

        <ol className="learning-sequence" aria-label="실습 순서"><li><span>1</span><div><strong>학습</strong><small>강의·목표·CVE</small></div></li><li><span>2</span><div><strong>실습</strong><small>Desktop·VPN</small></div></li><li><span>3</span><div><strong>평가</strong><small>문제 제출·채점</small></div></li></ol>

        <section className="workspace-stage" aria-labelledby="learning-material-title">
          <div className="stage-heading"><span>01</span><div><small>LEARNING MATERIAL</small><h2 id="learning-material-title">강의 자료와 학습 목표</h2></div></div>
          {!selectedLab ? (
            <section className="panel"><EmptyState icon="◫" title="선택된 Lab이 없습니다" description="설계·검증에서 Lab을 선택하거나 새 Lab을 배포해 주세요." action={<button className="secondary-button" type="button" onClick={openSelectedLabReview}>Lab 선택하기</button>} /></section>
          ) : (
            <div className="learning-grid">
              <section className="panel learning-materials">
                <div className="panel-heading panel-heading--data"><div><span className="panel-kicker">LECTURE</span><h2>강의 자료</h2></div><span className="data-count">{learningSections.length}개 섹션</span></div>
                {learningSections.length === 0 ? <EmptyState icon="◫" title="제공된 강의 자료가 없습니다" description="Lab API가 학습 콘텐츠를 제공하면 이곳에 표시됩니다." /> : <div className="lecture-sections">{learningSections.map((section, index) => <article key={section.id || `section-${index}`}><span>{String(index + 1).padStart(2, "0")}</span><div><h3>{section.title || `학습 섹션 ${index + 1}`}</h3><p>{section.bodyMarkdown || "본문이 제공되지 않았습니다."}</p></div></article>)}</div>}
              </section>
              <div className="learning-side">
                <section className="panel objective-card"><div className="panel-heading panel-heading--data"><div><span className="panel-kicker">OBJECTIVES</span><h2>학습 목표</h2></div></div>{objectives.length === 0 ? <p className="compact-empty">제공된 학습 목표가 없습니다.</p> : <ul>{objectives.map((objective, index) => <li key={`${objective}-${index}`}><span aria-hidden="true">✓</span>{objective}</li>)}</ul>}{prerequisites.length > 0 && <div className="prerequisites"><strong>선수 지식</strong><p>{prerequisites.join(" · ")}</p></div>}</section>
                <section className="panel cve-card"><div className="panel-heading panel-heading--data"><div><span className="panel-kicker">SOURCE</span><h2>CVE 출처</h2></div></div>{cveIds.length === 0 ? <p className="compact-empty">연결된 CVE 출처가 없습니다.</p> : <div className="cve-list">{cveIds.map((id) => <a href={`https://www.cve.org/CVERecord?id=${encodeURIComponent(id.toUpperCase())}`} target="_blank" rel="noreferrer" key={id}><span>{id.toUpperCase()}</span><small>CVE.org에서 확인 ↗</small></a>)}</div>}{affectedProducts.length > 0 && <p className="affected-products"><strong>영향 제품</strong>{affectedProducts.join(", ")}</p>}</section>
              </div>
            </div>
          )}
        </section>

        <section className="workspace-stage" aria-labelledby="practice-environment-title">
          <div className="stage-heading"><span>02</span><div><small>ISOLATED ENVIRONMENT</small><h2 id="practice-environment-title">실습 환경 접속</h2></div></div>
          {!run ? (
            <section className="panel"><EmptyState icon="⌘" title="실행 중인 실습 환경이 없습니다" description="검증을 통과한 Lab을 배포하면 Ubuntu 또는 Kali 환경에 접속할 수 있습니다." action={<button className="primary-button" type="button" onClick={openSelectedLabReview}>Lab 배포하기</button>} /></section>
          ) : (
            <div className="workspace-grid">
              <section className="panel session-card"><div className="panel-heading"><div><span className="panel-kicker">ACTIVE SESSION</span><h2>{selectedLab ? labTitle(selectedLab) : "실습 세션"}</h2></div><span className={`os-mark os-mark--${run.desktopImage || run.environment || "ubuntu"}`} aria-hidden="true">{(run.desktopImage || run.environment) === "kali" ? "K" : "U"}</span></div><dl className="session-details"><div><dt>Run ID</dt><dd>{run.id}</dd></div><div><dt>환경 상태</dt><dd><span className={`run-status run-status--${run.status.toLowerCase()}`}><i aria-hidden="true" />{run.status}</span></dd></div><div><dt>접속 방식</dt><dd>{ACCESS_LABELS[run.accessMethod || (selectedLab ? labAccess(selectedLab) : "browser_desktop")]}</dd></div><div><dt>만료 시각</dt><dd>{formatDate(run.expiresAt)}</dd></div></dl>{!runIsTerminal(run) && <div className="provisioning" role="status"><span className="spinner" aria-hidden="true" /><div><strong>실습 환경을 준비하고 있습니다</strong><small>상태는 자동으로 갱신됩니다.</small></div></div>}</section>
              <LabTopology
                team={selectedLab ? labTeam(selectedLab) : (run.desktopImage || run.environment) === "kali" ? "red" : "blue"}
                mode="runtime"
                lab={selectedLab}
                run={run}
                ready={environmentReady}
                accessMethod={run.accessMethod || (selectedLab ? labAccess(selectedLab) : "browser_desktop")}
                connection={connection}
                desktopBusy={desktopLaunchState === "loading"}
                desktopError={desktopLaunchError}
                vpnBusy={vpnDownloadState === "loading"}
                vpnError={vpnDownloadError}
                onOpenDesktop={() => void handleDesktopLaunch()}
                onDownloadVpn={() => void handleVpnDownload()}
              />
            </div>
          )}
          {selectedLab && labTeam(selectedLab) === "blue" && (
            <ElkSearchPanel
              runId={run?.id || null}
              ready={environmentReady}
              locked={Boolean(submissionResult)}
              questions={labQuestions}
              appliedEvidenceIds={appliedElkEvidenceIds}
              onApply={(questionId, query, evidenceIds) =>
                updateQuestionAnswer(questionId, { query, evidenceIds })
              }
            />
          )}
          {actionError && <div className="alert alert--error page-alert" role="alert"><strong>실행 상태를 갱신하지 못했습니다.</strong><span>{actionError}</span></div>}
        </section>

        <section className="workspace-stage" aria-labelledby="challenge-title">
          <div className="stage-heading"><span>03</span><div><small>AUTO-GENERATED ASSESSMENT</small><h2 id="challenge-title">자동 생성 문제</h2></div></div>
          <section className="panel challenge-panel">
            <div className="panel-heading panel-heading--data"><div><span className="panel-kicker">{selectedLab && labTeam(selectedLab) === "blue" ? "BLUE TEAM · ELK + MITRE" : "RED TEAM · MIXED QUESTIONS"}</span><h2>실습 결과 제출</h2></div><span className="data-count">{labQuestions.length}문제</span></div>
            {!selectedLab ? <EmptyState icon="?" title="평가할 Lab이 없습니다" description="먼저 Lab을 선택해 주세요." /> : labQuestions.length === 0 ? <EmptyState icon="?" title="제공된 문제가 없습니다" description="Lab API가 공개 문제 콘텐츠를 제공하면 이곳에 표시됩니다." /> : (
              <form className="challenge-form" onSubmit={handleRunSubmission}>
                {!environmentReady && !submissionResult && <div className="alert alert--info"><strong>실습 환경이 준비되어야 답안을 입력할 수 있습니다.</strong><span>환경을 배포하고 상태가 ready가 될 때까지 기다려 주세요.</span></div>}
                <div className="question-list">{labQuestions.map((question, index) => { const grade = submissionResult?.grade.grades.find((item) => item.questionId === question.id); return <article className={`challenge-question${grade ? ` challenge-question--${grade.outcome}` : ""}`} key={question.id}><div className="question-heading"><span>{String(index + 1).padStart(2, "0")}</span><div><div className="tag-row"><span className="tag">{QUESTION_LABELS[question.type]}</span><span className="tag">{question.points}점</span></div><h3>{question.prompt}</h3></div>{grade && <span className={`grade-outcome grade-outcome--${grade.outcome}`}>{outcomeLabel(grade.outcome)}</span>}</div>{renderQuestionField(question)}{grade && <div className="question-feedback"><strong>{grade.awardedPoints} / {grade.maxPoints}점</strong><span>{feedbackLabel(grade.feedbackCode)}</span></div>}</article>; })}</div>
                {submissionError && <div className="alert alert--error" role="alert"><strong>답안을 제출하지 못했습니다.</strong><span>{submissionError}</span></div>}
                {submissionResult && <div className={submissionResult.grade.passed ? "grade-summary grade-summary--pass" : "grade-summary grade-summary--fail"} role="status"><span className="grade-summary__score">{submissionResult.grade.score}</span><div><strong>{submissionResult.grade.passed ? "평가를 통과했습니다" : "평가 결과를 확인해 주세요"}</strong><p>{submissionResult.grade.awardedPoints} / {submissionResult.grade.maxPoints}점 · 제출이 완료되어 재제출할 수 없습니다.</p></div></div>}
                <div className="challenge-submit"><span>{labQuestions.filter((question) => answerIsComplete(question, questionAnswers[question.id])).length} / {labQuestions.length} 답변 완료</span><button className="primary-button" type="submit" disabled={!environmentReady || !allLabAnswersComplete || submissionState === "loading" || Boolean(submissionResult)}>{submissionState === "loading" ? <><span className="spinner" aria-hidden="true" /> 서버 채점 중</> : submissionResult ? "제출 완료" : "답안 제출 및 채점"}</button></div>
              </form>
            )}
          </section>
        </section>
      </>
    );
  };

  const reportFailure = (scope: "personal" | "organization" | "platform") => (
    <section className="panel">
      <EmptyState
        icon="!"
        title="보고서를 불러오지 못했습니다"
        description={reportError || "잠시 후 다시 시도해 주세요."}
        action={<button className="secondary-button" type="button" onClick={() => void loadReport(scope)}>다시 시도</button>}
      />
    </section>
  );

  const personalReportView = (report: PersonalCapabilityReport) => (
    <>
      <section className="metric-grid" aria-label="개인 역량 요약">
        <MetricCard label="종합 점수" value={formatScore(report.overallScore)} note="검증된 채점 결과 기준" />
        <MetricCard label="완료한 Lab" value={report.completedLabs} note="제출 완료 세션" />
        <MetricCard label="성공률" value={formatPercent(report.successRate)} note="통과한 평가 비율" />
      </section>
      <div className="report-grid">
        <SkillsPanel skills={report.skills} />
        <section className="panel data-panel" aria-labelledby="recent-runs-title">
          <div className="panel-heading panel-heading--data"><div><span className="panel-kicker">RECENT RESULTS</span><h2 id="recent-runs-title">최근 실습 결과</h2></div><span className="generated-at">{formatDate(report.generatedAt)} 생성</span></div>
          {report.recentRuns.length === 0 ? (
            <EmptyState icon="◫" title="완료한 실습이 없습니다" description="실습을 제출하고 채점이 끝나면 결과가 표시됩니다." />
          ) : (
            <div className="table-scroll"><table className="data-table"><thead><tr><th>Lab</th><th>팀</th><th>점수</th><th>완료 시각</th></tr></thead><tbody>{report.recentRuns.map((item) => <tr key={item.runId}><td><strong>{item.title}</strong><small>{item.labId}</small></td><td><span className={`team-badge team-badge--${item.team}`}>{item.team === "blue" ? "BLUE" : "RED"}</span></td><td className="number-cell">{formatScore(item.score)}</td><td>{formatDate(item.completedAt)}</td></tr>)}</tbody></table></div>
          )}
        </section>
      </div>
    </>
  );

  const organizationReportView = (report: OrganizationCapabilityReport) => (
    <>
      <section className="metric-grid metric-grid--four" aria-label="조직 역량 요약">
        <MetricCard label="조직 종합 점수" value={formatScore(report.overallScore)} note={report.organization.name} />
        <MetricCard label="전체 구성원" value={report.memberCount} note="등록 구성원" />
        <MetricCard label="활성 구성원" value={report.activeMemberCount} note="최근 평가 참여" />
        <MetricCard label="활성 비율" value={formatPercent(report.memberCount ? (report.activeMemberCount / report.memberCount) * 100 : 0)} note="전체 구성원 대비" />
      </section>
      <div className="report-grid">
        <SkillsPanel skills={report.skills} />
        <section className="panel data-panel" aria-labelledby="member-table-title">
          <div className="panel-heading panel-heading--data"><div><span className="panel-kicker">MEMBERS</span><h2 id="member-table-title">구성원 역량</h2></div><span className="generated-at">{formatDate(report.generatedAt)} 생성</span></div>
          {report.members.length === 0 ? (
            <EmptyState icon="▦" title="집계할 구성원이 없습니다" description="구성원의 채점 결과가 수집되면 역량 현황이 표시됩니다." />
          ) : (
            <div className="table-scroll"><table className="data-table"><thead><tr><th>구성원</th><th>종합 점수</th><th>완료 Lab</th><th>성공률</th><th>최근 활동</th></tr></thead><tbody>{report.members.map((member) => <tr key={member.userId}><td><strong>{member.displayName || member.handle}</strong><small>@{member.handle}</small></td><td className="number-cell">{formatScore(member.overallScore)}</td><td className="number-cell">{member.completedLabs}</td><td className="number-cell">{formatPercent(member.successRate)}</td><td>{member.lastActiveAt ? formatDate(member.lastActiveAt) : "활동 없음"}</td></tr>)}</tbody></table></div>
          )}
        </section>
      </div>
    </>
  );

  const platformReportView = (report: PlatformCapabilityReport) => (
    <>
      <section className="metric-grid metric-grid--four" aria-label="플랫폼 운영 요약">
        <MetricCard label="플랫폼 종합 점수" value={formatScore(report.overallScore)} note="전체 채점 결과" />
        <MetricCard label="전체 사용자" value={report.userCount} note="등록 사용자" />
        <MetricCard label="활성 사용자" value={report.activeUserCount} note="최근 평가 참여" />
        <MetricCard label="조직" value={report.organizationCount} note="등록 조직" />
      </section>
      {platformReportScope === "all" ? (
        <SkillsPanel skills={report.skills} />
      ) : (
        <section className="panel data-panel" aria-labelledby="organization-table-title">
          <div className="panel-heading panel-heading--data"><div><span className="panel-kicker">ORGANIZATIONS</span><h2 id="organization-table-title">조직별 현황</h2></div><span className="generated-at">{formatDate(report.generatedAt)} 생성</span></div>
          {report.organizations.length === 0 ? (
            <EmptyState icon="▦" title="집계할 조직이 없습니다" description="조직과 구성원 활동이 수집되면 운영 현황이 표시됩니다." />
          ) : (
            <div className="table-scroll"><table className="data-table"><thead><tr><th>조직</th><th>구성원</th><th>활성 구성원</th><th>종합 점수</th></tr></thead><tbody>{report.organizations.map((item) => <tr key={item.organization.id}><td><strong>{item.organization.name}</strong><small>{item.organization.slug}</small></td><td className="number-cell">{item.memberCount}</td><td className="number-cell">{item.activeMemberCount}</td><td className="number-cell">{formatScore(item.overallScore)}</td></tr>)}</tbody></table></div>
          )}
        </section>
      )}
    </>
  );

  const renderReport = (scope: "personal" | "organization" | "platform") => {
    const copy = {
      personal: { eyebrow: "MY PERFORMANCE", title: "개인 보고서", description: "완료한 실습의 탐지 정확도, ATT&CK 이해도와 성장 추이를 확인합니다." },
      organization: { eyebrow: "ORGANIZATION INSIGHT", title: "조직 보고서", description: "조직 관리자가 구성원의 참여도, 역량 분포와 취약한 전술 영역을 분석합니다." },
      platform: { eyebrow: "PLATFORM OPERATIONS", title: "플랫폼 보고서", description: "플랫폼 관리자가 전체 운영 지표와 조직별 역량을 확인합니다." },
    }[scope];
    const forbidden =
      (scope === "organization" && user && !canViewOrganizationReport) ||
      (scope === "platform" && user && !canViewPlatformReport);
    return (
      <>
        <section className="hero-row hero-row--compact"><div><div className="eyebrow">{copy.eyebrow}</div><h1>{copy.title}</h1><p>{copy.description}</p></div>{reportData && <span className="report-updated">기준 {formatDate(reportData.generatedAt)}</span>}</section>
        {forbidden ? (
          <PermissionState
            role={scope === "organization" ? "org_admin" : "platform_admin"}
            description={scope === "organization" ? "조직 구성원 전체의 평가 결과는 조직 관리자에게만 공개됩니다." : "전체 사용자와 조직의 운영 지표는 플랫폼 관리자에게만 공개됩니다."}
          />
        ) : (
          <>
            {scope === "platform" && (
              <div className="report-scope" role="tablist" aria-label="플랫폼 보고서 범위">
                <button type="button" role="tab" aria-selected={platformReportScope === "all"} onClick={() => setPlatformReportScope("all")}>전체 운영 현황</button>
                <button type="button" role="tab" aria-selected={platformReportScope === "organization"} onClick={() => setPlatformReportScope("organization")}>조직별 현황</button>
              </div>
            )}
            {(reportState === "idle" || reportState === "loading") && <section className="panel"><DataLoading label={copy.title} /></section>}
            {reportState === "error" && reportFailure(scope)}
            {reportState === "ready" && !reportData && <section className="panel"><EmptyState icon="◌" title="보고서 데이터가 없습니다" description="채점 결과가 수집되면 보고서를 확인할 수 있습니다." /></section>}
            {reportState === "ready" && reportData?.scope === "personal" && scope === "personal" && personalReportView(reportData)}
            {reportState === "ready" && reportData?.scope === "organization" && scope === "organization" && organizationReportView(reportData)}
            {reportState === "ready" && reportData?.scope === "platform" && scope === "platform" && platformReportView(reportData)}
          </>
        )}
      </>
    );
  };

  const renderRanking = () => {
    const season = rankingData?.season ?? null;
    const viewer = rankingData?.viewer;
    const organizationBoard = rankingBoard === "organization";
    const podium = organizationBoard
      ? (rankingData?.organizations ?? []).slice(0, 3)
      : (rankingData?.entries ?? []).slice(0, 3);
    // The mockup orders the podium 2 / 1 / 3 so the leader sits centre stage.
    const podiumOrder = [podium[1], podium[0], podium[2]];
    const seasonRange = season
      ? formatSeasonDate(season.startsAt) + " – " + formatSeasonDate(season.endsAt)
      : "상시 집계";
    const rowsEmpty = organizationBoard
      ? (rankingData?.organizations.length ?? 0) === 0
      : (rankingData?.entries.length ?? 0) === 0;

    return (
      <>
        <section className="hero-row hero-row--compact">
          <div>
            <div className="eyebrow">VERIFIED SEASON RANKING</div>
            <h1>시즌 랭킹</h1>
            <p>AI와 정책 엔진이 정상 완료로 검증한 실습 결과만 반영되는 실전 역량 순위입니다.</p>
          </div>
          <div className="ranking-hero-actions">
            <button className="secondary-button" type="button" onClick={() => setRankingPolicyOpen((open) => !open)}>점수 산정 기준</button>
            <button className="primary-button" type="button" onClick={() => chooseView("report-personal")}>내 공개 설정</button>
          </div>
        </section>

        <section className="season-banner">
          <div>
            <span className="season-badge">{season ? season.name : "SEASON"}</span>
            <h2>검증된 성과로 경쟁하는 시즌</h2>
            <p>난이도, 증거 정확도, 필수 과제 완료율을 보정해 단순 문제 풀이 수보다 실제 대응 역량을 평가합니다.</p>
          </div>
          <div className="season-banner__meta">
            <span>현재 시즌</span>
            <strong>{seasonRange}</strong>
            {rankingData && <small>{formatDate(rankingData.generatedAt)} 기준</small>}
          </div>
        </section>

        <div className="ranking-controls">
          <div className="ranking-tabs" role="tablist" aria-label="랭킹 범위">
            <button type="button" role="tab" aria-selected={!organizationBoard} className={!organizationBoard ? "is-active" : ""} onClick={() => setRankingBoard("individual")}>개인 전체</button>
            <button type="button" role="tab" aria-selected={organizationBoard} className={organizationBoard ? "is-active" : ""} onClick={() => setRankingBoard("organization")}>조직 종합</button>
          </div>
          <div className="ranking-domains" role="group" aria-label="영역 필터">
            <button type="button" className={rankingDomain === null ? "is-active" : ""} onClick={() => setRankingDomain(null)}>종합</button>
            {RANKING_DOMAINS.map((item) => (
              <button key={item.key} type="button" className={rankingDomain === item.key ? "is-active" : ""} onClick={() => setRankingDomain(item.key)}>{item.label}</button>
            ))}
          </div>
        </div>

        {!organizationBoard && viewer && (
          <section className="metric-grid metric-grid--four" aria-label="내 시즌 요약">
            <article className="metric-card"><span>내 순위</span><strong>{viewer.rank ? viewer.rank + "위" : "—"}</strong><small>{viewer.totalParticipants.toLocaleString("ko-KR")}명 중{viewer.topPercent !== null ? " · 상위 " + viewer.topPercent + "%" : ""}</small></article>
            <article className="metric-card"><span>시즌 점수</span><strong>{viewer.points.toLocaleString("ko-KR")} XP</strong><small>직전 기간 대비 {viewer.pointsDelta >= 0 ? "+" : ""}{viewer.pointsDelta.toLocaleString("ko-KR")}</small></article>
            <article className="metric-card"><span>완료 Lab</span><strong>{viewer.completedLabs}개</strong><small>검증 완료 결과 · 정확도 {viewer.accuracy}%</small></article>
            <article className="metric-card"><span>연속 학습</span><strong>{viewer.streakDays}일</strong><small>개인 최고 {viewer.bestStreakDays}일</small></article>
          </section>
        )}

        {rankingState === "ready" && podium[0] && (
          <section className="podium" aria-label="상위 3위">
            {podiumOrder.map((item, index) => {
              if (!item) return <div key={"empty-" + index} className="podium-card podium-card--empty" aria-hidden="true" />;
              const place = organizationBoard
                ? (item as OrganizationRankingEntry).rank
                : (item as RankingEntry).rank;
              const name = organizationBoard
                ? (item as OrganizationRankingEntry).name
                : (item as RankingEntry).handle;
              const value = organizationBoard
                ? String((item as OrganizationRankingEntry).readiness)
                : (item as RankingEntry).points.toLocaleString("ko-KR") + " XP";
              return (
                <article key={name} className={place === 1 ? "podium-card podium-card--leader" : "podium-card"}>
                  <span className="podium-avatar" aria-hidden="true">{name.slice(0, 2).toUpperCase()}</span>
                  <span className="podium-place">{place}위</span>
                  <strong>{name}</strong>
                  <span className="podium-score">{value}</span>
                  <i className="podium-rank" aria-hidden="true">{place}</i>
                </article>
              );
            })}
          </section>
        )}

        <section className="panel ranking-panel">
          <div className="panel-heading">
            <div>
              <h2>{organizationBoard ? "조직 종합 순위" : "공개 개인 순위"}</h2>
              <p>{organizationBoard ? "랭킹 공개에 동의한 조직만 · 규모를 보정한 준비도 기준" : "랭킹 공개에 동의한 사용자와 검증 완료 결과만 표시"}</p>
            </div>
            <span className="ranking-badge">AI 난이도 보정 적용</span>
          </div>

          {rankingState === "idle" || rankingState === "loading" ? (
            <DataLoading label="시즌 랭킹" />
          ) : rankingState === "error" ? (
            <EmptyState icon="!" title="랭킹을 불러오지 못했습니다" description={rankingError || "잠시 후 다시 시도해 주세요."} action={<button className="secondary-button" type="button" onClick={() => void loadRankings(rankingScope, rankingPeriod, rankingDomain)}>다시 시도</button>} />
          ) : rowsEmpty ? (
            <EmptyState icon="△" title={organizationBoard ? "공개에 동의한 조직이 없습니다" : "집계된 시즌 기록이 없습니다"} description={organizationBoard ? "조직 관리자가 랭킹 공개에 동의하면 순위가 표시됩니다." : "공개에 동의한 사용자의 검증된 기록이 생기면 순위가 표시됩니다."} />
          ) : organizationBoard ? (
            <div className="table-scroll"><table className="data-table ranking-table"><thead><tr><th>순위</th><th>조직</th><th>규모</th><th>준비도</th><th>참여율</th><th>완료율</th><th>변동</th></tr></thead><tbody>
              {rankingData?.organizations.map((entry) => (
                <tr key={entry.organizationId} className={rankingData.currentOrganization?.organizationId === entry.organizationId ? "is-current-user" : ""}>
                  <td><strong className="rank-number">{entry.rank}</strong></td>
                  <td><span className="rank-name"><strong>{entry.name}</strong>{rankingData.currentOrganization?.organizationId === entry.organizationId && <span className="rank-mine">MY</span>}</span></td>
                  <td className="number-cell">{entry.memberCount}명</td>
                  <td className="number-cell">{entry.readiness}</td>
                  <td className="number-cell">{entry.participationRate}%</td>
                  <td className="number-cell">{entry.completionRate}%</td>
                  <td><RankChange change={entry.change} /></td>
                </tr>
              ))}
            </tbody></table></div>
          ) : (
            <div className="table-scroll"><table className="data-table ranking-table"><thead><tr><th>순위</th><th>사용자</th><th>주요 영역</th><th>시즌 점수</th><th>완료 Lab</th><th>정확도</th><th>변동</th></tr></thead><tbody>
              {rankingData?.entries.map((entry) => (
                <tr key={entry.userId + "-" + entry.rank} className={rankingData.currentUser?.userId === entry.userId ? "is-current-user" : ""}>
                  <td><strong className="rank-number">{entry.rank}</strong></td>
                  <td><span className="rank-name"><strong>{entry.handle}</strong>{rankingData.currentUser?.userId === entry.userId && <span className="rank-mine">MY</span>}</span></td>
                  <td>{entry.primaryDomain?.label ?? "—"}</td>
                  <td className="number-cell">{entry.points.toLocaleString("ko-KR")} XP</td>
                  <td className="number-cell">{entry.completedLabs}</td>
                  <td className="number-cell">{entry.accuracy}%</td>
                  <td><RankChange change={entry.change} /></td>
                </tr>
              ))}
            </tbody></table></div>
          )}
        </section>

        <div className="ranking-footer">
          <section className="panel scoring-policy">
            <span className="panel-kicker">SCORING POLICY</span>
            <h2>순위 산정 방식</h2>
            <ol>
              <li><strong>난이도 보정</strong><small>초급 100 · 중급 250 · 고급 500</small></li>
              <li><strong>증거 정확도</strong><small>필수 과제와 대응 증거의 완성도</small></li>
              <li><strong>시간 · 힌트</strong><small>시간 보너스 최대 20% · 힌트 감점 최대 20%</small></li>
            </ol>
          </section>
          <section className="panel privacy-scope">
            <span className="panel-kicker">PRIVACY BY SCOPE</span>
            <h2>랭킹에서도 활동 범위를 분리합니다.</h2>
            <p>글로벌 개인 랭킹은 공개에 동의한 핸들만 표시합니다. 조직 종합 순위는 공개에 동의한 조직만 집계되며, 조직 관리자는 개인 워크스페이스 기록을 볼 수 없습니다.</p>
            <button className="primary-button primary-button--wide" type="button" onClick={() => chooseView(hasOrganization ? "report-organization" : "signup")}>
              {hasOrganization ? "조직 리포트 보기" : "조직 연결 후 내부 랭킹 보기"}
            </button>
          </section>
        </div>

        {rankingPolicyOpen && (
          <section className="panel" role="note">
            <h2>점수 산정 기준</h2>
            <p>실습 한 건의 시즌 점수 = <strong>난이도 기본점 × 정확도 × (1 + 시간 보너스) × (1 − 힌트 감점)</strong> 이며, 시즌 점수는 검증을 통과한 모든 실습의 합계입니다.</p>
            <ul>
              <li><strong>난이도 기본점</strong> — 초급 100 · 중급 250 · 고급 500 (expert는 고급으로 집계)</li>
              <li><strong>정확도</strong> — 획득 점수 ÷ 배점 합계</li>
              <li><strong>시간 보너스</strong> — 이용 시간의 절반 안에 완료하면 최대 +20%, 시간을 모두 쓰면 0%</li>
              <li><strong>힌트 감점</strong> — 힌트 1회당 −4%, 최대 −20%. 힌트 기록이 없으면 감점하지 않습니다.</li>
              <li><strong>조직 준비도</strong> — 정확도 50% · 참여율 30% · 완료율 20%의 가중 평균</li>
            </ul>
          </section>
        )}
      </>
    );
  };

  const renderSignup = () => (
    <>
      <section className="hero-row hero-row--compact"><div><div className="eyebrow">CREATE ACCOUNT</div><h1>계정 유형을 선택해 시작하세요</h1><p>개인으로 학습하거나, 가입 코드를 사용해 하나의 조직에 소속될 수 있습니다.</p></div><span className="auth-mode-badge">{authMode === "oidc" ? "OIDC ONBOARDING" : "LOCAL DEVELOPMENT"}</span></section>
      <div className="signup-grid signup-grid--selector" role="radiogroup" aria-label="계정 유형">
        <button className={signupAccountType === "personal" ? "panel signup-card is-selected" : "panel signup-card"} type="button" role="radio" aria-checked={signupAccountType === "personal"} onClick={() => setSignupAccountType("personal")}><span className="signup-card__icon" aria-hidden="true">◎</span><span className="panel-kicker">PERSONAL</span><h2>개인 계정</h2><p>개인 Lab, 역량 보고서와 공개 랭킹을 관리합니다.</p><span className="select-account">{signupAccountType === "personal" ? "선택됨" : "선택"}</span></button>
        <button className={signupAccountType === "organization" ? "panel signup-card signup-card--organization is-selected" : "panel signup-card signup-card--organization"} type="button" role="radio" aria-checked={signupAccountType === "organization"} onClick={() => setSignupAccountType("organization")}><span className="signup-card__icon" aria-hidden="true">▦</span><span className="panel-kicker">SINGLE ORGANIZATION</span><h2>조직 계정</h2><p>가입 코드로 단일 조직에 소속되어 팀 훈련에 참여합니다.</p><span className="select-account">{signupAccountType === "organization" ? "선택됨" : "선택"}</span></button>
      </div>
      <div className="signup-scope-note"><span aria-hidden="true">i</span><p><strong>개인 기록 보호</strong> 모든 계정에 개인 워크스페이스가 생성되며, 조직 관리자는 조직이 배정하거나 조직 범위에서 수행한 결과만 볼 수 있습니다. 한 사용자는 최대 하나의 조직에만 소속됩니다.</p></div>

      <section className="panel signup-form-panel" aria-labelledby="signup-form-title">
        <div className="panel-heading"><div><span className="panel-kicker">{authMode === "oidc" ? "AUTHENTICATED ONBOARDING" : "DEVELOPMENT REGISTRATION"}</span><h2 id="signup-form-title">{signupAccountType === "personal" ? "개인 회원가입" : "조직 회원가입"}</h2></div></div>
        {authMode === "oidc" && <div className="alert alert--info auth-notice"><strong>OIDC 인증 후 온보딩 단계입니다.</strong><span>이메일은 검증된 토큰에서 가져오며 비밀번호를 API에 전송하지 않습니다.</span></div>}
        {signupResult ? (
          <div className="signup-success" role="status"><span aria-hidden="true">✓</span><div><strong>{signupResult.alreadyOnboarded ? "이미 온보딩된 계정입니다" : "계정 준비가 완료되었습니다"}</strong><p>{signupResult.user.displayName || signupResult.user.handle} 님의 사용자 컨텍스트가 적용되었습니다.</p><button className="primary-button" type="button" onClick={startNewLabDraft}>Lab 설계 시작</button></div></div>
        ) : (
          <form className="signup-form" onSubmit={handleSignup}>
            {passwordSignup && <div className="form-group"><label htmlFor="signup-email">이메일</label><input id="signup-email" type="email" value={signupEmail} onChange={(event) => setSignupEmail(event.target.value)} autoComplete="email" placeholder="name@example.com" required /></div>}
            <div className="signup-form__columns">
              <div className="form-group"><label htmlFor="signup-display-name">이름</label><input id="signup-display-name" type="text" value={signupDisplayName} onChange={(event) => setSignupDisplayName(event.target.value)} autoComplete="name" maxLength={80} placeholder="홍길동" required /></div>
              <div className="form-group"><label htmlFor="signup-affiliation">소속</label><input id="signup-affiliation" type="text" value={signupAffiliation} onChange={(event) => setSignupAffiliation(event.target.value)} autoComplete="organization" maxLength={80} placeholder="한빛금융 보안관제팀" required /><FieldHint>학교, 회사 또는 소속 팀을 입력하세요.</FieldHint></div>
            </div>
            {passwordSignup && <div className="form-group"><label htmlFor="signup-password">비밀번호</label><input id="signup-password" type="password" value={signupPassword} onChange={(event) => setSignupPassword(event.target.value)} autoComplete="new-password" minLength={8} placeholder="8자 이상 입력" required /><FieldHint>로컬 개발 등록에서만 사용됩니다. 운영 환경은 OIDC 인증을 사용합니다.</FieldHint></div>}
            {signupAccountType === "organization" && <div className="form-group"><label htmlFor="signup-join-code">조직 가입 코드</label><input id="signup-join-code" type="text" value={signupJoinCode} onChange={(event) => setSignupJoinCode(event.target.value.toUpperCase())} autoCapitalize="characters" placeholder="SECURITY-LAB" required /><FieldHint>조직 관리자로부터 받은 단일 조직 가입 코드를 입력하세요.</FieldHint></div>}
            <fieldset className="consent-block">
              <legend>개인정보 수집 및 이용 동의</legend>
              <p className="consent-block__intro">교육 플랫폼 서비스 이용을 위해 아래와 같이 개인정보를 수집·이용하고자 합니다. 내용을 확인하신 후 동의해 주시기 바랍니다.</p>

              <label className="consent-row consent-row--all">
                <input type="checkbox" checked={signupConsentComplete} onChange={(event) => { setSignupTermsAgreed(event.target.checked); setSignupPrivacyAgreed(event.target.checked); }} />
                <span><strong>전체 동의하기</strong> (선택 사항 포함)</span>
              </label>

              <div className="consent-row">
                <label>
                  <input type="checkbox" checked={signupTermsAgreed} onChange={(event) => setSignupTermsAgreed(event.target.checked)} required />
                  <span><em>(필수)</em> 서비스 이용약관 동의</span>
                </label>
                <details><summary>내용보기</summary><div className="consent-document">
                  <p>본 약관은 ZeroTOP 교육 플랫폼(이하 &quot;서비스&quot;)의 이용 조건과 절차, 회원과 서비스 제공자의 권리·의무를 규정합니다.</p>
                  <ol>
                    <li>회원은 서비스가 제공하는 실습 환경을 교육 목적으로만 이용하며, 허가되지 않은 외부 시스템에 대한 공격 행위에 사용할 수 없습니다.</li>
                    <li>회원은 계정 정보를 타인과 공유할 수 없으며, 계정을 통해 발생한 활동에 대한 책임을 집니다.</li>
                    <li>서비스는 실습 환경을 실행별로 격리하여 제공하며, 정해진 이용 시간이 지나면 환경을 자동으로 회수합니다.</li>
                    <li>회원이 본 약관을 위반한 경우 서비스 이용이 제한되거나 계정이 정지될 수 있습니다.</li>
                  </ol>
                </div></details>
              </div>

              <div className="consent-row">
                <label>
                  <input type="checkbox" checked={signupPrivacyAgreed} onChange={(event) => setSignupPrivacyAgreed(event.target.checked)} required />
                  <span><em>(필수)</em> 개인정보 수집 및 이용 동의</span>
                </label>
                <details><summary>내용보기</summary><div className="consent-document">
                  <dl>
                    <dt>1. 개인정보 수집 및 이용 목적</dt>
                    <dd>회원가입 및 식별, 교육 콘텐츠/서비스 제공, 수강 이력 관리, 회원 서비스 이용 안내</dd>
                    <dt>2. 수집하는 개인정보 항목</dt>
                    <dd>[필수] 이름, 이메일 주소, 소속, 비밀번호</dd>
                    <dt>3. 개인정보의 보유 및 이용 기간</dt>
                    <dd>회원 탈퇴 시까지 (단, 법령에서 정한 보존 기간이 있는 경우 해당 기간 동안 보관)</dd>
                    <dt>4. 동의 거부 권리 및 동의 거부 시 불이익</dt>
                    <dd>귀하는 개인정보 수집 및 이용에 대한 동의를 거부할 권리가 있습니다. 단, 필수 항목 동의 거부 시 회원가입 및 교육 서비스 이용이 불가능합니다.</dd>
                  </dl>
                </div></details>
              </div>
            </fieldset>
            {signupError && <div className="alert alert--error" role="alert"><strong>가입을 완료하지 못했습니다.</strong><span>{signupError}</span></div>}
            <button className="primary-button primary-button--wide" type="submit" disabled={!signupValid || signupState === "loading"}>{signupState === "loading" ? <><span className="spinner" aria-hidden="true" /> 처리 중</> : authMode === "oidc" ? "온보딩 완료" : "회원가입 완료"}</button>
          </form>
        )}
      </section>
    </>
  );

  const acceptConsent = async () => {
    if (consentBusy) return;
    setConsentBusy(true);
    setConsentError(null);
    try {
      const profile = await api.recordConsent();
      setUser(profile);
      setConsentRequired(false);
    } catch (error) {
      setConsentError(errorMessage(error));
    } finally {
      setConsentBusy(false);
    }
  };

  // Shown to accounts created before the consent requirement, or whose
  // agreement predates the current document versions. The server refuses every
  // other route until this is completed, so this replaces the whole view.
  const renderConsentGate = () => (
    <>
      <section className="hero-row hero-row--compact">
        <div>
          <div className="eyebrow">CONSENT REQUIRED</div>
          <h1>약관 동의가 필요합니다</h1>
          <p>서비스 이용을 계속하려면 아래 필수 항목에 동의해 주세요. 동의 전에는 다른 기능을 사용할 수 없습니다.</p>
        </div>
      </section>
      <section className="panel signup-form-panel">
        <fieldset className="consent-block">
          <legend>개인정보 수집 및 이용 동의</legend>
          <p className="consent-block__intro">교육 플랫폼 서비스 이용을 위해 아래와 같이 개인정보를 수집·이용하고자 합니다. 내용을 확인하신 후 동의해 주시기 바랍니다.</p>
          <div className="consent-row">
            <span><em>(필수)</em> 서비스 이용약관</span>
            <details><summary>내용보기</summary><div className="consent-document">
              <p>본 약관은 ZeroTOP 교육 플랫폼(이하 &quot;서비스&quot;)의 이용 조건과 절차, 회원과 서비스 제공자의 권리·의무를 규정합니다.</p>
              <ol>
                <li>회원은 서비스가 제공하는 실습 환경을 교육 목적으로만 이용하며, 허가되지 않은 외부 시스템에 대한 공격 행위에 사용할 수 없습니다.</li>
                <li>회원은 계정 정보를 타인과 공유할 수 없으며, 계정을 통해 발생한 활동에 대한 책임을 집니다.</li>
                <li>서비스는 실습 환경을 실행별로 격리하여 제공하며, 정해진 이용 시간이 지나면 환경을 자동으로 회수합니다.</li>
                <li>회원이 본 약관을 위반한 경우 서비스 이용이 제한되거나 계정이 정지될 수 있습니다.</li>
              </ol>
            </div></details>
          </div>
          <div className="consent-row">
            <span><em>(필수)</em> 개인정보 수집 및 이용</span>
            <details><summary>내용보기</summary><div className="consent-document">
              <dl>
                <dt>1. 개인정보 수집 및 이용 목적</dt>
                <dd>회원가입 및 식별, 교육 콘텐츠/서비스 제공, 수강 이력 관리, 회원 서비스 이용 안내</dd>
                <dt>2. 수집하는 개인정보 항목</dt>
                <dd>[필수] 이름, 이메일 주소, 소속, 비밀번호</dd>
                <dt>3. 개인정보의 보유 및 이용 기간</dt>
                <dd>회원 탈퇴 시까지 (단, 법령에서 정한 보존 기간이 있는 경우 해당 기간 동안 보관)</dd>
                <dt>4. 동의 거부 권리 및 동의 거부 시 불이익</dt>
                <dd>귀하는 개인정보 수집 및 이용에 대한 동의를 거부할 권리가 있습니다. 단, 필수 항목 동의 거부 시 회원가입 및 교육 서비스 이용이 불가능합니다.</dd>
              </dl>
            </div></details>
          </div>
        </fieldset>
        {consentError && <div className="alert alert--error" role="alert"><strong>동의를 저장하지 못했습니다.</strong><span>{consentError}</span></div>}
        <button className="primary-button primary-button--wide" type="button" disabled={consentBusy} onClick={() => void acceptConsent()}>
          {consentBusy ? <><span className="spinner" aria-hidden="true" /> 처리 중</> : "필수 항목에 모두 동의합니다"}
        </button>
      </section>
    </>
  );

  const renderContent = () => {
    switch (activeView) {
      case "home": return renderHome();
      case "course": return renderCourse();
      case "builder": return renderBuilder();
      case "workspace": return renderWorkspace();
      case "report-personal": return renderReport("personal");
      case "report-organization": return renderReport("organization");
      case "report-platform": return renderReport("platform");
      case "ranking": return renderRanking();
      case "admin": return <AdminConsole roles={roles} organizationName={user?.organization?.name || user?.organizationName} currentUserId={user?.id} organizationRole={user?.organization?.role} organizationRankingOptIn={user?.organization?.rankingOptIn} authMode={authentication.mode === "local" ? "dev" : authentication.mode} />;
      case "signup": return renderSignup();
    }
  };

  const displayName = user?.displayName || user?.name || user?.handle || "개발 사용자";
  const displaySecondary = user?.email || user?.organization?.name || user?.organizationName || (isDevelopmentIdentityEnabled() ? DEV_USER_ID : "사용자 정보 확인 중");
  const roleSummary = roles.length > 0 ? roles.map((role) => ROLE_LABELS[role]).join(" · ") : "역할 확인 중";

  // Password-session gate: shown before the app shell until the visitor logs in
  // or registers. Registration and login both store a session token and clear
  // this screen.
  if (authScreen) {
    return (
      <main className="auth-shell">
        <div className="auth-shell__inner">
          <div className="auth-shell__brand">
            <span className="brand__mark" aria-hidden="true"><img src="/zerotop-logo.png" alt="" /></span>
            <div>
              <div className="eyebrow">ZeroTOP · Zero-day Training Orchestration Platform</div>
              <h1>실전형 사이버 레인지</h1>
            </div>
          </div>
          {authScreen === "login" ? (
            <section className="panel signup-form-panel">
              <div className="panel-heading"><div><span className="panel-kicker">SIGN IN</span><h2>로그인</h2></div></div>
              <form className="signup-form" onSubmit={handleLogin}>
                <div className="form-group"><label htmlFor="login-email">이메일</label><input id="login-email" type="email" value={loginEmail} onChange={(event) => setLoginEmail(event.target.value)} autoComplete="email" placeholder="name@example.com" required /></div>
                <div className="form-group"><label htmlFor="login-password">비밀번호</label><input id="login-password" type="password" value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} autoComplete="current-password" required /></div>
                {loginError && <div className="alert alert--error" role="alert"><strong>로그인하지 못했습니다.</strong><span>{loginError}</span></div>}
                <button className="primary-button primary-button--wide" type="submit" disabled={loginState === "loading" || !loginEmail.trim() || !loginPassword}>{loginState === "loading" ? <><span className="spinner" aria-hidden="true" /> 확인 중</> : "로그인"}</button>
              </form>
              <p className="auth-shell__switch">계정이 없으신가요? <button type="button" className="text-button" onClick={() => { setAuthScreen("signup"); setActiveView("signup"); }}>회원가입</button></p>
            </section>
          ) : (
            <>
              {renderSignup()}
              <p className="auth-shell__switch">이미 계정이 있으신가요? <button type="button" className="text-button" onClick={() => setAuthScreen("login")}>로그인</button></p>
            </>
          )}
        </div>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <button className="brand" type="button" onClick={() => chooseView("home")} aria-label="ZeroTOP 홈">
          <span className="brand__mark" aria-hidden="true"><img src="/zerotop-logo.png" alt="" /></span>
          <span><strong>ZeroTOP</strong><small>Zero-day Training<br />Orchestration Platform</small></span>
        </button>

        <nav className="side-nav" aria-label="주 메뉴">
          {NAVIGATION.map((group) => (
            <div className="nav-group" key={group.label}>
              <span className="nav-group__label">{group.label}</span>
              {group.items.map((item) => {
                const locked = Boolean(
                  user && (
                    (item.requiredRole && !roles.includes(item.requiredRole)) ||
                    (item.adminOnly && !roles.includes("org_admin") && !roles.includes("platform_admin"))
                  ),
                );
                return (
                  <button key={item.key} type="button" className={`${activeView === item.key ? "nav-item is-active" : "nav-item"}${locked ? " is-locked" : ""}`} onClick={() => item.key === "builder" ? startNewLabDraft() : chooseView(item.key)} title={locked ? (item.adminOnly ? "관리자 권한 안내 보기" : item.requiredRole ? `${ROLE_LABELS[item.requiredRole]} 권한 안내 보기` : undefined) : undefined}>
                    <span className="nav-item__icon" aria-hidden="true">{item.icon}</span><span>{item.label}</span>{locked && <span className="nav-lock" aria-hidden="true">◇</span>}{item.key === "workspace" && run && <i className="nav-live" aria-label="실행 중" />}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="security-note"><span aria-hidden="true">◈</span><div><strong>격리 런타임</strong><small>외부 통신 기본 차단</small></div></div>
          <small>Zero-day Training Orchestration Platform · {authentication.mode === "dev" ? "Local" : "OIDC"}</small>
        </div>
      </aside>

      <div className="content-shell">
        <header className="topbar">
          <div className="breadcrumb"><span>ZeroTOP</span><i aria-hidden="true">/</i><strong>{VIEW_TITLES[activeView]}</strong></div>
          <div className="topbar-actions">
            <StatusDot state={health} />
            {isDevelopmentIdentityEnabled() && (
              <label className="demo-user-switch">
                <span>데모 계정</span>
                <select
                  value={user?.id || DEV_USER_ID}
                  onChange={(event) => {
                    setDevelopmentUserId(event.target.value);
                    window.location.reload();
                  }}
                  aria-label="데모 사용자 전환"
                >
                  {DEMO_IDENTITIES.map((identity) => <option value={identity.id} key={identity.id}>{identity.label}</option>)}
                </select>
              </label>
            )}
            {authentication.mode === "dev" ? (
              <button className="signup-button" type="button" onClick={() => chooseView("signup")}>회원가입</button>
            ) : authentication.mode === "local" ? (
              <button className="signup-button" type="button" onClick={handleLogout}>로그아웃</button>
            ) : (
              <button className="signup-button" type="button" onClick={() => void authentication.logout()}>로그아웃</button>
            )}
            <button className="top-create-button" type="button" onClick={startNewLabDraft}>✦ AI Lab 만들기</button>
            <div className="user-context" title={userError || roleSummary}>
              <span className="avatar" aria-hidden="true">{displayName.slice(0, 1).toUpperCase()}</span>
              <span><strong>{displayName}</strong><small>{userError ? "컨텍스트 연결 실패" : displaySecondary}</small></span>
              {isDevelopmentIdentityEnabled() && <em>DEV</em>}
            </div>
          </div>
        </header>

        <nav className="mobile-nav" aria-label="모바일 주 메뉴">
          {NAVIGATION.flatMap((group) => group.items).map((item) => {
            const locked = Boolean(
              user && (
                (item.requiredRole && !roles.includes(item.requiredRole)) ||
                (item.adminOnly && !roles.includes("org_admin") && !roles.includes("platform_admin"))
              ),
            );
            return <button key={item.key} type="button" className={`${activeView === item.key ? "is-active" : ""}${locked ? " is-locked" : ""}`} onClick={() => item.key === "builder" ? startNewLabDraft() : chooseView(item.key)}>{item.label}{locked ? " · 권한 안내" : ""}</button>;
          })}
        </nav>

        <main>{consentRequired ? renderConsentGate() : renderContent()}</main>
      </div>
    </div>
  );
}

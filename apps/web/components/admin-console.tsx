"use client";

import { type FormEvent, useCallback, useEffect, useMemo, useState } from "react";

import {
  api,
  errorMessage,
  type AdminAuditLog,
  type AdminLab,
  type AdminOrganization,
  type AdminOverview,
  type AdminPage,
  type AdminRun,
  type AdminUser,
  type OrganizationMember,
  type PlatformRole,
} from "../lib/api";

type AdminTab =
  | "overview"
  | "users"
  | "organizations"
  | "labs"
  | "runs"
  | "audit"
  | "members"
  | "orgAudit";
type AdminListItem =
  | AdminUser
  | AdminOrganization
  | AdminLab
  | AdminRun
  | AdminAuditLog
  | OrganizationMember;
type LoadState = "idle" | "loading" | "ready" | "error";

const PAGE_SIZE = 20;

const TAB_LABELS: Record<AdminTab, string> = {
  overview: "운영 개요",
  users: "사용자",
  organizations: "조직",
  labs: "Lab",
  runs: "실행 환경",
  audit: "감사 로그",
  members: "내 조직 구성원",
  orgAudit: "조직 감사 로그",
};

/** Known audited actions, newest-facing first. Unknown values still render raw. */
const AUDIT_ACTION_LABELS: Record<string, string> = {
  "admin.user_platform_role_changed": "플랫폼 역할 변경",
  "admin.user_suspended": "계정 정지",
  "admin.user_reinstated": "정지 해제",
  "admin.organization_member_role_changed": "조직 역할 변경",
  "admin.organization_member_removed": "조직 구성원 제거",
  "admin.organization_created": "조직 생성",
  "admin.organization_join_code_rotated": "가입 코드 회전",
  "admin.lab_quarantined": "Lab 격리",
  "admin.lab_quarantine_released": "Lab 격리 해제",
  "runtime.expired": "실행 환경 만료",
  "admin.runtime_terminated": "실행 강제 종료",
  "auth.user_registered": "회원 가입",
  "auth.identity_onboarded": "ID 온보딩",
  "lab.generated": "Lab 생성",
  "lab.validation_completed": "Lab 검증 완료",
  "lab.environment_build_started": "환경 빌드 시작",
  "runtime.deployed": "실행 환경 배포",
  "challenge.submitted": "문제 제출",
  "desktop_ticket.issued": "데스크톱 티켓 발급",
  "openvpn_ticket.issued": "OpenVPN 티켓 발급",
  "elk.search_executed": "ELK 검색",
  "report.organization_viewed": "조직 리포트 조회",
  "report.platform_viewed": "플랫폼 리포트 조회",
};

const AUDIT_RESOURCE_LABELS: Record<string, string> = {
  user: "사용자",
  organization: "조직",
  organization_membership: "조직 구성원",
  lab: "Lab",
  runtime_run: "실행 환경",
  challenge_result: "채점 결과",
  platform: "플랫폼",
};

function formatDate(value?: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("ko-KR", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function Metric({ label, value, note }: { label: string; value: number; note: string }) {
  return (
    <article className="metric-card">
      <span>{label}</span>
      <strong>{value.toLocaleString("ko-KR")}</strong>
      <small>{note}</small>
    </article>
  );
}

function ListLoading() {
  return (
    <div className="admin-state" role="status">
      <span className="spinner" aria-hidden="true" />
      <div><strong>운영 데이터를 불러오고 있습니다</strong><small>권한과 조직 범위를 확인한 뒤 최신 결과를 표시합니다.</small></div>
    </div>
  );
}

function ListEmpty({ label }: { label: string }) {
  return (
    <div className="admin-state admin-state--empty">
      <span aria-hidden="true">◌</span>
      <div><strong>표시할 {label} 데이터가 없습니다</strong><small>검색어와 필터를 바꾸거나 데이터가 생성된 뒤 다시 확인해 주세요.</small></div>
    </div>
  );
}

export function AdminConsole({
  roles,
  organizationName,
  currentUserId,
  organizationRole,
  authMode,
}: {
  roles: PlatformRole[];
  organizationName?: string | null;
  /** Used to grey out actions the server rejects with CANNOT_MODIFY_SELF. */
  currentUserId?: string | null;
  organizationRole?: string | null;
  authMode?: "dev" | "oidc";
}) {
  const platformAdmin = roles.includes("platform_admin");
  const organizationAdmin = roles.includes("org_admin");
  const organizationOwner = organizationRole === "owner";
  const tabs = useMemo<AdminTab[]>(() => {
    const available: AdminTab[] = platformAdmin
      ? ["overview", "users", "organizations", "labs", "runs", "audit"]
      : [];
    if (organizationAdmin) available.push("members", "orgAudit");
    return available;
  }, [organizationAdmin, platformAdmin]);
  const [activeTab, setActiveTab] = useState<AdminTab>(platformAdmin ? "overview" : "members");
  const [state, setState] = useState<LoadState>("idle");
  const [overview, setOverview] = useState<AdminOverview | null>(null);
  // Tagged with its source tab: selecting a tab re-renders before the effect
  // reloads, so untagged data would reach the new tab's renderer for a frame.
  const [pageData, setPageData] = useState<
    { tab: AdminTab; page: AdminPage<AdminListItem> } | null
  >(null);
  const [page, setPage] = useState(1);
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("");
  const [resourceFilter, setResourceFilter] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [mutationNotice, setMutationNotice] = useState<string | null>(null);
  const [busyResource, setBusyResource] = useState<string | null>(null);
  const [organizationNameInput, setOrganizationNameInput] = useState("");
  const [organizationSlugInput, setOrganizationSlugInput] = useState("");
  const [oneTimeCode, setOneTimeCode] = useState<{ organization: string; code: string } | null>(null);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "error">("idle");

  useEffect(() => {
    if (!tabs.includes(activeTab)) setActiveTab(tabs[0] || "members");
  }, [activeTab, tabs]);

  const load = useCallback(async () => {
    if (!tabs.includes(activeTab)) return;
    setState("loading");
    setError(null);
    try {
      if (activeTab === "overview") {
        setOverview(await api.adminOverview());
        setPageData(null);
      } else {
        const query = { page, pageSize: PAGE_SIZE, ...(search ? { search } : {}) };
        const result =
          activeTab === "users"
            ? await api.adminUsers({ ...query, ...(filter ? { platformRole: filter as "user" | "platform_admin" } : {}) })
            : activeTab === "organizations"
              ? await api.adminOrganizations(query)
              : activeTab === "labs"
                ? await api.adminLabs({ ...query, ...(filter ? { status: filter } : {}) })
                : activeTab === "runs"
                  ? await api.adminRuns({ ...query, ...(filter ? { status: filter } : {}) })
                  : activeTab === "audit"
                    ? await api.adminAuditLogs({
                        ...query,
                        ...(filter ? { action: filter } : {}),
                        ...(resourceFilter ? { resourceType: resourceFilter } : {}),
                      })
                    : activeTab === "orgAudit"
                      ? await api.organizationAuditLogs({
                          ...query,
                          ...(filter ? { action: filter } : {}),
                        })
                      : await api.organizationMembers({ ...query, ...(filter ? { role: filter as "owner" | "org_admin" | "member" } : {}) });
        setPageData({ tab: activeTab, page: result as AdminPage<AdminListItem> });
        setOverview(null);
      }
      setState("ready");
    } catch (reason) {
      setError(errorMessage(reason));
      setState("error");
    }
  }, [activeTab, filter, page, resourceFilter, search, tabs]);

  useEffect(() => {
    void load();
  }, [load]);

  const selectTab = (tab: AdminTab) => {
    setActiveTab(tab);
    setPage(1);
    setSearchInput("");
    setSearch("");
    setFilter("");
    setResourceFilter("");
    setMutationError(null);
    setMutationNotice(null);
  };

  const submitSearch = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPage(1);
    setSearch(searchInput.trim());
  };

  const runMutation = async (resource: string, work: () => Promise<void>) => {
    setBusyResource(resource);
    setMutationError(null);
    setMutationNotice(null);
    try {
      await work();
      await load();
    } catch (reason) {
      setMutationError(errorMessage(reason));
    } finally {
      setBusyResource(null);
    }
  };

  const createOrganization = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const name = organizationNameInput.trim();
    if (name.length < 2 || busyResource) return;
    await runMutation("organization-create", async () => {
      const result = await api.createOrganization({
        name,
        ...(organizationSlugInput.trim() ? { slug: organizationSlugInput.trim() } : {}),
      });
      setOrganizationNameInput("");
      setOrganizationSlugInput("");
      if (result.joinCode) {
        setOneTimeCode({ organization: result.organization.name, code: result.joinCode });
        setCopyState("idle");
      } else {
        setMutationNotice("조직은 생성되었지만 가입 코드는 이미 한 번 반환되어 다시 표시할 수 없습니다.");
      }
    });
  };

  const rotateJoinCode = async (organization: AdminOrganization) => {
    const confirmed = window.confirm(
      `${organization.name} 조직의 기존 가입 코드를 즉시 폐기하고 새 코드를 발급할까요?`,
    );
    if (!confirmed) return;
    await runMutation(`organization-${organization.id}`, async () => {
      const result = await api.rotateOrganizationJoinCode(organization.id);
      if (result.joinCode) {
        setOneTimeCode({ organization: result.organization.name, code: result.joinCode });
        setCopyState("idle");
      } else {
        setMutationNotice("가입 코드는 이미 한 번 반환되어 다시 표시할 수 없습니다. 필요하면 다시 회전하세요.");
      }
    });
  };

  const quarantineLab = async (lab: AdminLab) => {
    const reason = window.prompt(
      `${lab.title} Lab을 격리합니다. 감사 로그에 남길 사유를 입력하세요. 취소하면 작업하지 않습니다.`,
      "관리자 정책 검토에 따른 격리",
    );
    if (reason === null) return;
    await runMutation(`lab-${lab.id}`, async () => {
      await api.quarantineLab(lab.id, reason);
      setMutationNotice(`${lab.title} Lab을 격리했습니다. 이후 배포는 차단됩니다.`);
    });
  };

  const releaseLab = async (lab: AdminLab) => {
    const reason = window.prompt(
      `${lab.title} Lab의 격리를 해제합니다. 격리 이전 상태는 보관되지 않으므로 초안으로 복구되며, 배포하려면 검증을 다시 통과해야 합니다. 사유를 입력하세요.`,
      "오탐 확인에 따른 격리 해제",
    );
    if (reason === null) return;
    await runMutation(`lab-${lab.id}`, async () => {
      await api.releaseLab(lab.id, reason);
      setMutationNotice(`${lab.title} Lab의 격리를 해제했습니다. 초안 상태이므로 재검증이 필요합니다.`);
    });
  };

  const terminateRun = async (run: AdminRun) => {
    const reason = window.prompt(
      `${run.id} 실행 환경을 종료합니다. 학습자의 연결이 즉시 끊깁니다. 사유를 입력하거나 취소하세요.`,
      "관리자 요청에 따른 실행 종료",
    );
    if (reason === null) return;
    await runMutation(`run-${run.id}`, async () => {
      await api.terminateRun(run.id, reason);
      setMutationNotice(`${run.id} 실행 환경을 종료했습니다.`);
    });
  };

  const changePlatformRole = async (user: AdminUser) => {
    const promote = user.platformRole !== "platform_admin";
    const reason = window.prompt(
      promote
        ? `@${user.handle} 계정을 플랫폼 관리자로 승격합니다. 전체 조직의 운영 데이터에 접근할 수 있게 됩니다. 감사 로그에 남길 사유를 입력하세요.`
        : `@${user.handle} 계정의 플랫폼 관리자 권한을 회수합니다. 감사 로그에 남길 사유를 입력하세요.`,
      promote ? "운영 인수인계에 따른 승격" : "권한 정리에 따른 강등",
    );
    if (reason === null) return;
    await runMutation(`user-${user.id}`, async () => {
      await api.setUserPlatformRole(
        user.id,
        promote ? "platform_admin" : "user",
        reason,
      );
      setMutationNotice(
        promote
          ? `@${user.handle} 계정을 플랫폼 관리자로 승격했습니다.${
              authMode === "oidc"
                ? " OIDC 모드에서는 Keycloak에서 platform_admin 역할도 함께 부여해야 실제로 적용됩니다."
                : ""
            }`
          : `@${user.handle} 계정의 플랫폼 관리자 권한을 회수했습니다.`,
      );
    });
  };

  const changeSuspension = async (user: AdminUser) => {
    const suspend = !user.disabledAt;
    const reason = window.prompt(
      suspend
        ? `@${user.handle} 계정을 정지합니다. 진행 중인 세션이 즉시 차단되고 다시 로그인할 수 없습니다. 사유를 입력하세요.`
        : `@${user.handle} 계정의 정지를 해제합니다. 사유를 입력하세요.`,
      suspend ? "보안 정책 위반에 따른 계정 정지" : "소명 확인에 따른 정지 해제",
    );
    if (reason === null) return;
    await runMutation(`user-${user.id}`, async () => {
      await api.setUserSuspension(user.id, suspend, reason);
      setMutationNotice(
        suspend
          ? `@${user.handle} 계정을 정지했습니다.`
          : `@${user.handle} 계정의 정지를 해제했습니다.`,
      );
    });
  };

  const changeMemberRole = async (member: OrganizationMember) => {
    const promote = member.organizationRole !== "org_admin";
    const reason = window.prompt(
      promote
        ? `@${member.handle} 구성원에게 조직 관리자 권한을 부여합니다. 사유를 입력하세요.`
        : `@${member.handle} 구성원의 조직 관리자 권한을 회수합니다. 사유를 입력하세요.`,
      promote ? "조직 운영 담당자 지정" : "담당자 변경에 따른 권한 회수",
    );
    if (reason === null) return;
    await runMutation(`member-${member.id}`, async () => {
      await api.setOrganizationMemberRole(
        member.id,
        promote ? "org_admin" : "member",
        reason,
      );
      setMutationNotice(
        promote
          ? `@${member.handle} 구성원을 조직 관리자로 지정했습니다.${
              authMode === "oidc"
                ? " OIDC 모드에서는 Keycloak에서 org_admin 역할도 함께 부여해야 실제로 적용됩니다."
                : ""
            }`
          : `@${member.handle} 구성원의 조직 관리자 권한을 회수했습니다.`,
      );
    });
  };

  const removeMember = async (member: OrganizationMember) => {
    const reason = window.prompt(
      `@${member.handle} 구성원을 조직에서 제거합니다. 계정은 유지되지만 개인 사용자로 전환되며 조직 데이터에 접근할 수 없게 됩니다. 사유를 입력하세요.`,
      "퇴사 처리에 따른 조직 제외",
    );
    if (reason === null) return;
    await runMutation(`member-${member.id}`, async () => {
      await api.removeOrganizationMember(member.id, reason);
      setMutationNotice(`@${member.handle} 구성원을 조직에서 제거했습니다.`);
    });
  };

  const copyOneTimeCode = async () => {
    if (!oneTimeCode) return;
    try {
      await navigator.clipboard.writeText(oneTimeCode.code);
      setCopyState("copied");
    } catch {
      setCopyState("error");
    }
  };

  if (!platformAdmin && !organizationAdmin) {
    return (
      <section className="panel permission-panel">
        <div className="admin-state admin-state--empty">
          <span aria-hidden="true">◇</span>
          <div><strong>관리자 권한이 필요합니다</strong><small>운영 콘솔은 플랫폼 관리자 또는 단일 조직의 조직 관리자에게만 공개됩니다.</small></div>
        </div>
      </section>
    );
  }

  return (
    <>
      <section className="hero-row hero-row--compact">
        <div>
          <div className="eyebrow">ROLE-AWARE OPERATIONS</div>
          <h1>관리자 콘솔</h1>
          <p>{platformAdmin ? "플랫폼 전체 운영 상태와 조직, Lab, 실행 환경을 권한 범위 안에서 관리합니다." : `${organizationName || "소속 조직"} 구성원의 가입과 활동 현황을 확인합니다.`}</p>
        </div>
        <span className="auth-mode-badge">{platformAdmin ? "PLATFORM ADMIN" : "ORGANIZATION ADMIN"}</span>
      </section>

      <nav className="admin-tabs" aria-label="관리자 기능">
        {tabs.map((tab) => (
          <button key={tab} type="button" className={activeTab === tab ? "is-active" : ""} aria-current={activeTab === tab ? "page" : undefined} onClick={() => selectTab(tab)}>{TAB_LABELS[tab]}</button>
        ))}
      </nav>

      {oneTimeCode && (
        <section className="one-time-code" role="status" aria-labelledby="one-time-code-title">
          <div>
            <span className="panel-kicker">ONE-TIME JOIN CODE</span>
            <h2 id="one-time-code-title">{oneTimeCode.organization} 가입 코드</h2>
            <p>이 코드는 지금 한 번만 표시됩니다. 닫기 전에 안전한 채널로 전달하거나 보관하세요. 플랫폼에서는 평문 코드를 다시 조회할 수 없습니다.</p>
          </div>
          <code>{oneTimeCode.code}</code>
          <div className="one-time-code__actions">
            <button className="primary-button" type="button" onClick={() => void copyOneTimeCode()}>{copyState === "copied" ? "복사 완료" : "코드 복사"}</button>
            <button className="secondary-button" type="button" onClick={() => { setOneTimeCode(null); setCopyState("idle"); }}>확인 후 지우기</button>
          </div>
          {copyState === "error" && <small role="alert">자동 복사에 실패했습니다. 표시된 코드를 직접 복사하세요.</small>}
        </section>
      )}

      {mutationError && <div className="alert alert--error page-alert" role="alert"><strong>관리 작업을 완료하지 못했습니다.</strong><span>{mutationError}</span></div>}
      {mutationNotice && <div className="alert alert--info page-alert" role="status"><strong>관리 작업이 반영되었습니다.</strong><span>{mutationNotice}</span></div>}

      {activeTab === "organizations" && platformAdmin && (
        <section className="panel admin-create-panel" aria-labelledby="organization-create-title">
          <div><span className="panel-kicker">ORGANIZATION PROVISIONING</span><h2 id="organization-create-title">새 조직 생성</h2><p>가입 코드는 서버가 생성하며 해시만 저장됩니다.</p></div>
          <form onSubmit={(event) => void createOrganization(event)}>
            <label><span>조직 이름</span><input value={organizationNameInput} onChange={(event) => setOrganizationNameInput(event.target.value)} minLength={2} maxLength={120} placeholder="보안 대응팀" required /></label>
            <label><span>Slug (선택)</span><input value={organizationSlugInput} onChange={(event) => setOrganizationSlugInput(event.target.value.toLowerCase())} pattern="[a-z0-9]+(?:-[a-z0-9]+)*" maxLength={63} placeholder="security-response" /></label>
            <button className="primary-button" type="submit" disabled={organizationNameInput.trim().length < 2 || busyResource === "organization-create"}>{busyResource === "organization-create" ? "생성 중" : "조직 생성"}</button>
          </form>
        </section>
      )}

      {activeTab === "overview" ? (
        state === "loading" || state === "idle" ? <section className="panel"><ListLoading /></section> : state === "error" ? (
          <section className="panel"><div className="admin-state admin-state--empty"><span aria-hidden="true">!</span><div><strong>운영 개요를 불러오지 못했습니다</strong><small>{error}</small><button className="secondary-button" type="button" onClick={() => void load()}>다시 시도</button></div></div></section>
        ) : overview ? (
          <>
            <section className="metric-grid metric-grid--four" aria-label="플랫폼 운영 개요">
              <Metric label="전체 사용자" value={overview.users} note="온보딩된 계정" />
              <Metric label="등록 조직" value={overview.organizations} note="단일 소속 조직" />
              <Metric label="전체 Lab" value={overview.labs} note={`격리 ${overview.quarantinedLabs.toLocaleString("ko-KR")}개`} />
              <Metric label="활성 실행" value={overview.activeRuns} note={`실패 ${overview.failedRuns.toLocaleString("ko-KR")}개`} />
            </section>
            <section className="panel admin-overview-detail">
              <div><span>누적 실행 환경</span><strong>{overview.runs.toLocaleString("ko-KR")}</strong></div>
              <div><span>채점 완료</span><strong>{overview.completedChallenges.toLocaleString("ko-KR")}</strong></div>
              <div><span>기준 시각</span><strong>{formatDate(overview.generatedAt)}</strong></div>
            </section>
          </>
        ) : <section className="panel"><ListEmpty label="운영" /></section>
      ) : (
        <section className="panel admin-data-panel">
          <div className="admin-toolbar">
            <form onSubmit={submitSearch} role="search">
              <label htmlFor="admin-search" className="sr-only">{TAB_LABELS[activeTab]} 검색</label>
              <input id="admin-search" type="search" value={searchInput} onChange={(event) => setSearchInput(event.target.value)} maxLength={100} placeholder={`${TAB_LABELS[activeTab]} 검색`} />
              <button className="secondary-button" type="submit">검색</button>
            </form>
            {activeTab !== "organizations" && (
              <label className="admin-filter"><span>필터</span><select value={filter} onChange={(event) => { setFilter(event.target.value); setPage(1); }}>
                <option value="">전체</option>
                {activeTab === "users" && <><option value="user">일반 사용자</option><option value="platform_admin">플랫폼 관리자</option></>}
                {activeTab === "labs" && <><option value="draft">초안</option><option value="validated">검증 완료</option><option value="quarantined">격리</option></>}
                {activeTab === "runs" && <><option value="provisioning">배포 중</option><option value="ready">준비 완료</option><option value="failed">실패</option><option value="stopped">종료</option><option value="expired">만료</option></>}
                {activeTab === "members" && <><option value="owner">소유자</option><option value="org_admin">조직 관리자</option><option value="member">구성원</option></>}
                {(activeTab === "audit" || activeTab === "orgAudit") && Object.entries(AUDIT_ACTION_LABELS).map(([action, label]) => <option key={action} value={action}>{label}</option>)}
              </select></label>
            )}
            {activeTab === "audit" && (
              <label className="admin-filter"><span>리소스</span><select value={resourceFilter} onChange={(event) => { setResourceFilter(event.target.value); setPage(1); }}>
                <option value="">전체</option>
                {Object.entries(AUDIT_RESOURCE_LABELS).map(([type, label]) => <option key={type} value={type}>{label}</option>)}
              </select></label>
            )}
            <button className="text-button" type="button" onClick={() => void load()} disabled={state === "loading"}>↻ 새로고침</button>
          </div>

          {state === "error" ? (
            <div className="admin-state admin-state--empty"><span aria-hidden="true">!</span><div><strong>목록을 불러오지 못했습니다</strong><small>{error}</small><button className="secondary-button" type="button" onClick={() => void load()}>다시 시도</button></div></div>
          ) : state === "loading" || state === "idle" || pageData?.tab !== activeTab ? <ListLoading /> : pageData.page.items.length === 0 ? <ListEmpty label={TAB_LABELS[activeTab]} /> : (
            <>
              <div className="table-scroll">{renderTable(activeTab, pageData.page.items, busyResource, { rotateJoinCode, quarantineLab, releaseLab, terminateRun, changePlatformRole, changeSuspension, changeMemberRole, removeMember }, { currentUserId, organizationOwner })}</div>
              <div className="admin-pagination">
                <span>전체 {pageData.page.pagination.total.toLocaleString("ko-KR")}개 · {pageData.page.pagination.page} / {Math.max(1, pageData.page.pagination.totalPages)} 페이지</span>
                <div><button className="secondary-button" type="button" disabled={pageData.page.pagination.page <= 1} onClick={() => setPage((current) => Math.max(1, current - 1))}>이전</button><button className="secondary-button" type="button" disabled={pageData.page.pagination.totalPages === 0 || pageData.page.pagination.page >= pageData.page.pagination.totalPages} onClick={() => setPage((current) => current + 1)}>다음</button></div>
              </div>
            </>
          )}
        </section>
      )}
    </>
  );
}

function renderTable(
  tab: Exclude<AdminTab, "overview">,
  items: AdminListItem[],
  busyResource: string | null,
  actions: {
    rotateJoinCode(organization: AdminOrganization): Promise<void>;
    quarantineLab(lab: AdminLab): Promise<void>;
    releaseLab(lab: AdminLab): Promise<void>;
    terminateRun(run: AdminRun): Promise<void>;
    changePlatformRole(user: AdminUser): Promise<void>;
    changeSuspension(user: AdminUser): Promise<void>;
    changeMemberRole(member: OrganizationMember): Promise<void>;
    removeMember(member: OrganizationMember): Promise<void>;
  },
  viewer: { currentUserId?: string | null; organizationOwner: boolean },
) {
  if (tab === "users") {
    const users = items as AdminUser[];
    return <table className="data-table"><thead><tr><th>사용자</th><th>플랫폼 역할</th><th>상태</th><th>조직</th><th>조직 역할</th><th>랭킹 공개</th><th>가입일</th><th><span className="sr-only">작업</span></th></tr></thead><tbody>{users.map((user) => {
      const self = Boolean(viewer.currentUserId) && user.id === viewer.currentUserId;
      const busy = busyResource === `user-${user.id}`;
      return <tr key={user.id}><td><strong>{user.displayName}</strong><small>@{user.handle}</small></td><td>{user.platformRole === "platform_admin" ? "플랫폼 관리자" : "사용자"}</td><td>{user.disabledAt ? <span className="status-pill status-pill--danger" title={user.disabledReason || undefined}>정지</span> : <span className="status-pill status-pill--pass">활성</span>}</td><td>{user.organization?.name || "개인"}</td><td>{user.organization?.role || "—"}</td><td>{user.globalRankingOptIn ? "동의" : "비공개"}</td><td>{formatDate(user.createdAt)}</td><td>{self ? <small>본인 계정</small> : <div className="table-action-group"><button className="table-action" type="button" disabled={busy} onClick={() => void actions.changePlatformRole(user)}>{user.platformRole === "platform_admin" ? "관리자 해제" : "관리자 승격"}</button><button className={user.disabledAt ? "table-action" : "table-action table-action--danger"} type="button" disabled={busy} onClick={() => void actions.changeSuspension(user)}>{user.disabledAt ? "정지 해제" : "계정 정지"}</button></div>}</td></tr>;
    })}</tbody></table>;
  }
  if (tab === "organizations") {
    const organizations = items as AdminOrganization[];
    return <table className="data-table"><thead><tr><th>조직</th><th>구성원</th><th>Lab</th><th>코드 회전 시각</th><th>가입일</th><th><span className="sr-only">작업</span></th></tr></thead><tbody>{organizations.map((organization) => <tr key={organization.id}><td><strong>{organization.name}</strong><small>{organization.slug}</small></td><td className="number-cell">{organization.memberCount}</td><td className="number-cell">{organization.labCount}</td><td>{formatDate(organization.joinCodeRotatedAt)}</td><td>{formatDate(organization.createdAt)}</td><td><button className="table-action" type="button" disabled={busyResource === `organization-${organization.id}`} onClick={() => void actions.rotateJoinCode(organization)}>{busyResource === `organization-${organization.id}` ? "회전 중" : "가입 코드 회전"}</button></td></tr>)}</tbody></table>;
  }
  if (tab === "labs") {
    const labs = items as AdminLab[];
    return <table className="data-table"><thead><tr><th>Lab</th><th>팀</th><th>상태</th><th>소유자</th><th>조직</th><th>생성일</th><th><span className="sr-only">작업</span></th></tr></thead><tbody>{labs.map((lab) => <tr key={lab.id}><td><strong>{lab.title}</strong><small>{lab.id}</small></td><td>{lab.team === "blue" ? "블루팀" : "레드팀"}</td><td><span className={`status-pill ${lab.validationStatus === "validated" ? "status-pill--pass" : lab.validationStatus === "quarantined" ? "status-pill--danger" : "status-pill--neutral"}`}>{lab.validationStatus}</span></td><td>{lab.ownerHandle ? `@${lab.ownerHandle}` : "—"}</td><td>{lab.organizationName || "개인"}</td><td>{formatDate(lab.createdAt)}</td><td>{lab.validationStatus === "quarantined" ? <div className="table-action-group"><button className="table-action" type="button" disabled={busyResource === `lab-${lab.id}`} onClick={() => void actions.releaseLab(lab)}>{busyResource === `lab-${lab.id}` ? "해제 중" : "격리 해제"}</button>{lab.quarantineReason && <small>{lab.quarantineReason}</small>}</div> : <button className="table-action table-action--danger" type="button" disabled={busyResource === `lab-${lab.id}`} onClick={() => void actions.quarantineLab(lab)}>{busyResource === `lab-${lab.id}` ? "격리 중" : "격리"}</button>}</td></tr>)}</tbody></table>;
  }
  if (tab === "runs") {
    const runs = items as AdminRun[];
    return <table className="data-table"><thead><tr><th>실행 환경</th><th>Lab</th><th>사용자</th><th>상태</th><th>접속 방식</th><th>만료</th><th><span className="sr-only">작업</span></th></tr></thead><tbody>{runs.map((run) => <tr key={run.id}><td><strong>{run.id}</strong><small>{run.environment || "환경 미상"}</small></td><td>{run.labTitle}</td><td>{run.userHandle ? `@${run.userHandle}` : "—"}</td><td><span className={`run-status run-status--${run.status}`}><i aria-hidden="true" />{run.status}</span></td><td>{run.accessMethod}</td><td>{formatDate(run.expiresAt)}</td><td>{["stopped", "expired"].includes(run.status) ? <small>종료됨</small> : <button className="table-action table-action--danger" type="button" disabled={busyResource === `run-${run.id}`} onClick={() => void actions.terminateRun(run)}>{busyResource === `run-${run.id}` ? "종료 중" : "강제 종료"}</button>}</td></tr>)}</tbody></table>;
  }
  if (tab === "audit" || tab === "orgAudit") {
    const logs = items as AdminAuditLog[];
    return <table className="data-table data-table--audit"><thead><tr><th>시각</th><th>행위자</th><th>출처 IP</th><th>액션</th><th>대상</th><th>세부 정보</th></tr></thead><tbody>{logs.map((log) => {
      const entries = Object.entries(log.metadata ?? {});
      return <tr key={log.id}><td className="audit-time">{formatDate(log.createdAt)}</td><td>{!log.actor ? <small>시스템</small> : log.actor.handle ? <><strong>{log.actor.displayName || log.actor.handle}</strong><small>@{log.actor.handle}</small></> : <><strong>삭제된 계정</strong><small>{log.actor.id}</small></>}</td><td className="audit-ip">{log.actorIp || <small>—</small>}</td><td><strong>{AUDIT_ACTION_LABELS[log.action] || log.action}</strong><small>{log.action}</small></td><td>{AUDIT_RESOURCE_LABELS[log.resourceType] || log.resourceType}<small>{log.resourceId}</small></td><td>{entries.length === 0 ? <small>—</small> : <dl className="audit-metadata">{entries.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{typeof value === "string" ? value : JSON.stringify(value)}</dd></div>)}</dl>}</td></tr>;
    })}</tbody></table>;
  }
  const members = items as OrganizationMember[];
  return <table className="data-table"><thead><tr><th>구성원</th><th>조직 역할</th><th>플랫폼 역할</th><th>가입일</th><th><span className="sr-only">작업</span></th></tr></thead><tbody>{members.map((member) => {
    const self = Boolean(viewer.currentUserId) && member.id === viewer.currentUserId;
    const owner = member.organizationRole === "owner";
    const admin = member.organizationRole === "org_admin";
    // Revoking org_admin is owner-only; the server enforces this too.
    const manageable = !self && !owner && (!admin || viewer.organizationOwner);
    const busy = busyResource === `member-${member.id}`;
    return <tr key={member.id}><td><strong>{member.displayName}</strong><small>@{member.handle}</small></td><td>{owner ? "소유자" : admin ? "조직 관리자" : "구성원"}</td><td>{member.platformRole === "platform_admin" ? "플랫폼 관리자" : "사용자"}</td><td>{formatDate(member.joinedAt)}</td><td>{self ? <small>본인 계정</small> : owner ? <small>소유자</small> : !manageable ? <small>소유자만 변경 가능</small> : <div className="table-action-group"><button className="table-action" type="button" disabled={busy} onClick={() => void actions.changeMemberRole(member)}>{admin ? "관리자 해제" : "관리자 지정"}</button><button className="table-action table-action--danger" type="button" disabled={busy} onClick={() => void actions.removeMember(member)}>조직에서 제거</button></div>}</td></tr>;
  })}</tbody></table>;
}

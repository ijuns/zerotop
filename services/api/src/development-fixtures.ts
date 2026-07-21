import { hashPassword } from "./security.ts";

import { DEV_USER_ID, SECURITY_LAB_ORG_ID } from "./types.ts";

export const DEVELOPMENT_FIXTURE_CREATED_AT = "2026-01-01T00:00:00.000Z";
export const DEVELOPMENT_FIXTURE_PASSWORD = "ZeroTOP!2026";

/**
 * Every seed account shares one password, and scrypt is deliberately slow, so
 * the digest is computed once per process instead of once per fixture row.
 * Sharing a hash across synthetic accounts reveals nothing a shared plaintext
 * does not already reveal.
 */
let cachedFixturePasswordHash: string | null | undefined;
export function developmentFixturePasswordHash(): string | null {
  if (cachedFixturePasswordHash === undefined) {
    cachedFixturePasswordHash = hashPassword(DEVELOPMENT_FIXTURE_PASSWORD);
  }
  return cachedFixturePasswordHash;
}
/**
 * Seed accounts are synthetic, so recording their consent fabricates nothing
 * about a real person. It keeps the sample data usable behind the consent gate
 * that real pre-existing accounts have to pass.
 */
export const DEVELOPMENT_FIXTURE_AFFILIATION = "ZeroTOP 개발 샘플";

export interface DevelopmentOrganizationFixture {
  id: string;
  name: string;
  slug: string;
  joinCode: string;
}

export interface DevelopmentUserFixture {
  id: string;
  email: string;
  handle: string;
  displayName: string;
  platformRole: "user" | "platform_admin";
  globalRankingOptIn: boolean;
  organizationId: string | null;
  organizationRole: "owner" | "org_admin" | "member" | null;
}

export interface DevelopmentCapabilityLabFixture {
  id: string;
  ownerUserId: string;
  organizationId: string | null;
  name: string;
  description: string;
  teamType: "blue" | "red";
  questionTypes: readonly string[];
  environment: "ubuntu" | "kali";
}

export interface DevelopmentCapabilityAttemptFixture {
  id: string;
  runId: string;
  labId: string;
  userId: string;
  score: number;
  maxScore: number;
  skills: Record<
    string,
    { label: string; points: number; maxPoints: number }
  >;
  completedAt: string;
  runCreatedAt: string;
  runExpiresAt: string;
}

export const DEVELOPMENT_ORGANIZATIONS = [
  {
    id: SECURITY_LAB_ORG_ID,
    name: "Security Lab",
    slug: "security-lab",
    joinCode: "SECURITY-LAB",
  },
  {
    id: "org_hanbit_finance",
    name: "한빛금융 보안대응팀",
    slug: "hanbit-finance-security",
    joinCode: "HANBIT-2026",
  },
  {
    id: "org_neocloud_soc",
    name: "네오클라우드 SOC",
    slug: "neocloud-soc",
    joinCode: "NEOCLOUD-2026",
  },
  {
    id: "org_cyber_academy",
    name: "사이버보안 아카데미",
    slug: "cyber-security-academy",
    joinCode: "ACADEMY-2026",
  },
] as const satisfies readonly DevelopmentOrganizationFixture[];

export const DEVELOPMENT_USERS = [
  {
    id: DEV_USER_ID,
    email: "admin@zerotop.local",
    handle: "zerotop_admin",
    displayName: "ZeroTOP 관리자",
    platformRole: "platform_admin",
    globalRankingOptIn: true,
    organizationId: SECURITY_LAB_ORG_ID,
    organizationRole: "owner",
  },
  {
    id: "user_zerotop_org_admin",
    email: "org-admin@zerotop.local",
    handle: "zerotop_org_admin",
    displayName: "김서준",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: SECURITY_LAB_ORG_ID,
    organizationRole: "org_admin",
  },
  {
    id: "user_zerotop_red",
    email: "red@zerotop.local",
    handle: "zerotop_red",
    displayName: "박도윤",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: SECURITY_LAB_ORG_ID,
    organizationRole: "member",
  },
  {
    id: "user_zerotop_blue",
    email: "blue@zerotop.local",
    handle: "zerotop_blue",
    displayName: "이하린",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: SECURITY_LAB_ORG_ID,
    organizationRole: "member",
  },
  {
    id: "user_hanbit_owner",
    email: "ciso@hanbit.zerotop.local",
    handle: "hanbit_ciso",
    displayName: "최민준",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: "org_hanbit_finance",
    organizationRole: "owner",
  },
  {
    id: "user_hanbit_admin",
    email: "soc-admin@hanbit.zerotop.local",
    handle: "hanbit_soc_admin",
    displayName: "정유나",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: "org_hanbit_finance",
    organizationRole: "org_admin",
  },
  {
    id: "user_hanbit_analyst_01",
    email: "analyst1@hanbit.zerotop.local",
    handle: "hanbit_analyst1",
    displayName: "오지훈",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: "org_hanbit_finance",
    organizationRole: "member",
  },
  {
    id: "user_hanbit_analyst_02",
    email: "analyst2@hanbit.zerotop.local",
    handle: "hanbit_analyst2",
    displayName: "윤채원",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: "org_hanbit_finance",
    organizationRole: "member",
  },
  {
    id: "user_neocloud_owner",
    email: "lead@neocloud.zerotop.local",
    handle: "neocloud_lead",
    displayName: "강현우",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: "org_neocloud_soc",
    organizationRole: "owner",
  },
  {
    id: "user_neocloud_admin",
    email: "admin@neocloud.zerotop.local",
    handle: "neocloud_admin",
    displayName: "한서아",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: "org_neocloud_soc",
    organizationRole: "org_admin",
  },
  {
    id: "user_neocloud_member",
    email: "analyst@neocloud.zerotop.local",
    handle: "neocloud_analyst",
    displayName: "임태영",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: "org_neocloud_soc",
    organizationRole: "member",
  },
  {
    id: "user_academy_owner",
    email: "director@academy.zerotop.local",
    handle: "academy_director",
    displayName: "송지아",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: "org_cyber_academy",
    organizationRole: "owner",
  },
  {
    id: "user_academy_instructor",
    email: "instructor@academy.zerotop.local",
    handle: "academy_instructor",
    displayName: "배준호",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: "org_cyber_academy",
    organizationRole: "org_admin",
  },
  {
    id: "user_academy_student",
    email: "student@academy.zerotop.local",
    handle: "academy_student",
    displayName: "문가은",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: "org_cyber_academy",
    organizationRole: "member",
  },
  {
    id: "user_personal_red",
    email: "redlearner@personal.zerotop.local",
    handle: "red_pathfinder",
    displayName: "개인 사용자 · 레드팀",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: null,
    organizationRole: null,
  },
  {
    id: "user_personal_blue",
    email: "bluelearner@personal.zerotop.local",
    handle: "blue_observer",
    displayName: "개인 사용자 · 블루팀",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: null,
    organizationRole: null,
  },
  {
    id: "user_personal_researcher",
    email: "researcher@personal.zerotop.local",
    handle: "cve_researcher",
    displayName: "개인 사용자 · 연구원",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: null,
    organizationRole: null,
  },
  {
    id: "user_personal_student",
    email: "student@personal.zerotop.local",
    handle: "security_student",
    displayName: "개인 사용자 · 취업준비생",
    platformRole: "user",
    globalRankingOptIn: true,
    organizationId: null,
    organizationRole: null,
  },
] as const satisfies readonly DevelopmentUserFixture[];

const DEVELOPMENT_TRAINING_TEMPLATES = [
  {
    key: "web-cve",
    title: "공개 CVE 웹 침투",
    description: "공개된 N-day 취약점을 분석하고 웹 서비스의 공격 경로를 검증합니다.",
    teamType: "red",
    questionTypes: ["single_choice", "free_text", "mitre_attack"],
    environment: "kali",
    skills: [
      { key: "web_exploitation", label: "웹 취약점 공격", maxPoints: 55 },
      { key: "exploit_analysis", label: "PoC 분석", maxPoints: 45 },
    ],
  },
  {
    key: "elk-hunt",
    title: "ELK 위협 헌팅",
    description: "ELK에서 공격 흔적을 추적하고 MITRE ATT&CK 전술과 연결합니다.",
    teamType: "blue",
    questionTypes: ["elk_search", "mitre_attack"],
    environment: "ubuntu",
    skills: [
      { key: "log_analysis", label: "로그 분석", maxPoints: 60 },
      { key: "incident_response", label: "침해 대응", maxPoints: 40 },
    ],
  },
  {
    key: "privilege-escalation",
    title: "Linux 권한 상승 분석",
    description: "Linux 호스트의 권한 상승 경로를 식별하고 공격 흐름을 설명합니다.",
    teamType: "red",
    questionTypes: ["multiple_choice", "free_text", "mitre_attack"],
    environment: "kali",
    skills: [
      { key: "privilege_escalation", label: "권한 상승", maxPoints: 50 },
      { key: "mitre_attack", label: "MITRE ATT&CK", maxPoints: 50 },
    ],
  },
] as const;

/**
 * Builds realistic, deterministic-shape demo evidence around the seed time.
 * The explicit development seeder calls this function; normal repository
 * initialization does not, so API unit tests remain isolated from demo scores.
 */
export function buildDevelopmentCapabilityFixtures(
  seedTime = new Date(),
): {
  labs: DevelopmentCapabilityLabFixture[];
  attempts: DevelopmentCapabilityAttemptFixture[];
} {
  const anchor = Number.isFinite(seedTime.getTime()) ? seedTime : new Date();
  const organizationCohorts = DEVELOPMENT_ORGANIZATIONS.map((organization) => {
    const owner = DEVELOPMENT_USERS.find(
      (user) =>
        user.organizationId === organization.id && user.organizationRole === "owner",
    );
    if (!owner) throw new Error(`Development organization ${organization.id} has no owner.`);
    return {
      key: organization.id,
      name: organization.name,
      organizationId: organization.id,
      ownerUserId: owner.id,
    };
  });
  const personalCohorts = DEVELOPMENT_USERS.filter(
    (user) => user.organizationId === null,
  ).map((user) => ({
    key: user.id,
    name: user.displayName,
    organizationId: null,
    ownerUserId: user.id,
  }));
  const cohorts = [...organizationCohorts, ...personalCohorts];
  const safeKey = (value: string) => value.replace(/[^a-zA-Z0-9_-]/g, "_");

  const labs = cohorts.flatMap((cohort) =>
    DEVELOPMENT_TRAINING_TEMPLATES.map((template) => ({
      id: `lab_seed_${safeKey(cohort.key)}_${template.key}`,
      ownerUserId: cohort.ownerUserId,
      organizationId: cohort.organizationId,
      name: `${cohort.name} · ${template.title}`,
      description: template.description,
      teamType: template.teamType,
      questionTypes: template.questionTypes,
      environment: template.environment,
    })),
  );

  const cohortForUser = (user: DevelopmentUserFixture) =>
    user.organizationId ?? user.id;
  const scoreFor = (userIndex: number, attemptIndex: number): number => {
    if (attemptIndex === 0) return 62 + ((userIndex * 13) % 36);
    if (attemptIndex === 1) return 58 + ((userIndex * 17) % 40);
    return 55 + ((userIndex * 19) % 40);
  };
  const completedAtFor = (userIndex: number, attemptIndex: number): Date => {
    const dayOffset =
      attemptIndex < 2
        ? 1 + ((userIndex + attemptIndex * 2) % 5)
        : 9 + (userIndex % 4);
    return new Date(anchor.getTime() - dayOffset * 86_400_000 - attemptIndex * 3_600_000);
  };

  const attempts = DEVELOPMENT_USERS.flatMap((user, userIndex) =>
    DEVELOPMENT_TRAINING_TEMPLATES.map((template, attemptIndex) => {
      const score = scoreFor(userIndex, attemptIndex);
      const firstSkill = template.skills[0];
      const secondSkill = template.skills[1];
      const firstPoints = Math.round((score * firstSkill.maxPoints) / 100);
      const completedAt = completedAtFor(userIndex, attemptIndex);
      const fixtureKey = `${safeKey(user.id)}_${template.key}`;
      return {
        id: `result_seed_${fixtureKey}`,
        runId: `run_seed_${fixtureKey}`,
        labId: `lab_seed_${safeKey(cohortForUser(user))}_${template.key}`,
        userId: user.id,
        score,
        maxScore: 100,
        skills: {
          [firstSkill.key]: {
            label: firstSkill.label,
            points: firstPoints,
            maxPoints: firstSkill.maxPoints,
          },
          [secondSkill.key]: {
            label: secondSkill.label,
            points: score - firstPoints,
            maxPoints: secondSkill.maxPoints,
          },
        },
        completedAt: completedAt.toISOString(),
        runCreatedAt: new Date(completedAt.getTime() - 45 * 60_000).toISOString(),
        runExpiresAt: new Date(completedAt.getTime() + 15 * 60_000).toISOString(),
      };
    }),
  );

  return { labs, attempts };
}

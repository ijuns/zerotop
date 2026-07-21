import type {
  OrganizationCapabilityReport,
  PersonalCapabilityReport,
  PlatformCapabilityReport,
  RankingEntry,
  RankingPeriod,
  RankingResponse,
  SkillScore,
  Team,
} from "@codegate/contracts";

export interface CapabilityUser {
  id: string;
  handle: string;
  displayName: string;
  organizationId: string | null;
  globalRankingOptIn: boolean;
}

export interface CapabilityOrganization {
  id: string;
  name: string;
  slug: string;
}

export interface CapabilityEvidence {
  userId: string;
  organizationId: string | null;
  runId: string;
  labId: string;
  labTitle: string;
  team: Team;
  points: number;
  maxPoints: number;
  completedAt: string;
  skills: Record<string, { label: string; points: number; maxPoints: number }>;
}

export interface ReportingDataset {
  users: CapabilityUser[];
  organizations: CapabilityOrganization[];
  evidence: CapabilityEvidence[];
}

export interface ReportOptions {
  now?: Date;
  activeWithinDays?: number;
  trendWindowDays?: number;
}

export function personalReport(
  dataset: ReportingDataset,
  userId: string,
  options: ReportOptions = {},
): PersonalCapabilityReport {
  const now = options.now ?? new Date();
  const user = requireUser(dataset, userId);
  const evidence = validEvidence(dataset.evidence).filter((item) => item.userId === userId);
  const totals = scoreTotals(evidence);
  return {
    scope: "personal",
    user: { id: user.id, handle: user.handle, displayName: user.displayName },
    generatedAt: now.toISOString(),
    overallScore: totals.score,
    completedLabs: evidence.length,
    successRate: successRate(evidence),
    skills: skillScores(evidence, now, options.trendWindowDays ?? 30),
    recentRuns: [...evidence]
      .sort((a, b) => Date.parse(b.completedAt) - Date.parse(a.completedAt))
      .slice(0, 10)
      .map((item) => ({
        runId: item.runId,
        labId: item.labId,
        title: item.labTitle,
        team: item.team,
        score: percent(item.points, item.maxPoints),
        completedAt: item.completedAt,
      })),
  };
}

export function organizationReport(
  dataset: ReportingDataset,
  organizationId: string,
  options: ReportOptions = {},
): OrganizationCapabilityReport {
  const now = options.now ?? new Date();
  const organization = dataset.organizations.find((item) => item.id === organizationId);
  if (!organization) throw new Error("Organization not found");
  const users = dataset.users.filter((item) => item.organizationId === organizationId);
  const evidence = validEvidence(dataset.evidence).filter(
    (item) => item.organizationId === organizationId,
  );
  const activeThreshold = now.getTime() - (options.activeWithinDays ?? 30) * DAY_MS;
  const lastActive = latestCompletionByUser(evidence);
  return {
    scope: "organization",
    organization: {
      id: organization.id,
      name: organization.name,
      slug: organization.slug,
    },
    generatedAt: now.toISOString(),
    memberCount: users.length,
    activeMemberCount: users.filter(
      (user) => (lastActive.get(user.id)?.getTime() ?? 0) >= activeThreshold,
    ).length,
    overallScore: scoreTotals(evidence).score,
    skills: skillScores(evidence, now, options.trendWindowDays ?? 30),
    members: users
      .map((user) => {
        const memberEvidence = evidence.filter((item) => item.userId === user.id);
        return {
          userId: user.id,
          handle: user.handle,
          displayName: user.displayName,
          overallScore: scoreTotals(memberEvidence).score,
          completedLabs: memberEvidence.length,
          successRate: successRate(memberEvidence),
          lastActiveAt: lastActive.get(user.id)?.toISOString() ?? null,
          skills: skillScores(memberEvidence, now, options.trendWindowDays ?? 30),
        };
      })
      .sort((a, b) => b.overallScore - a.overallScore || a.handle.localeCompare(b.handle)),
  };
}

export function platformReport(
  dataset: ReportingDataset,
  options: ReportOptions = {},
): PlatformCapabilityReport {
  const now = options.now ?? new Date();
  const evidence = validEvidence(dataset.evidence);
  const activeThreshold = now.getTime() - (options.activeWithinDays ?? 30) * DAY_MS;
  const lastActive = latestCompletionByUser(evidence);
  return {
    scope: "platform",
    generatedAt: now.toISOString(),
    userCount: dataset.users.length,
    organizationCount: dataset.organizations.length,
    activeUserCount: dataset.users.filter(
      (user) => (lastActive.get(user.id)?.getTime() ?? 0) >= activeThreshold,
    ).length,
    overallScore: scoreTotals(evidence).score,
    skills: skillScores(evidence, now, options.trendWindowDays ?? 30),
    organizations: dataset.organizations
      .map((organization) => {
        const members = dataset.users.filter(
          (user) => user.organizationId === organization.id,
        );
        const organizationEvidence = evidence.filter(
          (item) => item.organizationId === organization.id,
        );
        return {
          organization: {
            id: organization.id,
            name: organization.name,
            slug: organization.slug,
          },
          memberCount: members.length,
          activeMemberCount: members.filter(
            (user) => (lastActive.get(user.id)?.getTime() ?? 0) >= activeThreshold,
          ).length,
          overallScore: scoreTotals(organizationEvidence).score,
        };
      })
      .sort(
        (a, b) =>
          b.overallScore - a.overallScore ||
          a.organization.name.localeCompare(b.organization.name),
      ),
  };
}

export function ranking(
  dataset: ReportingDataset,
  scope: "global" | "organization",
  period: RankingPeriod,
  options: { now?: Date; organizationId?: string; currentUserId?: string } = {},
): RankingResponse {
  const now = options.now ?? new Date();
  if (scope === "organization" && !options.organizationId) {
    throw new Error("organizationId is required for organization ranking");
  }
  const currentWindow = periodWindow(period, now, 0);
  const previousWindow = periodWindow(period, now, 1);
  const eligibleUsers = dataset.users.filter((user) =>
    scope === "global"
      ? user.globalRankingOptIn
      : user.organizationId === options.organizationId,
  );
  const current = rankWindow(dataset, eligibleUsers, currentWindow);
  const previous = rankWindow(dataset, eligibleUsers, previousWindow);
  const previousRank = new Map(previous.map((entry) => [entry.userId, entry.rank]));
  const entries = current.map((entry) => ({
    ...entry,
    change: previousRank.has(entry.userId)
      ? (previousRank.get(entry.userId) as number) - entry.rank
      : 0,
  }));
  return {
    scope,
    period,
    generatedAt: now.toISOString(),
    entries,
    ...(options.currentUserId
      ? { currentUser: entries.find((item) => item.userId === options.currentUserId) }
      : {}),
  };
}

function skillScores(
  evidence: CapabilityEvidence[],
  now: Date,
  windowDays: number,
): SkillScore[] {
  const currentStart = now.getTime() - windowDays * DAY_MS;
  const previousStart = currentStart - windowDays * DAY_MS;
  const keys = new Set(evidence.flatMap((item) => Object.keys(item.skills)));
  return [...keys]
    .map((key) => {
      const all = aggregateSkill(evidence, key);
      const current = aggregateSkill(
        evidence.filter((item) => Date.parse(item.completedAt) >= currentStart),
        key,
      );
      const previous = aggregateSkill(
        evidence.filter((item) => {
          const timestamp = Date.parse(item.completedAt);
          return timestamp >= previousStart && timestamp < currentStart;
        }),
        key,
      );
      return {
        key,
        label: all.label,
        score: all.score,
        evidenceCount: all.count,
        delta: current.count > 0 && previous.count > 0 ? current.score - previous.score : 0,
      };
    })
    .sort((a, b) => b.score - a.score || a.key.localeCompare(b.key));
}

function aggregateSkill(evidence: CapabilityEvidence[], key: string) {
  let points = 0;
  let maxPoints = 0;
  let count = 0;
  let label = key;
  for (const item of evidence) {
    const skill = item.skills[key];
    if (!skill || skill.maxPoints <= 0) continue;
    label = skill.label;
    points += skill.points;
    maxPoints += skill.maxPoints;
    count += 1;
  }
  return { label, score: percent(points, maxPoints), count };
}

function rankWindow(
  dataset: ReportingDataset,
  users: CapabilityUser[],
  window: { start: number; end: number },
): RankingEntry[] {
  const organizations = new Map(dataset.organizations.map((item) => [item.id, item]));
  const rows = users
    .map((user) => {
      const evidence = validEvidence(dataset.evidence).filter((item) => {
        const timestamp = Date.parse(item.completedAt);
        return item.userId === user.id && timestamp >= window.start && timestamp < window.end;
      });
      return {
        userId: user.id,
        handle: user.handle,
        organizationName: user.organizationId
          ? organizations.get(user.organizationId)?.name ?? null
          : null,
        points: evidence.reduce((total, item) => total + item.points, 0),
        completedLabs: evidence.length,
      };
    })
    .filter((item) => item.points > 0)
    .sort((a, b) => b.points - a.points || b.completedLabs - a.completedLabs || a.handle.localeCompare(b.handle));
  let rank = 0;
  let previousPoints: number | null = null;
  return rows.map((row, index) => {
    if (previousPoints !== row.points) rank = index + 1;
    previousPoints = row.points;
    return { rank, ...row, change: 0 };
  });
}

function periodWindow(period: RankingPeriod, now: Date, offset: number) {
  if (period === "all_time") {
    return offset === 0
      ? { start: 0, end: now.getTime() + 1 }
      : { start: 0, end: 0 };
  }
  const days = period === "weekly" ? 7 : 30;
  return {
    start: now.getTime() - days * (offset + 1) * DAY_MS,
    end: now.getTime() - days * offset * DAY_MS,
  };
}

function validEvidence(evidence: CapabilityEvidence[]): CapabilityEvidence[] {
  return evidence.filter(
    (item) =>
      item.maxPoints > 0 &&
      item.points >= 0 &&
      Number.isFinite(item.points) &&
      Number.isFinite(Date.parse(item.completedAt)),
  );
}

function scoreTotals(evidence: CapabilityEvidence[]) {
  const points = evidence.reduce((total, item) => total + item.points, 0);
  const maxPoints = evidence.reduce((total, item) => total + item.maxPoints, 0);
  return { points, maxPoints, score: percent(points, maxPoints) };
}

function successRate(evidence: CapabilityEvidence[]): number {
  if (evidence.length === 0) return 0;
  const successful = evidence.filter(
    (item) => percent(item.points, item.maxPoints) >= 70,
  ).length;
  return Math.round((successful / evidence.length) * 100);
}

function latestCompletionByUser(evidence: CapabilityEvidence[]): Map<string, Date> {
  const result = new Map<string, Date>();
  for (const item of evidence) {
    const completedAt = new Date(item.completedAt);
    const previous = result.get(item.userId);
    if (!previous || previous < completedAt) result.set(item.userId, completedAt);
  }
  return result;
}

function requireUser(dataset: ReportingDataset, userId: string): CapabilityUser {
  const user = dataset.users.find((item) => item.id === userId);
  if (!user) throw new Error("User not found");
  return user;
}

function percent(points: number, maxPoints: number): number {
  if (maxPoints <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((points / maxPoints) * 100)));
}

const DAY_MS = 86_400_000;

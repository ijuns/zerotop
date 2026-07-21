import { RANKING_DOMAINS } from "@codegate/contracts";
import type {
  OrganizationRankingEntry,
  RankingDomain,
  RankingSeason,
  RankingViewerSummary,
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
  /** Cross-organization ranking is opt-in; see migration 014. */
  rankingOptIn?: boolean;
  memberCount?: number;
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
  options: {
    now?: Date;
    organizationId?: string;
    currentUserId?: string;
    season?: RankingSeason | null;
    domain?: RankingDomain | null;
  } = {},
): RankingResponse {
  const now = options.now ?? new Date();
  if (scope === "organization" && !options.organizationId) {
    throw new Error("organizationId is required for organization ranking");
  }
  const season = options.season ?? null;
  const domain = options.domain ?? null;
  // A season, when one is running, replaces the rolling period: the board is
  // "this season" rather than "the last 7 days".
  const currentWindow = season
    ? { start: Date.parse(season.startsAt), end: Date.parse(season.endsAt) }
    : periodWindow(period, now, 0);
  const previousWindow = season
    ? shiftWindow(currentWindow)
    : periodWindow(period, now, 1);

  const eligibleUsers = dataset.users.filter((user) =>
    scope === "global"
      ? user.globalRankingOptIn
      : user.organizationId === options.organizationId,
  );
  const current = rankWindow(dataset, eligibleUsers, currentWindow, domain);
  const previous = rankWindow(dataset, eligibleUsers, previousWindow, domain);
  const previousRank = new Map(previous.map((entry) => [entry.userId, entry.rank]));
  const entries = current.map((entry) => ({
    ...entry,
    change: previousRank.has(entry.userId)
      ? (previousRank.get(entry.userId) as number) - entry.rank
      : 0,
  }));

  const organizations = rankOrganizations(
    dataset,
    currentWindow,
    previousWindow,
    domain,
  );
  const currentUser = options.currentUserId
    ? entries.find((item) => item.userId === options.currentUserId)
    : undefined;
  const currentOrganization = options.organizationId
    ? organizations.find((item) => item.organizationId === options.organizationId)
    : undefined;

  return {
    scope,
    period,
    generatedAt: now.toISOString(),
    season,
    domain,
    entries,
    organizations,
    viewer: viewerSummary(
      dataset,
      options.currentUserId,
      currentWindow,
      previousWindow,
      domain,
      entries,
    ),
    ...(currentUser ? { currentUser } : {}),
    ...(currentOrganization ? { currentOrganization } : {}),
  };
}

/** Skill keys that count towards a domain filter. */
function domainSkills(domain: RankingDomain | null): Set<string> | null {
  if (!domain) return null;
  const found = RANKING_DOMAINS.find((item) => item.key === domain);
  return found ? new Set<string>(found.skills) : null;
}

/** Points a piece of evidence contributes once a domain filter is applied. */
function evidencePoints(
  item: CapabilityEvidence,
  skills: Set<string> | null,
): { points: number; maxPoints: number } {
  if (!skills) return { points: item.points, maxPoints: item.maxPoints };
  let points = 0;
  let maxPoints = 0;
  for (const [key, skill] of Object.entries(item.skills)) {
    if (!skills.has(key) || skill.maxPoints <= 0) continue;
    points += skill.points;
    maxPoints += skill.maxPoints;
  }
  return { points, maxPoints };
}

/** The domain a user scored highest in, used as their headline speciality. */
function primaryDomainOf(
  evidence: CapabilityEvidence[],
): { key: RankingDomain; label: string } | null {
  let best: { key: RankingDomain; label: string; points: number } | null = null;
  for (const domain of RANKING_DOMAINS) {
    const skills = new Set<string>(domain.skills);
    let points = 0;
    for (const item of evidence) {
      points += evidencePoints(item, skills).points;
    }
    if (points > 0 && (!best || points > best.points)) {
      best = { key: domain.key, label: domain.label, points };
    }
  }
  return best ? { key: best.key, label: best.label } : null;
}

/** Longest run of consecutive UTC days present in the timestamps. */
function longestStreak(timestamps: string[]): number {
  const days = [
    ...new Set(timestamps.map((value) => Math.floor(Date.parse(value) / DAY_MS))),
  ].sort((a, b) => a - b);
  let best = 0;
  let run = 0;
  let previous: number | null = null;
  for (const day of days) {
    run = previous !== null && day === previous + 1 ? run + 1 : 1;
    previous = day;
    if (run > best) best = run;
  }
  return best;
}

/** Streak counted backwards from today; 0 once a day is missed. */
function currentStreak(timestamps: string[], now: Date): number {
  const days = new Set(
    timestamps.map((value) => Math.floor(Date.parse(value) / DAY_MS)),
  );
  let cursor = Math.floor(now.getTime() / DAY_MS);
  // Today may not have activity yet, so an unbroken streak can end yesterday.
  if (!days.has(cursor)) cursor -= 1;
  let streak = 0;
  while (days.has(cursor)) {
    streak += 1;
    cursor -= 1;
  }
  return streak;
}

function viewerSummary(
  dataset: ReportingDataset,
  userId: string | undefined,
  current: { start: number; end: number },
  previous: { start: number; end: number },
  domain: RankingDomain | null,
  entries: RankingEntry[],
): RankingViewerSummary {
  const totalParticipants = entries.length;
  const empty: RankingViewerSummary = {
    rank: null,
    totalParticipants,
    topPercent: null,
    points: 0,
    pointsDelta: 0,
    completedLabs: 0,
    accuracy: 0,
    streakDays: 0,
    bestStreakDays: 0,
  };
  if (!userId) return empty;

  const skills = domainSkills(domain);
  const mine = validEvidence(dataset.evidence).filter(
    (item) => item.userId === userId,
  );
  const inWindow = (window: { start: number; end: number }) =>
    mine.filter((item) => {
      const timestamp = Date.parse(item.completedAt);
      return timestamp >= window.start && timestamp < window.end;
    });

  const currentEvidence = inWindow(current);
  let points = 0;
  let maxPoints = 0;
  for (const item of currentEvidence) {
    const scored = evidencePoints(item, skills);
    points += scored.points;
    maxPoints += scored.maxPoints;
  }
  const previousPoints = inWindow(previous).reduce(
    (total, item) => total + evidencePoints(item, skills).points,
    0,
  );
  const rank = entries.find((item) => item.userId === userId)?.rank ?? null;

  return {
    rank,
    totalParticipants,
    topPercent:
      rank !== null && totalParticipants > 0
        ? Math.max(0.1, Math.round((rank / totalParticipants) * 1000) / 10)
        : null,
    points,
    pointsDelta: points - previousPoints,
    completedLabs: currentEvidence.length,
    accuracy: percent(points, maxPoints),
    streakDays: currentStreak(
      mine.map((item) => item.completedAt),
      new Date(Math.min(current.end, Date.now())),
    ),
    bestStreakDays: longestStreak(mine.map((item) => item.completedAt)),
  };
}

/**
 * Ranks organizations against each other. Only organizations that opted in are
 * listed: headcount and readiness would otherwise be visible to competitors.
 */
function rankOrganizations(
  dataset: ReportingDataset,
  current: { start: number; end: number },
  previous: { start: number; end: number },
  domain: RankingDomain | null,
): OrganizationRankingEntry[] {
  const score = (window: { start: number; end: number }) => {
    const skills = domainSkills(domain);
    const evidence = validEvidence(dataset.evidence).filter((item) => {
      const timestamp = Date.parse(item.completedAt);
      return timestamp >= window.start && timestamp < window.end;
    });
    return dataset.organizations
      .filter((organization) => organization.rankingOptIn)
      .map((organization) => {
        const members = dataset.users.filter(
          (user) => user.organizationId === organization.id,
        );
        const memberCount = organization.memberCount ?? members.length;
        const mine = evidence.filter(
          (item) => item.organizationId === organization.id,
        );
        let points = 0;
        let maxPoints = 0;
        for (const item of mine) {
          const scored = evidencePoints(item, skills);
          points += scored.points;
          maxPoints += scored.maxPoints;
        }
        const active = new Set(mine.map((item) => item.userId)).size;
        const accuracy = percent(points, maxPoints);
        const participationRate = percent(active, memberCount);
        // Completion is the share of attempts that were graded as passing,
        // which is the closest signal available to "finished the assignment".
        const completionRate = percent(
          mine.filter((item) => item.points > 0).length,
          mine.length,
        );
        return {
          organizationId: organization.id,
          name: organization.name,
          memberCount,
          accuracy,
          participationRate,
          completionRate,
          // Weighted so a small, highly engaged team is not beaten purely on
          // headcount, and a large idle one cannot coast on a few experts.
          readiness:
            Math.round(
              (accuracy * 0.5 + participationRate * 0.3 + completionRate * 0.2) * 10,
            ) / 10,
          attempts: mine.length,
        };
      })
      .filter((item) => item.attempts > 0)
      .sort(
        (a, b) =>
          b.readiness - a.readiness ||
          b.participationRate - a.participationRate ||
          a.name.localeCompare(b.name),
      );
  };

  const previousRank = new Map(
    score(previous).map((item, index) => [item.organizationId, index + 1]),
  );
  return score(current).map((item, index) => {
    const rank = index + 1;
    const before = previousRank.get(item.organizationId);
    return {
      rank,
      organizationId: item.organizationId,
      name: item.name,
      memberCount: item.memberCount,
      readiness: item.readiness,
      participationRate: item.participationRate,
      completionRate: item.completionRate,
      change: before ? before - rank : 0,
    };
  });
}

/** The equally sized window immediately before the given one. */
function shiftWindow(window: { start: number; end: number }) {
  const span = window.end - window.start;
  return { start: window.start - span, end: window.start };
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
  domain: RankingDomain | null = null,
): RankingEntry[] {
  const organizations = new Map(dataset.organizations.map((item) => [item.id, item]));
  const skills = domainSkills(domain);
  const rows = users
    .map((user) => {
      const evidence = validEvidence(dataset.evidence).filter((item) => {
        const timestamp = Date.parse(item.completedAt);
        return item.userId === user.id && timestamp >= window.start && timestamp < window.end;
      });
      let points = 0;
      let maxPoints = 0;
      for (const item of evidence) {
        const scored = evidencePoints(item, skills);
        points += scored.points;
        maxPoints += scored.maxPoints;
      }
      return {
        userId: user.id,
        handle: user.handle,
        organizationName: user.organizationId
          ? organizations.get(user.organizationId)?.name ?? null
          : null,
        points,
        completedLabs: evidence.length,
        accuracy: percent(points, maxPoints),
        primaryDomain: primaryDomainOf(evidence),
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

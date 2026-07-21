import assert from "node:assert/strict";
import test from "node:test";
import {
  organizationReport,
  personalReport,
  platformReport,
  ranking,
  type ReportingDataset,
} from "../src/index.ts";

const now = new Date("2026-07-21T12:00:00.000Z");
const dataset: ReportingDataset = {
  organizations: [{ id: "org-1", name: "Security Lab", slug: "security-lab" }],
  users: [
    { id: "u1", handle: "alice", displayName: "Alice", organizationId: "org-1", globalRankingOptIn: true },
    { id: "u2", handle: "bob", displayName: "Bob", organizationId: "org-1", globalRankingOptIn: true },
    { id: "u3", handle: "private", displayName: "Private", organizationId: null, globalRankingOptIn: false },
  ],
  evidence: [
    {
      userId: "u1", organizationId: "org-1", runId: "r1", labId: "l1", labTitle: "ELK Hunt", team: "blue",
      points: 80, maxPoints: 100, completedAt: "2026-07-20T12:00:00.000Z",
      skills: { detection: { label: "탐지", points: 80, maxPoints: 100 } },
    },
    {
      userId: "u2", organizationId: "org-1", runId: "r2", labId: "l2", labTitle: "Web Range", team: "red",
      points: 60, maxPoints: 100, completedAt: "2026-07-19T12:00:00.000Z",
      skills: { exploitation: { label: "공격 경로", points: 60, maxPoints: 100 } },
    },
    {
      userId: "u3", organizationId: null, runId: "r3", labId: "l3", labTitle: "Private Lab", team: "red",
      points: 100, maxPoints: 100, completedAt: "2026-07-18T12:00:00.000Z",
      skills: { exploitation: { label: "공격 경로", points: 100, maxPoints: 100 } },
    },
  ],
};

test("builds personal, organization and platform capability scopes", () => {
  const personal = personalReport(dataset, "u1", { now });
  assert.equal(personal.overallScore, 80);
  assert.equal(personal.completedLabs, 1);

  const organization = organizationReport(dataset, "org-1", { now });
  assert.equal(organization.memberCount, 2);
  assert.equal(organization.activeMemberCount, 2);
  assert.equal(organization.overallScore, 70);
  assert.equal(organization.members[0].handle, "alice");

  const platform = platformReport(dataset, { now });
  assert.equal(platform.userCount, 3);
  assert.equal(platform.organizationCount, 1);
  assert.equal(platform.overallScore, 80);
});

test("global ranking honors privacy opt-in and organization ranking is tenant scoped", () => {
  const global = ranking(dataset, "global", "weekly", { now, currentUserId: "u1" });
  assert.deepEqual(global.entries.map((item) => item.handle), ["alice", "bob"]);
  assert.equal(global.currentUser?.rank, 1);

  const organization = ranking(dataset, "organization", "weekly", {
    now,
    organizationId: "org-1",
  });
  assert.deepEqual(organization.entries.map((item) => item.handle), ["alice", "bob"]);
});

test("organization ranking requires the tenant id", () => {
  assert.throws(() => ranking(dataset, "organization", "weekly", { now }), /organizationId/);
});

test("season score applies difficulty, time and hints per the policy", () => {
  const base = {
    organizationId: null,
    runId: "r",
    labId: "l",
    labTitle: "Lab",
    team: "red" as const,
    completedAt: "2026-07-20T12:00:00.000Z",
    skills: {},
    maxPoints: 100,
  };
  const build = (evidence: ReportingDataset["evidence"]): ReportingDataset => ({
    organizations: [],
    users: [
      { id: "s", handle: "solo", displayName: "Solo", organizationId: null, globalRankingOptIn: true },
    ],
    evidence,
  });
  const scoreOf = (extra: Partial<ReportingDataset["evidence"][number]>) =>
    ranking(build([{ ...base, userId: "s", points: 100, ...extra }]), "global", "all_time", {
      now,
    }).entries[0].points;

  // Advanced base 500 × 100% accuracy, no timing/hints → 500.
  assert.equal(scoreOf({ difficulty: "advanced" }), 500);
  // Beginner base 100; intermediate default 250.
  assert.equal(scoreOf({ difficulty: "beginner" }), 100);
  assert.equal(scoreOf({}), 250);
  // Half accuracy halves the score.
  assert.equal(scoreOf({ difficulty: "advanced", points: 50 }), 250);

  // Finishing within half the TTL earns the full +20%.
  assert.equal(
    scoreOf({ difficulty: "advanced", durationSeconds: 60, ttlSeconds: 600 }),
    600,
  );
  // Using the whole TTL earns no bonus.
  assert.equal(
    scoreOf({ difficulty: "advanced", durationSeconds: 600, ttlSeconds: 600 }),
    500,
  );

  // Each hint removes 4%, capped at 20%; five or more hits the floor.
  assert.equal(scoreOf({ difficulty: "advanced", hintsUsed: 1 }), 480);
  assert.equal(scoreOf({ difficulty: "advanced", hintsUsed: 5 }), 400);
  assert.equal(scoreOf({ difficulty: "advanced", hintsUsed: 99 }), 400);

  // The honest default: no hint data means no penalty, not an assumed one.
  assert.equal(scoreOf({ difficulty: "advanced", hintsUsed: 0 }), 500);
  assert.equal(scoreOf({ difficulty: "advanced" }), 500);
});

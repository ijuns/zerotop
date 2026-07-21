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

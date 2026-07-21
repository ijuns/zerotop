import { randomUUID } from "node:crypto";

import { SqliteDevelopmentRepository } from "./database.ts";
import type { PlatformRepository } from "./ports.ts";

const DAY_MS = 86_400_000;

/**
 * Populates a freshly started instance with demonstration data so a public
 * deployment shows a populated season ranking immediately. Free hosts have an
 * ephemeral filesystem, so this runs on every boot and must be idempotent:
 * the capability fixtures upsert, a season is created only when none is active,
 * and opt-in is naturally idempotent.
 *
 * Enabled with DEMO_SEED=true. Never enable it against real data.
 */
export async function seedDemoData(repository: PlatformRepository): Promise<void> {
  // Verified challenge results are what the ranking is computed from. Only the
  // SQLite development repository ships the fixture generator.
  if (repository instanceof SqliteDevelopmentRepository) {
    repository.seedDevelopmentCapabilityData();
  }

  const now = new Date();
  const active = await repository.getActiveSeason(now.toISOString());
  if (!active) {
    try {
      await repository.createSeason({
        id: `season_${randomUUID()}`,
        name: "Live Demo Season",
        // A window centred on now so the seeded results always fall inside it.
        slug: `demo-${now.getFullYear()}-${now.getMonth() + 1}`,
        startsAt: new Date(now.getTime() - 45 * DAY_MS).toISOString(),
        endsAt: new Date(now.getTime() + 45 * DAY_MS).toISOString(),
        createdAt: now.toISOString(),
      });
    } catch {
      // An overlapping season already exists; leave the current one in place.
    }
  }

  // Show the cross-organization board by opting every seeded organization in.
  const dataset = (await repository.getReportingDataset({})) as {
    organizations?: Array<{ id: string }>;
  };
  for (const organization of dataset.organizations ?? []) {
    await repository.setOrganizationRankingOptIn(organization.id, true);
  }
}

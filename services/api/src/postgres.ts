import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";

import { RepositoryError } from "./errors.ts";
import { hashOrganizationJoinCode, hashPassword } from "./security.ts";
import {
  developmentFixturePasswordHash,
  DEVELOPMENT_FIXTURE_AFFILIATION,
  DEVELOPMENT_FIXTURE_CREATED_AT,
  DEVELOPMENT_FIXTURE_PASSWORD,
  DEVELOPMENT_ORGANIZATIONS,
  DEVELOPMENT_USERS,
} from "./development-fixtures.ts";
import type {
  AuditEvent,
  IdempotencyRecord,
  PlatformRepository,
  ReportingDatasetFilter,
} from "./ports.ts";
import {
  DEV_USER_ID,
  PRIVACY_POLICY_VERSION,
  TERMS_VERSION,
  type ChallengeResultInput,
  type IdentityOnboardingInput,
  type AccessTicketInput,
  type AdminPageQuery,
  type AdminPageResult,
  type LabGenerationInput,
  type OrganizationCreateInput,
  type SeasonInput,
  type RegistrationInput,
  type ResolvedRegistrationInput,
  type RuntimeRunInput,
  type RuntimeRunStatusInput,
  type ValidationEvidenceInput,
  type JsonObject,
} from "./types.ts";

type Row = Record<string, unknown>;

const MIGRATIONS = [
  {
    version: 1,
    name: "initial",
    url: new URL("../migrations/001_initial.sql", import.meta.url),
  },
  {
    version: 2,
    name: "reporting",
    url: new URL("../migrations/002_reporting.sql", import.meta.url),
  },
  {
    version: 3,
    name: "grading",
    url: new URL("../migrations/003_grading.sql", import.meta.url),
  },
  {
    version: 4,
    name: "oidc_identity",
    url: new URL("../migrations/004_oidc_identity.sql", import.meta.url),
  },
  {
    version: 5,
    name: "runtime_provisioning",
    url: new URL("../migrations/005_runtime_provisioning.sql", import.meta.url),
  },
  {
    version: 6,
    name: "access_tickets",
    url: new URL("../migrations/006_access_tickets.sql", import.meta.url),
  },
  {
    version: 7,
    name: "combined_access_method",
    url: new URL("../migrations/007_combined_access_method.sql", import.meta.url),
  },
  {
    version: 8,
    name: "runtime_failed_status",
    url: new URL("../migrations/008_runtime_failed_status.sql", import.meta.url),
  },
  {
    version: 9,
    name: "admin_organizations",
    url: new URL("../migrations/009_admin_organizations.sql", import.meta.url),
  },
  {
    version: 10,
    name: "admin_user_management",
    url: new URL("../migrations/010_admin_user_management.sql", import.meta.url),
  },
  {
    version: 11,
    name: "audit_log_listing",
    url: new URL("../migrations/011_audit_log_listing.sql", import.meta.url),
  },
  {
    version: 12,
    name: "registration_consent",
    url: new URL("../migrations/012_registration_consent.sql", import.meta.url),
  },
  {
    version: 13,
    name: "audit_source_address",
    url: new URL("../migrations/013_audit_source_address.sql", import.meta.url),
  },
  {
    version: 14,
    name: "ranking_seasons",
    url: new URL("../migrations/014_ranking_seasons.sql", import.meta.url),
  },
] as const;

function nowIso(): string {
  return new Date().toISOString();
}

function timestamp(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function jsonValue<T>(value: unknown, fallback: T): T {
  if (typeof value !== "string") return (value as T) ?? fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function userFromRow(row: Row | undefined): unknown | null {
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    handle: row.handle,
    displayName: row.display_name,
    platformRole: row.platform_role ?? "user",
    globalRankingOptIn: row.global_ranking_opt_in === true,
    affiliation: (row.affiliation as string | null) ?? null,
    consent: {
      termsAgreedAt: row.terms_agreed_at ? timestamp(row.terms_agreed_at) : null,
      termsVersion: (row.terms_version as string | null) ?? null,
      privacyAgreedAt: row.privacy_agreed_at
        ? timestamp(row.privacy_agreed_at)
        : null,
      privacyVersion: (row.privacy_version as string | null) ?? null,
    },
    createdAt: timestamp(row.created_at),
    disabledAt: row.disabled_at ? timestamp(row.disabled_at) : null,
    organization: row.organization_id
      ? {
          id: row.organization_id,
          name: row.organization_name,
          slug: row.organization_slug,
          role: row.organization_role,
          rankingOptIn: row.organization_ranking_opt_in === true,
        }
      : null,
  };
}

const ADMIN_USER_COLUMNS = `u.id, u.email, u.handle, u.display_name, u.platform_role,
              u.global_ranking_opt_in, u.disabled_at, u.disabled_reason,
              u.created_at, m.role AS membership_role,
              o.id AS organization_id, o.name AS organization_name,
              o.slug AS organization_slug`;

const ADMIN_USER_FROM = `FROM users u
      LEFT JOIN organization_memberships m ON m.user_id = u.id
      LEFT JOIN organizations o ON o.id = m.organization_id`;

function adminUserFromRow(row: Row): unknown {
  return {
    id: row.id,
    email: row.email,
    handle: row.handle,
    displayName: row.display_name,
    platformRole: row.platform_role,
    globalRankingOptIn: row.global_ranking_opt_in === true,
    disabledAt: row.disabled_at ? timestamp(row.disabled_at) : null,
    disabledReason: (row.disabled_reason as string | null) ?? null,
    organization: row.organization_id
      ? {
          id: row.organization_id,
          name: row.organization_name,
          slug: row.organization_slug,
          role: row.membership_role,
        }
      : null,
    createdAt: timestamp(row.created_at),
  };
}

function auditLogFromRow(row: Row): unknown {
  return {
    id: row.id,
    action: row.action,
    resourceType: row.resource_type,
    resourceId: row.resource_id,
    actor: row.actor_user_id
      ? {
          id: row.actor_user_id,
          handle: row.actor_handle,
          displayName: row.actor_display_name,
        }
      : null,
    metadata: jsonValue<Record<string, unknown>>(row.metadata_json, {}),
    actorIp: (row.actor_ip as string | null) ?? null,
    createdAt: timestamp(row.created_at),
  };
}

function seasonFromRow(row: Row): unknown {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    startsAt: timestamp(row.starts_at),
    endsAt: timestamp(row.ends_at),
  };
}

function organizationMemberFromRow(row: Row): unknown {
  return {
    id: row.id,
    email: row.email,
    handle: row.handle,
    displayName: row.display_name,
    platformRole: row.platform_role,
    organizationRole: row.role,
    joinedAt: timestamp(row.joined_at),
  };
}

function labFromRow(row: Row | undefined): unknown | null {
  if (!row) return null;
  const questionTypes = jsonValue<unknown[]>(row.question_types_json, []);
  const accessModes = jsonValue<string[]>(row.access_modes_json, []);
  const storedConfig = jsonValue<Record<string, unknown>>(row.config_json, {});
  const { builderSpec: _hiddenBuilderSpec, ...config } = storedConfig;
  const scenario =
    typeof config.scenario === "object" && config.scenario !== null
      ? (config.scenario as Record<string, unknown>)
      : {};
  const accessMethod =
    accessModes.includes("browser_desktop") && accessModes.includes("openvpn")
      ? "both"
      : accessModes[0];
  const canonicalStatus =
    row.validation_status === "validated"
      ? "approved"
      : row.validation_status === "quarantined"
        ? "quarantined"
        : "draft";
  return {
    id: row.id,
    version: 1,
    title: row.name,
    prompt: row.description,
    team: row.team_type,
    desktopImage: row.environment,
    accessMethod,
    questionTypes,
    status: canonicalStatus,
    network: { egress: "deny", isolation: "per_run" },
    scenario: {
      summary: scenario.objective ?? row.description,
      logSources: row.team_type === "blue" ? ["elasticsearch", "endpoint"] : [],
      attackChain: Array.isArray(scenario.mitreTechniques)
        ? scenario.mitreTechniques.map((id) => ({ id, name: id, tactic: "unknown" }))
        : [],
    },
    // Compatibility aliases for the pre-contract web client.
    name: row.name,
    description: row.description,
    teamType: row.team_type,
    environment: row.environment,
    accessModes,
    validationStatus: row.validation_status,
    config,
    owner: { id: row.owner_user_id, displayName: row.owner_display_name },
    organization: row.organization_id
      ? { id: row.organization_id, name: row.organization_name }
      : null,
    createdAt: timestamp(row.created_at),
    updatedAt: timestamp(row.updated_at),
  };
}

function evidenceFromRow(row: Row): unknown {
  return {
    id: row.id,
    check: row.check_name,
    outcome: row.outcome,
    details: jsonValue(row.details_json, {}),
    createdAt: timestamp(row.created_at),
  };
}

function runFromRow(row: Row | undefined): unknown | null {
  if (!row) return null;
  const metadata = jsonValue<Record<string, unknown>>(row.metadata_json, {});
  const openVpn = jsonValue<Record<string, unknown> | null>(
    row.openvpn_profile_json,
    null,
  );
  return {
    id: row.id,
    labId: row.lab_id,
    userId: row.user_id,
    status: row.status,
    desktopImage: row.environment,
    environment: row.environment,
    accessMethod: row.access_method,
    browserDesktopUrl: row.browser_url ?? undefined,
    browserDesktop: row.browser_url
      ? { protocol: "noVNC", url: row.browser_url, desktop: metadata.desktop }
      : null,
    openVpn,
    openvpn: openVpn,
    expiresAt: timestamp(row.expires_at),
    metadata,
    createdAt: timestamp(row.created_at),
  };
}

function adminOrganizationFromRow(row: Row | undefined): unknown | null {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    memberCount: Number(row.member_count ?? 0),
    labCount: Number(row.lab_count ?? 0),
    joinCodeRotatedAt: timestamp(row.join_code_rotated_at),
    createdAt: timestamp(row.created_at),
  };
}

function adminLabFromRow(row: Row | undefined): unknown | null {
  if (!row) return null;
  return {
    id: row.id,
    title: row.name,
    prompt: row.description,
    team: row.team_type,
    questionTypes: jsonValue(row.question_types_json, []),
    desktopImage: row.environment,
    accessModes: jsonValue(row.access_modes_json, []),
    validationStatus: row.validation_status,
    owner: { id: row.owner_user_id, handle: row.owner_handle },
    organization: row.organization_id
      ? { id: row.organization_id, name: row.organization_name }
      : null,
    adminQuarantine: row.admin_quarantined_at
      ? {
          quarantinedAt: timestamp(row.admin_quarantined_at),
          quarantinedBy: row.admin_quarantined_by,
          reason: row.admin_quarantine_reason,
        }
      : null,
    createdAt: timestamp(row.created_at),
    updatedAt: timestamp(row.updated_at),
  };
}

function adminRunFromRow(row: Row | undefined): unknown | null {
  if (!row) return null;
  const metadata = jsonValue<Record<string, unknown>>(row.metadata_json, {});
  return {
    id: row.id,
    labId: row.lab_id,
    labTitle: row.lab_title,
    userId: row.user_id,
    userHandle: row.user_handle,
    organizationId: row.organization_id ?? null,
    status: row.status,
    environment: row.environment,
    accessMethod: row.access_method,
    namespace: metadata.namespace ?? null,
    readiness: metadata.runtimeReadiness ?? null,
    expiresAt: timestamp(row.expires_at),
    createdAt: timestamp(row.created_at),
  };
}

function escapedLike(value: string): string {
  return `%${value.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_")}%`;
}

function bind(parameters: unknown[], value: unknown): string {
  parameters.push(value);
  return `$${parameters.length}`;
}

async function rollback(client: any): Promise<void> {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Preserve the original transaction error.
  }
}

/** PostgreSQL repository used by default outside explicit development mode. */
export class PostgresRepository implements PlatformRepository {
  private pool: any = null;
  private readonly databaseUrl: string;

  constructor(databaseUrl: string) {
    if (!databaseUrl) {
      throw new RepositoryError(
        "DATABASE_URL_REQUIRED",
        "DATABASE_URL is required when REPOSITORY_MODE=postgres.",
        500,
      );
    }

    this.databaseUrl = databaseUrl;
  }

  async initialize(): Promise<void> {
    const pgModule = await import("pg");
    const Pool = pgModule.default?.Pool ?? pgModule.Pool;
    this.pool = new Pool({
      connectionString: this.databaseUrl,
      max: Number.parseInt(process.env.PG_POOL_MAX ?? "10", 10),
      application_name: "codegate-range-api",
    });
    const client = await this.pool.connect();
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
          version INTEGER PRIMARY KEY,
          name TEXT NOT NULL,
          applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);

      for (const migration of MIGRATIONS) {
        await client.query("BEGIN");
        try {
          await client.query("SELECT pg_advisory_xact_lock($1)", [0x434f4445]);
          const applied = await client.query(
            "SELECT version FROM schema_migrations WHERE version = $1",
            [migration.version],
          );
          if (applied.rowCount === 0) {
            const sql = await readFile(migration.url, "utf8");
            await client.query(sql);
            await client.query(
              "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)",
              [migration.version, migration.name],
            );
          }
          await client.query("COMMIT");
        } catch (error) {
          await rollback(client);
          throw error;
        }
      }

      if (process.env.SEED_DEVELOPMENT_DATA === "true") {
        await client.query("BEGIN");
        try {
          for (const organization of DEVELOPMENT_ORGANIZATIONS) {
            await client.query(
              `INSERT INTO organizations
                (id, name, slug, join_code_hash, join_code_rotated_at, created_at)
               VALUES ($1, $2, $3, $4, $5, $5)
               ON CONFLICT (id) DO NOTHING`,
              [
                organization.id,
                organization.name,
                organization.slug,
                hashOrganizationJoinCode(organization.joinCode),
                DEVELOPMENT_FIXTURE_CREATED_AT,
              ],
            );
          }

          for (const user of DEVELOPMENT_USERS) {
            await client.query(
              `INSERT INTO users
                (id, email, handle, display_name, affiliation, password_hash,
                 platform_role, global_ranking_opt_in, terms_agreed_at,
                 terms_version, privacy_agreed_at, privacy_version, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $9, $11, $9)
               ON CONFLICT (id) DO NOTHING`,
              [
                user.id,
                user.email,
                user.handle,
                user.displayName,
                DEVELOPMENT_FIXTURE_AFFILIATION,
                developmentFixturePasswordHash(),
                user.platformRole,
                user.globalRankingOptIn,
                DEVELOPMENT_FIXTURE_CREATED_AT,
                TERMS_VERSION,
                PRIVACY_POLICY_VERSION,
              ],
            );
            if (user.organizationId && user.organizationRole) {
              await client.query(
                `INSERT INTO organization_memberships
                  (user_id, organization_id, role, created_at)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (user_id) DO NOTHING`,
                [
                  user.id,
                  user.organizationId,
                  user.organizationRole,
                  DEVELOPMENT_FIXTURE_CREATED_AT,
                ],
              );
            }
          }

          const developmentActor = DEVELOPMENT_USERS.find(
            (user) => user.id === DEV_USER_ID,
          );
          if (!developmentActor) {
            throw new Error("The development fixture must include DEV_USER_ID.");
          }
          await client.query(
            `UPDATE users
                SET email = $1, handle = $2, display_name = $3,
                    password_hash = $4, platform_role = 'platform_admin',
                    global_ranking_opt_in = TRUE
              WHERE id = $5`,
            [
              developmentActor.email,
              developmentActor.handle,
              developmentActor.displayName,
              developmentFixturePasswordHash(),
              DEV_USER_ID,
            ],
          );
          await client.query("COMMIT");
        } catch (error) {
          await rollback(client);
          throw error;
        }
      }
    } finally {
      client.release();
    }
  }

  async getUser(userId: string): Promise<unknown | null> {
    const result = await this.pool.query(
      `SELECT u.*, m.role AS organization_role,
              o.id AS organization_id, o.name AS organization_name,
              o.slug AS organization_slug,
              o.ranking_opt_in AS organization_ranking_opt_in
         FROM users u
         LEFT JOIN organization_memberships m ON m.user_id = u.id
         LEFT JOIN organizations o ON o.id = m.organization_id
        WHERE u.id = $1`,
      [userId],
    );
    return userFromRow(result.rows[0]);
  }

  async getUserByExternalSubject(subject: string): Promise<unknown | null> {
    const result = await this.pool.query(
      `SELECT u.*, m.role AS organization_role,
              o.id AS organization_id, o.name AS organization_name,
              o.slug AS organization_slug,
              o.ranking_opt_in AS organization_ranking_opt_in
         FROM users u
         LEFT JOIN organization_memberships m ON m.user_id = u.id
         LEFT JOIN organizations o ON o.id = m.organization_id
        WHERE u.external_subject = $1`,
      [subject],
    );
    return userFromRow(result.rows[0]);
  }

  async register(input: ResolvedRegistrationInput): Promise<unknown> {
    const client = await this.pool.connect();
    const id = `user_${randomUUID()}`;
    const createdAt = nowIso();
    try {
      await client.query("BEGIN");
      const duplicate = await client.query(
        "SELECT id FROM users WHERE lower(email) = lower($1) OR lower(handle) = lower($2)",
        [input.email, input.handle],
      );
      if (duplicate.rowCount > 0) {
        throw new RepositoryError(
          "ACCOUNT_EXISTS",
          "An account with that email or handle already exists.",
          409,
        );
      }

      let organizationId: string | null = null;
      if (input.accountType === "organization") {
        const organization = input.organizationId
          ? await client.query("SELECT id FROM organizations WHERE id = $1", [
              input.organizationId,
            ])
          : await client.query(
              "SELECT id FROM organizations WHERE join_code_hash = $1",
              [hashOrganizationJoinCode(input.organizationJoinCode as string)],
            );
        if (organization.rowCount === 0) {
          throw new RepositoryError(
            "ORGANIZATION_NOT_FOUND",
            "The organization or join code was not found.",
            404,
          );
        }
        organizationId = String(organization.rows[0].id);
      }

      await client.query(
        `INSERT INTO users
          (id, email, handle, display_name, affiliation, password_hash,
           terms_agreed_at, terms_version, privacy_agreed_at, privacy_version,
           created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $7, $9, $7)`,
        [
          id,
          input.email,
          input.handle,
          input.displayName,
          input.affiliation,
          hashPassword(input.password),
          createdAt,
          TERMS_VERSION,
          PRIVACY_POLICY_VERSION,
        ],
      );
      if (organizationId) {
        await client.query(
          `INSERT INTO organization_memberships
            (user_id, organization_id, role, created_at)
           VALUES ($1, $2, 'member', $3)`,
          [id, organizationId, createdAt],
        );
      }
      await client.query("COMMIT");
    } catch (error: unknown) {
      await rollback(client);
      if (
        !(error instanceof RepositoryError) &&
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "23505"
      ) {
        throw new RepositoryError(
          "ACCOUNT_EXISTS",
          "An account with that email or handle already exists.",
          409,
        );
      }
      throw error;
    } finally {
      client.release();
    }
    return this.getUser(id);
  }

  async onboardIdentity(input: IdentityOnboardingInput): Promise<unknown> {
    const client = await this.pool.connect();
    const id = `user_${randomUUID()}`;
    const createdAt = nowIso();
    try {
      await client.query("BEGIN");
      const duplicate = await client.query(
        `SELECT id FROM users
          WHERE external_subject = $1
             OR lower(email) = lower($2)
             OR lower(handle) = lower($3)`,
        [input.externalSubject, input.email, input.handle],
      );
      if (duplicate.rowCount > 0) {
        throw new RepositoryError(
          "IDENTITY_ALREADY_ONBOARDED",
          "This identity, email or handle is already onboarded.",
          409,
        );
      }

      let organizationId: string | null = null;
      if (input.accountType === "organization") {
        const organization = input.organizationId
          ? await client.query("SELECT id FROM organizations WHERE id = $1", [
              input.organizationId,
            ])
          : await client.query(
              "SELECT id FROM organizations WHERE join_code_hash = $1",
              [hashOrganizationJoinCode(input.organizationJoinCode as string)],
            );
        if (organization.rowCount === 0) {
          throw new RepositoryError(
            "ORGANIZATION_NOT_FOUND",
            "The organization or join code was not found.",
            404,
          );
        }
        organizationId = String(organization.rows[0].id);
      }

      await client.query(
        `INSERT INTO users
          (id, email, handle, display_name, affiliation, password_hash,
           external_subject, platform_role, terms_agreed_at, terms_version,
           privacy_agreed_at, privacy_version, created_at)
         VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, $8, $9, $8, $10, $8)`,
        [
          id,
          input.email,
          input.handle,
          input.displayName,
          input.affiliation,
          input.externalSubject,
          input.platformRole,
          createdAt,
          TERMS_VERSION,
          PRIVACY_POLICY_VERSION,
        ],
      );
      if (organizationId) {
        await client.query(
          `INSERT INTO organization_memberships
            (user_id, organization_id, role, created_at)
           VALUES ($1, $2, $3, $4)`,
          [id, organizationId, input.organizationRole, createdAt],
        );
      }
      await client.query("COMMIT");
    } catch (error: unknown) {
      await rollback(client);
      if (
        !(error instanceof RepositoryError) &&
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "23505"
      ) {
        throw new RepositoryError(
          "IDENTITY_ALREADY_ONBOARDED",
          "This identity, email or handle is already onboarded.",
          409,
        );
      }
      throw error;
    } finally {
      client.release();
    }
    return this.getUser(id);
  }

  async createLab(userId: string, input: LabGenerationInput): Promise<unknown> {
    const client = await this.pool.connect();
    const id = `lab_${randomUUID()}`;
    const createdAt = nowIso();
    try {
      await client.query("BEGIN");
      const membership = await client.query(
        "SELECT organization_id FROM organization_memberships WHERE user_id = $1",
        [userId],
      );
      await client.query(
        `INSERT INTO labs
          (id, owner_user_id, organization_id, name, description, team_type,
           question_types_json, environment, access_modes_json, validation_status,
           config_json, grading_config_json, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9::jsonb,
                 'draft', $10::jsonb, $11::jsonb, $12, $12)`,
        [
          id,
          userId,
          membership.rows[0]?.organization_id ?? null,
          input.title,
          input.prompt,
          input.team,
          JSON.stringify(input.questionTypes),
          input.desktopImage,
          JSON.stringify(input.accessModes),
          JSON.stringify(input.config),
          JSON.stringify({ questions: input.gradingQuestions }),
          createdAt,
        ],
      );
      await client.query("COMMIT");
    } catch (error) {
      await rollback(client);
      throw error;
    } finally {
      client.release();
    }
    return this.getLab(userId, id);
  }

  async listLabs(userId: string): Promise<unknown[]> {
    const result = await this.pool.query(
      `SELECT l.*, u.display_name AS owner_display_name,
              o.name AS organization_name
         FROM labs l
         JOIN users u ON u.id = l.owner_user_id
         LEFT JOIN organizations o ON o.id = l.organization_id
        WHERE l.owner_user_id = $1
           OR l.organization_id IN (
             SELECT organization_id FROM organization_memberships WHERE user_id = $1
           )
        ORDER BY l.created_at DESC, l.id DESC`,
      [userId],
    );
    return result.rows.map(labFromRow);
  }

  async getLab(userId: string, labId: string): Promise<unknown | null> {
    const result = await this.pool.query(
      `SELECT l.*, u.display_name AS owner_display_name,
              o.name AS organization_name
         FROM labs l
         JOIN users u ON u.id = l.owner_user_id
         LEFT JOIN organizations o ON o.id = l.organization_id
        WHERE l.id = $1
          AND (
            l.owner_user_id = $2
            OR l.organization_id IN (
              SELECT organization_id FROM organization_memberships WHERE user_id = $2
            )
          )`,
      [labId, userId],
    );
    return labFromRow(result.rows[0]);
  }

  async getLabBuildSpec(userId: string, labId: string): Promise<JsonObject | null> {
    const result = await this.pool.query(
      `SELECT l.config_json
         FROM labs l
         LEFT JOIN organization_memberships m
           ON m.organization_id = l.organization_id AND m.user_id = $1
        WHERE l.id = $2 AND (l.owner_user_id = $1 OR m.user_id IS NOT NULL)`,
      [userId, labId],
    );
    const config = jsonValue<Record<string, unknown>>(result.rows[0]?.config_json, {});
    return typeof config.builderSpec === "object" && config.builderSpec !== null && !Array.isArray(config.builderSpec)
      ? config.builderSpec as JsonObject
      : null;
  }

  async updateLabConfig(labId: string, patch: JsonObject, updatedAt: string): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE labs
          SET config_json = config_json || $2::jsonb, updated_at = $3
        WHERE id = $1 AND validation_status = 'draft'
      RETURNING id`,
      [labId, JSON.stringify(patch), updatedAt],
    );
    return (result.rowCount ?? 0) === 1;
  }

  async saveValidation(
    labId: string,
    status: "validated" | "quarantined",
    evidence: ValidationEvidenceInput[],
  ): Promise<unknown[]> {
    const client = await this.pool.connect();
    const createdAt = nowIso();
    try {
      await client.query("BEGIN");
      for (const item of evidence) {
        await client.query(
          `INSERT INTO validation_evidence
            (id, lab_id, check_name, outcome, details_json, created_at)
           VALUES ($1, $2, $3, $4, $5::jsonb, $6)
           ON CONFLICT (lab_id, check_name) DO UPDATE SET
             outcome = EXCLUDED.outcome,
             details_json = EXCLUDED.details_json`,
          [
            item.id,
            labId,
            item.checkName,
            item.outcome,
            JSON.stringify(item.details),
            createdAt,
          ],
        );
      }
      await client.query(
        `UPDATE labs
            SET validation_status = CASE
                  WHEN admin_quarantined_at IS NOT NULL THEN 'quarantined'
                  ELSE $1
                END,
                updated_at = $2
          WHERE id = $3`,
        [status, createdAt, labId],
      );
      await client.query("COMMIT");
    } catch (error) {
      await rollback(client);
      throw error;
    } finally {
      client.release();
    }

    const result = await this.pool.query(
      `SELECT * FROM validation_evidence
        WHERE lab_id = $1 ORDER BY check_name ASC`,
      [labId],
    );
    return result.rows.map(evidenceFromRow);
  }

  async createRun(input: RuntimeRunInput): Promise<unknown> {
    await this.pool.query(
      `INSERT INTO runtime_runs
        (id, lab_id, user_id, status, environment, access_method, browser_url,
         openvpn_profile_json, expires_at, metadata_json, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10::jsonb, $11)`,
      [
        input.id,
        input.labId,
        input.userId,
        input.status,
        input.environment,
        input.accessMethod,
        input.browserUrl,
        input.openvpnProfile ? JSON.stringify(input.openvpnProfile) : null,
        input.expiresAt,
        JSON.stringify(input.metadata),
        input.createdAt,
      ],
    );
    return this.getRun(input.userId, input.id);
  }

  async getRun(userId: string, runId: string): Promise<unknown | null> {
    const result = await this.pool.query(
      "SELECT * FROM runtime_runs WHERE id = $1 AND user_id = $2",
      [runId, userId],
    );
    return runFromRow(result.rows[0]);
  }

  async updateRunReadiness(
    userId: string,
    runId: string,
    readiness: RuntimeRunStatusInput,
  ): Promise<unknown | null> {
    if (readiness.status === "provisioning") return this.getRun(userId, runId);
    await this.pool.query(
      `UPDATE runtime_runs
          SET status = $1,
              metadata_json = metadata_json || jsonb_build_object(
                'runtimeReadiness', $2::jsonb
              )
        WHERE id = $3 AND user_id = $4 AND status = 'provisioning'`,
      [
        readiness.status,
        JSON.stringify(persistedReadiness(readiness)),
        runId,
        userId,
      ],
    );
    return this.getRun(userId, runId);
  }

  async getLabGradingQuestions(userId: string, labId: string): Promise<unknown[]> {
    const result = await this.pool.query(
      `SELECT l.grading_config_json
         FROM labs l
        WHERE l.id = $1
          AND (
            l.owner_user_id = $2
            OR l.organization_id IN (
              SELECT organization_id FROM organization_memberships WHERE user_id = $2
            )
          )`,
      [labId, userId],
    );
    const grading = jsonValue<Record<string, unknown>>(
      result.rows[0]?.grading_config_json,
      {},
    );
    return Array.isArray(grading.questions) ? grading.questions : [];
  }

  async getTrustedGradeEvidence(userId: string, runId: string): Promise<unknown[]> {
    const result = await this.pool.query(
      `SELECT e.*
         FROM trusted_grade_evidence e
         JOIN runtime_runs r ON r.id = e.run_id
        WHERE e.run_id = $1 AND r.user_id = $2
        ORDER BY e.question_id`,
      [runId, userId],
    );
    return result.rows.map((row: Row) => ({
      questionId: row.question_id,
      source: row.source,
      passed: row.passed === true,
      scoreRatio: row.score_ratio,
      policyVersion: row.policy_version,
      evidenceReference: row.evidence_reference,
    }));
  }

  async saveChallengeResult(input: ChallengeResultInput): Promise<unknown> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const existing = await client.query(
        "SELECT id FROM challenge_results WHERE run_id = $1 FOR UPDATE",
        [input.runId],
      );
      if (existing.rowCount > 0) {
        throw new RepositoryError(
          "RUN_ALREADY_SUBMITTED",
          "This runtime run already has a challenge result.",
          409,
        );
      }
      const membership = await client.query(
        "SELECT organization_id FROM organization_memberships WHERE user_id = $1",
        [input.userId],
      );
      await client.query(
        `INSERT INTO challenge_results
          (id, lab_id, user_id, run_id, score, max_score, answers_json,
           evidence_json, skills_json, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9::jsonb, $10)`,
        [
          input.id,
          input.labId,
          input.userId,
          input.runId,
          input.awardedPoints,
          input.maxPoints,
          JSON.stringify(input.answers),
          JSON.stringify(input.gradeEvidence),
          JSON.stringify(input.skills),
          input.completedAt,
        ],
      );
      await client.query(
        `INSERT INTO score_events
          (id, result_id, user_id, organization_id, event_type, points_delta,
           max_points, payload_json, occurred_at)
         VALUES ($1, $2, $3, $4, 'challenge.graded', $5, $6, $7::jsonb, $8)`,
        [
          `score_${randomUUID()}`,
          input.id,
          input.userId,
          membership.rows[0]?.organization_id ?? null,
          input.awardedPoints,
          input.maxPoints,
          JSON.stringify({ labId: input.labId, runId: input.runId }),
          input.completedAt,
        ],
      );
      await client.query("COMMIT");
    } catch (error: unknown) {
      await rollback(client);
      if (
        !(error instanceof RepositoryError) &&
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "23505"
      ) {
        throw new RepositoryError(
          "RUN_ALREADY_SUBMITTED",
          "This runtime run already has a challenge result.",
          409,
        );
      }
      throw error;
    } finally {
      client.release();
    }

    return {
      id: input.id,
      labId: input.labId,
      runId: input.runId,
      userId: input.userId,
      awardedPoints: input.awardedPoints,
      maxPoints: input.maxPoints,
      score: Math.round((input.awardedPoints / input.maxPoints) * 100),
      completedAt: input.completedAt,
    };
  }

  async createAccessTicket(input: AccessTicketInput): Promise<void> {
    await this.pool.query(
      `INSERT INTO access_tickets
        (ticket_hash, run_id, user_id, kind, expires_at, consumed_at, created_at)
       VALUES ($1, $2, $3, $4, $5, NULL, $6)`,
      [
        input.ticketHash,
        input.runId,
        input.userId,
        input.kind,
        input.expiresAt,
        input.createdAt,
      ],
    );
  }

  async consumeAccessTicket(
    ticketHash: string,
    kind: "desktop" | "openvpn",
    consumedAt: string,
  ): Promise<unknown | null> {
    const result = await this.pool.query(
      `WITH consumed AS (
         UPDATE access_tickets t
            SET consumed_at = $3
          WHERE t.ticket_hash = $1 AND t.kind = $2
            AND t.consumed_at IS NULL AND t.expires_at > $3
             AND EXISTS (
               SELECT 1 FROM runtime_runs ready_run
                WHERE ready_run.id = t.run_id AND ready_run.status = 'ready'
             )
          RETURNING t.run_id, t.user_id, t.expires_at AS ticket_expires_at
       ), audited AS (
         INSERT INTO audit_logs
           (id, actor_user_id, action, resource_type, resource_id,
            metadata_json, created_at)
         SELECT $4, c.user_id, $5, 'runtime_run', c.run_id,
                jsonb_build_object('kind', $2::text), $3
           FROM consumed c
         RETURNING id
       )
       SELECT c.run_id, c.user_id, c.ticket_expires_at,
              r.expires_at, r.metadata_json, r.openvpn_profile_json,
              (SELECT count(*) FROM audited) AS audit_count
         FROM consumed c
         JOIN runtime_runs r ON r.id = c.run_id`,
      [
        ticketHash,
        kind,
        consumedAt,
        `audit_${randomUUID()}`,
        `${kind}_ticket.consumed`,
      ],
    );
    const row = result.rows[0] as Row | undefined;
    if (!row) return null;
    const metadata = jsonValue<Record<string, unknown>>(row.metadata_json, {});
    return {
      runId: row.run_id,
      userId: row.user_id,
      namespace: metadata.namespace ?? null,
      openVpn: jsonValue(row.openvpn_profile_json, null),
      expiresAt: timestamp(row.expires_at),
      ticketExpiresAt: timestamp(row.ticket_expires_at),
    };
  }

  async getReportingDataset(filter: ReportingDatasetFilter = {}): Promise<unknown> {
    let userWhere = "";
    let organizationWhere = "";
    let evidenceWhere = "";
    let parameters: unknown[] = [];
    if (filter.userId) {
      parameters = [filter.userId];
      userWhere = "WHERE u.id = $1";
      organizationWhere = `WHERE o.id IN (
        SELECT organization_id FROM organization_memberships WHERE user_id = $1
      )`;
      evidenceWhere = "WHERE cr.user_id = $1";
    } else if (filter.organizationId) {
      parameters = [filter.organizationId];
      userWhere = "WHERE m.organization_id = $1";
      organizationWhere = "WHERE o.id = $1";
      evidenceWhere = "WHERE m.organization_id = $1";
    }

    const [usersResult, organizationsResult, evidenceResult] = await Promise.all([
      this.pool.query(
        `SELECT u.id, u.handle, u.display_name, u.global_ranking_opt_in,
                m.organization_id
           FROM users u
           LEFT JOIN organization_memberships m ON m.user_id = u.id
           ${userWhere}`,
        parameters,
      ),
      this.pool.query(
        `SELECT o.id, o.name, o.slug, o.ranking_opt_in,
                (SELECT count(*) FROM organization_memberships m
                  WHERE m.organization_id = o.id) AS member_count
           FROM organizations o ${organizationWhere}`,
        parameters,
      ),
      this.pool.query(
        `SELECT cr.id, cr.user_id, cr.run_id, cr.lab_id, cr.score, cr.max_score,
                cr.completed_at, cr.skills_json, cr.evidence_json,
                l.name AS lab_title, l.team_type, m.organization_id
           FROM challenge_results cr
           JOIN labs l ON l.id = cr.lab_id
           LEFT JOIN organization_memberships m ON m.user_id = cr.user_id
           ${evidenceWhere}`,
        parameters,
      ),
    ]);

    return {
      users: usersResult.rows.map((row: Row) => ({
        id: row.id,
        handle: row.handle,
        displayName: row.display_name,
        organizationId: row.organization_id ?? null,
        globalRankingOptIn: row.global_ranking_opt_in === true,
      })),
      organizations: organizationsResult.rows.map((row: Row) => ({
        id: row.id,
        name: row.name,
        slug: row.slug,
        rankingOptIn: row.ranking_opt_in === true,
        memberCount: Number(row.member_count ?? 0),
      })),
      evidence: evidenceResult.rows.map((row: Row) => {
        const storedSkills = jsonValue<Record<string, unknown>>(row.skills_json, {});
        const storedEvidence = jsonValue<Record<string, unknown>>(row.evidence_json, {});
        const skills =
          Object.keys(storedSkills).length > 0
            ? storedSkills
            : typeof storedEvidence.skills === "object" && storedEvidence.skills !== null
              ? storedEvidence.skills
              : {};
        return {
          userId: row.user_id,
          organizationId: row.organization_id ?? null,
          runId: row.run_id ?? `result_${row.id}`,
          labId: row.lab_id,
          labTitle: row.lab_title,
          team: row.team_type,
          points: row.score,
          maxPoints: row.max_score,
          completedAt: timestamp(row.completed_at),
          skills,
        };
      }),
    };
  }

  async getAdminOverview(): Promise<unknown> {
    const result = await this.pool.query(
      `SELECT
        (SELECT count(*) FROM users) AS users,
        (SELECT count(*) FROM organizations) AS organizations,
        (SELECT count(*) FROM labs) AS labs,
        (SELECT count(*) FROM labs
          WHERE validation_status = 'quarantined') AS quarantined_labs,
        (SELECT count(*) FROM runtime_runs) AS runs,
        (SELECT count(*) FROM runtime_runs
          WHERE status IN ('provisioning', 'ready')) AS active_runs,
        (SELECT count(*) FROM runtime_runs
          WHERE status = 'failed') AS failed_runs,
        (SELECT count(*) FROM challenge_results) AS completed_challenges`,
    );
    const row = result.rows[0] as Row;
    return {
      users: Number(row.users),
      organizations: Number(row.organizations),
      labs: Number(row.labs),
      quarantinedLabs: Number(row.quarantined_labs),
      runs: Number(row.runs),
      activeRuns: Number(row.active_runs),
      failedRuns: Number(row.failed_runs),
      completedChallenges: Number(row.completed_challenges),
      generatedAt: nowIso(),
    };
  }

  async listAdminUsers(query: AdminPageQuery): Promise<AdminPageResult> {
    const conditions: string[] = [];
    const parameters: unknown[] = [];
    if (query.search) {
      const term = bind(parameters, escapedLike(query.search));
      conditions.push(
        `(u.email ILIKE ${term} ESCAPE '\\'
          OR u.handle ILIKE ${term} ESCAPE '\\'
          OR u.display_name ILIKE ${term} ESCAPE '\\')`,
      );
    }
    if (query.platformRole) {
      conditions.push(`u.platform_role = ${bind(parameters, query.platformRole)}`);
    }
    if (query.organizationId) {
      conditions.push(`m.organization_id = ${bind(parameters, query.organizationId)}`);
    }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const from = ADMIN_USER_FROM;
    const totalResult = await this.pool.query(
      `SELECT count(*) AS total ${from} ${where}`,
      parameters,
    );
    const limit = bind(parameters, query.limit);
    const offset = bind(parameters, query.offset);
    const result = await this.pool.query(
      `SELECT ${ADMIN_USER_COLUMNS}
         ${from} ${where}
        ORDER BY u.created_at DESC, u.id DESC
        LIMIT ${limit} OFFSET ${offset}`,
      parameters,
    );
    return {
      total: Number(totalResult.rows[0].total),
      items: result.rows.map(adminUserFromRow),
    };
  }

  async listAdminOrganizations(query: AdminPageQuery): Promise<AdminPageResult> {
    const conditions: string[] = [];
    const parameters: unknown[] = [];
    if (query.search) {
      const term = bind(parameters, escapedLike(query.search));
      conditions.push(
        `(o.name ILIKE ${term} ESCAPE '\\' OR o.slug ILIKE ${term} ESCAPE '\\')`,
      );
    }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const totalResult = await this.pool.query(
      `SELECT count(*) AS total FROM organizations o ${where}`,
      parameters,
    );
    const limit = bind(parameters, query.limit);
    const offset = bind(parameters, query.offset);
    const result = await this.pool.query(
      `SELECT o.id, o.name, o.slug, o.join_code_rotated_at, o.created_at,
              (SELECT count(*) FROM organization_memberships m
                WHERE m.organization_id = o.id) AS member_count,
              (SELECT count(*) FROM labs l
                WHERE l.organization_id = o.id) AS lab_count
         FROM organizations o ${where}
        ORDER BY o.created_at DESC, o.id DESC
        LIMIT ${limit} OFFSET ${offset}`,
      parameters,
    );
    return {
      total: Number(totalResult.rows[0].total),
      items: result.rows.map((row: Row) => adminOrganizationFromRow(row)),
    };
  }

  async listAdminLabs(query: AdminPageQuery): Promise<AdminPageResult> {
    const conditions: string[] = [];
    const parameters: unknown[] = [];
    if (query.search) {
      const term = bind(parameters, escapedLike(query.search));
      conditions.push(
        `(l.name ILIKE ${term} ESCAPE '\\' OR l.description ILIKE ${term} ESCAPE '\\')`,
      );
    }
    if (query.team) {
      conditions.push(`l.team_type = ${bind(parameters, query.team)}`);
    }
    if (query.labStatus) {
      conditions.push(`l.validation_status = ${bind(parameters, query.labStatus)}`);
    }
    if (query.organizationId) {
      conditions.push(`l.organization_id = ${bind(parameters, query.organizationId)}`);
    }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const from = `FROM labs l
      JOIN users u ON u.id = l.owner_user_id
      LEFT JOIN organizations o ON o.id = l.organization_id`;
    const totalResult = await this.pool.query(
      `SELECT count(*) AS total ${from} ${where}`,
      parameters,
    );
    const limit = bind(parameters, query.limit);
    const offset = bind(parameters, query.offset);
    const result = await this.pool.query(
      `SELECT l.id, l.name, l.description, l.team_type,
              l.question_types_json, l.environment, l.access_modes_json,
              l.validation_status, l.owner_user_id, u.handle AS owner_handle,
              l.organization_id, o.name AS organization_name,
              l.admin_quarantined_at, l.admin_quarantined_by,
              l.admin_quarantine_reason, l.created_at, l.updated_at
         ${from} ${where}
        ORDER BY l.created_at DESC, l.id DESC
        LIMIT ${limit} OFFSET ${offset}`,
      parameters,
    );
    return {
      total: Number(totalResult.rows[0].total),
      items: result.rows.map((row: Row) => adminLabFromRow(row)),
    };
  }

  async listAdminRuns(query: AdminPageQuery): Promise<AdminPageResult> {
    const conditions: string[] = [];
    const parameters: unknown[] = [];
    if (query.search) {
      const term = bind(parameters, escapedLike(query.search));
      conditions.push(
        `(r.id ILIKE ${term} ESCAPE '\\'
          OR u.handle ILIKE ${term} ESCAPE '\\'
          OR l.name ILIKE ${term} ESCAPE '\\')`,
      );
    }
    if (query.runStatus) {
      conditions.push(`r.status = ${bind(parameters, query.runStatus)}`);
    }
    if (query.accessMethod) {
      conditions.push(`r.access_method = ${bind(parameters, query.accessMethod)}`);
    }
    if (query.organizationId) {
      conditions.push(`l.organization_id = ${bind(parameters, query.organizationId)}`);
    }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const from = `FROM runtime_runs r
      JOIN labs l ON l.id = r.lab_id
      JOIN users u ON u.id = r.user_id`;
    const totalResult = await this.pool.query(
      `SELECT count(*) AS total ${from} ${where}`,
      parameters,
    );
    const limit = bind(parameters, query.limit);
    const offset = bind(parameters, query.offset);
    const result = await this.pool.query(
      `SELECT r.id, r.lab_id, r.user_id, r.status, r.environment,
              r.access_method, r.expires_at, r.metadata_json, r.created_at,
              l.name AS lab_title, l.organization_id,
              u.handle AS user_handle
         ${from} ${where}
        ORDER BY r.created_at DESC, r.id DESC
        LIMIT ${limit} OFFSET ${offset}`,
      parameters,
    );
    return {
      total: Number(totalResult.rows[0].total),
      items: result.rows.map((row: Row) => adminRunFromRow(row)),
    };
  }

  async listOrganizationMembers(
    organizationId: string,
    query: AdminPageQuery,
  ): Promise<AdminPageResult> {
    const parameters: unknown[] = [organizationId];
    const conditions = ["m.organization_id = $1"];
    if (query.search) {
      const term = bind(parameters, escapedLike(query.search));
      conditions.push(
        `(u.email ILIKE ${term} ESCAPE '\\'
          OR u.handle ILIKE ${term} ESCAPE '\\'
          OR u.display_name ILIKE ${term} ESCAPE '\\')`,
      );
    }
    if (query.membershipRole) {
      conditions.push(`m.role = ${bind(parameters, query.membershipRole)}`);
    }
    const where = `WHERE ${conditions.join(" AND ")}`;
    const from = `FROM organization_memberships m
      JOIN users u ON u.id = m.user_id`;
    const totalResult = await this.pool.query(
      `SELECT count(*) AS total ${from} ${where}`,
      parameters,
    );
    const limit = bind(parameters, query.limit);
    const offset = bind(parameters, query.offset);
    const result = await this.pool.query(
      `SELECT u.id, u.email, u.handle, u.display_name, u.platform_role,
              m.role, m.created_at AS joined_at
         ${from} ${where}
        ORDER BY m.created_at ASC, u.id ASC
        LIMIT ${limit} OFFSET ${offset}`,
      parameters,
    );
    return {
      total: Number(totalResult.rows[0].total),
      items: result.rows.map(organizationMemberFromRow),
    };
  }

  async createOrganization(input: OrganizationCreateInput): Promise<unknown> {
    try {
      await this.pool.query(
        `INSERT INTO organizations
          (id, name, slug, join_code_hash, join_code_rotated_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $5)`,
        [input.id, input.name, input.slug, input.joinCodeHash, input.createdAt],
      );
    } catch (error: unknown) {
      if (
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "23505"
      ) {
        throw new RepositoryError(
          "ORGANIZATION_EXISTS",
          "An organization with that slug already exists.",
          409,
        );
      }
      throw error;
    }
    const result = await this.pool.query(
      `SELECT o.id, o.name, o.slug, o.join_code_rotated_at, o.created_at,
              0 AS member_count, 0 AS lab_count
         FROM organizations o WHERE o.id = $1`,
      [input.id],
    );
    return adminOrganizationFromRow(result.rows[0]);
  }

  async rotateOrganizationJoinCode(
    organizationId: string,
    joinCodeHash: string,
    rotatedAt: string,
  ): Promise<unknown | null> {
    const updated = await this.pool.query(
      `UPDATE organizations
          SET join_code_hash = $1, join_code_rotated_at = $2
        WHERE id = $3 RETURNING id`,
      [joinCodeHash, rotatedAt, organizationId],
    );
    if (updated.rowCount !== 1) return null;
    const result = await this.pool.query(
      `SELECT o.id, o.name, o.slug, o.join_code_rotated_at, o.created_at,
              (SELECT count(*) FROM organization_memberships m
                WHERE m.organization_id = o.id) AS member_count,
              (SELECT count(*) FROM labs l
                WHERE l.organization_id = o.id) AS lab_count
         FROM organizations o WHERE o.id = $1`,
      [organizationId],
    );
    return adminOrganizationFromRow(result.rows[0]);
  }

  async listOrganizationAuditLogs(
    organizationId: string,
    query: AdminPageQuery,
  ): Promise<AdminPageResult> {
    const parameters: unknown[] = [];
    const org = bind(parameters, organizationId);
    const conditions = [
      `a.resource_type IN ('organization', 'organization_membership')`,
      `(a.resource_id = ${org} OR a.metadata_json->>'organizationId' = ${org})`,
    ];
    if (query.search) {
      const term = bind(parameters, escapedLike(query.search));
      conditions.push(
        `(a.resource_id ILIKE ${term} ESCAPE '\'
          OR u.handle ILIKE ${term} ESCAPE '\'
          OR u.display_name ILIKE ${term} ESCAPE '\')`,
      );
    }
    if (query.auditAction) {
      conditions.push(`a.action = ${bind(parameters, query.auditAction)}`);
    }
    const where = `WHERE ${conditions.join(" AND ")}`;
    const from = "FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id";
    const totalResult = await this.pool.query(
      `SELECT count(*) AS total ${from} ${where}`,
      parameters,
    );
    const limit = bind(parameters, query.limit);
    const offset = bind(parameters, query.offset);
    const result = await this.pool.query(
      `SELECT a.id, a.action, a.resource_type, a.resource_id,
              a.metadata_json, a.actor_ip, a.created_at, a.actor_user_id,
              u.handle AS actor_handle, u.display_name AS actor_display_name
         ${from} ${where}
        ORDER BY a.created_at DESC, a.id DESC
        LIMIT ${limit} OFFSET ${offset}`,
      parameters,
    );
    return {
      total: Number(totalResult.rows[0].total),
      items: result.rows.map(auditLogFromRow),
    };
  }

  async recordUserConsent(
    userId: string,
    agreedAt: string,
    termsVersion: string,
    privacyVersion: string,
  ): Promise<unknown | null> {
    const result = await this.pool.query(
      `UPDATE users
          SET terms_agreed_at = $1, terms_version = $2,
              privacy_agreed_at = $1, privacy_version = $3
        WHERE id = $4 RETURNING id`,
      [agreedAt, termsVersion, privacyVersion, userId],
    );
    if (result.rowCount !== 1) return null;
    return this.getUser(userId);
  }

  async getActiveSeason(at: string): Promise<unknown | null> {
    const result = await this.pool.query(
      `SELECT * FROM ranking_seasons
        WHERE starts_at <= $1 AND ends_at > $1
        ORDER BY starts_at DESC LIMIT 1`,
      [at],
    );
    return result.rowCount === 0 ? null : seasonFromRow(result.rows[0]);
  }

  async listSeasons(): Promise<unknown[]> {
    const result = await this.pool.query(
      "SELECT * FROM ranking_seasons ORDER BY starts_at DESC",
    );
    return result.rows.map(seasonFromRow);
  }

  async createSeason(input: SeasonInput): Promise<unknown> {
    const overlap = await this.pool.query(
      "SELECT id FROM ranking_seasons WHERE starts_at < $1 AND ends_at > $2",
      [input.endsAt, input.startsAt],
    );
    if (overlap.rowCount > 0) {
      throw new RepositoryError(
        "SEASON_OVERLAPS",
        "A season already covers part of that period.",
        409,
      );
    }
    try {
      await this.pool.query(
        `INSERT INTO ranking_seasons
          (id, name, slug, starts_at, ends_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [input.id, input.name, input.slug, input.startsAt, input.endsAt, input.createdAt],
      );
    } catch (error: unknown) {
      if (
        typeof error === "object" && error !== null && "code" in error &&
        error.code === "23505"
      ) {
        throw new RepositoryError(
          "SEASON_EXISTS",
          "A season with that slug already exists.",
          409,
        );
      }
      throw error;
    }
    const result = await this.pool.query(
      "SELECT * FROM ranking_seasons WHERE id = $1",
      [input.id],
    );
    return seasonFromRow(result.rows[0]);
  }

  async deleteSeason(seasonId: string): Promise<boolean> {
    const result = await this.pool.query(
      "DELETE FROM ranking_seasons WHERE id = $1",
      [seasonId],
    );
    return result.rowCount === 1;
  }

  async setOrganizationRankingOptIn(
    organizationId: string,
    optIn: boolean,
  ): Promise<unknown | null> {
    const updated = await this.pool.query(
      "UPDATE organizations SET ranking_opt_in = $1 WHERE id = $2 RETURNING id",
      [optIn, organizationId],
    );
    if (updated.rowCount !== 1) return null;
    const result = await this.pool.query(
      `SELECT o.id, o.name, o.slug, o.join_code_rotated_at, o.created_at,
              o.ranking_opt_in,
              (SELECT count(*) FROM organization_memberships m
                WHERE m.organization_id = o.id) AS member_count,
              (SELECT count(*) FROM labs l
                WHERE l.organization_id = o.id) AS lab_count
         FROM organizations o WHERE o.id = $1`,
      [organizationId],
    );
    return adminOrganizationFromRow(result.rows[0]);
  }

  async findAvailableHandle(base: string): Promise<string> {
    const taken = async (candidate: string) =>
      (
        await this.pool.query(
          "SELECT 1 FROM users WHERE lower(handle) = lower($1)",
          [candidate],
        )
      ).rowCount > 0;
    if (!(await taken(base))) return base;
    for (let suffix = 2; suffix < 1000; suffix += 1) {
      const candidate = `${base.slice(0, 24 - String(suffix).length)}${suffix}`;
      if (!(await taken(candidate))) return candidate;
    }
    return `${base.slice(0, 14)}${randomUUID().slice(0, 8)}`;
  }

  async listAdminAuditLogs(query: AdminPageQuery): Promise<AdminPageResult> {
    const parameters: unknown[] = [];
    const conditions: string[] = [];
    if (query.search) {
      const term = bind(parameters, escapedLike(query.search));
      conditions.push(
        `(a.resource_id ILIKE ${term} ESCAPE '\\'
          OR u.handle ILIKE ${term} ESCAPE '\\'
          OR u.display_name ILIKE ${term} ESCAPE '\\')`,
      );
    }
    if (query.auditAction) {
      conditions.push(`a.action = ${bind(parameters, query.auditAction)}`);
    }
    if (query.auditResourceType) {
      conditions.push(
        `a.resource_type = ${bind(parameters, query.auditResourceType)}`,
      );
    }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const from = "FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id";
    const totalResult = await this.pool.query(
      `SELECT count(*) AS total ${from} ${where}`,
      parameters,
    );
    const limit = bind(parameters, query.limit);
    const offset = bind(parameters, query.offset);
    const result = await this.pool.query(
      `SELECT a.id, a.action, a.resource_type, a.resource_id,
              a.metadata_json, a.actor_ip, a.created_at, a.actor_user_id,
              u.handle AS actor_handle, u.display_name AS actor_display_name
         ${from} ${where}
        ORDER BY a.created_at DESC, a.id DESC
        LIMIT ${limit} OFFSET ${offset}`,
      parameters,
    );
    return {
      total: Number(totalResult.rows[0].total),
      items: result.rows.map(auditLogFromRow),
    };
  }

  async releaseLabQuarantine(
    labId: string,
    releasedAt: string,
  ): Promise<unknown | null> {
    const result = await this.pool.query(
      `UPDATE labs
          SET validation_status = 'draft', updated_at = $1,
              admin_quarantined_at = NULL, admin_quarantined_by = NULL,
              admin_quarantine_reason = NULL
        WHERE id = $2 AND validation_status = 'quarantined'
        RETURNING id`,
      [releasedAt, labId],
    );
    if (result.rowCount !== 1) return null;
    const selected = await this.pool.query(
      `SELECT l.id, l.name, l.description, l.team_type,
              l.question_types_json, l.environment, l.access_modes_json,
              l.validation_status, l.owner_user_id, u.handle AS owner_handle,
              l.organization_id, o.name AS organization_name,
              l.admin_quarantined_at, l.admin_quarantined_by,
              l.admin_quarantine_reason, l.created_at, l.updated_at
         FROM labs l
         JOIN users u ON u.id = l.owner_user_id
         LEFT JOIN organizations o ON o.id = l.organization_id
        WHERE l.id = $1`,
      [labId],
    );
    return adminLabFromRow(selected.rows[0]);
  }

  async getAdminUser(userId: string): Promise<unknown | null> {
    const result = await this.pool.query(
      `SELECT ${ADMIN_USER_COLUMNS} ${ADMIN_USER_FROM} WHERE u.id = $1`,
      [userId],
    );
    if (result.rowCount === 0) return null;
    return adminUserFromRow(result.rows[0]);
  }

  async setUserPlatformRole(
    userId: string,
    platformRole: "user" | "platform_admin",
  ): Promise<unknown | null> {
    const result = await this.pool.query(
      "UPDATE users SET platform_role = $1 WHERE id = $2 RETURNING id",
      [platformRole, userId],
    );
    if (result.rowCount !== 1) return null;
    return this.getAdminUser(userId);
  }

  async setUserDisabled(
    userId: string,
    disabled: boolean,
    actorUserId: string,
    reason: string,
    changedAt: string,
  ): Promise<unknown | null> {
    const result = await this.pool.query(
      `UPDATE users
          SET disabled_at = $1, disabled_by = $2, disabled_reason = $3
        WHERE id = $4 RETURNING id`,
      [
        disabled ? changedAt : null,
        disabled ? actorUserId : null,
        disabled ? reason : null,
        userId,
      ],
    );
    if (result.rowCount !== 1) return null;
    return this.getAdminUser(userId);
  }

  async getOrganizationMember(
    organizationId: string,
    userId: string,
  ): Promise<unknown | null> {
    const result = await this.pool.query(
      `SELECT u.id, u.email, u.handle, u.display_name, u.platform_role,
              m.role, m.created_at AS joined_at
         FROM organization_memberships m
         JOIN users u ON u.id = m.user_id
        WHERE m.organization_id = $1 AND m.user_id = $2`,
      [organizationId, userId],
    );
    if (result.rowCount === 0) return null;
    return organizationMemberFromRow(result.rows[0]);
  }

  async setOrganizationMemberRole(
    organizationId: string,
    userId: string,
    role: "org_admin" | "member",
  ): Promise<unknown | null> {
    const result = await this.pool.query(
      `UPDATE organization_memberships SET role = $1
        WHERE organization_id = $2 AND user_id = $3 AND role <> 'owner'
        RETURNING user_id`,
      [role, organizationId, userId],
    );
    if (result.rowCount !== 1) return null;
    return this.getOrganizationMember(organizationId, userId);
  }

  async removeOrganizationMember(
    organizationId: string,
    userId: string,
  ): Promise<boolean> {
    const result = await this.pool.query(
      `DELETE FROM organization_memberships
        WHERE organization_id = $1 AND user_id = $2 AND role <> 'owner'`,
      [organizationId, userId],
    );
    return result.rowCount === 1;
  }

  async quarantineLab(
    labId: string,
    quarantinedAt: string,
    actorUserId: string,
    reason: string,
  ): Promise<unknown | null> {
    const result = await this.pool.query(
      `UPDATE labs
          SET validation_status = 'quarantined', updated_at = $1,
              admin_quarantined_at = $1, admin_quarantined_by = $2,
              admin_quarantine_reason = $3
        WHERE id = $4
        RETURNING id`,
      [quarantinedAt, actorUserId, reason, labId],
    );
    if (result.rowCount !== 1) return null;
    const selected = await this.pool.query(
      `SELECT l.id, l.name, l.description, l.team_type,
              l.question_types_json, l.environment, l.access_modes_json,
              l.validation_status, l.owner_user_id, u.handle AS owner_handle,
              l.organization_id, o.name AS organization_name,
              l.admin_quarantined_at, l.admin_quarantined_by,
              l.admin_quarantine_reason, l.created_at, l.updated_at
         FROM labs l
         JOIN users u ON u.id = l.owner_user_id
         LEFT JOIN organizations o ON o.id = l.organization_id
        WHERE l.id = $1`,
      [labId],
    );
    return adminLabFromRow(selected.rows[0]);
  }

  async getAdminRun(runId: string): Promise<unknown | null> {
    const result = await this.pool.query(
      `SELECT r.id, r.lab_id, r.user_id, r.status, r.environment,
              r.access_method, r.expires_at, r.metadata_json, r.created_at,
              l.name AS lab_title, l.organization_id,
              u.handle AS user_handle
         FROM runtime_runs r
         JOIN labs l ON l.id = r.lab_id
         JOIN users u ON u.id = r.user_id
        WHERE r.id = $1`,
      [runId],
    );
    return adminRunFromRow(result.rows[0]);
  }

  async listExpiredRunIds(now: string, limit: number): Promise<string[]> {
    const result = await this.pool.query(
      `SELECT id FROM runtime_runs
        WHERE status IN ('provisioning', 'ready') AND expires_at <= $1
        ORDER BY expires_at ASC LIMIT $2`,
      [now, limit],
    );
    return result.rows.map((row: Row) => String(row.id));
  }

  async listActiveRunIdsForUser(userId: string): Promise<string[]> {
    const result = await this.pool.query(
      `SELECT id FROM runtime_runs
        WHERE user_id = $1 AND status IN ('provisioning', 'ready')
        ORDER BY created_at ASC`,
      [userId],
    );
    return result.rows.map((row: Row) => String(row.id));
  }

  async markRunExpired(runId: string, expiredAt: string): Promise<unknown | null> {
    await this.pool.query(
      `UPDATE runtime_runs
          SET status = 'expired', browser_url = NULL,
              openvpn_profile_json = NULL,
              metadata_json = metadata_json || jsonb_build_object(
                'termination',
                jsonb_build_object(
                  'actorUserId', NULL,
                  'stoppedAt', $1::text,
                  'reason', 'ttl_expired'
                )
              )
        WHERE id = $2 AND status NOT IN ('stopped', 'expired')`,
      [expiredAt, runId],
    );
    return this.getAdminRun(runId);
  }

  async markRunStopped(
    runId: string,
    stoppedAt: string,
    actorUserId: string,
    reason = "platform_admin",
  ): Promise<unknown | null> {
    const result = await this.pool.query(
      `UPDATE runtime_runs
          SET status = 'stopped', browser_url = NULL,
              openvpn_profile_json = NULL,
              metadata_json = metadata_json || jsonb_build_object(
                'termination',
                jsonb_build_object(
                  'actorUserId', $1::text,
                  'stoppedAt', $2::text,
                  'reason', $4::text
                )
              )
        WHERE id = $3 AND status NOT IN ('stopped', 'expired')
        RETURNING id`,
      [actorUserId, stoppedAt, runId, reason],
    );
    if (result.rowCount === 0) {
      const existing = await this.getAdminRun(runId);
      if (!existing) return null;
    }
    return this.getAdminRun(runId);
  }

  async getIdempotencyRecord(
    userId: string,
    operation: string,
    key: string,
  ): Promise<IdempotencyRecord | null> {
    const result = await this.pool.query(
      `SELECT request_hash, resource_id, response_json, created_at
         FROM idempotency_records
        WHERE user_id = $1 AND operation = $2 AND idempotency_key = $3`,
      [userId, operation, key],
    );
    const row = result.rows[0] as Row | undefined;
    if (!row) return null;
    return {
      requestHash: String(row.request_hash),
      resourceId: String(row.resource_id),
      response: jsonValue(row.response_json, null),
      createdAt: timestamp(row.created_at),
    };
  }

  async saveIdempotencyRecord(
    userId: string,
    operation: string,
    key: string,
    requestHash: string,
    resourceId: string,
    response: unknown,
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO idempotency_records
        (user_id, operation, idempotency_key, request_hash, resource_id,
         response_json, created_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
      [
        userId,
        operation,
        key,
        requestHash,
        resourceId,
        JSON.stringify(response),
        nowIso(),
      ],
    );
  }

  async recordAudit(event: AuditEvent): Promise<void> {
    await this.pool.query(
      `INSERT INTO audit_logs
        (id, actor_user_id, action, resource_type, resource_id, metadata_json,
         actor_ip, created_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
      [
        `audit_${randomUUID()}`,
        event.actorUserId,
        event.action,
        event.resourceType,
        event.resourceId,
        JSON.stringify(event.metadata ?? {}),
        event.actorIp ?? null,
        nowIso(),
      ],
    );
  }

  async close(): Promise<void> {
    if (this.pool) await this.pool.end();
  }
}

function persistedReadiness(readiness: RuntimeRunStatusInput): Record<string, unknown> {
  return {
    status: readiness.status,
    namespace: readiness.namespace,
    expiresAt: readiness.expiresAt,
    checks: readiness.checks,
    reason: readiness.reason ?? null,
    checkedAt: new Date().toISOString(),
  };
}

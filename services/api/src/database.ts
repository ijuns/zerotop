import { createHash, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { RepositoryError } from "./errors.ts";
import { hashOrganizationJoinCode } from "./security.ts";
import {
  buildDevelopmentCapabilityFixtures,
  DEVELOPMENT_FIXTURE_CREATED_AT,
  DEVELOPMENT_FIXTURE_PASSWORD,
  DEVELOPMENT_ORGANIZATIONS,
  DEVELOPMENT_USERS,
} from "./development-fixtures.ts";

import {
  DEV_USER_ID,
  type LabGenerationInput,
  type RegistrationInput,
  type RuntimeRunInput,
  type RuntimeRunStatusInput,
  type ValidationEvidenceInput,
  type ChallengeResultInput,
  type IdentityOnboardingInput,
  type AccessTicketInput,
  type AdminPageQuery,
  type AdminPageResult,
  type OrganizationCreateInput,
  type JsonObject,
} from "./types.ts";
import type {
  AuditEvent,
  IdempotencyRecord,
  PlatformRepository,
  ReportingDatasetFilter,
} from "./ports.ts";

type Row = Record<string, unknown>;

function nowIso(): string {
  return new Date().toISOString();
}

function parseJson<T>(value: unknown, fallback: T): T {
  if (typeof value !== "string") return fallback;

  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function passwordDigest(password: string | undefined): string | null {
  if (!password) return null;
  return createHash("sha256").update(password, "utf8").digest("hex");
}

function ensureColumn(
  database: DatabaseSync,
  table: "users" | "organizations" | "labs" | "challenge_results",
  column: string,
  definition: string,
): void {
  const columns = database.prepare(`PRAGMA table_info(${table})`).all() as Row[];
  if (!columns.some((item) => item.name === column)) {
    database.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

function migrateOrganizationJoinCodes(database: DatabaseSync): void {
  let columns = database.prepare("PRAGMA table_info(organizations)").all() as Row[];
  const hasLegacyJoinCode = columns.some((item) => item.name === "join_code");
  if (!columns.some((item) => item.name === "join_code_hash")) {
    database.exec("ALTER TABLE organizations ADD COLUMN join_code_hash TEXT");
    const rows = database
      .prepare("SELECT id, join_code FROM organizations")
      .all() as Row[];
    const update = database.prepare(
      "UPDATE organizations SET join_code_hash = ? WHERE id = ?",
    );
    for (const row of rows) {
      update.run(hashOrganizationJoinCode(String(row.join_code)), String(row.id));
    }
  }
  columns = database.prepare("PRAGMA table_info(organizations)").all() as Row[];
  if (!columns.some((item) => item.name === "join_code_rotated_at")) {
    database.exec("ALTER TABLE organizations ADD COLUMN join_code_rotated_at TEXT");
  }
  database.exec(
    "UPDATE organizations SET join_code_rotated_at = created_at WHERE join_code_rotated_at IS NULL",
  );
  database.exec(
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_join_code_hash
       ON organizations(join_code_hash)`,
  );
  if (hasLegacyJoinCode) {
    database.exec(
      "UPDATE organizations SET join_code = join_code_hash WHERE join_code <> join_code_hash",
    );
  }
}

function userFromRow(row: Row | undefined): JsonValue | null {
  if (!row) return null;

  const organization = row.organization_id
    ? {
        id: row.organization_id,
        name: row.organization_name,
        slug: row.organization_slug,
        role: row.organization_role,
      }
    : null;

  return {
    id: row.id,
    email: row.email,
    handle: row.handle,
    displayName: row.display_name,
    platformRole: row.platform_role ?? "user",
    globalRankingOptIn: row.global_ranking_opt_in === 1,
    createdAt: row.created_at,
    organization,
  };
}

function labFromRow(row: Row | undefined): JsonValue | null {
  if (!row) return null;

  const questionTypes = parseJson<unknown[]>(row.question_types_json, []);
  const accessModes = parseJson<string[]>(row.access_modes_json, []);
  const storedConfig = parseJson<Record<string, unknown>>(row.config_json, {});
  const { builderSpec: _hiddenBuilderSpec, ...config } = storedConfig;
  const scenario =
    typeof config.scenario === "object" && config.scenario !== null
      ? (config.scenario as Record<string, unknown>)
      : {};
  const learning =
    typeof config.learning === "object" && config.learning !== null
      ? config.learning
      : undefined;
  const target =
    typeof config.target === "object" && config.target !== null
      ? config.target
      : undefined;
  const questions = Array.isArray(config.questions) ? config.questions : undefined;
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
      summary: scenario.summary ?? scenario.objective ?? row.description,
      logSources: Array.isArray(scenario.logSources)
        ? scenario.logSources
        : row.team_type === "blue" ? ["elasticsearch", "endpoint"] : [],
      attackChain: Array.isArray(scenario.attackChain)
        ? scenario.attackChain
        : Array.isArray(scenario.mitreTechniques)
          ? scenario.mitreTechniques.map((id) => ({ id, name: id, tactic: "unknown" }))
          : [],
    },
    ...(learning ? { learning } : {}),
    ...(target ? { target } : {}),
    ...(questions ? { questions } : {}),
    // Compatibility aliases for the pre-contract web client.
    name: row.name,
    description: row.description,
    teamType: row.team_type,
    environment: row.environment,
    accessModes,
    validationStatus: row.validation_status,
    config,
    owner: {
      id: row.owner_user_id,
      displayName: row.owner_display_name,
    },
    organization: row.organization_id
      ? { id: row.organization_id, name: row.organization_name }
      : null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function evidenceFromRow(row: Row): JsonValue {
  return {
    id: row.id,
    check: row.check_name,
    outcome: row.outcome,
    details: parseJson(row.details_json, {}),
    createdAt: row.created_at,
  };
}

function runFromRow(row: Row | undefined): JsonValue | null {
  if (!row) return null;

  const metadata = parseJson<Record<string, unknown>>(row.metadata_json, {});
  const browserDesktop = row.browser_url
    ? {
        protocol: "noVNC",
        url: row.browser_url,
        desktop: metadata.desktop,
      }
    : null;
  const openVpn = parseJson<Record<string, unknown> | null>(
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
    browserDesktop,
    openVpn,
    openvpn: openVpn,
    expiresAt: row.expires_at,
    metadata,
    createdAt: row.created_at,
  };
}

function adminOrganizationFromRow(row: Row | undefined): JsonValue | null {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    memberCount: Number(row.member_count ?? 0),
    labCount: Number(row.lab_count ?? 0),
    joinCodeRotatedAt: row.join_code_rotated_at,
    createdAt: row.created_at,
  };
}

function adminLabFromRow(row: Row | undefined): JsonValue | null {
  if (!row) return null;
  return {
    id: row.id,
    title: row.name,
    prompt: row.description,
    team: row.team_type,
    questionTypes: parseJson(row.question_types_json, []),
    desktopImage: row.environment,
    accessModes: parseJson(row.access_modes_json, []),
    validationStatus: row.validation_status,
    owner: { id: row.owner_user_id, handle: row.owner_handle },
    organization: row.organization_id
      ? { id: row.organization_id, name: row.organization_name }
      : null,
    adminQuarantine: row.admin_quarantined_at
      ? {
          quarantinedAt: row.admin_quarantined_at,
          quarantinedBy: row.admin_quarantined_by,
          reason: row.admin_quarantine_reason,
        }
      : null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function adminRunFromRow(row: Row | undefined): JsonValue | null {
  if (!row) return null;
  const metadata = parseJson<Record<string, unknown>>(row.metadata_json, {});
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
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
}

function escapedLike(value: string): string {
  return `%${value.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_")}%`;
}

type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | { [key: string]: JsonValue | unknown };

export function createDatabase(databasePath: string): DatabaseSync {
  if (databasePath !== ":memory:") {
    const absolutePath = resolve(databasePath);
    mkdirSync(dirname(absolutePath), { recursive: true });
  }

  const database = new DatabaseSync(databasePath);
  database.exec("PRAGMA foreign_keys = ON");
  database.exec("PRAGMA journal_mode = WAL");
  database.exec("PRAGMA busy_timeout = 5000");
  return database;
}

/** Development-only persistence adapter. Production deployments should provide PostgreSQL. */
export class SqliteDevelopmentRepository implements PlatformRepository {
  readonly database: DatabaseSync;

  constructor(database: DatabaseSync) {
    this.database = database;
  }

  initialize(): void {
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        handle TEXT NOT NULL UNIQUE COLLATE NOCASE,
        display_name TEXT NOT NULL,
        password_hash TEXT,
        external_subject TEXT,
        platform_role TEXT NOT NULL DEFAULT 'user'
          CHECK (platform_role IN ('user', 'platform_admin')),
        global_ranking_opt_in INTEGER NOT NULL DEFAULT 0
          CHECK (global_ranking_opt_in IN (0, 1)),
        created_at TEXT NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS organizations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT NOT NULL UNIQUE COLLATE NOCASE,
        join_code_hash TEXT NOT NULL UNIQUE,
        join_code_rotated_at TEXT NOT NULL,
        created_at TEXT NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS organization_memberships (
        user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK (role IN ('owner', 'org_admin', 'member')),
        created_at TEXT NOT NULL,
        UNIQUE (organization_id, user_id)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS labs (
        id TEXT PRIMARY KEY,
        owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        organization_id TEXT REFERENCES organizations(id) ON DELETE SET NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        team_type TEXT NOT NULL CHECK (team_type IN ('blue', 'red')),
        question_types_json TEXT NOT NULL,
        environment TEXT NOT NULL CHECK (environment IN ('ubuntu', 'kali')),
        access_modes_json TEXT NOT NULL,
        validation_status TEXT NOT NULL DEFAULT 'draft'
          CHECK (validation_status IN ('draft', 'validated', 'quarantined')),
        config_json TEXT NOT NULL,
        grading_config_json TEXT NOT NULL DEFAULT '{"questions":[]}',
        admin_quarantined_at TEXT,
        admin_quarantined_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        admin_quarantine_reason TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS validation_evidence (
        id TEXT PRIMARY KEY,
        lab_id TEXT NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
        check_name TEXT NOT NULL,
        outcome TEXT NOT NULL CHECK (outcome IN ('pass', 'fail')),
        details_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE (lab_id, check_name)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS runtime_runs (
        id TEXT PRIMARY KEY,
        lab_id TEXT NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        status TEXT NOT NULL CHECK (status IN ('provisioning', 'ready', 'failed', 'stopped', 'expired')),
        environment TEXT NOT NULL CHECK (environment IN ('ubuntu', 'kali')),
        access_method TEXT NOT NULL CHECK (access_method IN ('browser_desktop', 'openvpn', 'both')),
        browser_url TEXT,
        openvpn_profile_json TEXT,
        expires_at TEXT NOT NULL,
        metadata_json TEXT NOT NULL,
        created_at TEXT NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS challenge_results (
        id TEXT PRIMARY KEY,
        lab_id TEXT NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        run_id TEXT REFERENCES runtime_runs(id) ON DELETE SET NULL,
        score INTEGER NOT NULL CHECK (score >= 0),
        max_score INTEGER NOT NULL CHECK (max_score > 0 AND score <= max_score),
        answers_json TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        skills_json TEXT NOT NULL DEFAULT '{}',
        completed_at TEXT NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS idempotency_records (
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        operation TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        response_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (user_id, operation, idempotency_key)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
        action TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        metadata_json TEXT NOT NULL,
        created_at TEXT NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS trusted_grade_evidence (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL REFERENCES runtime_runs(id) ON DELETE CASCADE,
        question_id TEXT NOT NULL,
        source TEXT NOT NULL CHECK (source IN ('elk', 'ai_rubric')),
        passed INTEGER NOT NULL CHECK (passed IN (0, 1)),
        score_ratio REAL NOT NULL CHECK (score_ratio >= 0 AND score_ratio <= 1),
        policy_version TEXT NOT NULL,
        evidence_reference TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE (run_id, question_id)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS score_events (
        id TEXT PRIMARY KEY,
        result_id TEXT NOT NULL REFERENCES challenge_results(id) ON DELETE RESTRICT,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
        organization_id TEXT REFERENCES organizations(id) ON DELETE RESTRICT,
        event_type TEXT NOT NULL CHECK (event_type = 'challenge.graded'),
        points_delta INTEGER NOT NULL CHECK (points_delta >= 0),
        max_points INTEGER NOT NULL CHECK (max_points > 0),
        payload_json TEXT NOT NULL,
        occurred_at TEXT NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS access_tickets (
        ticket_hash TEXT PRIMARY KEY,
        run_id TEXT NOT NULL REFERENCES runtime_runs(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('desktop', 'openvpn')),
        expires_at TEXT NOT NULL,
        consumed_at TEXT,
        created_at TEXT NOT NULL
      ) STRICT;

      CREATE INDEX IF NOT EXISTS idx_memberships_organization
        ON organization_memberships(organization_id);
      CREATE INDEX IF NOT EXISTS idx_labs_owner ON labs(owner_user_id);
      CREATE INDEX IF NOT EXISTS idx_labs_organization ON labs(organization_id);
      CREATE INDEX IF NOT EXISTS idx_evidence_lab ON validation_evidence(lab_id);
      CREATE INDEX IF NOT EXISTS idx_runs_lab_user ON runtime_runs(lab_id, user_id);
      CREATE INDEX IF NOT EXISTS idx_results_lab_user ON challenge_results(lab_id, user_id);
      CREATE INDEX IF NOT EXISTS idx_audit_resource
        ON audit_logs(resource_type, resource_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_score_events_user_time
        ON score_events(user_id, occurred_at);
      CREATE INDEX IF NOT EXISTS idx_score_events_organization_time
        ON score_events(organization_id, occurred_at);
      CREATE INDEX IF NOT EXISTS idx_access_tickets_expiry
        ON access_tickets(expires_at) WHERE consumed_at IS NULL;

      CREATE TRIGGER IF NOT EXISTS score_events_no_update
      BEFORE UPDATE ON score_events
      BEGIN
        SELECT RAISE(ABORT, 'score_events are append-only');
      END;

      CREATE TRIGGER IF NOT EXISTS score_events_no_delete
      BEFORE DELETE ON score_events
      BEGIN
        SELECT RAISE(ABORT, 'score_events are append-only');
      END;
    `);

    ensureColumn(
      this.database,
      "users",
      "platform_role",
      "TEXT NOT NULL DEFAULT 'user' CHECK (platform_role IN ('user', 'platform_admin'))",
    );
    ensureColumn(this.database, "users", "external_subject", "TEXT");
    this.database.exec(
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_subject
         ON users(external_subject) WHERE external_subject IS NOT NULL`,
    );
    ensureColumn(
      this.database,
      "users",
      "global_ranking_opt_in",
      "INTEGER NOT NULL DEFAULT 0 CHECK (global_ranking_opt_in IN (0, 1))",
    );
    ensureColumn(this.database, "challenge_results", "run_id", "TEXT");
    ensureColumn(
      this.database,
      "labs",
      "grading_config_json",
      "TEXT NOT NULL DEFAULT '{\"questions\":[]}'",
    );
    ensureColumn(this.database, "labs", "admin_quarantined_at", "TEXT");
    ensureColumn(this.database, "labs", "admin_quarantined_by", "TEXT");
    ensureColumn(this.database, "labs", "admin_quarantine_reason", "TEXT");
    ensureColumn(
      this.database,
      "challenge_results",
      "skills_json",
      "TEXT NOT NULL DEFAULT '{}'",
    );
    this.database.exec(
      "CREATE INDEX IF NOT EXISTS idx_results_run ON challenge_results(run_id)",
    );
    this.database.exec(
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_results_run_unique
         ON challenge_results(run_id) WHERE run_id IS NOT NULL`,
    );
    migrateOrganizationJoinCodes(this.database);

    const organizationColumns = this.database
      .prepare("PRAGMA table_info(organizations)")
      .all() as Row[];
    const hasLegacyJoinCode = organizationColumns.some(
      (item) => item.name === "join_code",
    );
    const organizationInsert = this.database.prepare(
      hasLegacyJoinCode
        ? `INSERT OR IGNORE INTO organizations
            (id, name, slug, join_code, join_code_hash,
             join_code_rotated_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        : `INSERT OR IGNORE INTO organizations
            (id, name, slug, join_code_hash, join_code_rotated_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
    );
    for (const organization of DEVELOPMENT_ORGANIZATIONS) {
      const joinCodeHash = hashOrganizationJoinCode(organization.joinCode);
      organizationInsert.run(
        organization.id,
        organization.name,
        organization.slug,
        ...(hasLegacyJoinCode ? [joinCodeHash] : []),
        joinCodeHash,
        DEVELOPMENT_FIXTURE_CREATED_AT,
        DEVELOPMENT_FIXTURE_CREATED_AT,
      );
    }

    const userInsert = this.database.prepare(
      `INSERT OR IGNORE INTO users
        (id, email, handle, display_name, password_hash, platform_role,
         global_ranking_opt_in, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const membershipInsert = this.database.prepare(
      `INSERT OR IGNORE INTO organization_memberships
        (user_id, organization_id, role, created_at)
       VALUES (?, ?, ?, ?)`,
    );
    for (const user of DEVELOPMENT_USERS) {
      userInsert.run(
        user.id,
        user.email,
        user.handle,
        user.displayName,
        passwordDigest(DEVELOPMENT_FIXTURE_PASSWORD),
        user.platformRole,
        user.globalRankingOptIn ? 1 : 0,
        DEVELOPMENT_FIXTURE_CREATED_AT,
      );
      if (user.organizationId && user.organizationRole) {
        membershipInsert.run(
          user.id,
          user.organizationId,
          user.organizationRole,
          DEVELOPMENT_FIXTURE_CREATED_AT,
        );
      }
    }

    // Refresh the well-known development actor when upgrading an existing local
    // database so the visible profile matches the current sample data.
    const developmentActor = DEVELOPMENT_USERS.find(
      (user) => user.id === DEV_USER_ID,
    );
    if (!developmentActor) {
      throw new Error("The development fixture must include DEV_USER_ID.");
    }
    this.database
      .prepare(
        `UPDATE users
            SET email = ?, handle = ?, display_name = ?, password_hash = ?,
                platform_role = 'platform_admin', global_ranking_opt_in = 1
          WHERE id = ?`,
      )
      .run(
        developmentActor.email,
        developmentActor.handle,
        developmentActor.displayName,
        passwordDigest(DEVELOPMENT_FIXTURE_PASSWORD),
        DEV_USER_ID,
      );
  }

  /** Adds refreshable score/report fixtures only when explicitly requested. */
  seedDevelopmentCapabilityData(seedTime = new Date()): void {
    const fixtures = buildDevelopmentCapabilityFixtures(seedTime);
    const labById = new Map(fixtures.labs.map((lab) => [lab.id, lab]));
    const labInsert = this.database.prepare(
      `INSERT INTO labs
        (id, owner_user_id, organization_id, name, description, team_type,
         question_types_json, environment, access_modes_json, validation_status,
         config_json, grading_config_json, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'validated', ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         owner_user_id = excluded.owner_user_id,
         organization_id = excluded.organization_id,
         name = excluded.name,
         description = excluded.description,
         team_type = excluded.team_type,
         question_types_json = excluded.question_types_json,
         environment = excluded.environment,
         access_modes_json = excluded.access_modes_json,
         validation_status = 'validated',
         config_json = excluded.config_json,
         grading_config_json = excluded.grading_config_json,
         updated_at = excluded.updated_at`,
    );
    const validationInsert = this.database.prepare(
      `INSERT INTO validation_evidence
        (id, lab_id, check_name, outcome, details_json, created_at)
       VALUES (?, ?, 'ai-autonomous-validation', 'pass', ?, ?)
       ON CONFLICT(lab_id, check_name) DO UPDATE SET
         outcome = 'pass', details_json = excluded.details_json,
         created_at = excluded.created_at`,
    );
    const runInsert = this.database.prepare(
      `INSERT INTO runtime_runs
        (id, lab_id, user_id, status, environment, access_method, browser_url,
         openvpn_profile_json, expires_at, metadata_json, created_at)
       VALUES (?, ?, ?, 'stopped', ?, 'browser_desktop', NULL, NULL, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         lab_id = excluded.lab_id,
         user_id = excluded.user_id,
         status = 'stopped',
         environment = excluded.environment,
         access_method = 'browser_desktop',
         browser_url = NULL,
         openvpn_profile_json = NULL,
         expires_at = excluded.expires_at,
         metadata_json = excluded.metadata_json,
         created_at = excluded.created_at`,
    );
    const resultInsert = this.database.prepare(
      `INSERT INTO challenge_results
        (id, lab_id, user_id, run_id, score, max_score, answers_json,
         evidence_json, skills_json, completed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         lab_id = excluded.lab_id,
         user_id = excluded.user_id,
         run_id = excluded.run_id,
         score = excluded.score,
         max_score = excluded.max_score,
         answers_json = excluded.answers_json,
         evidence_json = excluded.evidence_json,
         skills_json = excluded.skills_json,
         completed_at = excluded.completed_at`,
    );
    const trustedEvidenceInsert = this.database.prepare(
      `INSERT INTO trusted_grade_evidence
        (id, run_id, question_id, source, passed, score_ratio, policy_version,
         evidence_reference, created_at)
       VALUES (?, ?, 'fixture-q1', ?, 1, ?, 'development-seed-v1', ?, ?)
       ON CONFLICT(run_id, question_id) DO UPDATE SET
         source = excluded.source,
         passed = excluded.passed,
         score_ratio = excluded.score_ratio,
         policy_version = excluded.policy_version,
         evidence_reference = excluded.evidence_reference,
         created_at = excluded.created_at`,
    );

    this.database.exec("BEGIN IMMEDIATE");
    try {
      for (const lab of fixtures.labs) {
        labInsert.run(
          lab.id,
          lab.ownerUserId,
          lab.organizationId,
          lab.name,
          lab.description,
          lab.teamType,
          JSON.stringify(lab.questionTypes),
          lab.environment,
          JSON.stringify(["browser_desktop"]),
          JSON.stringify(lab.config),
          JSON.stringify({ questions: lab.gradingQuestions }),
          DEVELOPMENT_FIXTURE_CREATED_AT,
          seedTime.toISOString(),
        );
        validationInsert.run(
          `validation_seed_${lab.id}`,
          lab.id,
          JSON.stringify({
            validator: "ZeroTOP AI Safety Validator",
            policyVersion: "development-seed-v1",
            checks: ["isolation", "health", "grading-contract"],
          }),
          seedTime.toISOString(),
        );
      }

      for (const attempt of fixtures.attempts) {
        const lab = labById.get(attempt.labId);
        if (!lab) throw new Error(`Development capability lab ${attempt.labId} is missing.`);
        runInsert.run(
          attempt.runId,
          attempt.labId,
          attempt.userId,
          lab.environment,
          attempt.runExpiresAt,
          JSON.stringify({
            fixture: true,
            completionStatus: "verified",
            namespace: `zerotop-seed-${attempt.runId}`,
          }),
          attempt.runCreatedAt,
        );
        resultInsert.run(
          attempt.id,
          attempt.labId,
          attempt.userId,
          attempt.runId,
          attempt.score,
          attempt.maxScore,
          JSON.stringify([{ questionId: "fixture-q1", response: "verified-fixture" }]),
          JSON.stringify({
            verified: true,
            source: lab.teamType === "blue" ? "elk" : "ai_rubric",
            policyVersion: "development-seed-v1",
          }),
          JSON.stringify(attempt.skills),
          attempt.completedAt,
        );
        trustedEvidenceInsert.run(
          `trusted_seed_${attempt.runId}`,
          attempt.runId,
          lab.teamType === "blue" ? "elk" : "ai_rubric",
          attempt.score / attempt.maxScore,
          `development-fixture/${attempt.runId}/fixture-q1`,
          attempt.completedAt,
        );
      }
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  getUser(userId: string): JsonValue | null {
    const row = this.database
      .prepare(
        `SELECT u.*, m.role AS organization_role,
                o.id AS organization_id, o.name AS organization_name,
                o.slug AS organization_slug
           FROM users u
           LEFT JOIN organization_memberships m ON m.user_id = u.id
           LEFT JOIN organizations o ON o.id = m.organization_id
          WHERE u.id = ?`,
      )
      .get(userId) as Row | undefined;

    return userFromRow(row);
  }

  getUserByExternalSubject(subject: string): JsonValue | null {
    const row = this.database
      .prepare(
        `SELECT u.*, m.role AS organization_role,
                o.id AS organization_id, o.name AS organization_name,
                o.slug AS organization_slug
           FROM users u
           LEFT JOIN organization_memberships m ON m.user_id = u.id
           LEFT JOIN organizations o ON o.id = m.organization_id
          WHERE u.external_subject = ?`,
      )
      .get(subject) as Row | undefined;
    return userFromRow(row);
  }

  register(input: RegistrationInput): JsonValue {
    const duplicate = this.database
      .prepare("SELECT id FROM users WHERE email = ? OR handle = ?")
      .get(input.email, input.handle) as Row | undefined;

    if (duplicate) {
      throw new RepositoryError(
        "ACCOUNT_EXISTS",
        "An account with that email or handle already exists.",
        409,
      );
    }

    let organization: Row | undefined;
    if (input.accountType === "organization") {
      if (input.organizationId) {
        organization = this.database
          .prepare("SELECT id, name FROM organizations WHERE id = ?")
          .get(input.organizationId) as Row | undefined;
      } else if (input.organizationJoinCode) {
        organization = this.database
          .prepare("SELECT id, name FROM organizations WHERE join_code_hash = ?")
          .get(hashOrganizationJoinCode(input.organizationJoinCode)) as Row | undefined;
      }

      if (!organization) {
        throw new RepositoryError(
          "ORGANIZATION_NOT_FOUND",
          "The organization or join code was not found.",
          404,
        );
      }
    }

    const id = `user_${randomUUID()}`;
    const createdAt = nowIso();
    this.database.exec("BEGIN IMMEDIATE");

    try {
      this.database
        .prepare(
          `INSERT INTO users
            (id, email, handle, display_name, password_hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(
          id,
          input.email,
          input.handle,
          input.displayName,
          passwordDigest(input.password),
          createdAt,
        );

      if (organization) {
        this.database
          .prepare(
            `INSERT INTO organization_memberships
              (user_id, organization_id, role, created_at)
             VALUES (?, ?, 'member', ?)`,
          )
          .run(id, String(organization.id), createdAt);
      }

      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }

    return this.getUser(id) as JsonValue;
  }

  onboardIdentity(input: IdentityOnboardingInput): JsonValue {
    if (this.getUserByExternalSubject(input.externalSubject)) {
      throw new RepositoryError(
        "IDENTITY_ALREADY_ONBOARDED",
        "This identity has already been onboarded.",
        409,
      );
    }
    const duplicate = this.database
      .prepare("SELECT id FROM users WHERE email = ? OR handle = ?")
      .get(input.email, input.handle) as Row | undefined;
    if (duplicate) {
      throw new RepositoryError(
        "ACCOUNT_EXISTS",
        "An account with that email or handle already exists.",
        409,
      );
    }

    let organization: Row | undefined;
    if (input.accountType === "organization") {
      organization = input.organizationId
        ? (this.database
            .prepare("SELECT id FROM organizations WHERE id = ?")
            .get(input.organizationId) as Row | undefined)
        : (this.database
            .prepare("SELECT id FROM organizations WHERE join_code_hash = ?")
            .get(
              hashOrganizationJoinCode(input.organizationJoinCode as string),
            ) as Row | undefined);
      if (!organization) {
        throw new RepositoryError(
          "ORGANIZATION_NOT_FOUND",
          "The organization or join code was not found.",
          404,
        );
      }
    }

    const id = `user_${randomUUID()}`;
    const createdAt = nowIso();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO users
            (id, email, handle, display_name, password_hash, external_subject,
             platform_role, created_at)
           VALUES (?, ?, ?, ?, NULL, ?, ?, ?)`,
        )
        .run(
          id,
          input.email,
          input.handle,
          input.displayName,
          input.externalSubject,
          input.platformRole,
          createdAt,
        );
      if (organization) {
        this.database
          .prepare(
            `INSERT INTO organization_memberships
              (user_id, organization_id, role, created_at)
             VALUES (?, ?, ?, ?)`,
          )
          .run(id, String(organization.id), input.organizationRole, createdAt);
      }
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.getUser(id) as JsonValue;
  }

  createLab(userId: string, input: LabGenerationInput): JsonValue {
    const membership = this.database
      .prepare(
        "SELECT organization_id FROM organization_memberships WHERE user_id = ?",
      )
      .get(userId) as Row | undefined;
    const id = `lab_${randomUUID()}`;
    const createdAt = nowIso();

    this.database
      .prepare(
        `INSERT INTO labs
          (id, owner_user_id, organization_id, name, description, team_type,
           question_types_json, environment, access_modes_json, validation_status,
           config_json, grading_config_json, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?)`,
      )
      .run(
        id,
        userId,
        typeof membership?.organization_id === "string"
          ? membership.organization_id
          : null,
        input.title,
        input.prompt,
        input.team,
        JSON.stringify(input.questionTypes),
        input.desktopImage,
        JSON.stringify(input.accessModes),
        JSON.stringify(input.config),
        JSON.stringify({ questions: input.gradingQuestions }),
        createdAt,
        createdAt,
      );

    return this.getLab(userId, id) as JsonValue;
  }

  listLabs(userId: string): JsonValue[] {
    const rows = this.database
      .prepare(
        `SELECT l.*, u.display_name AS owner_display_name,
                o.name AS organization_name
           FROM labs l
           JOIN users u ON u.id = l.owner_user_id
           LEFT JOIN organizations o ON o.id = l.organization_id
          WHERE l.owner_user_id = ?
             OR l.organization_id IN (
               SELECT organization_id FROM organization_memberships WHERE user_id = ?
             )
          ORDER BY l.created_at DESC, l.id DESC`,
      )
      .all(userId, userId) as Row[];

    return rows.map((row) => labFromRow(row) as JsonValue);
  }

  getLab(userId: string, labId: string): JsonValue | null {
    const row = this.database
      .prepare(
        `SELECT l.*, u.display_name AS owner_display_name,
                o.name AS organization_name
           FROM labs l
           JOIN users u ON u.id = l.owner_user_id
           LEFT JOIN organizations o ON o.id = l.organization_id
          WHERE l.id = ?
            AND (
              l.owner_user_id = ?
              OR l.organization_id IN (
                SELECT organization_id FROM organization_memberships WHERE user_id = ?
              )
            )`,
      )
      .get(labId, userId, userId) as Row | undefined;

    return labFromRow(row);
  }

  getLabBuildSpec(userId: string, labId: string): JsonObject | null {
    const row = this.database
      .prepare(
        `SELECT l.config_json
           FROM labs l
           LEFT JOIN organization_memberships m
             ON m.organization_id = l.organization_id AND m.user_id = ?
          WHERE l.id = ? AND (l.owner_user_id = ? OR m.user_id IS NOT NULL)`,
      )
      .get(userId, labId, userId) as Row | undefined;
    const config = parseJson<Record<string, unknown>>(row?.config_json, {});
    return typeof config.builderSpec === "object" && config.builderSpec !== null && !Array.isArray(config.builderSpec)
      ? config.builderSpec as JsonObject
      : null;
  }

  updateLabConfig(labId: string, patch: JsonObject, updatedAt: string): boolean {
    const row = this.database
      .prepare("SELECT config_json FROM labs WHERE id = ? AND validation_status = 'draft'")
      .get(labId) as Row | undefined;
    if (!row) return false;
    const current = parseJson<Record<string, unknown>>(row.config_json, {});
    const result = this.database
      .prepare(
        `UPDATE labs SET config_json = ?, updated_at = ?
          WHERE id = ? AND validation_status = 'draft'`,
      )
      .run(JSON.stringify({ ...current, ...patch }), updatedAt, labId);
    return result.changes === 1;
  }

  saveValidation(
    labId: string,
    status: "validated" | "quarantined",
    evidence: ValidationEvidenceInput[],
  ): JsonValue[] {
    const createdAt = nowIso();
    this.database.exec("BEGIN IMMEDIATE");

    try {
      const statement = this.database.prepare(
        `INSERT INTO validation_evidence
          (id, lab_id, check_name, outcome, details_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(lab_id, check_name) DO UPDATE SET
           outcome = excluded.outcome,
           details_json = excluded.details_json`,
      );

      for (const item of evidence) {
        statement.run(
          item.id,
          labId,
          item.checkName,
          item.outcome,
          JSON.stringify(item.details),
          createdAt,
        );
      }

      this.database
        .prepare(
          `UPDATE labs
              SET validation_status = CASE
                    WHEN admin_quarantined_at IS NOT NULL THEN 'quarantined'
                    ELSE ?
                  END,
                  updated_at = ?
            WHERE id = ?`,
        )
        .run(status, createdAt, labId);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }

    const rows = this.database
      .prepare(
        `SELECT * FROM validation_evidence
          WHERE lab_id = ? ORDER BY check_name ASC`,
      )
      .all(labId) as Row[];
    return rows.map(evidenceFromRow);
  }

  createRun(input: RuntimeRunInput): JsonValue {
    this.database
      .prepare(
        `INSERT INTO runtime_runs
          (id, lab_id, user_id, status, environment, access_method, browser_url,
           openvpn_profile_json, expires_at, metadata_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
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
      );

    return this.getRun(input.userId, input.id) as JsonValue;
  }

  getRun(userId: string, runId: string): JsonValue | null {
    const row = this.database
      .prepare("SELECT * FROM runtime_runs WHERE id = ? AND user_id = ?")
      .get(runId, userId) as Row | undefined;
    return runFromRow(row);
  }

  updateRunReadiness(
    userId: string,
    runId: string,
    readiness: RuntimeRunStatusInput,
  ): JsonValue | null {
    if (readiness.status === "provisioning") return this.getRun(userId, runId);
    const row = this.database
      .prepare("SELECT metadata_json FROM runtime_runs WHERE id = ? AND user_id = ?")
      .get(runId, userId) as Row | undefined;
    if (!row) return null;
    const metadata = parseJson<Record<string, unknown>>(row.metadata_json, {});
    metadata.runtimeReadiness = persistedReadiness(readiness);
    this.database
      .prepare(
        `UPDATE runtime_runs
            SET status = ?, metadata_json = ?
          WHERE id = ? AND user_id = ? AND status = 'provisioning'`,
      )
      .run(readiness.status, JSON.stringify(metadata), runId, userId);
    return this.getRun(userId, runId);
  }

  getLabGradingQuestions(userId: string, labId: string): unknown[] {
    const row = this.database
      .prepare(
        `SELECT l.grading_config_json
           FROM labs l
          WHERE l.id = ?
            AND (
              l.owner_user_id = ?
              OR l.organization_id IN (
                SELECT organization_id FROM organization_memberships WHERE user_id = ?
              )
            )`,
      )
      .get(labId, userId, userId) as Row | undefined;
    const grading = parseJson<Record<string, unknown>>(row?.grading_config_json, {});
    return Array.isArray(grading.questions) ? grading.questions : [];
  }

  getTrustedGradeEvidence(userId: string, runId: string): unknown[] {
    const rows = this.database
      .prepare(
        `SELECT e.*
           FROM trusted_grade_evidence e
           JOIN runtime_runs r ON r.id = e.run_id
          WHERE e.run_id = ? AND r.user_id = ?
          ORDER BY e.question_id`,
      )
      .all(runId, userId) as Row[];
    return rows.map((row) => ({
      questionId: row.question_id,
      source: row.source,
      passed: row.passed === 1,
      scoreRatio: row.score_ratio,
      policyVersion: row.policy_version,
      evidenceReference: row.evidence_reference,
    }));
  }

  saveChallengeResult(input: ChallengeResultInput): JsonValue {
    const duplicate = this.database
      .prepare("SELECT id FROM challenge_results WHERE run_id = ?")
      .get(input.runId) as Row | undefined;
    if (duplicate) {
      throw new RepositoryError(
        "RUN_ALREADY_SUBMITTED",
        "This runtime run already has a challenge result.",
        409,
      );
    }
    const membership = this.database
      .prepare(
        "SELECT organization_id FROM organization_memberships WHERE user_id = ?",
      )
      .get(input.userId) as Row | undefined;

    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO challenge_results
            (id, lab_id, user_id, run_id, score, max_score, answers_json,
             evidence_json, skills_json, completed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
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
        );
      this.database
        .prepare(
          `INSERT INTO score_events
            (id, result_id, user_id, organization_id, event_type, points_delta,
             max_points, payload_json, occurred_at)
           VALUES (?, ?, ?, ?, 'challenge.graded', ?, ?, ?, ?)`,
        )
        .run(
          `score_${randomUUID()}`,
          input.id,
          input.userId,
          typeof membership?.organization_id === "string"
            ? membership.organization_id
            : null,
          input.awardedPoints,
          input.maxPoints,
          JSON.stringify({ labId: input.labId, runId: input.runId }),
          input.completedAt,
        );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
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

  createAccessTicket(input: AccessTicketInput): void {
    this.database
      .prepare(
        `INSERT INTO access_tickets
          (ticket_hash, run_id, user_id, kind, expires_at, consumed_at, created_at)
         VALUES (?, ?, ?, ?, ?, NULL, ?)`,
      )
      .run(
        input.ticketHash,
        input.runId,
        input.userId,
        input.kind,
        input.expiresAt,
        input.createdAt,
      );
  }

  consumeAccessTicket(
    ticketHash: string,
    kind: "desktop" | "openvpn",
    consumedAt: string,
  ): JsonValue | null {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const row = this.database
        .prepare(
          `SELECT t.run_id, t.user_id, t.expires_at AS ticket_expires_at,
                  r.expires_at, r.metadata_json, r.openvpn_profile_json
             FROM access_tickets t
             JOIN runtime_runs r ON r.id = t.run_id
            WHERE t.ticket_hash = ? AND t.kind = ?
              AND t.consumed_at IS NULL AND t.expires_at > ?
              AND r.status = 'ready'`,
        )
        .get(ticketHash, kind, consumedAt) as Row | undefined;
      if (!row) {
        this.database.exec("ROLLBACK");
        return null;
      }
      const update = this.database
        .prepare(
          `UPDATE access_tickets SET consumed_at = ?
            WHERE ticket_hash = ? AND kind = ? AND consumed_at IS NULL
              AND expires_at > ?`,
        )
        .run(consumedAt, ticketHash, kind, consumedAt);
      if (update.changes !== 1) {
        this.database.exec("ROLLBACK");
        return null;
      }
      this.database
        .prepare(
          `INSERT INTO audit_logs
            (id, actor_user_id, action, resource_type, resource_id,
             metadata_json, created_at)
           VALUES (?, ?, ?, 'runtime_run', ?, ?, ?)`,
        )
        .run(
          `audit_${randomUUID()}`,
          String(row.user_id),
          `${kind}_ticket.consumed`,
          String(row.run_id),
          JSON.stringify({ kind }),
          consumedAt,
        );
      this.database.exec("COMMIT");
      const metadata = parseJson<Record<string, unknown>>(row.metadata_json, {});
      return {
        runId: row.run_id,
        userId: row.user_id,
        namespace: metadata.namespace ?? null,
        openVpn: parseJson(row.openvpn_profile_json, null),
        expiresAt: row.expires_at,
        ticketExpiresAt: row.ticket_expires_at,
      };
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  getReportingDataset(filter: ReportingDatasetFilter = {}): JsonValue {
    let users: Row[];
    let organizations: Row[];
    let evidence: Row[];

    if (filter.userId) {
      users = this.database
        .prepare(
          `SELECT u.id, u.handle, u.display_name, u.global_ranking_opt_in,
                  m.organization_id
             FROM users u
             LEFT JOIN organization_memberships m ON m.user_id = u.id
            WHERE u.id = ?`,
        )
        .all(filter.userId) as Row[];
      organizations = this.database
        .prepare(
          `SELECT id, name, slug FROM organizations
            WHERE id IN (
              SELECT organization_id FROM organization_memberships WHERE user_id = ?
            )`,
        )
        .all(filter.userId) as Row[];
      evidence = this.database
        .prepare(
          `SELECT cr.id, cr.user_id, cr.run_id, cr.lab_id, cr.score, cr.max_score,
                  cr.completed_at, cr.skills_json, cr.evidence_json,
                  l.name AS lab_title, l.team_type, m.organization_id
             FROM challenge_results cr
             JOIN labs l ON l.id = cr.lab_id
             LEFT JOIN organization_memberships m ON m.user_id = cr.user_id
            WHERE cr.user_id = ?`,
        )
        .all(filter.userId) as Row[];
    } else if (filter.organizationId) {
      users = this.database
        .prepare(
          `SELECT u.id, u.handle, u.display_name, u.global_ranking_opt_in,
                  m.organization_id
             FROM users u
             JOIN organization_memberships m ON m.user_id = u.id
            WHERE m.organization_id = ?`,
        )
        .all(filter.organizationId) as Row[];
      organizations = this.database
        .prepare("SELECT id, name, slug FROM organizations WHERE id = ?")
        .all(filter.organizationId) as Row[];
      evidence = this.database
        .prepare(
          `SELECT cr.id, cr.user_id, cr.run_id, cr.lab_id, cr.score, cr.max_score,
                  cr.completed_at, cr.skills_json, cr.evidence_json,
                  l.name AS lab_title, l.team_type, m.organization_id
             FROM challenge_results cr
             JOIN labs l ON l.id = cr.lab_id
             JOIN organization_memberships m ON m.user_id = cr.user_id
            WHERE m.organization_id = ?`,
        )
        .all(filter.organizationId) as Row[];
    } else {
      users = this.database
        .prepare(
          `SELECT u.id, u.handle, u.display_name, u.global_ranking_opt_in,
                  m.organization_id
             FROM users u
             LEFT JOIN organization_memberships m ON m.user_id = u.id`,
        )
        .all() as Row[];
      organizations = this.database
        .prepare("SELECT id, name, slug FROM organizations")
        .all() as Row[];
      evidence = this.database
        .prepare(
          `SELECT cr.id, cr.user_id, cr.run_id, cr.lab_id, cr.score, cr.max_score,
                  cr.completed_at, cr.skills_json, cr.evidence_json,
                  l.name AS lab_title, l.team_type, m.organization_id
             FROM challenge_results cr
             JOIN labs l ON l.id = cr.lab_id
             LEFT JOIN organization_memberships m ON m.user_id = cr.user_id`,
        )
        .all() as Row[];
    }

    return {
      users: users.map((row) => ({
        id: row.id,
        handle: row.handle,
        displayName: row.display_name,
        organizationId: row.organization_id ?? null,
        globalRankingOptIn: row.global_ranking_opt_in === 1,
      })),
      organizations: organizations.map((row) => ({
        id: row.id,
        name: row.name,
        slug: row.slug,
      })),
      evidence: evidence.map((row) => {
        const storedSkills = parseJson<Record<string, unknown>>(row.skills_json, {});
        const storedEvidence = parseJson<Record<string, unknown>>(row.evidence_json, {});
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
          completedAt: row.completed_at,
          skills,
        };
      }),
    };
  }

  getAdminOverview(): JsonValue {
    const count = (sql: string): number =>
      Number((this.database.prepare(sql).get() as Row | undefined)?.count ?? 0);
    return {
      users: count("SELECT count(*) AS count FROM users"),
      organizations: count("SELECT count(*) AS count FROM organizations"),
      labs: count("SELECT count(*) AS count FROM labs"),
      quarantinedLabs: count(
        "SELECT count(*) AS count FROM labs WHERE validation_status = 'quarantined'",
      ),
      runs: count("SELECT count(*) AS count FROM runtime_runs"),
      activeRuns: count(
        "SELECT count(*) AS count FROM runtime_runs WHERE status IN ('provisioning', 'ready')",
      ),
      failedRuns: count(
        "SELECT count(*) AS count FROM runtime_runs WHERE status = 'failed'",
      ),
      completedChallenges: count(
        "SELECT count(*) AS count FROM challenge_results",
      ),
      generatedAt: nowIso(),
    };
  }

  listAdminUsers(query: AdminPageQuery): AdminPageResult {
    const conditions: string[] = [];
    const parameters: (string | number)[] = [];
    if (query.search) {
      conditions.push(
        `(u.email LIKE ? ESCAPE '\\' COLLATE NOCASE
          OR u.handle LIKE ? ESCAPE '\\' COLLATE NOCASE
          OR u.display_name LIKE ? ESCAPE '\\' COLLATE NOCASE)`,
      );
      const term = escapedLike(query.search);
      parameters.push(term, term, term);
    }
    if (query.platformRole) {
      conditions.push("u.platform_role = ?");
      parameters.push(query.platformRole);
    }
    if (query.organizationId) {
      conditions.push("m.organization_id = ?");
      parameters.push(query.organizationId);
    }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const from = `FROM users u
      LEFT JOIN organization_memberships m ON m.user_id = u.id
      LEFT JOIN organizations o ON o.id = m.organization_id`;
    const total = Number(
      (this.database
        .prepare(`SELECT count(*) AS total ${from} ${where}`)
        .get(...parameters) as Row).total,
    );
    const rows = this.database
      .prepare(
        `SELECT u.id, u.email, u.handle, u.display_name, u.platform_role,
                u.global_ranking_opt_in, u.created_at, m.role AS membership_role,
                o.id AS organization_id, o.name AS organization_name,
                o.slug AS organization_slug
           ${from} ${where}
          ORDER BY u.created_at DESC, u.id DESC LIMIT ? OFFSET ?`,
      )
      .all(...parameters, query.limit, query.offset) as Row[];
    return {
      total,
      items: rows.map((row) => ({
        id: row.id,
        email: row.email,
        handle: row.handle,
        displayName: row.display_name,
        platformRole: row.platform_role,
        globalRankingOptIn: row.global_ranking_opt_in === 1,
        organization: row.organization_id
          ? {
              id: row.organization_id,
              name: row.organization_name,
              slug: row.organization_slug,
              role: row.membership_role,
            }
          : null,
        createdAt: row.created_at,
      })),
    };
  }

  listAdminOrganizations(query: AdminPageQuery): AdminPageResult {
    const conditions: string[] = [];
    const parameters: (string | number)[] = [];
    if (query.search) {
      conditions.push(
        "(o.name LIKE ? ESCAPE '\\' COLLATE NOCASE OR o.slug LIKE ? ESCAPE '\\' COLLATE NOCASE)",
      );
      const term = escapedLike(query.search);
      parameters.push(term, term);
    }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const total = Number(
      (this.database
        .prepare(`SELECT count(*) AS total FROM organizations o ${where}`)
        .get(...parameters) as Row).total,
    );
    const rows = this.database
      .prepare(
        `SELECT o.*,
                (SELECT count(*) FROM organization_memberships m
                  WHERE m.organization_id = o.id) AS member_count,
                (SELECT count(*) FROM labs l
                  WHERE l.organization_id = o.id) AS lab_count
           FROM organizations o ${where}
          ORDER BY o.created_at DESC, o.id DESC LIMIT ? OFFSET ?`,
      )
      .all(...parameters, query.limit, query.offset) as Row[];
    return {
      total,
      items: rows.map((row) => adminOrganizationFromRow(row) as JsonValue),
    };
  }

  listAdminLabs(query: AdminPageQuery): AdminPageResult {
    const conditions: string[] = [];
    const parameters: (string | number)[] = [];
    if (query.search) {
      conditions.push(
        "(l.name LIKE ? ESCAPE '\\' COLLATE NOCASE OR l.description LIKE ? ESCAPE '\\' COLLATE NOCASE)",
      );
      const term = escapedLike(query.search);
      parameters.push(term, term);
    }
    if (query.team) {
      conditions.push("l.team_type = ?");
      parameters.push(query.team);
    }
    if (query.labStatus) {
      conditions.push("l.validation_status = ?");
      parameters.push(query.labStatus);
    }
    if (query.organizationId) {
      conditions.push("l.organization_id = ?");
      parameters.push(query.organizationId);
    }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const from = `FROM labs l
      JOIN users u ON u.id = l.owner_user_id
      LEFT JOIN organizations o ON o.id = l.organization_id`;
    const total = Number(
      (this.database
        .prepare(`SELECT count(*) AS total ${from} ${where}`)
        .get(...parameters) as Row).total,
    );
    const rows = this.database
      .prepare(
        `SELECT l.id, l.name, l.description, l.team_type,
                l.question_types_json, l.environment, l.access_modes_json,
                l.validation_status, l.owner_user_id, u.handle AS owner_handle,
                l.organization_id, o.name AS organization_name,
                l.admin_quarantined_at, l.admin_quarantined_by,
                l.admin_quarantine_reason,
                l.created_at, l.updated_at
           ${from} ${where}
          ORDER BY l.created_at DESC, l.id DESC LIMIT ? OFFSET ?`,
      )
      .all(...parameters, query.limit, query.offset) as Row[];
    return {
      total,
      items: rows.map((row) => adminLabFromRow(row) as JsonValue),
    };
  }

  listAdminRuns(query: AdminPageQuery): AdminPageResult {
    const conditions: string[] = [];
    const parameters: (string | number)[] = [];
    if (query.search) {
      conditions.push(
        `(r.id LIKE ? ESCAPE '\\' COLLATE NOCASE
          OR u.handle LIKE ? ESCAPE '\\' COLLATE NOCASE
          OR l.name LIKE ? ESCAPE '\\' COLLATE NOCASE)`,
      );
      const term = escapedLike(query.search);
      parameters.push(term, term, term);
    }
    if (query.runStatus) {
      conditions.push("r.status = ?");
      parameters.push(query.runStatus);
    }
    if (query.accessMethod) {
      conditions.push("r.access_method = ?");
      parameters.push(query.accessMethod);
    }
    if (query.organizationId) {
      conditions.push("l.organization_id = ?");
      parameters.push(query.organizationId);
    }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const from = `FROM runtime_runs r
      JOIN labs l ON l.id = r.lab_id
      JOIN users u ON u.id = r.user_id`;
    const total = Number(
      (this.database
        .prepare(`SELECT count(*) AS total ${from} ${where}`)
        .get(...parameters) as Row).total,
    );
    const rows = this.database
      .prepare(
        `SELECT r.*, l.name AS lab_title, l.organization_id,
                u.handle AS user_handle
           ${from} ${where}
          ORDER BY r.created_at DESC, r.id DESC LIMIT ? OFFSET ?`,
      )
      .all(...parameters, query.limit, query.offset) as Row[];
    return {
      total,
      items: rows.map((row) => adminRunFromRow(row) as JsonValue),
    };
  }

  listOrganizationMembers(
    organizationId: string,
    query: AdminPageQuery,
  ): AdminPageResult {
    const conditions = ["m.organization_id = ?"];
    const parameters: (string | number)[] = [organizationId];
    if (query.search) {
      conditions.push(
        `(u.email LIKE ? ESCAPE '\\' COLLATE NOCASE
          OR u.handle LIKE ? ESCAPE '\\' COLLATE NOCASE
          OR u.display_name LIKE ? ESCAPE '\\' COLLATE NOCASE)`,
      );
      const term = escapedLike(query.search);
      parameters.push(term, term, term);
    }
    if (query.membershipRole) {
      conditions.push("m.role = ?");
      parameters.push(query.membershipRole);
    }
    const where = `WHERE ${conditions.join(" AND ")}`;
    const from = `FROM organization_memberships m
      JOIN users u ON u.id = m.user_id`;
    const total = Number(
      (this.database
        .prepare(`SELECT count(*) AS total ${from} ${where}`)
        .get(...parameters) as Row).total,
    );
    const rows = this.database
      .prepare(
        `SELECT u.id, u.email, u.handle, u.display_name, u.platform_role,
                m.role, m.created_at AS joined_at
           ${from} ${where}
          ORDER BY m.created_at ASC, u.id ASC LIMIT ? OFFSET ?`,
      )
      .all(...parameters, query.limit, query.offset) as Row[];
    return {
      total,
      items: rows.map((row) => ({
        id: row.id,
        email: row.email,
        handle: row.handle,
        displayName: row.display_name,
        platformRole: row.platform_role,
        organizationRole: row.role,
        joinedAt: row.joined_at,
      })),
    };
  }

  createOrganization(input: OrganizationCreateInput): JsonValue {
    try {
      const columns = this.database
        .prepare("PRAGMA table_info(organizations)")
        .all() as Row[];
      const hasLegacyJoinCode = columns.some((item) => item.name === "join_code");
      if (hasLegacyJoinCode) {
        this.database
          .prepare(
            `INSERT INTO organizations
              (id, name, slug, join_code, join_code_hash,
               join_code_rotated_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(
            input.id,
            input.name,
            input.slug,
            input.joinCodeHash,
            input.joinCodeHash,
            input.createdAt,
            input.createdAt,
          );
      } else {
        this.database
          .prepare(
            `INSERT INTO organizations
              (id, name, slug, join_code_hash, join_code_rotated_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?)`,
          )
          .run(
            input.id,
            input.name,
            input.slug,
            input.joinCodeHash,
            input.createdAt,
            input.createdAt,
          );
      }
    } catch (error: unknown) {
      const code =
        typeof error === "object" && error !== null && "code" in error
          ? String(error.code)
          : "";
      if (!code.startsWith("SQLITE_CONSTRAINT")) throw error;
      throw new RepositoryError(
        "ORGANIZATION_EXISTS",
        "An organization with that slug already exists.",
        409,
      );
    }
    const row = this.database
      .prepare(
        `SELECT o.*, 0 AS member_count, 0 AS lab_count
           FROM organizations o WHERE o.id = ?`,
      )
      .get(input.id) as Row;
    return adminOrganizationFromRow(row) as JsonValue;
  }

  rotateOrganizationJoinCode(
    organizationId: string,
    joinCodeHash: string,
    rotatedAt: string,
  ): JsonValue | null {
    const columns = this.database
      .prepare("PRAGMA table_info(organizations)")
      .all() as Row[];
    const hasLegacyJoinCode = columns.some((item) => item.name === "join_code");
    const result = hasLegacyJoinCode
      ? this.database
          .prepare(
            `UPDATE organizations
                SET join_code = ?, join_code_hash = ?, join_code_rotated_at = ?
              WHERE id = ?`,
          )
          .run(joinCodeHash, joinCodeHash, rotatedAt, organizationId)
      : this.database
          .prepare(
            `UPDATE organizations
                SET join_code_hash = ?, join_code_rotated_at = ?
              WHERE id = ?`,
          )
          .run(joinCodeHash, rotatedAt, organizationId);
    if (result.changes !== 1) return null;
    const row = this.database
      .prepare(
        `SELECT o.*,
                (SELECT count(*) FROM organization_memberships m
                  WHERE m.organization_id = o.id) AS member_count,
                (SELECT count(*) FROM labs l
                  WHERE l.organization_id = o.id) AS lab_count
           FROM organizations o WHERE o.id = ?`,
      )
      .get(organizationId) as Row;
    return adminOrganizationFromRow(row) as JsonValue;
  }

  quarantineLab(
    labId: string,
    quarantinedAt: string,
    actorUserId: string,
    reason: string,
  ): JsonValue | null {
    const result = this.database
      .prepare(
        `UPDATE labs
            SET validation_status = 'quarantined', updated_at = ?,
                admin_quarantined_at = ?, admin_quarantined_by = ?,
                admin_quarantine_reason = ?
          WHERE id = ?`,
      )
      .run(quarantinedAt, quarantinedAt, actorUserId, reason, labId);
    if (result.changes !== 1) return null;
    const row = this.database
      .prepare(
        `SELECT l.id, l.name, l.description, l.team_type,
                l.question_types_json, l.environment, l.access_modes_json,
                l.validation_status, l.owner_user_id, u.handle AS owner_handle,
                l.organization_id, o.name AS organization_name,
                l.admin_quarantined_at, l.admin_quarantined_by,
                l.admin_quarantine_reason, l.created_at, l.updated_at
           FROM labs l JOIN users u ON u.id = l.owner_user_id
           LEFT JOIN organizations o ON o.id = l.organization_id
          WHERE l.id = ?`,
      )
      .get(labId) as Row;
    return adminLabFromRow(row);
  }

  getAdminRun(runId: string): JsonValue | null {
    const row = this.database
      .prepare(
        `SELECT r.*, l.name AS lab_title, l.organization_id,
                u.handle AS user_handle
           FROM runtime_runs r JOIN labs l ON l.id = r.lab_id
           JOIN users u ON u.id = r.user_id WHERE r.id = ?`,
      )
      .get(runId) as Row | undefined;
    return adminRunFromRow(row);
  }

  markRunStopped(
    runId: string,
    stoppedAt: string,
    actorUserId: string,
  ): JsonValue | null {
    const row = this.database
      .prepare("SELECT metadata_json FROM runtime_runs WHERE id = ?")
      .get(runId) as Row | undefined;
    if (!row) return null;
    const metadata = parseJson<Record<string, unknown>>(row.metadata_json, {});
    metadata.termination = { actorUserId, stoppedAt, reason: "platform_admin" };
    this.database
      .prepare(
        `UPDATE runtime_runs
            SET status = 'stopped', browser_url = NULL,
                openvpn_profile_json = NULL, metadata_json = ?
          WHERE id = ? AND status NOT IN ('stopped', 'expired')`,
      )
      .run(JSON.stringify(metadata), runId);
    return this.getAdminRun(runId);
  }

  getIdempotencyRecord(
    userId: string,
    operation: string,
    key: string,
  ): IdempotencyRecord | null {
    const row = this.database
      .prepare(
        `SELECT request_hash, resource_id, response_json, created_at
           FROM idempotency_records
          WHERE user_id = ? AND operation = ? AND idempotency_key = ?`,
      )
      .get(userId, operation, key) as Row | undefined;
    if (!row) return null;

    return {
      requestHash: String(row.request_hash),
      resourceId: String(row.resource_id),
      response: parseJson(row.response_json, null),
      createdAt: String(row.created_at),
    };
  }

  saveIdempotencyRecord(
    userId: string,
    operation: string,
    key: string,
    requestHash: string,
    resourceId: string,
    response: unknown,
  ): void {
    this.database
      .prepare(
        `INSERT INTO idempotency_records
          (user_id, operation, idempotency_key, request_hash, resource_id,
           response_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        userId,
        operation,
        key,
        requestHash,
        resourceId,
        JSON.stringify(response),
        nowIso(),
      );
  }

  recordAudit(event: AuditEvent): void {
    this.database
      .prepare(
        `INSERT INTO audit_logs
          (id, actor_user_id, action, resource_type, resource_id, metadata_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        `audit_${randomUUID()}`,
        event.actorUserId,
        event.action,
        event.resourceType,
        event.resourceId,
        JSON.stringify(event.metadata ?? {}),
        nowIso(),
      );
  }

  close(): void {
    this.database.close();
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

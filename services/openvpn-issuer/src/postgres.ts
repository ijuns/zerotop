import { readFile } from "node:fs/promises";

import type { Pool } from "pg";

import { ServiceError } from "./errors.ts";
import type {
  ProfileRepository,
  StoredEncryptedBundle,
  StoredProfileInput,
} from "./types.ts";

export class PostgresProfileRepository implements ProfileRepository {
  private readonly databaseUrl: string;
  private pool: Pool | null = null;

  constructor(databaseUrl: string) {
    if (!databaseUrl) throw new Error("DATABASE_URL is required.");
    this.databaseUrl = databaseUrl;
  }

  async initialize(): Promise<void> {
    const pgModule = await import("pg");
    const PoolConstructor = pgModule.default?.Pool ?? pgModule.Pool;
    this.pool = new PoolConstructor({
      connectionString: this.databaseUrl,
      application_name: "codegate-openvpn-issuer",
      max: integerEnvironment("PG_POOL_MAX", 10, 1, 50),
    });
    const migration = await readFile(
      new URL("../migrations/001_profiles.sql", import.meta.url),
      "utf8",
    );
    await this.pool.query(migration);
  }

  async close(): Promise<void> {
    await this.pool?.end();
    this.pool = null;
  }

  async create(input: StoredProfileInput): Promise<void> {
    try {
      await this.requiredPool().query(
        `INSERT INTO openvpn_profiles
          (run_id, profile_id, user_id, namespace, endpoint, assigned_ip,
           allowed_cidr, expires_at, encrypted_client_bundle,
           encrypted_server_bundle, bootstrap_token_hash, created_at)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, $11, $12)`,
        [
          input.runId,
          input.profileId,
          input.userId,
          input.namespace,
          input.endpoint,
          input.assignedIp,
          input.allowedCidr,
          input.expiresAt,
          JSON.stringify(input.encryptedClientBundle),
          JSON.stringify(input.encryptedServerBundle),
          input.bootstrapTokenHash,
          input.createdAt,
        ],
      );
    } catch (error) {
      if (postgresCode(error) === "23505") {
        throw new ServiceError(
          409,
          "profile_already_exists",
          "An OpenVPN profile already exists for this run.",
        );
      }
      throw error;
    }
  }

  async revoke(runId: string, revokedAt: string): Promise<boolean> {
    const result = await this.requiredPool().query(
      `UPDATE openvpn_profiles
          SET revoked_at = $2
        WHERE run_id = $1 AND revoked_at IS NULL
      RETURNING run_id`,
      [runId, revokedAt],
    );
    return (result.rowCount ?? 0) === 1;
  }

  async consumeGatewayBootstrap(
    runId: string,
    profileId: string,
    bootstrapTokenHash: string,
    consumedAt: string,
  ): Promise<StoredEncryptedBundle | null> {
    const result = await this.requiredPool().query(
      `UPDATE openvpn_profiles
          SET bootstrap_consumed_at = $4
        WHERE run_id = $1 AND profile_id = $2
          AND bootstrap_token_hash = $3
          AND revoked_at IS NULL AND expires_at > $4
      RETURNING run_id, profile_id, encrypted_server_bundle`,
      [runId, profileId, bootstrapTokenHash, consumedAt],
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    return row
      ? {
          runId: String(row.run_id),
          profileId: String(row.profile_id),
          encryptedBundle: row.encrypted_server_bundle as StoredEncryptedBundle["encryptedBundle"],
        }
      : null;
  }

  async getActiveClientBundle(
    runId: string,
    profileId: string,
    accessedAt: string,
  ): Promise<StoredEncryptedBundle | null> {
    const result = await this.requiredPool().query(
      `SELECT run_id, profile_id, encrypted_client_bundle
         FROM openvpn_profiles
        WHERE run_id = $1 AND profile_id = $2
          AND revoked_at IS NULL AND expires_at > $3`,
      [runId, profileId, accessedAt],
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    return row
      ? {
          runId: String(row.run_id),
          profileId: String(row.profile_id),
          encryptedBundle: row.encrypted_client_bundle as StoredEncryptedBundle["encryptedBundle"],
        }
      : null;
  }

  private requiredPool(): Pool {
    if (!this.pool) throw new Error("The PostgreSQL repository is not initialized.");
    return this.pool;
  }
}

function postgresCode(value: unknown): string | null {
  return typeof value === "object" && value !== null && "code" in value
    ? String(value.code)
    : null;
}

function integerEnvironment(
  name: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} is invalid.`);
  }
  return value;
}

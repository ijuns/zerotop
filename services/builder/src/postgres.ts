import { readFile } from "node:fs/promises";
import { Pool, type PoolClient, type QueryResultRow } from "pg";

import type { BuildRecord } from "./contracts.ts";
import { BuilderError } from "./errors.ts";
import type { BuildRepository, BuildTransition, CreateRecordResult } from "./repository.ts";

type Row = QueryResultRow & Record<string, unknown>;

export class PostgresBuildRepository implements BuildRepository {
  private readonly pool: Pool;

  constructor(databaseUrl: string, options: { maxConnections?: number } = {}) {
    if (!/^postgres(?:ql)?:\/\//.test(databaseUrl)) throw new Error("DATABASE_URL must be a PostgreSQL URL");
    this.pool = new Pool({ connectionString: databaseUrl, max: options.maxConnections ?? 10, statement_timeout: 20_000, query_timeout: 25_000 });
  }

  async migrate(): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("SELECT pg_advisory_lock($1)", [1_908_271_001]);
      const sql = await readFile(new URL("../migrations/001_initial.sql", import.meta.url), "utf8");
      await client.query("BEGIN");
      await client.query(sql);
      await client.query(
        "INSERT INTO builder_schema_migrations(version, name) VALUES (1, 'initial') ON CONFLICT (version) DO NOTHING",
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      await client.query("SELECT pg_advisory_unlock($1)", [1_908_271_001]).catch(() => undefined);
      client.release();
    }
  }

  async create(record: BuildRecord): Promise<CreateRecordResult> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const inserted = await client.query<Row>(
        `INSERT INTO environment_builds (
          id, lab_id, lab_version, requested_by, idempotency_key, request_digest, spec_digest, spec_json,
          resolved_packages_json, status, namespace, job_name, created_at, deadline_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$11,$12,$13,$14)
        ON CONFLICT (requested_by, idempotency_key) DO NOTHING RETURNING *`,
        [record.id, record.labId, record.labVersion, record.requestedBy, record.idempotencyKey, record.requestDigest,
          record.specDigest, JSON.stringify(record.spec), JSON.stringify(record.resolvedPackages), record.status,
          record.namespace, record.jobName, record.createdAt, record.deadlineAt],
      );
      if (inserted.rows[0]) {
        await client.query(
          `INSERT INTO builder_audit_events(build_id, actor, action, next_status, details_json)
           VALUES ($1,$2,'build.created','queued',$3::jsonb)`,
          [record.id, record.requestedBy, JSON.stringify({ requestDigest: record.requestDigest, specDigest: record.specDigest })],
        );
        await client.query("COMMIT");
        return { record: rowToBuild(inserted.rows[0]), created: true };
      }
      const existing = await client.query<Row>(
        "SELECT * FROM environment_builds WHERE requested_by=$1 AND idempotency_key=$2 FOR UPDATE",
        [record.requestedBy, record.idempotencyKey],
      );
      const row = existing.rows[0];
      if (!row) throw new Error("Idempotency conflict row disappeared");
      if (row.request_digest !== record.requestDigest) {
        throw new BuilderError(409, "idempotency_conflict", "Idempotency-Key was already used for a different request");
      }
      await client.query("COMMIT");
      return { record: rowToBuild(row), created: false };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async get(id: string): Promise<BuildRecord | null> {
    const result = await this.pool.query<Row>("SELECT * FROM environment_builds WHERE id=$1", [id]);
    return result.rows[0] ? rowToBuild(result.rows[0]) : null;
  }

  async listActive(limit: number): Promise<BuildRecord[]> {
    const result = await this.pool.query<Row>(
      "SELECT * FROM environment_builds WHERE status IN ('queued','running') ORDER BY created_at ASC LIMIT $1",
      [limit],
    );
    return result.rows.map(rowToBuild);
  }

  async listCleanupPending(limit: number): Promise<BuildRecord[]> {
    const result = await this.pool.query<Row>(
      "SELECT * FROM environment_builds WHERE status IN ('succeeded','failed','cancelled') AND cleaned_at IS NULL ORDER BY finished_at ASC LIMIT $1",
      [limit],
    );
    return result.rows.map(rowToBuild);
  }

  async transition(id: string, transition: BuildTransition): Promise<BuildRecord | null> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const locked = await client.query<Row>("SELECT status FROM environment_builds WHERE id=$1 FOR UPDATE", [id]);
      const previousStatus = locked.rows[0]?.status;
      if (typeof previousStatus !== "string" || !transition.from.includes(previousStatus as BuildRecord["status"])) {
        await client.query("ROLLBACK");
        return null;
      }
      const updated = await client.query<Row>(
        `UPDATE environment_builds SET
          status=$2,
          started_at=COALESCE($3::timestamptz, started_at),
          finished_at=COALESCE($4::timestamptz, finished_at),
          image_ref=COALESCE($5, image_ref),
          image_digest=COALESCE($6, image_digest),
          provenance_json=COALESCE($7::jsonb, provenance_json),
          consumable_json=COALESCE($8::jsonb, consumable_json),
          failure_code=COALESCE($9, failure_code),
          failure_detail=COALESCE($10, failure_detail)
         WHERE id=$1 RETURNING *`,
        [id, transition.to, transition.startedAt ?? null, transition.finishedAt ?? null, transition.imageRef ?? null,
          transition.imageDigest ?? null, transition.buildProvenance ? JSON.stringify(transition.buildProvenance) : null,
          transition.consumable ? JSON.stringify(transition.consumable) : null, transition.failureCode ?? null,
          transition.failureDetail ?? null],
      );
      const row = updated.rows[0];
      if (!row) {
        await client.query("ROLLBACK");
        return null;
      }
      await writeAudit(client, rowToBuild(row), previousStatus, transition);
      await client.query("COMMIT");
      return rowToBuild(row);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async markCleaned(id: string, cleanedAt: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const updated = await client.query<Row>(
        "UPDATE environment_builds SET cleaned_at=$2 WHERE id=$1 AND cleaned_at IS NULL RETURNING requested_by, status",
        [id, cleanedAt],
      );
      const row = updated.rows[0];
      if (row) {
        await client.query(
          `INSERT INTO builder_audit_events(build_id, actor, action, previous_status, next_status, details_json)
           VALUES ($1,$2,'build.namespace_cleaned',$3,$3,'{}'::jsonb)`,
          [id, row.requested_by, row.status],
        );
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

async function writeAudit(client: PoolClient, record: BuildRecord, previousStatus: string, transition: BuildTransition): Promise<void> {
  await client.query(
    `INSERT INTO builder_audit_events(build_id, actor, action, previous_status, next_status, details_json)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb)`,
    [record.id, record.requestedBy, transition.auditAction, previousStatus, transition.to, JSON.stringify(transition.auditDetails ?? {})],
  );
}

function rowToBuild(row: Row): BuildRecord {
  return {
    id: String(row.id), labId: String(row.lab_id), labVersion: Number(row.lab_version), requestedBy: String(row.requested_by),
    idempotencyKey: String(row.idempotency_key), requestDigest: String(row.request_digest), specDigest: String(row.spec_digest),
    spec: json(row.spec_json) as BuildRecord["spec"], resolvedPackages: json(row.resolved_packages_json) as BuildRecord["resolvedPackages"],
    status: row.status as BuildRecord["status"], namespace: String(row.namespace), jobName: String(row.job_name),
    ...(row.image_ref ? { imageRef: String(row.image_ref) } : {}), ...(row.image_digest ? { imageDigest: String(row.image_digest) } : {}),
    ...(row.provenance_json ? { buildProvenance: json(row.provenance_json) as BuildRecord["buildProvenance"] } : {}),
    ...(row.consumable_json ? { consumable: json(row.consumable_json) as BuildRecord["consumable"] } : {}),
    ...(row.failure_code ? { failureCode: String(row.failure_code) } : {}), ...(row.failure_detail ? { failureDetail: String(row.failure_detail) } : {}),
    createdAt: timestamp(row.created_at), ...(row.started_at ? { startedAt: timestamp(row.started_at) } : {}),
    ...(row.finished_at ? { finishedAt: timestamp(row.finished_at) } : {}), deadlineAt: timestamp(row.deadline_at),
    ...(row.cleaned_at ? { cleanedAt: timestamp(row.cleaned_at) } : {}),
  };
}

function json(value: unknown): unknown {
  if (typeof value !== "string") return value;
  return JSON.parse(value) as unknown;
}

function timestamp(value: unknown): string {
  return value instanceof Date ? value.toISOString() : String(value);
}

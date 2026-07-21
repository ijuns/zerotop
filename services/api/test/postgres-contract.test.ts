import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createApplication, validateProductionEdgeConfiguration } from "../src/app.ts";
import { RepositoryError } from "../src/errors.ts";

test("production defaults to PostgreSQL and requires DATABASE_URL", () => {
  assert.throws(
    () =>
      createApplication({
        authMode: "production",
        repositoryMode: "postgres",
        databaseUrl: "",
      }),
    (error: unknown) =>
      error instanceof RepositoryError && error.code === "DATABASE_URL_REQUIRED",
  );
});

test("AUTH_MODE=dev selects the explicit development SQLite adapter", async () => {
  const application = createApplication({ authMode: "dev", databasePath: ":memory:" });
  try {
    await application.ready;
    assert.equal(application.repositoryMode, "sqlite");
  } finally {
    await application.close();
  }
});

test("production edge URLs, origins, and peer tokens fail closed", () => {
  const valid = {
    allowedOrigins: ["https://range.example.com"],
    desktopGatewayInternalToken: "desktop-production-token-000000000",
    desktopGatewayPublicUrl: "https://desktop.example.com",
    openVpnDownloadInternalToken: "vpn-production-token-000000000000",
    openVpnDownloadPublicUrl: "https://vpn.example.com/download",
  };
  assert.doesNotThrow(() => validateProductionEdgeConfiguration(valid));
  assert.throws(() => validateProductionEdgeConfiguration({ ...valid, allowedOrigins: [] }), (error: unknown) => error instanceof RepositoryError && error.code === "PRODUCTION_ORIGINS_REQUIRED");
  assert.throws(() => validateProductionEdgeConfiguration({ ...valid, desktopGatewayPublicUrl: "https://desktop.codegate.invalid" }), (error: unknown) => error instanceof RepositoryError && error.code === "PRODUCTION_PUBLIC_URL_INVALID");
  assert.throws(() => validateProductionEdgeConfiguration({ ...valid, openVpnDownloadInternalToken: "" }), (error: unknown) => error instanceof RepositoryError && error.code === "PRODUCTION_PEER_TOKEN_INVALID");
  assert.throws(() => validateProductionEdgeConfiguration({ ...valid, allowedOrigins: ["http://range.example.com"] }), (error: unknown) => error instanceof RepositoryError && error.code === "PRODUCTION_ORIGIN_INVALID");
});

test("PostgreSQL migration covers repository invariants", async () => {
  const sql = await readFile(
    new URL("../migrations/001_initial.sql", import.meta.url),
    "utf8",
  );
  for (const table of [
    "users",
    "organizations",
    "organization_memberships",
    "labs",
    "validation_evidence",
    "runtime_runs",
    "challenge_results",
    "idempotency_records",
    "audit_logs",
  ]) {
    assert.match(sql, new RegExp(`CREATE TABLE ${table}\\b`));
  }
  assert.match(sql, /user_id TEXT PRIMARY KEY REFERENCES users\(id\)/);
  assert.match(sql, /response_json JSONB NOT NULL/);
  assert.match(sql, /metadata_json JSONB NOT NULL/);

  const readinessMigration = await readFile(
    new URL("../migrations/008_runtime_failed_status.sql", import.meta.url),
    "utf8",
  );
  assert.match(readinessMigration, /'provisioning', 'ready', 'failed'/);

  const adminMigration = await readFile(
    new URL("../migrations/009_admin_organizations.sql", import.meta.url),
    "utf8",
  );
  assert.match(adminMigration, /join_code_hash TEXT/);
  assert.match(adminMigration, /digest\(lower\(btrim\(join_code\)\), 'sha256'\)/);
  assert.match(adminMigration, /DROP COLUMN IF EXISTS join_code/);
  assert.match(adminMigration, /admin_quarantined_at TIMESTAMPTZ/);
  assert.match(adminMigration, /admin_quarantined_by TEXT REFERENCES users\(id\)/);
});

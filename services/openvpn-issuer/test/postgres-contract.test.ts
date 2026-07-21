import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("PostgreSQL profile state keeps encrypted bundles and scoped bootstrap audit state", async () => {
  const migration = await readFile(
    new URL("../migrations/001_profiles.sql", import.meta.url),
    "utf8",
  );
  for (const fragment of [
    "CREATE TABLE IF NOT EXISTS openvpn_profiles",
    "encrypted_client_bundle JSONB NOT NULL",
    "encrypted_server_bundle JSONB NOT NULL",
    "bootstrap_token_hash CHAR(64) NOT NULL",
    "bootstrap_consumed_at TIMESTAMPTZ",
    "revoked_at TIMESTAMPTZ",
  ]) {
    assert.match(migration, new RegExp(fragment.replace(/[()]/g, "\\$&")));
  }
  assert.doesNotMatch(migration, /client_private_key|server_private_key/i);
});

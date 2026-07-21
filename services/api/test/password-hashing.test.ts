import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { createDatabase, SqliteDevelopmentRepository } from "../src/database.ts";
import {
  hashPassword,
  needsPasswordRehash,
  verifyPassword,
} from "../src/security.ts";

const PASSWORD = "correct horse battery staple";

test("stored passwords are salted, parameterised and non-reversible", () => {
  const stored = hashPassword(PASSWORD);
  assert.ok(stored);

  // Self-describing so the cost can be raised without invalidating old hashes.
  const parts = stored.split("$");
  assert.equal(parts.length, 6);
  assert.equal(parts[0], "scrypt");
  assert.equal(Number(parts[1]), 32_768);

  // The plaintext never appears, and neither does the old bare digest.
  assert.doesNotMatch(stored, new RegExp(PASSWORD, "i"));
  const legacy = createHash("sha256").update(PASSWORD, "utf8").digest("hex");
  assert.equal(stored.includes(legacy), false);

  // Salted: the same password hashes differently every time.
  assert.notEqual(hashPassword(PASSWORD), stored);

  assert.equal(verifyPassword(PASSWORD, stored), true);
  assert.equal(verifyPassword("wrong password", stored), false);
  assert.equal(verifyPassword(PASSWORD, null), false);
  assert.equal(verifyPassword(undefined, stored), false);
  assert.equal(hashPassword(undefined), null);
  assert.equal(hashPassword(""), null);
});

test("pre-scrypt rows still verify and are flagged for upgrade", () => {
  const legacy = createHash("sha256").update(PASSWORD, "utf8").digest("hex");

  // Accounts written before this change keep working.
  assert.equal(verifyPassword(PASSWORD, legacy), true);
  assert.equal(verifyPassword("wrong password", legacy), false);

  assert.equal(needsPasswordRehash(legacy), true);
  assert.equal(needsPasswordRehash(hashPassword(PASSWORD)), false);
  assert.equal(needsPasswordRehash(null), false);

  // A weaker cost is treated as needing an upgrade.
  assert.equal(needsPasswordRehash("scrypt$1024$8$1$c2FsdA$aGFzaA"), true);
  // Anything unrecognised is not accepted as a valid password.
  assert.equal(verifyPassword(PASSWORD, "not-a-hash"), false);
  assert.equal(verifyPassword(PASSWORD, "scrypt$broken"), false);
});

test("registration persists a scrypt hash, never the plaintext", () => {
  const database = createDatabase(":memory:");
  const repository = new SqliteDevelopmentRepository(database);
  try {
    repository.initialize();
    repository.register({
      email: "hashing@example.test",
      handle: "hashing_user",
      displayName: "Hashing User",
      affiliation: "보안관제팀",
      password: PASSWORD,
      accountType: "personal",
      consent: { terms: true, privacy: true },
    });

    const row = database
      .prepare("SELECT password_hash FROM users WHERE email = ?")
      .get("hashing@example.test") as { password_hash: string };

    assert.match(row.password_hash, /^scrypt\$32768\$8\$1\$/);
    assert.doesNotMatch(row.password_hash, new RegExp(PASSWORD, "i"));
    assert.equal(verifyPassword(PASSWORD, row.password_hash), true);

    // The seeded development accounts are hashed the same way.
    const fixture = database
      .prepare("SELECT password_hash FROM users WHERE id = 'user_dev'")
      .get() as { password_hash: string } | undefined;
    if (fixture) assert.match(fixture.password_hash, /^scrypt\$/);
  } finally {
    repository.close();
  }
});

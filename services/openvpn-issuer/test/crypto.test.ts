import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";

import { BundleCipher } from "../src/crypto.ts";

test("AES-256-GCM bundle encryption round-trips and binds associated data", () => {
  const cipher = new BundleCipher(randomBytes(32));
  const plaintext = {
    privateKey: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
  };
  const encrypted = cipher.encrypt(plaintext, "client:run-1:profile-1");

  assert.equal(encrypted.algorithm, "AES-256-GCM");
  assert.doesNotMatch(JSON.stringify(encrypted), /PRIVATE KEY|secret/);
  assert.deepEqual(
    cipher.decrypt(encrypted, "client:run-1:profile-1"),
    plaintext,
  );
  assert.throws(() => cipher.decrypt(encrypted, "server:run-1:profile-1"));
});

test("master key parsing accepts only canonical base64 with 32 bytes", () => {
  const valid = randomBytes(32).toString("base64");
  assert.ok(BundleCipher.fromBase64(valid));
  assert.throws(() => BundleCipher.fromBase64(randomBytes(31).toString("base64")));
  assert.throws(() => BundleCipher.fromBase64("not base64"));
});

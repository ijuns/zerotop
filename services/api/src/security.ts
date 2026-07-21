import {
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

/** Join codes are 192-bit random capabilities; only this digest is persisted. */
export function generateOrganizationJoinCode(): string {
  return `cg_${randomBytes(24).toString("base64url")}`;
}

export function hashOrganizationJoinCode(value: string): string {
  return createHash("sha256")
    .update(value.trim().toLowerCase(), "utf8")
    .digest("hex");
}

/**
 * Password storage.
 *
 * scrypt is memory-hard, so a stolen table cannot be attacked with the
 * throughput a plain digest allows. Parameters are stored in the encoded value
 * rather than assumed, so they can be raised later without invalidating
 * existing hashes. Node's implementation is used deliberately: the service
 * keeps a single runtime dependency and a native password library would drag a
 * toolchain into every image build.
 */
const SCRYPT_PREFIX = "scrypt";
const SCRYPT_COST = 32_768; // N
const SCRYPT_BLOCK_SIZE = 8; // r
const SCRYPT_PARALLELISM = 1; // p
const SCRYPT_KEY_LENGTH = 32;
// 128 * N * r is 32 MiB here, which is exactly Node's default limit, so the
// budget is raised rather than sitting on the boundary.
const SCRYPT_MAX_MEMORY = 64 * 1024 * 1024;

/** A pre-scrypt digest: bare lowercase SHA-256 hex, no salt and no parameters. */
const LEGACY_DIGEST = /^[0-9a-f]{64}$/;

function derive(password: string, salt: Buffer): Buffer {
  return scryptSync(password.normalize("NFKC"), salt, SCRYPT_KEY_LENGTH, {
    N: SCRYPT_COST,
    r: SCRYPT_BLOCK_SIZE,
    p: SCRYPT_PARALLELISM,
    maxmem: SCRYPT_MAX_MEMORY,
  });
}

export function hashPassword(password: string | undefined): string | null {
  if (!password) return null;
  const salt = randomBytes(16);
  const key = derive(password, salt);
  return [
    SCRYPT_PREFIX,
    SCRYPT_COST,
    SCRYPT_BLOCK_SIZE,
    SCRYPT_PARALLELISM,
    salt.toString("base64url"),
    key.toString("base64url"),
  ].join("$");
}

function equals(left: Buffer, right: Buffer): boolean {
  // timingSafeEqual throws on a length mismatch, which would itself leak.
  return left.length === right.length && timingSafeEqual(left, right);
}

/**
 * Verifies a password against either encoding. Rows written before scrypt still
 * validate, so existing accounts keep working; use `needsPasswordRehash` to
 * upgrade them once the plaintext is available.
 */
export function verifyPassword(
  password: string | undefined,
  stored: string | null | undefined,
): boolean {
  if (!password || !stored) return false;

  if (LEGACY_DIGEST.test(stored)) {
    const candidate = createHash("sha256").update(password, "utf8").digest();
    return equals(candidate, Buffer.from(stored, "hex"));
  }

  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== SCRYPT_PREFIX) return false;
  const [, cost, blockSize, parallelism, salt, key] = parts;
  const expected = Buffer.from(key, "base64url");
  let candidate: Buffer;
  try {
    candidate = scryptSync(
      password.normalize("NFKC"),
      Buffer.from(salt, "base64url"),
      expected.length,
      {
        N: Number(cost),
        r: Number(blockSize),
        p: Number(parallelism),
        maxmem: SCRYPT_MAX_MEMORY,
      },
    );
  } catch {
    return false;
  }
  return equals(candidate, expected);
}

/** True when the stored value should be replaced on the next successful use. */
export function needsPasswordRehash(stored: string | null | undefined): boolean {
  if (!stored) return false;
  if (LEGACY_DIGEST.test(stored)) return true;
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== SCRYPT_PREFIX) return true;
  return (
    Number(parts[1]) < SCRYPT_COST ||
    Number(parts[2]) < SCRYPT_BLOCK_SIZE ||
    Number(parts[3]) < SCRYPT_PARALLELISM
  );
}

/**
 * Stateless session tokens for password login.
 *
 * A token is `base64url(payload).base64url(hmac)`, where payload is
 * `{ sub, exp }`. Signing statelessly avoids a sessions table, which keeps the
 * free single-container deployment simple; the trade-off is that a token cannot
 * be revoked before it expires, so the lifetime is kept short.
 */
const SESSION_TOKEN_TTL_SECONDS = 12 * 60 * 60;

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

function sign(payload: string, secret: string): string {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

export function createSessionToken(
  userId: string,
  secret: string,
  ttlSeconds: number = SESSION_TOKEN_TTL_SECONDS,
): string {
  const payload = b64url(
    JSON.stringify({ sub: userId, exp: Math.floor(Date.now() / 1000) + ttlSeconds }),
  );
  return `${payload}.${sign(payload, secret)}`;
}

/** Returns the user id if the token is well-formed, unexpired and correctly signed. */
export function verifySessionToken(
  token: string | undefined,
  secret: string,
): string | null {
  if (!token || !secret) return null;
  const [payload, signature] = token.split(".");
  if (!payload || !signature) return null;
  const expected = sign(payload, secret);
  const provided = Buffer.from(signature);
  const wanted = Buffer.from(expected);
  if (provided.length !== wanted.length || !timingSafeEqual(provided, wanted)) {
    return null;
  }
  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (
      typeof decoded?.sub !== "string" ||
      typeof decoded?.exp !== "number" ||
      decoded.exp <= Math.floor(Date.now() / 1000)
    ) {
      return null;
    }
    return decoded.sub;
  } catch {
    return null;
  }
}

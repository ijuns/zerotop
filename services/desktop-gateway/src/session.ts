import { createHmac, timingSafeEqual } from "node:crypto";
import { desktopHost, type AuthorizedRun } from "./routing.ts";

interface SessionPayload {
  runId: string;
  namespace: string;
  exp: number;
}

export interface DesktopSession {
  token: string;
  expiresAt: string;
}

const defaultMaximumLifetimeMs = 4 * 60 * 60 * 1000;

export function createDesktopSession(
  run: AuthorizedRun & { expiresAt?: string },
  signingKey: string,
  now = Date.now(),
  maximumLifetimeMs = defaultMaximumLifetimeMs,
): DesktopSession {
  if (!Number.isFinite(maximumLifetimeMs) || maximumLifetimeMs <= 0) {
    throw new Error("Desktop session maximum lifetime is invalid");
  }
  const runExpiry = run.expiresAt ? Date.parse(run.expiresAt) : Number.NaN;
  const maximum = now + maximumLifetimeMs;
  const rawExpiresAt = Number.isFinite(runExpiry) ? Math.min(runExpiry, maximum) : maximum;
  const expiresAt = Math.floor(rawExpiresAt / 1000) * 1000;
  if (expiresAt <= now) throw new Error("Run is already expired");
  const payload: SessionPayload = {
    runId: run.runId,
    namespace: run.namespace,
    exp: Math.floor(expiresAt / 1000),
  };
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return {
    token: `${body}.${signature(body, signingKey)}`,
    expiresAt: new Date(expiresAt).toISOString(),
  };
}

export function createSessionToken(
  run: AuthorizedRun & { expiresAt?: string },
  signingKey: string,
  now = Date.now(),
): string {
  return createDesktopSession(run, signingKey, now).token;
}

export function desktopSessionCookie(
  name: string,
  token: string,
  path: string,
  expiresAt: string,
  secure: boolean,
  now = Date.now(),
): string {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) throw new Error("Desktop session cookie name is invalid");
  if (!path.startsWith("/") || /[;\r\n]/.test(path)) throw new Error("Desktop session cookie path is invalid");
  const expiry = Date.parse(expiresAt);
  if (!Number.isFinite(expiry) || expiry <= now) throw new Error("Desktop session cookie expiry is invalid");
  const maxAge = Math.max(1, Math.floor((expiry - now) / 1000));
  const secureFlag = secure ? "; Secure" : "";
  return `${name}=${encodeURIComponent(token)}; Path=${path}; Max-Age=${maxAge}; Expires=${new Date(expiry).toUTCString()}; HttpOnly${secureFlag}; SameSite=Strict`;
}

export function verifySessionToken(
  token: string,
  expectedRunId: string,
  signingKey: string,
  now = Date.now(),
): AuthorizedRun {
  const [body, provided, extra] = token.split(".");
  if (!body || !provided || extra) throw new Error("Malformed desktop session");
  const expected = signature(body, signingKey);
  const left = Buffer.from(provided, "base64url");
  const right = Buffer.from(expected, "base64url");
  if (left.length !== right.length || !timingSafeEqual(left, right)) {
    throw new Error("Invalid desktop session signature");
  }
  let payload: SessionPayload;
  try {
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as SessionPayload;
  } catch {
    throw new Error("Malformed desktop session payload");
  }
  if (payload.runId !== expectedRunId) throw new Error("Desktop session run mismatch");
  if (!Number.isInteger(payload.exp) || payload.exp * 1000 <= now) {
    throw new Error("Desktop session expired");
  }
  desktopHost(payload.namespace);
  return {
    runId: payload.runId,
    namespace: payload.namespace,
    status: "ready",
    expiresAt: new Date(payload.exp * 1000).toISOString(),
  };
}

export function cookieValue(cookieHeader: string | undefined, name: string): string | null {
  if (!cookieHeader) return null;
  for (const item of cookieHeader.split(";")) {
    const separator = item.indexOf("=");
    if (separator < 0) continue;
    if (item.slice(0, separator).trim() === name) {
      return decodeURIComponent(item.slice(separator + 1).trim());
    }
  }
  return null;
}

function signature(body: string, key: string): string {
  return createHmac("sha256", key).update(body).digest("base64url");
}

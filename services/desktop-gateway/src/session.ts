import { createHmac, timingSafeEqual } from "node:crypto";
import { desktopHost, type AuthorizedRun } from "./routing.ts";

interface SessionPayload {
  runId: string;
  namespace: string;
  exp: number;
}

export function createSessionToken(
  run: AuthorizedRun & { expiresAt?: string },
  signingKey: string,
  now = Date.now(),
): string {
  const runExpiry = run.expiresAt ? Date.parse(run.expiresAt) : Number.NaN;
  const maximum = now + 4 * 60 * 60 * 1000;
  const expiresAt = Number.isFinite(runExpiry) ? Math.min(runExpiry, maximum) : maximum;
  if (expiresAt <= now) throw new Error("Run is already expired");
  const payload: SessionPayload = {
    runId: run.runId,
    namespace: run.namespace,
    exp: Math.floor(expiresAt / 1000),
  };
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${body}.${signature(body, signingKey)}`;
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

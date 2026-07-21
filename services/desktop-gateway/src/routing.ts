export interface AuthorizedRun {
  runId: string;
  namespace: string;
  status: string;
  expiresAt?: string;
}

export function runIdFromPath(pathname: string): string | null {
  const match = pathname.match(/^\/sessions\/([^/]+)\/desktop(?:\/.*)?$/);
  if (!match) return null;
  const runId = decodeURIComponent(match[1]);
  return /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$/.test(runId) ? runId : null;
}

export function backendPath(pathname: string, search: string, runId: string): string {
  const prefix = `/sessions/${encodeURIComponent(runId)}/desktop`;
  if (!pathname.startsWith(prefix)) throw new Error("Path is outside the desktop session");
  const suffix = pathname.slice(prefix.length);
  return `${suffix || "/"}${search}`;
}

export function desktopHost(namespace: string): string {
  if (!/^range-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(namespace)) {
    throw new Error("Runtime returned an invalid namespace");
  }
  return `desktop.${namespace}.svc.cluster.local`;
}

export function parseAuthorizedRun(payload: unknown, expectedRunId: string): AuthorizedRun {
  const root = record(payload);
  const data = record(root.data ?? root);
  const run = record(data.run ?? data);
  const metadata = record(run.metadata);
  if (run.id !== expectedRunId) throw new Error("Run response does not match the request");
  if (typeof run.status !== "string" || !["provisioning", "ready", "running"].includes(run.status)) {
    throw new Error("Run is not available for desktop access");
  }
  if (typeof metadata.namespace !== "string") {
    throw new Error("Run has no runtime namespace");
  }
  desktopHost(metadata.namespace);
  return { runId: expectedRunId, namespace: metadata.namespace, status: run.status };
}

export function parseTicketExchange(payload: unknown, expectedRunId: string): AuthorizedRun {
  const root = record(payload);
  const envelope = record(root.data ?? root);
  const data = record(envelope.access ?? envelope);
  if (data.runId !== expectedRunId) throw new Error("Ticket does not match the requested run");
  if (typeof data.namespace !== "string") throw new Error("Ticket has no runtime namespace");
  if (typeof data.expiresAt !== "string" || !Number.isFinite(Date.parse(data.expiresAt))) {
    throw new Error("Ticket has no valid expiration");
  }
  desktopHost(data.namespace);
  return {
    runId: expectedRunId,
    namespace: data.namespace,
    status: "ready",
    expiresAt: data.expiresAt,
  };
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

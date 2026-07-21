import { ServiceError } from "./errors.ts";
import { parseIpv4Cidr } from "./network.ts";
import { endpointParts } from "./render.ts";
import type { BootstrapRequest, IssueProfileRequest } from "./types.ts";

type JsonRecord = Record<string, unknown>;

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const NAMESPACE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const BOOTSTRAP_TOKEN = /^[A-Za-z0-9_-]{43,128}$/;
const DOWNLOAD_TICKET = /^[A-Za-z0-9_-]{32,256}$/;

export function parseIssueProfileRequest(
  value: unknown,
  options: {
    now: Date;
    maxTtlMinutes: number;
    allowedCidr: string;
  },
): IssueProfileRequest {
  const input = object(value, "request");
  rejectUnknown(input, [
    "runId",
    "userId",
    "namespace",
    "expiresAt",
    "gatewayEndpoint",
    "isolationMode",
    "routes",
    "allowedCidr",
  ]);
  const runId = identifier(input.runId, "runId");
  const userId = identifier(input.userId, "userId");
  const namespace = string(input.namespace, "namespace");
  if (!NAMESPACE.test(namespace) || !namespace.startsWith("range-")) {
    invalid("namespace must be a run-scoped Kubernetes namespace.");
  }
  const expiresAt = string(input.expiresAt, "expiresAt");
  const expiration = Date.parse(expiresAt);
  const minimum = options.now.getTime() + 60_000;
  const maximum = options.now.getTime() + options.maxTtlMinutes * 60_000 + 5_000;
  if (!Number.isFinite(expiration) || expiration < minimum || expiration > maximum) {
    invalid(`expiresAt must be between 1 and ${options.maxTtlMinutes} minutes ahead.`);
  }
  const gatewayEndpoint = string(input.gatewayEndpoint, "gatewayEndpoint");
  try {
    endpointParts(gatewayEndpoint);
  } catch (error) {
    invalid(error instanceof Error ? error.message : "gatewayEndpoint is invalid.");
  }
  if (input.isolationMode !== "per_run_gateway") {
    invalid("isolationMode must be per_run_gateway.");
  }
  if (!Array.isArray(input.routes) || input.routes.length !== 1) {
    invalid("routes must contain exactly one run namespace.");
  }
  const route = object(input.routes[0], "routes[0]");
  rejectUnknown(route, ["namespace"]);
  if (route.namespace !== namespace) {
    invalid("The only route must match the run namespace.");
  }
  const configuredCidr = parseCidr(options.allowedCidr, "OPENVPN_ALLOWED_CIDR");
  const requestedCidr =
    input.allowedCidr === undefined
      ? configuredCidr
      : parseCidr(string(input.allowedCidr, "allowedCidr"), "allowedCidr");
  if (requestedCidr !== configuredCidr) {
    invalid("allowedCidr must match the server-side route policy.");
  }
  return {
    runId,
    userId,
    namespace,
    expiresAt: new Date(expiration).toISOString(),
    gatewayEndpoint,
    isolationMode: "per_run_gateway",
    routes: [{ namespace }],
    allowedCidr: configuredCidr,
  };
}

export function parseBootstrapRequest(value: unknown): BootstrapRequest {
  const input = object(value, "request");
  rejectUnknown(input, ["runId", "profileId", "bootstrapToken"]);
  const runId = identifier(input.runId, "runId");
  const profileId = identifier(input.profileId, "profileId");
  const bootstrapToken = string(input.bootstrapToken, "bootstrapToken");
  if (!BOOTSTRAP_TOKEN.test(bootstrapToken)) {
    invalid("bootstrapToken is malformed.");
  }
  return { runId, profileId, bootstrapToken };
}

export function parseDownloadTicket(value: string | null): string {
  if (!value || !DOWNLOAD_TICKET.test(value)) {
    invalid("The OpenVPN download ticket is malformed.");
  }
  return value;
}

export function parseRunId(value: string): string {
  try {
    return identifier(decodeURIComponent(value), "runId");
  } catch {
    invalid("runId is malformed.");
  }
}

function parseCidr(value: string, field: string): string {
  try {
    return parseIpv4Cidr(value, field).cidr;
  } catch (error) {
    invalid(error instanceof Error ? error.message : `${field} is invalid.`);
  }
}

function identifier(value: unknown, field: string): string {
  const result = string(value, field);
  if (!IDENTIFIER.test(result)) invalid(`${field} is malformed.`);
  return result;
}

function string(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0) {
    invalid(`${field} must be a non-empty string.`);
  }
  return value;
}

function object(value: unknown, field: string): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    invalid(`${field} must be an object.`);
  }
  return value as JsonRecord;
}

function rejectUnknown(value: JsonRecord, allowed: string[]): void {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) invalid(`Unknown field: ${unknown[0]}.`);
}

function invalid(message: string): never {
  throw new ServiceError(400, "invalid_request", message);
}

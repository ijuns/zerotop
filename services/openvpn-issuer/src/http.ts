import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { ServiceError } from "./errors.ts";
import {
  parseBootstrapRequest,
  parseDownloadTicket,
  parseIssueProfileRequest,
  parseRunId,
} from "./input.ts";
import type { IssuerOperations } from "./types.ts";

interface IssuerHttpOptions {
  operations: IssuerOperations;
  issuerToken: string;
  maxTtlMinutes: number;
  allowedCidr: string;
  clock?: () => Date;
}

export function createIssuerHttpServer(options: IssuerHttpOptions) {
  if (options.issuerToken.length < 24) {
    throw new Error("OPENVPN_ISSUER_TOKEN must contain at least 24 characters.");
  }
  const clock = options.clock ?? (() => new Date());
  return createServer((request, response) => {
    void route(request, response, options, clock).catch((error: unknown) => {
      if (response.headersSent) return response.destroy();
      const serviceError =
        error instanceof ServiceError
          ? error
          : new ServiceError(500, "internal_error", "OpenVPN issuer failure.");
      json(response, serviceError.status, {
        error: { code: serviceError.code, message: serviceError.message },
      });
    });
  });
}

async function route(
  request: IncomingMessage,
  response: ServerResponse,
  options: IssuerHttpOptions,
  clock: () => Date,
): Promise<void> {
  const method = request.method ?? "GET";
  const url = new URL(request.url ?? "/", "http://issuer.local");
  if (method === "GET" && url.pathname === "/health") {
    return json(response, 200, { status: "ok", service: "openvpn-issuer" });
  }
  if (method === "GET" && url.pathname === "/download") {
    if (
      [...url.searchParams.keys()].some((key) => key !== "ticket") ||
      url.searchParams.getAll("ticket").length !== 1
    ) {
      throw new ServiceError(400, "invalid_request", "Only one ticket is accepted.");
    }
    const ticket = parseDownloadTicket(url.searchParams.get("ticket"));
    const result = await options.operations.download(ticket);
    const filename = `codegate-${result.profileId}.ovpn`;
    response.writeHead(200, {
      "content-type": "application/x-openvpn-profile; charset=utf-8",
      "content-length": Buffer.byteLength(result.profile),
      "content-disposition": `attachment; filename="${filename}"`,
      "cache-control": "no-store, no-cache, must-revalidate",
      pragma: "no-cache",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    });
    response.end(result.profile);
    return;
  }
  if (method === "POST" && url.pathname === "/v1/gateways/bootstrap") {
    const input = parseBootstrapRequest(await readJson(request));
    const bundle = await options.operations.bootstrap(input);
    return json(response, 200, { bundle });
  }
  if (method === "POST" && url.pathname === "/v1/profiles") {
    requireBearer(request, options.issuerToken);
    const input = parseIssueProfileRequest(await readJson(request), {
      now: clock(),
      maxTtlMinutes: options.maxTtlMinutes,
      allowedCidr: options.allowedCidr,
    });
    const provision = await options.operations.issue(input);
    return json(response, 201, provision);
  }
  const revokeMatch = url.pathname.match(/^\/v1\/profiles\/([^/]+)$/);
  if (method === "DELETE" && revokeMatch) {
    requireBearer(request, options.issuerToken);
    const removed = await options.operations.revoke(parseRunId(revokeMatch[1]));
    if (!removed) {
      throw new ServiceError(404, "profile_not_found", "Profile was not found.");
    }
    response.writeHead(204, securityHeaders());
    response.end();
    return;
  }
  throw new ServiceError(404, "not_found", "Route was not found.");
}

function requireBearer(request: IncomingMessage, token: string): void {
  const supplied = String(request.headers.authorization ?? "");
  const expected = `Bearer ${token}`;
  const left = Buffer.from(supplied);
  const right = Buffer.from(expected);
  if (left.length !== right.length || !timingSafeEqual(left, right)) {
    throw new ServiceError(401, "unauthorized", "Internal authentication failed.");
  }
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const data = Buffer.from(chunk);
    size += data.length;
    if (size > 1024 * 1024) {
      throw new ServiceError(413, "payload_too_large", "Request body exceeds 1 MiB.");
    }
    chunks.push(data);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new ServiceError(400, "invalid_json", "Request body is not valid JSON.");
  }
}

function json(response: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    ...securityHeaders(),
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
  });
  response.end(body);
}

function securityHeaders(): Record<string, string> {
  return {
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
  };
}

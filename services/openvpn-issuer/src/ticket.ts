import { ServiceError } from "./errors.ts";
import type { TicketAccess, TicketExchanger } from "./types.ts";

type JsonRecord = Record<string, unknown>;

interface PlatformApiTicketExchangerOptions {
  apiUrl: string;
  internalToken: string;
  fetchImpl?: typeof fetch;
}

export class PlatformApiTicketExchanger implements TicketExchanger {
  private readonly apiUrl: string;
  private readonly internalToken: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: PlatformApiTicketExchangerOptions) {
    this.apiUrl = safeServiceUrl(options.apiUrl, "PLATFORM_API_URL");
    if (options.internalToken.length < 24) {
      throw new Error("OPENVPN_DOWNLOAD_INTERNAL_TOKEN must contain at least 24 characters.");
    }
    this.internalToken = options.internalToken;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async exchange(ticket: string): Promise<TicketAccess> {
    let response: Response;
    try {
      response = await this.fetchImpl(
        `${this.apiUrl}/v1/internal/openvpn-tickets/exchange`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${this.internalToken}`,
            "content-type": "application/json",
            accept: "application/json",
          },
          body: JSON.stringify({ ticket }),
          signal: AbortSignal.timeout(5_000),
        },
      );
    } catch {
      throw new ServiceError(
        503,
        "ticket_exchange_unavailable",
        "OpenVPN ticket exchange is temporarily unavailable.",
      );
    }
    if (!response.ok) {
      throw new ServiceError(
        response.status >= 500 ? 503 : 410,
        "ticket_rejected",
        "The OpenVPN download ticket is invalid, expired or already consumed.",
      );
    }
    const payload = record(await response.json().catch(() => null));
    const data = record(payload.data);
    const access = record(data.access);
    const openVpn = record(access.openVpn);
    const runId = access.runId;
    const profileId = openVpn.profileId;
    if (
      typeof runId !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(runId) ||
      typeof profileId !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(profileId)
    ) {
      throw new ServiceError(
        502,
        "invalid_ticket_exchange",
        "The platform API returned invalid OpenVPN access metadata.",
      );
    }
    return { runId, profileId };
  }
}

function safeServiceUrl(value: string, field: string): string {
  const url = new URL(value);
  const clusterLocal =
    url.hostname.endsWith(".svc.cluster.local") || !url.hostname.includes(".");
  if (url.protocol !== "https:" && !clusterLocal && url.hostname !== "localhost") {
    throw new Error(`${field} must use HTTPS outside the cluster.`);
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(`${field} must not contain credentials, a query or a fragment.`);
  }
  return value.replace(/\/$/, "");
}

function record(value: unknown): JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonRecord)
    : {};
}

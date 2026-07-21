import { createHash, randomUUID } from "node:crypto";

export interface OpenVpnProfile {
  profileId: string;
  endpoint: string;
  assignedIp: string;
  allowedCidr: string;
  expiresAt: string;
}

export interface OpenVpnProvision {
  profile: OpenVpnProfile;
  /** One-time, run-scoped credential consumed only by the run gateway. */
  gatewayBootstrapToken: string;
}

export interface OpenVpnIssueRequest {
  runId: string;
  userId: string;
  namespace: string;
  expiresAt: string;
  gatewayEndpoint: string;
  allowedCidr: string;
}

export interface OpenVpnIssuer {
  issue(input: OpenVpnIssueRequest): Promise<OpenVpnProvision>;
  revoke(runId: string): Promise<void>;
}

export class LocalOpenVpnIssuer implements OpenVpnIssuer {
  async issue(input: OpenVpnIssueRequest): Promise<OpenVpnProvision> {
    const octet = (Number.parseInt(createHash("sha256").update(input.runId).digest("hex").slice(0, 4), 16) % 200) + 20;
    return {
      profile: {
        profileId: `local-${randomUUID()}`,
        endpoint: input.gatewayEndpoint,
        assignedIp: `10.203.0.${octet}`,
        allowedCidr: input.allowedCidr,
        expiresAt: input.expiresAt,
      },
      gatewayBootstrapToken: randomUUID() + randomUUID(),
    };
  }
  async revoke(_runId: string): Promise<void> {}
}

export class ExternalPkiOpenVpnIssuer implements OpenVpnIssuer {
  private readonly endpoint: string;
  private readonly token: string;

  constructor(endpoint: string, token: string) {
    this.endpoint = endpoint;
    this.token = token;
  }

  async issue(input: OpenVpnIssueRequest): Promise<OpenVpnProvision> {
    const response = await fetch(`${this.endpoint}/v1/profiles`, {
      method: "POST",
      headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json" },
      body: JSON.stringify({
        ...input,
        isolationMode: "per_run_gateway",
        routes: [{ namespace: input.namespace }],
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`OpenVPN issuer failed with ${response.status}`);
    const payload = await response.json() as Record<string, unknown>;
    const rawProfile = isRecord(payload.profile) ? payload.profile : payload;
    const profile = profileFrom(rawProfile);
    if (profile.endpoint !== input.gatewayEndpoint) {
      throw new Error("OpenVPN issuer returned an endpoint outside the run gateway contract");
    }
    if (profile.allowedCidr !== input.allowedCidr) {
      throw new Error("OpenVPN issuer returned routes outside the configured cluster CIDR");
    }
    const gatewayBootstrapToken = String(payload.gatewayBootstrapToken ?? "");
    if (gatewayBootstrapToken.length < 32) {
      throw new Error("OpenVPN issuer did not return a strong run-scoped gateway token");
    }
    return { profile, gatewayBootstrapToken };
  }

  async revoke(runId: string): Promise<void> {
    const response = await fetch(`${this.endpoint}/v1/profiles/${encodeURIComponent(runId)}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${this.token}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok && response.status !== 404) throw new Error(`OpenVPN revoke failed with ${response.status}`);
  }
}

function profileFrom(value: Record<string, unknown>): OpenVpnProfile {
  const profile = {
    profileId: String(value.profileId ?? ""),
    endpoint: String(value.endpoint ?? ""),
    assignedIp: String(value.assignedIp ?? ""),
    allowedCidr: String(value.allowedCidr ?? ""),
    expiresAt: String(value.expiresAt ?? ""),
  };
  if (
    !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(profile.profileId) ||
    !/^[a-zA-Z0-9.-]+:\d{1,5}$/.test(profile.endpoint) ||
    !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(profile.assignedIp) ||
    !/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(profile.allowedCidr) ||
    !Number.isFinite(Date.parse(profile.expiresAt))
  ) {
    throw new Error("OpenVPN issuer returned malformed profile metadata");
  }
  return profile;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

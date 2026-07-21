import { createPublicKey, verify as verifySignature, type JsonWebKey } from "node:crypto";

export type PlatformRole = "individual" | "org_member" | "org_admin" | "platform_admin";

export interface AuthPrincipal {
  subject: string;
  email?: string;
  displayName?: string;
  roles: PlatformRole[];
  organizationId?: string;
  mode: "oidc" | "dev";
}

export interface OidcVerifierOptions {
  issuer: string;
  audience: string;
  clientId: string;
  clockToleranceSeconds?: number;
  jwksCacheSeconds?: number;
  fetchImpl?: typeof fetch;
}

type JwtClaims = {
  sub: string;
  iss: string;
  aud: string | string[];
  exp: number;
  nbf?: number;
  email?: string;
  name?: string;
  org_id?: string;
  realm_access?: { roles?: string[] };
  resource_access?: Record<string, { roles?: string[] }>;
};

type JwkSet = { keys: Array<JsonWebKey & { kid?: string; alg?: string; use?: string }> };

export class AuthenticationError extends Error {
  readonly status: number;

  constructor(message: string, status = 401) {
    super(message);
    this.status = status;
  }
}

export class OidcVerifier {
  private jwks?: { expiresAt: number; value: JwkSet };
  private readonly fetchImpl: typeof fetch;
  private readonly issuer: string;
  private readonly options: OidcVerifierOptions;

  constructor(options: OidcVerifierOptions) {
    this.options = options;
    this.issuer = options.issuer.replace(/\/$/, "");
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async verify(token: string): Promise<AuthPrincipal> {
    const parts = token.split(".");
    if (parts.length !== 3) throw new AuthenticationError("Malformed bearer token");
    const header = decodeJson<{ alg?: string; kid?: string }>(parts[0]);
    const claims = decodeJson<JwtClaims>(parts[1]);
    if (header.alg !== "RS256" || !header.kid) throw new AuthenticationError("Only keyed RS256 tokens are accepted");
    const key = await this.findKey(header.kid);
    const verified = verifySignature(
      "RSA-SHA256",
      Buffer.from(`${parts[0]}.${parts[1]}`),
      createPublicKey({ key, format: "jwk" }),
      Buffer.from(parts[2], "base64url"),
    );
    if (!verified) throw new AuthenticationError("Invalid token signature");
    this.validateClaims(claims);

    const realmRoles = claims.realm_access?.roles ?? [];
    const clientRoles = claims.resource_access?.[this.options.clientId]?.roles ?? [];
    const roles = [...new Set([...realmRoles, ...clientRoles])].filter(isPlatformRole);
    return {
      subject: claims.sub,
      email: claims.email,
      displayName: claims.name,
      roles,
      organizationId: claims.org_id,
      mode: "oidc",
    };
  }

  private validateClaims(claims: JwtClaims): void {
    const now = Math.floor(Date.now() / 1000);
    const tolerance = this.options.clockToleranceSeconds ?? 30;
    if (!claims.sub) throw new AuthenticationError("Token has no subject");
    if (claims.iss !== this.issuer) throw new AuthenticationError("Unexpected token issuer");
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audiences.includes(this.options.audience)) throw new AuthenticationError("Unexpected token audience");
    if (!claims.exp || claims.exp < now - tolerance) throw new AuthenticationError("Token expired");
    if (claims.nbf && claims.nbf > now + tolerance) throw new AuthenticationError("Token is not active yet");
  }

  private async findKey(kid: string): Promise<JsonWebKey> {
    const now = Date.now();
    if (!this.jwks || this.jwks.expiresAt < now) {
      const response = await this.fetchImpl(`${this.issuer}/protocol/openid-connect/certs`, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(5_000),
      });
      if (!response.ok) throw new AuthenticationError("Unable to load identity provider keys", 503);
      const value = await response.json() as JwkSet;
      this.jwks = { expiresAt: now + (this.options.jwksCacheSeconds ?? 300) * 1000, value };
    }
    const key = this.jwks.value.keys.find((item) => item.kid === kid && (!item.alg || item.alg === "RS256"));
    if (!key) throw new AuthenticationError("No matching signing key");
    return key;
  }
}

export async function authenticateRequest(
  request: Pick<Request, "headers">,
  config: { mode: "dev" | "oidc"; verifier?: OidcVerifier },
): Promise<AuthPrincipal> {
  if (config.mode === "dev") {
    const subject = request.headers.get("x-user-id");
    if (!subject) throw new AuthenticationError("x-user-id is required in explicit dev auth mode");
    const roles = (request.headers.get("x-dev-roles") ?? "individual").split(",").map((item) => item.trim()).filter(isPlatformRole);
    return { subject, roles, mode: "dev" };
  }
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) throw new AuthenticationError("Bearer token is required");
  if (!config.verifier) throw new AuthenticationError("OIDC verifier is not configured", 503);
  return config.verifier.verify(authorization.slice(7));
}

export function requireAnyRole(principal: AuthPrincipal, roles: PlatformRole[]): void {
  if (!principal.roles.some((role) => roles.includes(role))) throw new AuthenticationError("Insufficient role", 403);
}

function decodeJson<T>(segment: string): T {
  try {
    return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as T;
  } catch {
    throw new AuthenticationError("Malformed token encoding");
  }
}

function isPlatformRole(value: string): value is PlatformRole {
  return value === "individual" || value === "org_member" || value === "org_admin" || value === "platform_admin";
}

export type WebAuthMode = "dev" | "local" | "oidc";

export interface WebRuntimeConfig {
  apiUrl: string;
  authMode: WebAuthMode;
  keycloakUrl: string;
  keycloakRealm: string;
  keycloakClientId: string;
  developmentIdentityEnabled: boolean;
  developmentUserId: string;
}

/**
 * Read by the Next.js server at deployment runtime and serialized as public
 * client configuration. These values must never contain secrets.
 */
export function webRuntimeConfig(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): WebRuntimeConfig {
  const developmentIdentityEnabled =
    environment.CODEGATE_WEB_DEVELOPMENT_IDENTITY === "true";
  const rawAuthMode = environment.CODEGATE_WEB_AUTH_MODE?.trim();
  // Password-session mode is explicit; otherwise dev identity implies dev, and
  // its absence implies OIDC, preserving the previous behaviour.
  const authMode: WebAuthMode =
    rawAuthMode === "local"
      ? "local"
      : rawAuthMode === "oidc"
        ? "oidc"
        : rawAuthMode === "dev" || developmentIdentityEnabled
          ? "dev"
          : "oidc";
  const keycloakUrl = environment.CODEGATE_WEB_KEYCLOAK_URL?.trim() || "";
  if (authMode === "oidc" && !keycloakUrl) {
    throw new Error(
      "CODEGATE_WEB_KEYCLOAK_URL is required when development identity is disabled",
    );
  }
  return {
    authMode,
    apiUrl: publicEndpoint(
      "CODEGATE_WEB_API_URL",
      environment.CODEGATE_WEB_API_URL?.trim() || "/api",
      true,
    ),
    keycloakUrl: keycloakUrl
      ? publicEndpoint("CODEGATE_WEB_KEYCLOAK_URL", keycloakUrl, false)
      : "",
    keycloakRealm: safeIdentifier(
      "CODEGATE_WEB_KEYCLOAK_REALM",
      environment.CODEGATE_WEB_KEYCLOAK_REALM?.trim() || "codegate",
    ),
    keycloakClientId:
      safeIdentifier(
        "CODEGATE_WEB_KEYCLOAK_CLIENT_ID",
        environment.CODEGATE_WEB_KEYCLOAK_CLIENT_ID?.trim() || "codegate-web",
      ),
    developmentIdentityEnabled,
    developmentUserId:
      safeIdentifier(
        "CODEGATE_WEB_DEV_USER_ID",
        environment.CODEGATE_WEB_DEV_USER_ID?.trim() || "user-dev-personal",
      ),
  };
}

function publicEndpoint(name: string, value: string, allowRelative: boolean): string {
  if (allowRelative && /^\/[A-Za-z0-9/_-]*$/.test(value) && !value.startsWith("//")) {
    return value.replace(/\/$/, "") || "/";
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} must be an HTTP(S) URL${allowRelative ? " or root-relative path" : ""}`);
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new Error(`${name} must be an HTTP(S) URL without embedded credentials`);
  }
  return value.replace(/\/$/, "");
}

function safeIdentifier(name: string, value: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

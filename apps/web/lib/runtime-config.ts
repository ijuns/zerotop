export interface WebRuntimeConfig {
  apiUrl: string;
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
  const keycloakUrl = environment.CODEGATE_WEB_KEYCLOAK_URL?.trim() || "";
  if (!developmentIdentityEnabled && !keycloakUrl) {
    throw new Error(
      "CODEGATE_WEB_KEYCLOAK_URL is required when development identity is disabled",
    );
  }
  return {
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

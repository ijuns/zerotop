"use client";

import Keycloak from "keycloak-js";
import {
  createContext,
  type ReactNode,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  configureClientRuntime,
  isDevelopmentIdentityEnabled,
  setAccessTokenProvider,
} from "../lib/api";
import type { WebRuntimeConfig } from "../lib/runtime-config";

interface AuthContextValue {
  mode: "dev" | "oidc";
  ready: boolean;
  authenticated: boolean;
  login(): Promise<void>;
  register(): Promise<void>;
  logout(): Promise<void>;
}

const noop = async () => {};
const AuthContext = createContext<AuthContextValue>({
  mode: "dev",
  ready: true,
  authenticated: true,
  login: noop,
  register: noop,
  logout: noop,
});

let keycloak: Keycloak | null = null;
let initialization: Promise<boolean> | null = null;

function oidcClient(config: WebRuntimeConfig): Keycloak {
  if (keycloak) return keycloak;
  const url = config.keycloakUrl.replace(/\/$/, "");
  const realm = config.keycloakRealm;
  const clientId = config.keycloakClientId;
  if (!url) throw new Error("CODEGATE_WEB_KEYCLOAK_URL이 설정되지 않았습니다.");
  keycloak = new Keycloak({ url, realm, clientId });
  return keycloak;
}

async function initializeOidc(config: WebRuntimeConfig): Promise<boolean> {
  const client = oidcClient(config);
  initialization ??= client.init({
    onLoad: "check-sso",
    flow: "standard",
    pkceMethod: "S256",
    checkLoginIframe: true,
    enableLogging: false,
  });
  return initialization;
}

export function AuthProvider({
  children,
  runtimeConfig,
}: {
  children: ReactNode;
  runtimeConfig: WebRuntimeConfig;
}) {
  configureClientRuntime(runtimeConfig);
  const development = isDevelopmentIdentityEnabled();
  const [ready, setReady] = useState(development);
  const [authenticated, setAuthenticated] = useState(development);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (development) {
      setAccessTokenProvider(null);
      return;
    }
    let active = true;
    let client: Keycloak;
    try {
      client = oidcClient(runtimeConfig);
    } catch (reason) {
      setAccessTokenProvider(null);
      setAuthenticated(false);
      setError(reason instanceof Error ? reason.message : "OIDC 설정이 올바르지 않습니다.");
      setReady(true);
      return;
    }
    client.onAuthLogout = () => {
      setAccessTokenProvider(null);
      if (active) setAuthenticated(false);
    };
    client.onAuthRefreshError = () => {
      client.clearToken();
      setAccessTokenProvider(null);
      if (active) setAuthenticated(false);
    };
    void initializeOidc(runtimeConfig)
      .then((isAuthenticated) => {
        if (!active) return;
        if (isAuthenticated) {
          setAccessTokenProvider(async () => {
            try {
              await client.updateToken(30);
              return client.token ?? null;
            } catch {
              client.clearToken();
              return null;
            }
          });
        } else {
          setAccessTokenProvider(null);
        }
        setAuthenticated(isAuthenticated);
        setReady(true);
      })
      .catch((reason: unknown) => {
        if (!active) return;
        setAccessTokenProvider(null);
        setAuthenticated(false);
        setError(reason instanceof Error ? reason.message : "OIDC 초기화에 실패했습니다.");
        setReady(true);
      });
    return () => {
      active = false;
    };
  }, [development, runtimeConfig]);

  const value = useMemo<AuthContextValue>(() => ({
    mode: development ? "dev" : "oidc",
    ready,
    authenticated,
    async login() {
      if (development) return;
      await oidcClient(runtimeConfig).login({ redirectUri: window.location.origin });
    },
    async register() {
      if (development) return;
      await oidcClient(runtimeConfig).register({ redirectUri: window.location.origin });
    },
    async logout() {
      if (development) return;
      setAccessTokenProvider(null);
      await oidcClient(runtimeConfig).logout({ redirectUri: window.location.origin });
    },
  }), [authenticated, development, ready, runtimeConfig]);

  if (!ready) return <AuthGate state="loading" />;
  if (!development && !authenticated) {
    return (
      <AuthGate
        state={error ? "error" : "anonymous"}
        error={error}
        onLogin={() => void value.login()}
        onRegister={() => void value.register()}
      />
    );
  }
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

function AuthGate({
  state,
  error,
  onLogin,
  onRegister,
}: {
  state: "loading" | "anonymous" | "error";
  error?: string | null;
  onLogin?: () => void;
  onRegister?: () => void;
}) {
  return (
    <main className="auth-gate">
      <section className="auth-gate__card" aria-live="polite">
        <span className="auth-gate__brand" aria-hidden="true"><img src="/zerotop-logo.png" alt="" /></span>
        <div className="eyebrow">ZeroTOP · Zero-day Training Orchestration Platform</div>
        <h1>{state === "loading" ? "보안 세션을 확인하고 있습니다" : "실전형 사이버 레인지에 접속하세요"}</h1>
        <p>
          {state === "loading"
            ? "OIDC 세션과 PKCE 응답을 검증하는 중입니다."
            : "개인 학습자 또는 하나의 조직에 소속된 구성원으로 로그인할 수 있습니다."}
        </p>
        {error && <div className="alert alert--error" role="alert"><strong>인증 서비스를 시작하지 못했습니다.</strong><span>{error}</span></div>}
        {state !== "loading" && (
          <div className="auth-gate__actions">
            <button className="primary-button" type="button" onClick={onLogin}>로그인</button>
            <button className="secondary-button" type="button" onClick={onRegister}>회원가입</button>
          </div>
        )}
      </section>
    </main>
  );
}

export function useAuth(): AuthContextValue {
  return useContext(AuthContext);
}

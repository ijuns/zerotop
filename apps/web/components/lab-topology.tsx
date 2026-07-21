import type {
  AccessMethod,
  Lab,
  RunConnection,
  RuntimeRun,
  Team,
} from "../lib/api";

type LabTopologyProps = {
  team: Team;
  mode: "preview" | "runtime";
  lab?: Lab | null;
  run?: RuntimeRun | null;
  ready?: boolean;
  accessMethod?: AccessMethod;
  connection?: RunConnection | null;
  desktopBusy?: boolean;
  desktopError?: string | null;
  vpnBusy?: boolean;
  vpnError?: string | null;
  onOpenDesktop?: () => void;
  onDownloadVpn?: () => void;
};

type TopologyNode = {
  eyebrow: string;
  title: string;
  detail: string;
  icon: string;
  tone: "neutral" | "blue" | "red" | "dark";
  badge?: string;
};

function recordOf(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function stringFrom(value: unknown, keys: string[]): string | null {
  const source = recordOf(value);
  if (!source) return null;
  for (const key of keys) {
    const candidate = source[key];
    if (typeof candidate === "string" && candidate.trim()) return candidate.trim();
  }
  return null;
}

function shortRunId(run?: RuntimeRun | null) {
  if (!run?.id) return "배포 시 자동 생성";
  return run.id.length > 19 ? `${run.id.slice(0, 19)}…` : run.id;
}

function runExpiryLabel(run?: RuntimeRun | null) {
  if (!run?.expiresAt) return "Run 종료 전";
  const value = new Date(run.expiresAt);
  if (Number.isNaN(value.getTime())) return "Run 종료 전";
  return new Intl.DateTimeFormat("ko-KR", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(value);
}

function targetLabel(lab?: Lab | null) {
  const products = Array.isArray(lab?.target?.affectedProducts)
    ? lab.target.affectedProducts.filter((item) => typeof item === "string" && item.trim())
    : [];
  if (products[0]) return products[0];
  return lab?.team === "blue" || lab?.teamType === "blue"
    ? "모니터링 대상 VM"
    : "취약 대상 VM";
}

function runtimeTarget(run?: RuntimeRun | null) {
  const direct = stringFrom(run, ["targetAddress", "targetIp", "targetHost"]);
  if (direct) return direct;
  const metadata = recordOf(run?.metadata);
  return stringFrom(metadata, ["targetAddress", "targetIp", "targetHost"])
    || "target:8080";
}

function redTargetAccess(lab?: Lab | null, run?: RuntimeRun | null) {
  const target = recordOf(lab?.target);
  const service = recordOf(target?.service);
  const runtimeContract = recordOf(target?.runtimeContract);
  const metadata = recordOf(run?.metadata);
  const topology = recordOf(run?.topology) || recordOf(metadata?.topology);
  const topologyTarget = recordOf(topology?.target);
  const directAddress = stringFrom(run, ["targetAddress", "targetIp", "targetHost"])
    || stringFrom(metadata, ["targetAddress", "targetIp", "targetHost"]);
  const hostname = directAddress
    || stringFrom(topologyTarget, ["hostname"])
    || stringFrom(target, ["hostname"])
    || "target";
  const port = numberFrom(run, ["targetPort"])
    ?? numberFrom(metadata, ["targetPort"])
    ?? numberFrom(service, ["port"])
    ?? numberFrom(runtimeContract, ["port"])
    ?? 8080;
  const configuredProtocol = stringFrom(service, ["protocol"])
    || stringFrom(runtimeContract, ["protocol"])
    || "http";
  const protocol = configuredProtocol.toLowerCase() === "tcp" ? "tcp" : "http";
  const normalizedHost = hostname
    .replace(/^https?:\/\//i, "")
    .replace(/:\d+\/?$/, "")
    .replace(/\/$/, "");
  const endpoint = protocol === "http"
    ? `http://${normalizedHost}:${port}`
    : `${normalizedHost}:${port}`;
  return {
    hostname: normalizedHost,
    port,
    protocol,
    endpoint,
    command: protocol === "http"
      ? `curl -i ${endpoint}`
      : `nc -vz ${normalizedHost} ${port}`,
  };
}

function namespaceOf(run?: RuntimeRun | null) {
  const direct = stringFrom(run, ["namespace"]);
  if (direct) return direct;
  const metadata = recordOf(run?.metadata);
  return stringFrom(metadata, ["namespace"]) || shortRunId(run);
}

function numberFrom(value: unknown, keys: string[]): number | null {
  const source = recordOf(value);
  if (!source) return null;
  for (const key of keys) {
    const candidate = source[key];
    if (typeof candidate === "number" && Number.isFinite(candidate)) return candidate;
  }
  return null;
}

function telemetryOf(run?: RuntimeRun | null) {
  const direct = recordOf(run?.telemetry);
  const metadata = recordOf(run?.metadata);
  const topology = recordOf(run?.topology) || recordOf(metadata?.topology);
  return direct || recordOf(topology?.telemetry);
}

function lastEventLabel(run?: RuntimeRun | null, ready = false) {
  const telemetry = telemetryOf(run);
  const value = stringFrom(telemetry, ["lastEventAt", "lastLogAt", "lastSeenAt"]);
  if (!value) return ready ? "실시간 수신 중" : "수집 대기";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("ko-KR", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

function agentLabel(run?: RuntimeRun | null, ready = false) {
  const telemetry = telemetryOf(run);
  const online = numberFrom(telemetry, ["agentsOnline", "onlineAgents", "agentOnline"]);
  const total = numberFrom(telemetry, ["agentsTotal", "totalAgents", "agentTotal"]);
  if (online !== null || total !== null) return `${online ?? 0} / ${total ?? online ?? 0} online`;
  return ready ? "1 / 1 online" : "0 / 1 waiting";
}

function blueNodes(lab?: Lab | null): TopologyNode[] {
  const sources = Array.isArray(lab?.scenario?.logSources)
    ? lab.scenario.logSources.filter((item) => typeof item === "string" && item.trim())
    : [];
  return [
    {
      eyebrow: "SCENARIO REPLAY",
      title: "악성 행위 재현기",
      detail: "안전한 이벤트로 공격 흐름 재현",
      icon: "✦",
      tone: "dark",
      badge: "AI GENERATED",
    },
    {
      eyebrow: "MONITORED TARGET",
      title: targetLabel(lab),
      detail: sources.length > 0 ? sources.slice(0, 2).join(" · ") : "Sysmon · Audit · Application",
      icon: "▤",
      tone: "neutral",
      badge: "ELASTIC AGENT",
    },
    {
      eyebrow: "LOG PIPELINE",
      title: "Elasticsearch",
      detail: "Run 전용 인덱스 · 증거 격리",
      icon: "≋",
      tone: "blue",
      badge: "INGEST",
    },
    {
      eyebrow: "LEARNER DESKTOP",
      title: "Ubuntu SOC · Kibana",
      detail: "브라우저 데스크톱에서 탐지·분석",
      icon: "U",
      tone: "blue",
      badge: "ELK",
    },
  ];
}

function redNodes(lab?: Lab | null): TopologyNode[] {
  const cveIds = [
    ...(Array.isArray(lab?.target?.cveIds) ? lab.target.cveIds : []),
    ...(Array.isArray(lab?.target?.expectedCves) ? lab.target.expectedCves : []),
  ].filter((item) => typeof item === "string" && item.trim());
  return [
    {
      eyebrow: "LEARNER ACCESS",
      title: "Browser / OpenVPN",
      detail: "1회용 세션 자격 증명",
      icon: "⌁",
      tone: "dark",
      badge: "ISOLATED",
    },
    {
      eyebrow: "ATTACK WORKSTATION",
      title: "Kali Attack Box",
      detail: "시나리오별 공격 도구와 자료",
      icon: "K",
      tone: "red",
      badge: "KALI",
    },
    {
      eyebrow: "RANGE NETWORK",
      title: "격리 훈련망",
      detail: "대상만 허용하는 네트워크 정책",
      icon: "⌘",
      tone: "neutral",
      badge: "DENY BY DEFAULT",
    },
    {
      eyebrow: "VULNERABLE TARGET",
      title: targetLabel(lab),
      detail: cveIds[0] || "AI가 생성한 취약 구성",
      icon: "◎",
      tone: "red",
      badge: "TARGET",
    },
  ];
}

export function LabTopology({
  team,
  mode,
  lab,
  run,
  ready = false,
  accessMethod = "browser_desktop",
  connection,
  desktopBusy = false,
  desktopError,
  vpnBusy = false,
  vpnError,
  onOpenDesktop,
  onDownloadVpn,
}: LabTopologyProps) {
  const blue = team === "blue";
  const nodes = blue ? blueNodes(lab) : redNodes(lab);
  const desktopEnabled = accessMethod === "browser_desktop" || accessMethod === "both";
  const vpnEnabled = accessMethod === "openvpn" || accessMethod === "both" || Boolean(connection?.endpoint);
  const sources = Array.isArray(lab?.scenario?.logSources)
    ? lab.scenario.logSources.filter((item) => typeof item === "string" && item.trim())
    : [];
  const redAccess = redTargetAccess(lab, run);
  const redCves = [...new Set([
    ...(Array.isArray(lab?.target?.cveIds) ? lab.target.cveIds : []),
    ...(Array.isArray(lab?.target?.expectedCves) ? lab.target.expectedCves : []),
  ].filter((item): item is string => typeof item === "string" && item.trim().length > 0))];
  const attackChain = Array.isArray(lab?.scenario?.attackChain)
    ? lab.scenario.attackChain.filter((item) => item && (item.id || item.name))
    : [];

  return (
    <section className={`lab-topology lab-topology--${team} lab-topology--${mode}`} aria-label={`${blue ? "블루팀" : "레드팀"} 실습 환경 토폴로지`}>
      <div className="lab-topology__heading">
        <div>
          <span className="panel-kicker">{blue ? "BLUE TEAM RANGE" : "RED TEAM RANGE"}</span>
          <h3>{mode === "preview" ? lab?.title?.trim() || "AI 생성 환경 미리보기" : "격리 환경 연결 지도"}</h3>
          <p>
            {mode === "preview" && lab?.prompt?.trim()
              ? lab.prompt.trim()
              : blue
                ? "대상 VM의 Elastic Agent가 시나리오 로그를 Run 전용 ELK로 전달합니다."
                : "Kali에서 격리된 훈련망을 통해 시나리오 전용 취약 대상에만 접근합니다."}
          </p>
        </div>
        <span className={`topology-live topology-live--${ready ? "ready" : "pending"}`}>
          <i aria-hidden="true" />
          {mode === "preview" ? "생성 계획" : ready ? "환경 연결됨" : "배포 준비 중"}
        </span>
      </div>

      <div className="topology-path" role="list">
        {nodes.map((node, index) => (
          <div className="topology-path__segment" key={`${team}-${node.eyebrow}`} role="listitem">
            <article className={`topology-node topology-node--${node.tone}`}>
              <div className="topology-node__icon" aria-hidden="true">{node.icon}</div>
              <div className="topology-node__copy">
                <small>{node.eyebrow}</small>
                <strong>{node.title}</strong>
                <span>{node.detail}</span>
              </div>
              {node.badge && <em>{node.badge}</em>}
            </article>
            {index < nodes.length - 1 && (
              <span className="topology-connector" aria-hidden="true">
                <i /><b>›</b>
              </span>
            )}
          </div>
        ))}
      </div>

      {mode === "runtime" && (
        <div className="runtime-strip">
          <div className="runtime-strip__facts">
            <span><small>RUN</small><strong>{shortRunId(run)}</strong></span>
            {blue ? (
              <>
                <span className="runtime-stream"><small>ELASTIC AGENT</small><strong><i aria-hidden="true" />{agentLabel(run, ready)}</strong></span>
                <span><small>LAST EVENT</small><strong>{lastEventLabel(run, ready)}</strong></span>
                <span><small>MONITORED TARGET</small><strong>{runtimeTarget(run)}</strong></span>
              </>
            ) : (
              <>
                <span><small>NAMESPACE</small><strong>{namespaceOf(run)}</strong></span>
                <span><small>TARGET</small><strong>{runtimeTarget(run)}</strong></span>
                <span><small>ROUTE</small><strong>{connection?.allowedCidr || "훈련망 내부 전용"}</strong></span>
              </>
            )}
          </div>

          {blue && (
            <div className="runtime-log-sources" aria-label="수집 로그 소스">
              <span>LOG SOURCES</span>
              {(sources.length > 0 ? sources : ["Sysmon", "Windows Security", "Application"]).slice(0, 4).map((source) => (
                <i key={source}>{source}</i>
              ))}
            </div>
          )}

          <div className="runtime-actions">
            {desktopEnabled && (
              <button className="primary-button" type="button" onClick={onOpenDesktop} disabled={!ready || desktopBusy || !onOpenDesktop}>
                {desktopBusy ? <><span className="spinner" aria-hidden="true" /> 새 입장 링크 발급 중</> : <>{blue ? "새 ELK 데스크톱 창 열기" : "새 Kali 데스크톱 창 열기"} <span aria-hidden="true">↗</span></>}
              </button>
            )}
            {vpnEnabled && (
              <button className="secondary-button" type="button" onClick={onDownloadVpn} disabled={!ready || vpnBusy || !onDownloadVpn}>
                {vpnBusy ? <><span className="spinner" aria-hidden="true" /> VPN 프로필 준비 중</> : "OpenVPN 프로필 받기"}
              </button>
            )}
            {!desktopEnabled && !vpnEnabled && <span className="unavailable-note">설정된 접속 방식이 없습니다.</span>}
          </div>

          {desktopEnabled && (
            <div className="runtime-entry-guide" role="note" aria-label="데스크톱 접속 안내">
              <div>
                <strong>5분 · 1회용 입장 링크</strong>
                <p>버튼을 누를 때마다 새 링크를 발급합니다. 5분은 최초 입장 제한이며, 접속 후 데스크톱은 Run 종료 시까지 유지됩니다.</p>
              </div>
              <span>
                RUN 만료
                {run?.expiresAt ? <time dateTime={run.expiresAt}>{runExpiryLabel(run)}</time> : <b>{runExpiryLabel(run)}</b>}
              </span>
            </div>
          )}

          {desktopEnabled && blue && (
            <div className="runtime-elk-guide">
              <strong>ELK 확인</strong>
              <span>데스크톱의 브라우저 → <code>http://kibana:5601</code> → <b>Analytics</b> → <b>Discover</b></span>
              <span>터미널 상태 확인 → <code>curl -fsS http://kibana:5601/api/status</code></span>
            </div>
          )}

          {!blue && (
            <section className="runtime-red-target" aria-label="레드팀 취약 대상 접속 정보">
              <header>
                <div>
                  <span>TARGET ACCESS</span>
                  <strong>취약 대상 접속 정보</strong>
                </div>
                <em>{ready ? "KALI에서 접근 가능" : "대상 준비 중"}</em>
              </header>
              <div className="runtime-red-target__endpoint">
                <code>{redAccess.endpoint}</code>
                <span>이 주소는 격리된 Kali 데스크톱 또는 발급된 OpenVPN 훈련망 안에서만 접근할 수 있습니다.</span>
              </div>
              <dl>
                <div><dt>HOST</dt><dd>{redAccess.hostname}</dd></div>
                <div><dt>PORT</dt><dd>{redAccess.port}</dd></div>
                <div><dt>PROTOCOL</dt><dd>{redAccess.protocol.toUpperCase()}</dd></div>
                <div><dt>QUICK CHECK</dt><dd><code>{redAccess.command}</code></dd></div>
              </dl>
              {(redCves.length > 0 || attackChain.length > 0) && (
                <div className="runtime-red-target__scenario">
                  {redCves.length > 0 && (
                    <div><span>대상 취약점</span>{redCves.slice(0, 4).map((cve) => <i key={cve}>{cve.toUpperCase()}</i>)}</div>
                  )}
                  {attackChain.length > 0 && (
                    <div><span>ATT&amp;CK 흐름</span>{attackChain.slice(0, 6).map((step, index) => <i key={`${step.id || step.name}-${index}`}>{step.id || step.name}</i>)}</div>
                  )}
                </div>
              )}
            </section>
          )}

          {(connection?.endpoint || connection?.username || connection?.password) && (
            <dl className="runtime-vpn-details">
              {connection.endpoint && <div><dt>VPN Endpoint</dt><dd>{connection.endpoint}</dd></div>}
              {connection.assignedIp && <div><dt>할당 IP</dt><dd>{connection.assignedIp}</dd></div>}
              {connection.allowedCidr && <div><dt>허용 CIDR</dt><dd>{connection.allowedCidr}</dd></div>}
              {connection.username && <div><dt>사용자</dt><dd>{connection.username}</dd></div>}
              {connection.password && <div><dt>비밀번호</dt><dd>{connection.password}</dd></div>}
            </dl>
          )}
          {(desktopError || vpnError) && (
            <div className="runtime-errors" role="alert">
              {desktopError && <span>{desktopError}</span>}
              {vpnError && <span>{vpnError}</span>}
            </div>
          )}
        </div>
      )}
    </section>
  );
}

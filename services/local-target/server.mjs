import { createServer } from "node:http";

const host = process.env.HOST ?? "0.0.0.0";
const port = Number(process.env.PORT ?? "8080");

const profiles = {
  command_injection: {
    path: "/api/diagnostics?host=127.0.0.1%3Bid",
    marker: "ZEROTOP_COMMAND_INJECTION_CONFIRMED",
    startingPath: "/api/diagnostics?host=127.0.0.1",
  },
  path_traversal: {
    path: "/download?file=../../../../etc/passwd",
    marker: "ZEROTOP_PATH_TRAVERSAL_CONFIRMED",
    startingPath: "/download?file=manual.txt",
  },
  sql_injection: {
    path: "/api/users?id=1%20OR%201=1",
    marker: "ZEROTOP_SQL_INJECTION_CONFIRMED",
    startingPath: "/api/users?id=1",
  },
  auth_bypass: {
    path: "/admin?role=admin",
    marker: "ZEROTOP_AUTH_BYPASS_CONFIRMED",
    startingPath: "/admin",
  },
  sensitive_data_exposure: {
    path: "/api/debug?view=config",
    marker: "ZEROTOP_SENSITIVE_DATA_EXPOSURE_CONFIRMED",
    startingPath: "/api/debug",
  },
};

const exercise = loadExercise(process.env.ZEROTOP_RED_EXERCISE_BASE64);

const server = createServer((request, response) => {
  const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "target"}`);
  const headers = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
  };

  if (request.method === "GET" && url.pathname === "/health") {
    return json(response, 200, { status: "ok", scenarioId: exercise.scenarioId }, headers);
  }
  if (request.method === "GET" && url.pathname === "/version") {
    return json(response, 200, {
      service: "zerotop-local-red-target",
      contract: "http-v1",
      mode: "bounded-behavioral",
      profile: exercise.profile,
    }, headers);
  }
  if (request.method === "GET" && url.pathname === "/.well-known/zerotop-lab") {
    return json(response, 200, publicExercise(exercise), headers);
  }
  if (request.method === "GET" && url.pathname === "/.well-known/codegate-lab") {
    return json(response, 200, publicExercise(exercise), headers);
  }
  if (request.method === "GET" && url.pathname === "/") {
    return html(response, 200, landingPage(exercise), headers);
  }

  if (request.method === "GET" && exercise.profile === "command_injection" && url.pathname === "/api/diagnostics") {
    const targetHost = url.searchParams.get("host") ?? "";
    if (/[;&|`]\s*(?:id|whoami)\b/i.test(targetHost)) {
      return json(response, 200, {
        host: "127.0.0.1",
        reachable: true,
        output: "uid=1001(websvc) gid=1001(websvc) groups=1001(websvc)",
        finding: profiles.command_injection.marker,
      }, headers);
    }
    if (!/^[a-z0-9.-]{1,253}$/i.test(targetHost)) {
      return json(response, 400, { error: "invalid_host" }, headers);
    }
    return json(response, 200, { host: targetHost, reachable: true, latencyMs: 2 }, headers);
  }

  if (request.method === "GET" && exercise.profile === "path_traversal" && url.pathname === "/download") {
    const file = url.searchParams.get("file") ?? "";
    if (file.includes("..") && /(?:^|\/)etc\/passwd$/i.test(file.replaceAll("\\", "/"))) {
      return text(response, 200,
        `root:x:0:0:root:/root:/sbin/nologin\nwebsvc:x:1001:1001:ZeroTOP Web:/srv/app:/sbin/nologin\n${profiles.path_traversal.marker}\n`,
        "text/plain; charset=utf-8", headers);
    }
    if (file === "manual.txt") {
      return text(response, 200, "ZeroTOP training service manual\n", "text/plain; charset=utf-8", headers);
    }
    return json(response, 404, { error: "file_not_found" }, headers);
  }

  if (request.method === "GET" && exercise.profile === "sql_injection" && url.pathname === "/api/users") {
    const id = url.searchParams.get("id") ?? "";
    if (/\bor\s+1\s*=\s*1\b|\bunion\s+select\b|'\s*--/i.test(id)) {
      return json(response, 200, {
        rows: [
          { id: 1, username: "learner" },
          { id: 2, username: "analyst" },
          { id: 3, username: "service_account" },
        ],
        finding: profiles.sql_injection.marker,
      }, headers);
    }
    if (!/^\d{1,6}$/.test(id)) return json(response, 400, { error: "invalid_id" }, headers);
    return json(response, 200, { rows: [{ id: Number(id), username: "learner" }] }, headers);
  }

  if (request.method === "GET" && exercise.profile === "auth_bypass" && url.pathname === "/admin") {
    if (url.searchParams.get("role") === "admin") {
      return json(response, 200, {
        panel: "training-administration",
        access: "granted",
        finding: profiles.auth_bypass.marker,
      }, headers);
    }
    return json(response, 401, { error: "authentication_required" }, headers);
  }

  if (request.method === "GET" && exercise.profile === "sensitive_data_exposure" && url.pathname === "/api/debug") {
    if (url.searchParams.get("view") === "config") {
      return json(response, 200, {
        environment: "training",
        databaseHost: "db.internal.invalid",
        syntheticApiKey: "ZT_TRAINING_REDACTED",
        finding: profiles.sensitive_data_exposure.marker,
      }, headers);
    }
    return json(response, 404, { error: "debug_view_not_found" }, headers);
  }

  return json(response, 404, { error: "not_found" }, headers);
});

server.listen(port, host, () => {
  console.log(JSON.stringify({
    level: "info",
    service: "local-target",
    host,
    port,
    scenarioId: exercise.scenarioId,
    profile: exercise.profile,
  }));
});

function loadExercise(encoded) {
  const fallback = {
    schemaVersion: 1,
    profile: "sensitive_data_exposure",
    scenarioId: "red-0000000000000000",
    title: "ZeroTOP 격리형 레드팀 대상",
    summary: "대상 서비스의 노출된 디버그 기능을 식별하고 안전하게 검증합니다.",
    expectedCves: [],
    attackTechniqueIds: ["T1190", "T1005"],
    simulationMode: "bounded_behavioral",
  };
  if (!encoded || encoded.length > 32_768) return fallback;
  try {
    const value = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) return fallback;
    if (!(value.profile in profiles)
      || value.schemaVersion !== 1
      || value.simulationMode !== "bounded_behavioral"
      || typeof value.scenarioId !== "string"
      || !/^red-[a-f0-9]{16}$/.test(value.scenarioId)) return fallback;
    return {
      schemaVersion: 1,
      profile: value.profile,
      scenarioId: value.scenarioId,
      title: displayText(value.title, 120, fallback.title),
      summary: displayText(value.summary, 500, fallback.summary),
      expectedCves: stringList(value.expectedCves, /^CVE-\d{4}-\d{4,7}$/, 20),
      attackTechniqueIds: stringList(value.attackTechniqueIds, /^T\d{4}(?:\.\d{3})?$/, 20),
      simulationMode: "bounded_behavioral",
    };
  } catch {
    return fallback;
  }
}

function publicExercise(value) {
  return {
    scenarioId: value.scenarioId,
    title: value.title,
    summary: value.summary,
    profile: value.profile,
    expectedCves: value.expectedCves,
    attackTechniqueIds: value.attackTechniqueIds,
    target: "http://target:8080",
    startingPath: profiles[value.profile].startingPath,
    scope: "This isolated target only. External egress is denied.",
  };
}

function landingPage(value) {
  const cves = value.expectedCves.length > 0 ? value.expectedCves.join(", ") : "프롬프트 기반 취약 조건";
  return `<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><title>${escapeHtml(value.title)}</title>
<style>body{font:16px system-ui;background:#08111d;color:#e7eef8;max-width:800px;margin:9vh auto;padding:32px;line-height:1.65}code{color:#66e3b4;background:#101d2d;padding:.15rem .4rem;border-radius:4px}small{color:#91a4ba}.card{border:1px solid #26364a;border-radius:12px;padding:20px;margin-top:24px;background:#0d1826}</style></head>
<body><small>ZEROTOP · ISOLATED RED TEAM TARGET</small><h1>${escapeHtml(value.title)}</h1>
<p>${escapeHtml(value.summary)}</p>
<div class="card"><strong>훈련 범위</strong><p>이 대상과 <code>http://target:8080</code>만 사용하세요. 외부 네트워크 연결은 차단되어 있습니다.</p>
<p><strong>연결된 취약점:</strong> ${escapeHtml(cves)}</p>
<p><strong>시작 지점:</strong> <code>${escapeHtml(profiles[value.profile].startingPath)}</code></p>
<p>메타데이터: <code>curl http://target:8080/.well-known/zerotop-lab</code></p></div></body></html>`;
}

function displayText(value, maximum, fallback) {
  if (typeof value !== "string") return fallback;
  const normalized = value.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  return (normalized || fallback).slice(0, maximum);
}

function stringList(value, pattern, maximum) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((item) => typeof item === "string" && pattern.test(item)).slice(0, maximum))];
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

function html(response, status, body, headers) {
  return text(response, status, body, "text/html; charset=utf-8", headers);
}

function text(response, status, body, contentType, headers) {
  response.writeHead(status, {
    ...headers,
    "content-type": contentType,
    "content-length": Buffer.byteLength(body),
  });
  response.end(body);
}

function json(response, status, value, headers) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    ...headers,
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
  });
  response.end(body);
}

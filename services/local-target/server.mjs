import { createServer } from "node:http";

const host = process.env.HOST ?? "0.0.0.0";
const port = Number(process.env.PORT ?? "8080");

const server = createServer((request, response) => {
  const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "target"}`);
  const headers = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  };

  if (request.method === "GET" && url.pathname === "/health") {
    return json(response, 200, { status: "ok" }, headers);
  }
  if (request.method === "GET" && url.pathname === "/version") {
    return json(response, 200, {
      service: "codegate-local-target",
      contract: "http-v1",
      mode: "local-connectivity",
    }, headers);
  }
  if (request.method === "GET" && url.pathname === "/.well-known/codegate-lab") {
    return json(response, 200, {
      target: "target:8080",
      purpose: "Local runtime connectivity target",
      note: "CVE-specific workloads replace this image after AI build and validation.",
    }, headers);
  }
  if (request.method === "GET" && url.pathname === "/") {
    const body = `<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><title>ZeroTOP Local Target</title>
<style>body{font:16px system-ui;background:#08111d;color:#e7eef8;max-width:760px;margin:12vh auto;padding:32px}code{color:#66e3b4}small{color:#91a4ba}</style></head>
<body><small>ISOLATED LAB TARGET</small><h1>로컬 실습 대상이 실행 중입니다.</h1>
<p>Ubuntu/Kali 워크스테이션에서 <code>curl http://target:8080/health</code>로 연결을 확인하세요.</p>
<p>CVE별 실제 취약 워크로드는 AI Builder와 검증 파이프라인이 생성한 이미지로 교체됩니다.</p></body></html>`;
    response.writeHead(200, {
      ...headers,
      "content-type": "text/html; charset=utf-8",
      "content-length": Buffer.byteLength(body),
    });
    return response.end(body);
  }

  return json(response, 404, { error: "not_found" }, headers);
});

server.listen(port, host, () => {
  console.log(JSON.stringify({ level: "info", service: "local-target", host, port }));
});

function json(response, status, value, headers) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    ...headers,
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
  });
  response.end(body);
}

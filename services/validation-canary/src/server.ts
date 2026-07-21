import { createServer, type Server } from "node:http";

export function createValidationCanaryServer(): Server {
  const server = createServer((request, response) => {
    if (request.method === "GET" && request.url === "/health") {
      const body = JSON.stringify({ status: "ok" });
      response.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "content-length": Buffer.byteLength(body),
        "cache-control": "no-store",
      });
      response.end(body);
      return;
    }
    response.writeHead(404, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
    response.end(JSON.stringify({ error: "not_found" }));
  });
  server.requestTimeout = 5_000;
  server.headersTimeout = 3_000;
  server.keepAliveTimeout = 1_000;
  return server;
}

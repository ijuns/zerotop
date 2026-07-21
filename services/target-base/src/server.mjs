import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";

const COMPONENT_SCHEMA_VERSION = "codegate-component/v1";
const COMPONENT_POLICY_SCHEMA_VERSION = "codegate-component-policy/v1";
const RUNTIME_ABI = "http-v1";
const RESERVED_PATHS = new Set(["/health", "/version"]);
const CONTENT_TYPES = new Set([
  "text/plain; charset=utf-8",
  "application/json; charset=utf-8",
]);
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;
const ROUTE_PATH = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}$/;
const ARTIFACT_PATH = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,180}$/;
const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_ARTIFACT_BYTES = 1024 * 1024;
const MAX_COMPONENTS = 100;
const MAX_ROUTES = 100;
const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const HANDLER_TIMEOUT_MS = 2_000;
const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);
export const COMPONENT_WORKER_RESOURCE_LIMITS = Object.freeze({
  maxOldGenerationSizeMb: 32,
  maxYoungGenerationSizeMb: 8,
  stackSizeMb: 2,
});

export async function loadComponentCatalog(options = {}) {
  const packageRoot = resolve(options.packageRoot ?? "/opt/codegate/packages");
  const artifactRoot = resolve(options.artifactRoot ?? "/opt/codegate/artifacts");
  const policyPath = resolve(options.policyPath ?? "/opt/codegate/component-policy.json");
  const expectedComponents = await loadComponentPolicy(policyPath);
  const expectedById = new Map(expectedComponents.map((item) => [item.componentId, item.runtimeKind]));
  const routes = new Map();
  const components = [];
  const findings = new Set();
  const entries = await safeDirectoryEntries(packageRoot);
  if (entries.length > MAX_COMPONENTS) throw new Error("component catalog exceeds its limit");

  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    if (!entry.isDirectory() || !IDENTIFIER.test(entry.name)) throw new Error(`unexpected component catalog entry ${entry.name}`);
    const expectedRuntimeKind = expectedById.get(entry.name);
    if (!expectedRuntimeKind) throw new Error(`component ${entry.name} is not present in the signed build policy`);
    const componentDirectory = join(packageRoot, entry.name);
    const componentStat = await lstat(componentDirectory);
    if (componentStat.isSymbolicLink()) throw new Error(`component ${entry.name} must not be a symbolic link`);
    const manifestPath = join(componentDirectory, "component.json");
    let manifestBytes;
    try {
      manifestBytes = await readFile(manifestPath);
    } catch (error) {
      if (error && typeof error === "object" && error.code === "ENOENT") throw new Error(`component ${entry.name} is missing component.json`);
      throw error;
    }
    if (manifestBytes.byteLength > MAX_MANIFEST_BYTES) throw new Error(`component ${entry.name} manifest is too large`);
    const manifestStat = await lstat(manifestPath);
    if (!manifestStat.isFile() || manifestStat.isSymbolicLink()) throw new Error(`component ${entry.name} manifest must be a regular file`);
    const manifest = parseManifest(JSON.parse(manifestBytes.toString("utf8")), entry.name);
    if (manifest.kind !== expectedRuntimeKind) throw new Error(`component ${entry.name} kind does not match the signed build policy`);
    components.push(manifest.componentId);
    for (const finding of manifest.findings) findings.add(finding);
    for (const route of manifest.routes) {
      const key = `${route.method} ${route.path}`;
      if (routes.has(key)) throw new Error(`duplicate component route ${key}`);
      if (routes.size >= MAX_ROUTES) throw new Error("component routes exceed their limit");
      routes.set(key, await materializeRoute(route, manifest, componentDirectory, artifactRoot));
    }
  }
  const missingComponents = expectedComponents.filter((item) => !components.includes(item.componentId));
  if (missingComponents.length > 0) throw new Error(`signed build policy component is missing: ${missingComponents[0].componentId}`);
  return Object.freeze({
    components: Object.freeze(components),
    findings: Object.freeze([...findings].sort()),
    routes,
  });
}

async function loadComponentPolicy(policyPath) {
  const policyBytes = await readFile(policyPath);
  if (policyBytes.byteLength > MAX_MANIFEST_BYTES) throw new Error("component policy is too large");
  const policyStat = await lstat(policyPath);
  if (!policyStat.isFile() || policyStat.isSymbolicLink()) throw new Error("component policy must be a regular file");
  const root = exactObject(JSON.parse(policyBytes.toString("utf8")), "component policy", ["schemaVersion", "components"]);
  if (root.schemaVersion !== COMPONENT_POLICY_SCHEMA_VERSION) throw new Error("component policy schemaVersion is invalid");
  if (!Array.isArray(root.components) || root.components.length > MAX_COMPONENTS) throw new Error("component policy components are invalid");
  const components = root.components.map((value, index) => {
    const entry = exactObject(value, `component policy components[${index}]`, ["componentId", "runtimeKind"]);
    if (typeof entry.componentId !== "string" || !IDENTIFIER.test(entry.componentId)) throw new Error("component policy componentId is invalid");
    if (entry.runtimeKind !== "declarative-http-v1" && entry.runtimeKind !== "signed-node-handler-v1") throw new Error("component policy runtimeKind is invalid");
    return { componentId: entry.componentId, runtimeKind: entry.runtimeKind };
  });
  if (new Set(components.map((item) => item.componentId)).size !== components.length) throw new Error("component policy component IDs must be unique");
  return components;
}

export function createTargetServer(catalog) {
  if (!catalog || !(catalog.routes instanceof Map)) throw new Error("a validated component catalog is required");
  return createServer((request, response) => {
    void handleRequest(catalog, request, response).catch((error) => {
      const status = error instanceof RequestLimitError ? 413 : 500;
      if (!response.headersSent) {
        send(response, request.method ?? "GET", status, "application/json; charset=utf-8", JSON.stringify({ error: status === 413 ? "request_too_large" : "component_failed" }));
      } else {
        response.destroy();
      }
    });
  });
}

async function handleRequest(catalog, request, response) {
  const method = request.method ?? "GET";
  if (!METHODS.has(method)) {
    response.writeHead(405, securityHeaders({ allow: [...METHODS].join(", ") }));
    response.end();
    return;
  }
  const url = new URL(request.url ?? "/", "http://target.invalid");
  if ((method === "GET" || method === "HEAD") && url.pathname === "/health") {
    send(response, method, 200, "text/plain; charset=utf-8", "ready\n");
    return;
  }
  if ((method === "GET" || method === "HEAD") && url.pathname === "/version") {
    send(response, method, 200, "application/json; charset=utf-8", JSON.stringify({
      service: "codegate-vulnerable-target",
      runtimeAbi: RUNTIME_ABI,
      components: catalog.components,
      findings: catalog.findings,
    }));
    return;
  }
  const route = catalog.routes.get(`${method} ${url.pathname}`)
    ?? (method === "HEAD" ? catalog.routes.get(`GET ${url.pathname}`) : undefined);
  if (!route) {
    send(response, method, 404, "application/json; charset=utf-8", JSON.stringify({ error: "not_found" }));
    return;
  }
  if (route.runtimeKind === "signed-node-handler-v1") {
    const body = await requestBody(request);
    const result = await invokeSignedHandler(route, {
      method,
      path: url.pathname,
      query: Object.fromEntries(url.searchParams.entries()),
      headers: selectedHeaders(request.headers),
      body: body.toString("utf8"),
    });
    send(response, method, result.status, result.contentType, result.body);
    return;
  }
  send(response, method, route.status, route.contentType, route.body);
}

function parseManifest(value, directoryName) {
  const root = exactObject(value, "component manifest", ["schemaVersion", "kind", "componentId", "findings", "routes"], ["handler"]);
  if (root.schemaVersion !== COMPONENT_SCHEMA_VERSION) throw new Error("component schemaVersion is invalid");
  if (typeof root.componentId !== "string" || !IDENTIFIER.test(root.componentId) || root.componentId !== directoryName) {
    throw new Error("componentId must match its catalog directory");
  }
  if (root.kind !== "declarative-http-v1" && root.kind !== "signed-node-handler-v1") throw new Error("component kind is invalid");
  if (!Array.isArray(root.findings) || root.findings.length > 40 || root.findings.some((item) => typeof item !== "string" || !IDENTIFIER.test(item))) {
    throw new Error("component findings are invalid");
  }
  if (new Set(root.findings).size !== root.findings.length) throw new Error("component findings must be unique");
  if (!Array.isArray(root.routes) || root.routes.length > MAX_ROUTES) throw new Error("component routes are invalid");
  const handler = root.kind === "signed-node-handler-v1" ? parseHandler(root.handler) : undefined;
  if (root.kind === "declarative-http-v1" && root.handler !== undefined) throw new Error("declarative components must not define a handler");
  return {
    kind: root.kind,
    componentId: root.componentId,
    findings: root.findings,
    ...(handler ? { handler } : {}),
    routes: root.routes.map((item, index) => parseRoute(item, index, root.kind)),
  };
}

function parseHandler(value) {
  const root = exactObject(value, "component handler", ["path", "sha256"]);
  if (root.path !== "handler.mjs") throw new Error("component handler path must be handler.mjs");
  if (typeof root.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(root.sha256)) throw new Error("component handler sha256 is invalid");
  return { path: root.path, sha256: root.sha256 };
}

function parseRoute(value, index, kind) {
  const path = `routes[${index}]`;
  const required = kind === "signed-node-handler-v1" ? ["method", "path", "operation"] : ["method", "path", "response"];
  const optional = kind === "signed-node-handler-v1" ? [] : [];
  const root = exactObject(value, path, required, optional);
  if (!METHODS.has(root.method)) throw new Error(`${path}.method is invalid`);
  if (typeof root.path !== "string" || !ROUTE_PATH.test(root.path) || root.path.includes("//") || RESERVED_PATHS.has(root.path)) {
    throw new Error(`${path}.path is invalid or reserved`);
  }
  if (kind === "signed-node-handler-v1") {
    if (typeof root.operation !== "string" || !IDENTIFIER.test(root.operation)) throw new Error(`${path}.operation is invalid`);
    return { method: root.method, path: root.path, operation: root.operation };
  }
  if (root.method !== "GET" && root.method !== "HEAD") throw new Error(`${path}.method must be GET or HEAD for declarative components`);
  const response = exactObject(root.response, `${path}.response`, ["status", "contentType"], ["inlineBody", "artifactPath"]);
  if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599) throw new Error(`${path}.response.status is invalid`);
  if (typeof response.contentType !== "string" || !CONTENT_TYPES.has(response.contentType)) throw new Error(`${path}.response.contentType is invalid`);
  const hasInline = typeof response.inlineBody === "string";
  const hasArtifact = typeof response.artifactPath === "string";
  if (hasInline === hasArtifact) throw new Error(`${path}.response requires exactly one body source`);
  if (hasInline && Buffer.byteLength(response.inlineBody, "utf8") > 65_536) throw new Error(`${path}.response.inlineBody is too large`);
  if (hasArtifact && (!ARTIFACT_PATH.test(response.artifactPath) || response.artifactPath.includes("..") || response.artifactPath.includes("//"))) {
    throw new Error(`${path}.response.artifactPath is invalid`);
  }
  return {
    method: root.method,
    path: root.path,
    status: response.status,
    contentType: response.contentType,
    ...(hasInline ? { inlineBody: response.inlineBody } : { artifactPath: response.artifactPath }),
  };
}

async function materializeRoute(route, manifest, componentDirectory, artifactRoot) {
  if (manifest.kind === "signed-node-handler-v1") {
    const handlerPath = resolve(componentDirectory, manifest.handler.path);
    if (!isWithin(componentDirectory, handlerPath)) throw new Error("component handler escapes its package directory");
    const resolvedHandler = await realpath(handlerPath);
    if (!isWithin(componentDirectory, resolvedHandler)) throw new Error("component handler symbolic links must not escape its package directory");
    const handlerStat = await lstat(resolvedHandler);
    if (!handlerStat.isFile() || handlerStat.isSymbolicLink() || handlerStat.size > MAX_ARTIFACT_BYTES) throw new Error("component handler must be a bounded regular file");
    const handlerBytes = await readFile(resolvedHandler);
    const digest = createHash("sha256").update(handlerBytes).digest("hex");
    if (digest !== manifest.handler.sha256) throw new Error("component handler digest does not match its signed manifest");
    return {
      ...route,
      runtimeKind: manifest.kind,
      componentId: manifest.componentId,
      handlerPath: resolvedHandler,
    };
  }
  if ("inlineBody" in route) return { ...route, body: Buffer.from(route.inlineBody, "utf8") };
  const root = await realpath(artifactRoot).catch(() => artifactRoot);
  const requested = resolve(artifactRoot, route.artifactPath);
  if (!isWithin(artifactRoot, requested)) throw new Error("artifact path escapes the artifact root");
  const resolved = await realpath(requested);
  if (!isWithin(root, resolved)) throw new Error("artifact symbolic links must not escape the artifact root");
  const artifactStat = await lstat(resolved);
  if (!artifactStat.isFile() || artifactStat.size > MAX_ARTIFACT_BYTES) throw new Error("artifact body is invalid or too large");
  return { ...route, body: await readFile(resolved) };
}

async function invokeSignedHandler(route, request) {
  return await new Promise((resolvePromise, rejectPromise) => {
    const worker = new Worker(new URL("./component-worker.mjs", import.meta.url), {
      resourceLimits: COMPONENT_WORKER_RESOURCE_LIMITS,
      workerData: {
        handlerPath: route.handlerPath,
        componentId: route.componentId,
        operation: route.operation,
        request,
      },
    });
    const timer = setTimeout(() => {
      void worker.terminate();
      rejectPromise(new Error("component handler timed out"));
    }, HANDLER_TIMEOUT_MS);
    timer.unref();
    worker.once("message", (message) => {
      clearTimeout(timer);
      void worker.terminate();
      try {
        resolvePromise(validateHandlerResponse(message));
      } catch (error) {
        rejectPromise(error);
      }
    });
    worker.once("error", (error) => {
      clearTimeout(timer);
      rejectPromise(error);
    });
    worker.once("exit", (code) => {
      if (code !== 0) {
        clearTimeout(timer);
        rejectPromise(new Error("component handler exited unexpectedly"));
      }
    });
  });
}

function validateHandlerResponse(value) {
  const root = exactObject(value, "component handler response", ["status", "contentType", "body"]);
  if (!Number.isInteger(root.status) || root.status < 100 || root.status > 599) throw new Error("component handler response status is invalid");
  if (typeof root.contentType !== "string" || !CONTENT_TYPES.has(root.contentType)) throw new Error("component handler response contentType is invalid");
  const body = typeof root.body === "string" ? root.body : JSON.stringify(root.body);
  if (Buffer.byteLength(body, "utf8") > MAX_RESPONSE_BYTES) throw new Error("component handler response is too large");
  return { status: root.status, contentType: root.contentType, body };
}

async function requestBody(request) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    total += bytes.byteLength;
    if (total > MAX_REQUEST_BYTES) throw new RequestLimitError();
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function selectedHeaders(headers) {
  const selected = {};
  for (const name of ["content-type", "user-agent", "authorization", "x-forwarded-for"]) {
    const value = headers[name];
    if (typeof value === "string") selected[name] = value.slice(0, 2_048);
  }
  return selected;
}

class RequestLimitError extends Error {}

function exactObject(value, name, required, optional = []) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
  const allowed = new Set([...required, ...optional]);
  const unsupported = Object.keys(value).filter((key) => !allowed.has(key));
  const missing = required.filter((key) => !Object.hasOwn(value, key));
  if (unsupported.length) throw new Error(`${name} contains unsupported fields: ${unsupported.join(", ")}`);
  if (missing.length) throw new Error(`${name} is missing fields: ${missing.join(", ")}`);
  return value;
}

async function safeDirectoryEntries(path) {
  try {
    return await readdir(path, { withFileTypes: true });
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") return [];
    throw error;
  }
}

function isWithin(root, candidate) {
  const path = relative(resolve(root), resolve(candidate));
  return path === "" || (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path));
}

function securityHeaders(extra = {}) {
  return {
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    ...extra,
  };
}

function send(response, method, status, contentType, body) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
  response.writeHead(status, securityHeaders({
    "content-type": contentType,
    "content-length": String(payload.byteLength),
  }));
  response.end(method === "HEAD" ? undefined : payload);
}

async function main() {
  const host = process.env.HOST ?? "0.0.0.0";
  const port = Number(process.env.PORT ?? 8_080);
  if (host !== "0.0.0.0") throw new Error("HOST must be 0.0.0.0 for the http-v1 ABI");
  if (port !== 8_080) throw new Error("PORT must be 8080 for the http-v1 ABI");
  const catalog = await loadComponentCatalog({
    packageRoot: process.env.CODEGATE_PACKAGE_ROOT,
    artifactRoot: process.env.CODEGATE_ARTIFACT_ROOT,
    policyPath: process.env.CODEGATE_COMPONENT_POLICY_PATH,
  });
  const server = createTargetServer(catalog);
  server.listen(port, host, () => {
    console.log(JSON.stringify({ level: "info", service: "codegate-target", runtimeAbi: RUNTIME_ABI, port }));
  });
}

const executablePath = process.argv[1] ? resolve(process.argv[1]) : "";
if (fileURLToPath(import.meta.url) === executablePath) {
  main().catch((error) => {
    console.error(JSON.stringify({ level: "error", service: "codegate-target", message: error instanceof Error ? error.message : String(error) }));
    process.exitCode = 1;
  });
}

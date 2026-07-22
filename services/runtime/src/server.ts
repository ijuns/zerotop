import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { KubeVirtRuntimeAdapter, LocalRuntimeAdapter, RuntimeRunNotFoundError } from "./adapter.ts";
import type { ProvisionRunRequest, RuntimeAdapter } from "./contracts.ts";
import { DockerRuntimeAdapter } from "./docker-adapter.ts";
import { validateProvisionRequest, validateRunId } from "./input.ts";
import { inClusterKubernetesApplier } from "./kubernetes-http.ts";
import { ExternalPkiOpenVpnIssuer, LocalOpenVpnIssuer, type OpenVpnIssuer } from "./openvpn.ts";
import { DevelopmentTelemetryValidator, ElasticsearchTelemetryValidator } from "./elasticsearch-validation.ts";
import { DevelopmentSandboxValidator, KubeVirtSandboxValidator, type SandboxValidator } from "./sandbox.ts";
import { parseSandboxValidationRequest } from "./validation-input.ts";

const runtimeMode = process.env.RUNTIME_MODE ?? "local";
const port = Number(process.env.PORT ?? "9000");
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535");
}
const internalToken = resolveInternalToken(runtimeMode);
const sandboxRunnerToken = resolveSandboxRunnerToken(runtimeMode);
const { adapter, sandboxValidator } = await createComponents();

const server = createServer(async (request, response) => {
  try {
    if (request.url === "/health" && request.method === "GET") {
      return json(response, 200, { status: "ok", adapter: runtimeMode });
    }
    if (request.url === "/v1/validation-runs" && request.method === "POST") {
      if (request.headers.authorization !== `Bearer ${sandboxRunnerToken}`) {
        return json(response, 401, { error: { code: "unauthorized", message: "Invalid sandbox runner token" } });
      }
      const body = await readJson(request);
      const input = parseSandboxValidationRequest(
        body,
        runtimeMode === "local" || runtimeMode === "docker" ? localRegistries(body) : requiredRegistries(),
      );
      return json(response, 200, { data: await sandboxValidator.validate(input) });
    }
    if (request.headers.authorization !== `Bearer ${internalToken}`) return json(response, 401, { error: { code: "unauthorized", message: "Invalid internal token" } });
    if (request.url === "/v1/runs/provision" && request.method === "POST") {
      const body = validateProvisionRequest(await readJson(request), {
        runtimeMode,
        allowedTargetRegistries: process.env.TARGET_IMAGE_REGISTRIES?.split(","),
      });
      return json(response, 202, await adapter.provision(body));
    }
    const match = request.url?.match(/^\/v1\/runs\/([^/]+)$/);
    if (match && request.method === "GET") {
      return json(response, 200, await adapter.get(validateRunId(decodeURIComponent(match[1]))));
    }
    if (match && request.method === "DELETE") {
      await adapter.destroy(validateRunId(decodeURIComponent(match[1])));
      response.writeHead(204).end();
      return;
    }
    return json(response, 404, { error: { code: "not_found", message: "Route not found" } });
  } catch (error) {
    if (error instanceof RuntimeRunNotFoundError) {
      return json(response, 404, { error: { code: "run_not_found", message: error.message } });
    }
    return json(response, 400, { error: { code: "invalid_request", message: error instanceof Error ? error.message : "Unknown error" } });
  }
});

server.listen(port, "0.0.0.0", () => console.log(`CODEGATE runtime listening on :${port} (${runtimeMode})`));

async function createComponents(): Promise<{ adapter: RuntimeAdapter; sandboxValidator: SandboxValidator }> {
  const vpnIssuer = createVpnIssuer();
  if (runtimeMode === "local") {
    const telemetry = new DevelopmentTelemetryValidator();
    return {
      adapter: new LocalRuntimeAdapter(vpnIssuer),
      sandboxValidator: new DevelopmentSandboxValidator(telemetry),
    };
  }
  if (runtimeMode === "docker") {
    const telemetry = new DevelopmentTelemetryValidator();
    return {
      adapter: new DockerRuntimeAdapter({
        network: process.env.LOCAL_DESKTOP_NETWORK ?? "codegate-local-desktops",
        gatewayContainer: process.env.LOCAL_DESKTOP_GATEWAY_CONTAINER ?? "codegate-local-desktop-gateway",
        ubuntuDesktopImage: process.env.LOCAL_UBUNTU_DESKTOP_IMAGE ?? "lscr.io/linuxserver/webtop:ubuntu-xfce",
        kaliDesktopImage: process.env.LOCAL_KALI_DESKTOP_IMAGE ?? "lscr.io/linuxserver/kali-linux:latest",
        localTargetImage: process.env.LOCAL_TARGET_IMAGE ?? "codegate/local-target:development",
        localTargetSourceImage: process.env.LOCAL_TARGET_SOURCE_IMAGE ?? `local.codegate.invalid/codegate/local-target@sha256:${"0".repeat(64)}`,
        elasticsearchImage: process.env.LOCAL_ELASTICSEARCH_IMAGE ?? "docker.elastic.co/elasticsearch/elasticsearch:8.17.0",
        kibanaImage: process.env.LOCAL_KIBANA_IMAGE ?? "docker.elastic.co/kibana/kibana:8.17.0",
        elasticAgentImage: process.env.LOCAL_ELASTIC_AGENT_IMAGE ?? "codegate/elastic-agent:development",
        scenarioLogGeneratorImage: process.env.LOCAL_SCENARIO_LOG_GENERATOR_IMAGE ?? "codegate/scenario-log-generator:development",
        desktopMemory: process.env.LOCAL_DESKTOP_MEMORY ?? "4g",
        desktopCpus: numberEnv("LOCAL_DESKTOP_CPUS", 2, 0.1, 64),
        desktopPidsLimit: integerEnv("LOCAL_DESKTOP_PIDS_LIMIT", 1024, 64, 32768),
        desktopShmSize: process.env.LOCAL_DESKTOP_SHM_SIZE ?? "1g",
        targetMemory: process.env.LOCAL_TARGET_MEMORY ?? "512m",
        targetCpus: numberEnv("LOCAL_TARGET_CPUS", 1, 0.1, 64),
        targetPidsLimit: integerEnv("LOCAL_TARGET_PIDS_LIMIT", 256, 32, 32768),
        cleanupIntervalMs: integerEnv("LOCAL_RUNTIME_CLEANUP_INTERVAL_MS", 60_000, 0, 86_400_000),
      }),
      sandboxValidator: new DevelopmentSandboxValidator(telemetry),
    };
  }
  if (runtimeMode !== "kubevirt") throw new Error(`Unsupported RUNTIME_MODE: ${runtimeMode}`);
  const kubernetes = await inClusterKubernetesApplier();
  const adapter = new KubeVirtRuntimeAdapter(
    kubernetes,
    vpnIssuer,
    {
      ubuntuDesktop: requiredEnv("UBUNTU_DESKTOP_IMAGE"),
      kaliDesktop: requiredEnv("KALI_DESKTOP_IMAGE"),
      elasticsearch: requiredEnv("RANGE_ELASTICSEARCH_IMAGE"),
      kibana: requiredEnv("RANGE_KIBANA_IMAGE"),
      elasticAgent: requiredEnv("RANGE_ELASTIC_AGENT_IMAGE"),
      scenarioLogGenerator: requiredEnv("RANGE_SCENARIO_LOG_GENERATOR_IMAGE"),
    },
    {
      image: requiredEnv("OPENVPN_GATEWAY_IMAGE"),
      baseDomain: requiredEnv("OPENVPN_GATEWAY_BASE_DOMAIN"),
      issuerUrl: requiredEnv("OPENVPN_ISSUER_URL"),
      allowedCidr: requiredEnv("OPENVPN_ALLOWED_CIDR"),
    },
    integerEnv("RUNTIME_READY_TIMEOUT_SECONDS", 600, 60, 1800),
  );
  const telemetry = new ElasticsearchTelemetryValidator(
    requiredEnv("ELASTICSEARCH_URL"),
    requiredSecret("ELASTICSEARCH_API_KEY", 24),
  );
  const sandboxValidator = new KubeVirtSandboxValidator(kubernetes, telemetry, {
    probeImage: requiredEnv("SANDBOX_PROBE_IMAGE"),
    timeoutSeconds: integerEnv("SANDBOX_TIMEOUT_SECONDS", 300, 60, 900),
    externalProbeHost: process.env.SANDBOX_EXTERNAL_PROBE_HOST ?? "1.1.1.1",
    externalProbePort: integerEnv("SANDBOX_EXTERNAL_PROBE_PORT", 443, 1, 65535),
    controlPlaneHost: requiredEnv("KUBERNETES_SERVICE_HOST"),
    controlPlanePort: integerEnv("KUBERNETES_SERVICE_PORT_HTTPS", 443, 1, 65535),
    canaryNamespace: process.env.SANDBOX_CANARY_NAMESPACE ?? "codegate-runtime-system",
    canaryService: process.env.SANDBOX_CANARY_SERVICE ?? "validation-canary",
    canaryPort: integerEnv("SANDBOX_CANARY_PORT", 8080, 1, 65535),
  });
  return { adapter, sandboxValidator };
}

function createVpnIssuer(): OpenVpnIssuer {
  if (runtimeMode === "local" || runtimeMode === "docker") return new LocalOpenVpnIssuer();
  return new ExternalPkiOpenVpnIssuer(requiredEnv("OPENVPN_ISSUER_URL"), requiredEnv("OPENVPN_ISSUER_TOKEN"));
}

function resolveInternalToken(mode: string): string {
  const configured = process.env.RUNTIME_INTERNAL_TOKEN?.trim();
  if (configured) return configured;
  if (mode === "local" || mode === "docker") return "local-runtime-token";
  throw new Error("RUNTIME_INTERNAL_TOKEN is required outside local runtime mode");
}

function resolveSandboxRunnerToken(mode: string): string {
  const configured = process.env.SANDBOX_RUNNER_INTERNAL_TOKEN?.trim();
  if (configured && configured.length >= 24) return configured;
  if (mode === "local" || mode === "docker") return "local-sandbox-runner-token";
  throw new Error("SANDBOX_RUNNER_INTERNAL_TOKEN with at least 24 characters is required outside local runtime mode");
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function requiredSecret(name: string, minimum: number): string {
  const value = requiredEnv(name);
  if (value.length < minimum) throw new Error(`${name} must contain at least ${minimum} characters`);
  return value;
}

function requiredRegistries(): string[] {
  const registries = (process.env.TARGET_IMAGE_REGISTRIES ?? "")
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  if (registries.length === 0) throw new Error("TARGET_IMAGE_REGISTRIES must contain at least one registry");
  return registries;
}

function localRegistries(body: unknown): string[] {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return ["registry.local"];
  const image = (body as Record<string, unknown>).image;
  if (typeof image !== "string" || !image.includes("/")) return ["registry.local"];
  return [image.split("/", 1)[0]!.toLowerCase()];
}

function integerEnv(name: string, fallback: number, minimum: number, maximum: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

function numberEnv(name: string, fallback: number, minimum: number, maximum: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be a number between ${minimum} and ${maximum}`);
  }
  return value;
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > 256_000) throw new Error("Request body is too large");
    chunks.push(buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function json(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  response.end(JSON.stringify(body));
}

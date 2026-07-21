import { execFile } from "node:child_process";

import type {
  ProvisionedRun,
  ProvisionRunRequest,
  RuntimeAdapter,
  RuntimeReadinessChecks,
  RuntimeRunStatus,
} from "./contracts.ts";
import { RuntimeRunNotFoundError } from "./adapter.ts";
import { namespaceForRun } from "./manifests.ts";

const MANAGED_LABEL = "codegate.ai.managed-by";
const RUN_ID_LABEL = "codegate.ai.run-id";
const NAMESPACE_LABEL = "codegate.ai.namespace";
const EXPIRES_AT_LABEL = "codegate.ai.expires-at";
const ACCESS_METHOD_LABEL = "codegate.ai.access-method";
const ROLE_LABEL = "codegate.ai.role";
const TEAM_LABEL = "codegate.ai.team";
const MANAGED_VALUE = "codegate-runtime";
type RuntimeRole = "desktop" | "target" | "elasticsearch" | "kibana" | "elastic-agent" | "scenario-log-generator";

export interface DockerCommandResult {
  stdout: string;
  stderr: string;
}

export interface DockerCommandRunner {
  run(args: readonly string[]): Promise<DockerCommandResult>;
}

export class DockerCommandError extends Error {
  readonly stderr: string;

  constructor(message: string, stderr = "") {
    super(message);
    this.name = "DockerCommandError";
    this.stderr = stderr;
  }
}

/** Executes Docker without a shell so request fields can never become shell syntax. */
export class DockerCliCommandRunner implements DockerCommandRunner {
  private readonly binary: string;
  private readonly timeoutMs: number;

  constructor(binary = "docker", timeoutMs = 10 * 60_000) {
    this.binary = binary;
    this.timeoutMs = timeoutMs;
  }

  run(args: readonly string[]): Promise<DockerCommandResult> {
    return new Promise((resolve, reject) => {
      execFile(
        this.binary,
        [...args],
        {
          encoding: "utf8",
          maxBuffer: 4 * 1024 * 1024,
          timeout: this.timeoutMs,
          windowsHide: true,
        },
        (error, stdout, stderr) => {
          if (error) {
            const detail = String(stderr).trim();
            reject(new DockerCommandError(
              detail ? `Docker command failed: ${detail}` : `Docker command failed: ${error.message}`,
              detail,
            ));
            return;
          }
          resolve({ stdout: String(stdout), stderr: String(stderr) });
        },
      );
    });
  }
}

export interface DockerRuntimeOptions {
  commandRunner?: DockerCommandRunner;
  network?: string;
  gatewayContainer?: string;
  ubuntuDesktopImage?: string;
  kaliDesktopImage?: string;
  localTargetImage?: string;
  localTargetSourceImage?: string;
  elasticsearchImage?: string;
  kibanaImage?: string;
  elasticAgentImage?: string;
  scenarioLogGeneratorImage?: string;
  desktopMemory?: string;
  desktopCpus?: number;
  desktopPidsLimit?: number;
  desktopShmSize?: string;
  targetMemory?: string;
  targetCpus?: number;
  targetPidsLimit?: number;
  cleanupIntervalMs?: number;
  now?: () => number;
  logger?: Pick<Console, "error" | "info">;
}

interface NormalizedDockerRuntimeOptions {
  commandRunner: DockerCommandRunner;
  network: string;
  gatewayContainer: string;
  ubuntuDesktopImage: string;
  kaliDesktopImage: string;
  localTargetImage: string;
  localTargetSourceImage: string;
  elasticsearchImage: string;
  kibanaImage: string;
  elasticAgentImage: string;
  scenarioLogGeneratorImage: string;
  desktopMemory: string;
  desktopCpus: number;
  desktopPidsLimit: number;
  desktopShmSize: string;
  targetMemory: string;
  targetCpus: number;
  targetPidsLimit: number;
  cleanupIntervalMs: number;
  now: () => number;
  logger: Pick<Console, "error" | "info">;
}

interface DockerInspectRecord {
  Id?: unknown;
  Name?: unknown;
  Config?: {
    Labels?: unknown;
  };
  State?: {
    Status?: unknown;
    Running?: unknown;
    ExitCode?: unknown;
    Error?: unknown;
    Health?: {
      Status?: unknown;
    };
  };
}

interface InspectedContainer {
  id: string;
  name: string;
  labels: Record<string, string>;
  running: boolean;
  status: string;
  health?: string;
  exitCode?: number;
  error?: string;
}

/**
 * Local-only runtime that gives the normal desktop gateway a real KasmVNC
 * upstream while preserving the same run/namespace contract as KubeVirt.
 */
export class DockerRuntimeAdapter implements RuntimeAdapter {
  private readonly options: NormalizedDockerRuntimeOptions;
  private readonly cleanupTimer?: NodeJS.Timeout;
  private readonly runLocks = new Map<string, Promise<void>>();
  private cleanupInFlight?: Promise<void>;

  constructor(options: DockerRuntimeOptions = {}) {
    this.options = normalizeOptions(options);
    if (this.options.cleanupIntervalMs > 0) {
      this.cleanupTimer = setInterval(() => {
        void this.cleanupExpired().catch((error: unknown) => {
          this.options.logger.error("Docker runtime cleanup failed", error);
        });
      }, this.options.cleanupIntervalMs);
      this.cleanupTimer.unref();
    }
  }

  async provision(request: ProvisionRunRequest): Promise<ProvisionedRun> {
    if (request.accessMethod !== "browser_desktop") {
      throw new Error("Docker runtime supports browser_desktop access only; OpenVPN requires the KubeVirt runtime");
    }
    return this.withRunLock(request.runId, async () => {
      await this.cleanupExpired();

      const existing = await this.inspectRunContainers(request.runId);
      if (existing.length > 0) {
        const current = statusFromInspection(request.runId, existing, this.options.now());
        if (
          current.namespace === namespaceForRun(request.runId)
          && current.status !== "failed"
          && hasRequiredRoles(existing, request.topology?.team)
        ) {
          return provisionedResult(request.runId, current.namespace, current.expiresAt, current.status);
        }
        await this.removeRunResources(request.runId);
      }

      const namespace = namespaceForRun(request.runId);
      const expiresAt = new Date(this.options.now() + request.ttlMinutes * 60_000).toISOString();
      const network = runNetworkName(this.options.network, request.runId);
      const targetName = containerName("target", namespace);
      const desktopName = containerName("desktop", namespace);
      try {
        this.approvedLocalTargetImage(request.targetImage);
        await this.createRunNetwork(request, namespace, expiresAt, network);
        if (request.topology?.team === "blue") {
          await this.createScenarioLogVolume(request, namespace, expiresAt);
        }
        const creates = request.topology?.team === "blue"
          ? this.blueContainerCreates(request, namespace, expiresAt, network)
          : [
              this.targetCreateArgs(request, namespace, expiresAt, targetName, network),
              this.desktopCreateArgs(request, namespace, expiresAt, desktopName, network),
            ];
        for (const args of creates) await this.options.commandRunner.run(args);
        // Elasticsearch is intentionally started first. The remaining blue
        // services retry their internal connections while it becomes ready.
        const startOrder = request.topology?.team === "blue"
          ? ["elasticsearch", "target", "scenario-log-generator", "elastic-agent", "kibana", "desktop"]
          : ["target", "desktop"];
        for (const role of startOrder) {
          await this.options.commandRunner.run(["container", "start", containerName(role as RuntimeRole, namespace)]);
        }
      } catch (error) {
        await this.removeRunResources(request.runId).catch(() => undefined);
        throw error;
      }

      return provisionedResult(request.runId, namespace, expiresAt, "provisioning");
    });
  }

  async get(runId: string): Promise<RuntimeRunStatus> {
    return this.withRunLock(runId, async () => {
      const containers = await this.inspectRunContainers(runId);
      if (containers.length === 0) throw new RuntimeRunNotFoundError(runId);
      const status = statusFromInspection(runId, containers, this.options.now());
      if (Date.parse(status.expiresAt) <= this.options.now()) {
        await this.removeRunResources(runId).catch(() => undefined);
      }
      return status;
    });
  }

  async destroy(runId: string): Promise<void> {
    await this.withRunLock(runId, () => this.removeRunResources(runId));
  }

  /** Stops the housekeeping timer; intended for graceful shutdown and tests. */
  close(): void {
    if (this.cleanupTimer) clearInterval(this.cleanupTimer);
  }

  async cleanupExpired(): Promise<void> {
    if (this.cleanupInFlight) return this.cleanupInFlight;
    const operation = this.cleanupExpiredContainers();
    this.cleanupInFlight = operation;
    try {
      await operation;
    } finally {
      if (this.cleanupInFlight === operation) this.cleanupInFlight = undefined;
    }
  }

  private async cleanupExpiredContainers(): Promise<void> {
    const ids = await this.listContainerIds([`label=${MANAGED_LABEL}=${MANAGED_VALUE}`]);
    if (ids.length === 0) return;
    const containers = await this.inspectContainers(ids);
    const remove = new Set<string>();
    const expiredRuns = new Set<string>();
    for (const container of containers) {
      const runId = container.labels[RUN_ID_LABEL];
      const namespace = container.labels[NAMESPACE_LABEL];
      const expiresAt = container.labels[EXPIRES_AT_LABEL];
      const accessMethod = container.labels[ACCESS_METHOD_LABEL];
      if (
        !runId
        || !namespace
        || !expiresAt
        || accessMethod !== "browser_desktop"
        || !Number.isFinite(Date.parse(expiresAt))
      ) {
        remove.add(container.id);
        continue;
      }
      if (Date.parse(expiresAt) <= this.options.now()) expiredRuns.add(runId);
    }
    for (const container of containers) {
      const runId = container.labels[RUN_ID_LABEL];
      if (runId && expiredRuns.has(runId)) remove.add(container.id);
    }
    for (const runId of expiredRuns) await this.removeRunResources(runId);
    const orphanIds = [...remove].filter((id) => {
      const match = containers.find((container) => container.id === id);
      return !match?.labels[RUN_ID_LABEL] || !expiredRuns.has(match.labels[RUN_ID_LABEL]);
    });
    await this.removeContainerIds(orphanIds);
  }

  private async createRunNetwork(
    request: ProvisionRunRequest,
    namespace: string,
    expiresAt: string,
    network: string,
  ): Promise<void> {
    await this.options.commandRunner.run([
      "network", "create", "--internal",
      "--label", `${MANAGED_LABEL}=${MANAGED_VALUE}`,
      "--label", `${RUN_ID_LABEL}=${request.runId}`,
      "--label", `${NAMESPACE_LABEL}=${namespace}`,
      "--label", `${EXPIRES_AT_LABEL}=${expiresAt}`,
      network,
    ]);
    await this.options.commandRunner.run([
      "network", "connect", "--alias", "desktop-gateway",
      network, this.options.gatewayContainer,
    ]);
  }

  private targetCreateArgs(
    request: ProvisionRunRequest,
    namespace: string,
    expiresAt: string,
    name: string,
    network: string,
  ): string[] {
    const redExercise = request.topology?.team === "red"
      ? request.topology.target.exercise
      : undefined;
    return [
      "container", "create",
      "--pull", "never",
      "--name", name,
      "--network", network,
      "--network-alias", `target.${namespace}.svc.cluster.local`,
      "--network-alias", "target",
      ...commonLabels(request, namespace, expiresAt, "target"),
      ...(request.topology?.team === "blue"
        ? ["--mount", `type=volume,source=${scenarioLogVolume(namespace)},target=/var/log/zerotop`]
        : []),
      ...(redExercise
        ? ["--env", `ZEROTOP_RED_EXERCISE_BASE64=${Buffer.from(JSON.stringify(redExercise), "utf8").toString("base64")}`]
        : []),
      "--memory", this.options.targetMemory,
      "--cpus", String(this.options.targetCpus),
      "--pids-limit", String(this.options.targetPidsLimit),
      "--read-only",
      "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864",
      "--cap-drop", "ALL",
      "--security-opt", "no-new-privileges=true",
      "--user", `${request.targetRuntimeContract.uid}:${request.targetRuntimeContract.gid}`,
      "--stop-timeout", "10",
      this.approvedLocalTargetImage(request.targetImage),
    ];
  }

  private desktopCreateArgs(
    request: ProvisionRunRequest,
    namespace: string,
    expiresAt: string,
    name: string,
    network: string,
  ): string[] {
    const image = request.desktopImage === "ubuntu"
      ? this.options.ubuntuDesktopImage
      : this.options.kaliDesktopImage;
    const redExercise = request.topology?.team === "red"
      ? request.topology.target.exercise
      : undefined;
    return [
      "container", "create",
      "--pull", "missing",
      "--name", name,
      "--network", network,
      "--network-alias", `desktop.${namespace}.svc.cluster.local`,
      "--network-alias", "workstation",
      ...commonLabels(request, namespace, expiresAt, "desktop"),
      "--memory", this.options.desktopMemory,
      "--cpus", String(this.options.desktopCpus),
      "--pids-limit", String(this.options.desktopPidsLimit),
      "--shm-size", this.options.desktopShmSize,
      "--env", "CUSTOM_PORT=6080",
      "--env", "CUSTOM_HTTPS_PORT=6443",
      "--env", `SUBFOLDER=/sessions/${request.runId}/desktop/`,
      ...(redExercise
        ? [
            "--env", "ZEROTOP_TARGET_URL=http://target:8080",
            "--env", `ZEROTOP_TARGET_PROFILE=${redExercise.profile}`,
            "--env", `ZEROTOP_TARGET_VERIFICATION_PATH=${redExercise.verification.path}`,
          ]
        : []),
      "--env", `TITLE=${request.topology?.team === "blue" ? "ZeroTOP SOC Analyst Desktop · Kibana http://kibana:5601" : "ZeroTOP Kali Attack Box · target:8080"}`,
      "--env", "DISABLE_IPV6=true",
      "--expose", "6080/tcp",
      "--health-cmd", "bash -c 'exec 3<>/dev/tcp/127.0.0.1/6080'",
      "--health-interval", "2s",
      "--health-timeout", "2s",
      "--health-start-period", "10s",
      "--health-retries", "60",
      "--stop-timeout", "20",
      image,
    ];
  }

  private blueContainerCreates(
    request: ProvisionRunRequest,
    namespace: string,
    expiresAt: string,
    network: string,
  ): string[][] {
    const topology = request.topology;
    if (topology?.team !== "blue" || !topology.telemetry) {
      throw new Error("Blue-team Docker provisioning requires validated telemetry topology");
    }
    const volume = scenarioLogVolume(namespace);
    const events = Buffer.from(JSON.stringify(topology.telemetry.events), "utf8").toString("base64");
    const generation = topology.telemetry.generation
      ? Buffer.from(JSON.stringify(topology.telemetry.generation), "utf8").toString("base64")
      : null;
    return [
      this.targetCreateArgs(request, namespace, expiresAt, containerName("target", namespace), network),
      [
        "container", "create", "--pull", "missing",
        "--name", containerName("elasticsearch", namespace),
        "--network", network,
        "--network-alias", "elasticsearch",
        ...commonLabels(request, namespace, expiresAt, "elasticsearch"),
        "--memory", "1536m", "--cpus", "1", "--pids-limit", "512",
        "--env", "discovery.type=single-node",
        "--env", "xpack.security.enabled=false",
        "--env", "xpack.ml.enabled=false",
        "--env", "ES_JAVA_OPTS=-Xms768m -Xmx768m",
        "--health-cmd", "curl -fsS http://127.0.0.1:9200/_cluster/health?wait_for_status=yellow",
        "--health-interval", "5s", "--health-timeout", "3s",
        "--health-start-period", "20s", "--health-retries", "60",
        "--stop-timeout", "30",
        this.options.elasticsearchImage,
      ],
      [
        "container", "create", "--pull", "missing",
        "--name", containerName("kibana", namespace),
        "--network", network,
        "--network-alias", "kibana",
        ...commonLabels(request, namespace, expiresAt, "kibana"),
        "--memory", "1g", "--cpus", "1", "--pids-limit", "512",
        "--env", "ELASTICSEARCH_HOSTS=http://elasticsearch:9200",
        "--env", "SERVER_HOST=0.0.0.0",
        "--env", "TELEMETRY_ENABLED=false",
        "--health-cmd", "curl -fsS http://127.0.0.1:5601/api/status",
        "--health-interval", "5s", "--health-timeout", "3s",
        "--health-start-period", "30s", "--health-retries", "60",
        "--stop-timeout", "30",
        this.options.kibanaImage,
      ],
      [
        "container", "create", "--pull", "never",
        "--name", containerName("scenario-log-generator", namespace),
        "--network", network,
        ...commonLabels(request, namespace, expiresAt, "scenario-log-generator"),
        "--mount", `type=volume,source=${volume},target=/var/log/zerotop`,
        "--env", `SCENARIO_EVENTS_BASE64=${events}`,
        ...(generation ? ["--env", `SCENARIO_GENERATION_BASE64=${generation}`] : []),
        "--env", "SCENARIO_LOG_PATH=/var/log/zerotop/scenario.ndjson",
        "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16777216",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
        "--memory", "128m", "--cpus", "0.25", "--pids-limit", "64",
        "--health-cmd", "test -s /var/log/zerotop/scenario.ndjson",
        "--health-interval", "2s", "--health-timeout", "2s", "--health-retries", "30",
        this.options.scenarioLogGeneratorImage,
      ],
      [
        "container", "create", "--pull", "never",
        "--name", containerName("elastic-agent", namespace),
        "--network", network,
        ...commonLabels(request, namespace, expiresAt, "elastic-agent"),
        "--mount", `type=volume,source=${volume},target=/var/log/zerotop,readonly`,
        "--env", "ELASTICSEARCH_HOST=http://elasticsearch:9200",
        "--env", "KIBANA_HOST=http://kibana:5601",
        "--env", `ELASTIC_INDEX=${telemetryIndexForRun(topology.telemetry.index, request.runId)}`,
        "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
        "--memory", "512m", "--cpus", "0.5", "--pids-limit", "256",
        "--health-cmd", "test -f /tmp/zerotop-agent-ready",
        "--health-interval", "3s", "--health-timeout", "2s", "--health-start-period", "10s", "--health-retries", "60",
        this.options.elasticAgentImage,
      ],
      this.desktopCreateArgs(request, namespace, expiresAt, containerName("desktop", namespace), network),
    ];
  }

  private async createScenarioLogVolume(
    request: ProvisionRunRequest,
    namespace: string,
    expiresAt: string,
  ): Promise<void> {
    await this.options.commandRunner.run([
      "volume", "create",
      "--label", `${MANAGED_LABEL}=${MANAGED_VALUE}`,
      "--label", `${RUN_ID_LABEL}=${request.runId}`,
      "--label", `${NAMESPACE_LABEL}=${namespace}`,
      "--label", `${EXPIRES_AT_LABEL}=${expiresAt}`,
      scenarioLogVolume(namespace),
    ]);
  }

  private approvedLocalTargetImage(sourceImage: string): string {
    if (sourceImage === this.options.localTargetImage || sourceImage === this.options.localTargetSourceImage) {
      return this.options.localTargetImage;
    }
    throw new Error("targetImage is not mapped to the operator-approved local target image");
  }

  private async inspectRunContainers(runId: string): Promise<InspectedContainer[]> {
    const ids = await this.listContainerIds([`label=${RUN_ID_LABEL}=${runId}`]);
    return ids.length === 0 ? [] : this.inspectContainers(ids);
  }

  private async listContainerIds(filters: string[]): Promise<string[]> {
    const args = ["container", "ls", "--all", "--quiet"];
    for (const filter of filters) args.push("--filter", filter);
    const result = await this.options.commandRunner.run(args);
    return result.stdout.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
  }

  private async inspectContainers(ids: string[]): Promise<InspectedContainer[]> {
    const result = await this.options.commandRunner.run(["container", "inspect", ...ids]);
    let records: unknown;
    try {
      records = JSON.parse(result.stdout);
    } catch (error) {
      throw new DockerCommandError("Docker returned an invalid container inspection", String(error));
    }
    if (!Array.isArray(records)) throw new DockerCommandError("Docker container inspection must be an array");
    return records.map(parseInspection);
  }

  private async removeRunResources(runId: string): Promise<void> {
    const ids = await this.listContainerIds([`label=${RUN_ID_LABEL}=${runId}`]);
    await this.removeContainerIds(ids);
    const network = runNetworkName(this.options.network, runId);
    try {
      await this.options.commandRunner.run([
        "network", "disconnect", "--force", network, this.options.gatewayContainer,
      ]);
    } catch (error) {
      if (!(error instanceof DockerCommandError) || !/not connected|no such network/i.test(error.stderr)) throw error;
    }
    try {
      await this.options.commandRunner.run(["network", "rm", network]);
    } catch (error) {
      if (!(error instanceof DockerCommandError) || !/no such network/i.test(error.stderr)) throw error;
    }
    const volume = scenarioLogVolume(namespaceForRun(runId));
    try {
      await this.options.commandRunner.run(["volume", "rm", volume]);
    } catch (error) {
      if (!(error instanceof DockerCommandError) || !/no such volume/i.test(error.stderr)) throw error;
    }
  }

  private async removeContainerIds(ids: string[]): Promise<void> {
    for (let index = 0; index < ids.length; index += 50) {
      const batch = ids.slice(index, index + 50);
      if (batch.length === 0) continue;
      try {
        await this.options.commandRunner.run(["container", "rm", "--force", ...batch]);
      } catch (error) {
        if (!(error instanceof DockerCommandError) || !/no such container/i.test(error.stderr)) throw error;
      }
    }
  }

  private async withRunLock<T>(runId: string, action: () => Promise<T>): Promise<T> {
    const previous = this.runLocks.get(runId) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => { release = resolve; });
    const tail = previous.catch(() => undefined).then(() => current);
    this.runLocks.set(runId, tail);
    await previous.catch(() => undefined);
    try {
      return await action();
    } finally {
      release();
      if (this.runLocks.get(runId) === tail) this.runLocks.delete(runId);
    }
  }
}

function normalizeOptions(options: DockerRuntimeOptions): NormalizedDockerRuntimeOptions {
  const normalized: NormalizedDockerRuntimeOptions = {
    commandRunner: options.commandRunner ?? new DockerCliCommandRunner(),
    network: options.network ?? "codegate-local-desktops",
    gatewayContainer: options.gatewayContainer ?? "codegate-local-desktop-gateway",
    ubuntuDesktopImage: options.ubuntuDesktopImage ?? "lscr.io/linuxserver/webtop:ubuntu-xfce",
    kaliDesktopImage: options.kaliDesktopImage ?? "lscr.io/linuxserver/kali-linux:latest",
    localTargetImage: options.localTargetImage ?? "codegate/local-target:development",
    localTargetSourceImage: options.localTargetSourceImage ?? "codegate/local-target:development",
    elasticsearchImage: options.elasticsearchImage ?? "docker.elastic.co/elasticsearch/elasticsearch:8.17.0",
    kibanaImage: options.kibanaImage ?? "docker.elastic.co/kibana/kibana:8.17.0",
    elasticAgentImage: options.elasticAgentImage ?? "codegate/elastic-agent:development",
    scenarioLogGeneratorImage: options.scenarioLogGeneratorImage ?? "codegate/scenario-log-generator:development",
    desktopMemory: options.desktopMemory ?? "4g",
    desktopCpus: options.desktopCpus ?? 2,
    desktopPidsLimit: options.desktopPidsLimit ?? 1024,
    desktopShmSize: options.desktopShmSize ?? "1g",
    targetMemory: options.targetMemory ?? "512m",
    targetCpus: options.targetCpus ?? 1,
    targetPidsLimit: options.targetPidsLimit ?? 256,
    cleanupIntervalMs: options.cleanupIntervalMs ?? 60_000,
    now: options.now ?? Date.now,
    logger: options.logger ?? console,
  };
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(normalized.network)) {
    throw new Error("LOCAL_DESKTOP_NETWORK is invalid");
  }
  validateImage(normalized.ubuntuDesktopImage, "LOCAL_UBUNTU_DESKTOP_IMAGE");
  validateImage(normalized.kaliDesktopImage, "LOCAL_KALI_DESKTOP_IMAGE");
  validateImage(normalized.localTargetImage, "LOCAL_TARGET_IMAGE");
  validateImage(normalized.localTargetSourceImage, "LOCAL_TARGET_SOURCE_IMAGE");
  validateImage(normalized.elasticsearchImage, "LOCAL_ELASTICSEARCH_IMAGE");
  validateImage(normalized.kibanaImage, "LOCAL_KIBANA_IMAGE");
  validateImage(normalized.elasticAgentImage, "LOCAL_ELASTIC_AGENT_IMAGE");
  validateImage(normalized.scenarioLogGeneratorImage, "LOCAL_SCENARIO_LOG_GENERATOR_IMAGE");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(normalized.gatewayContainer)) {
    throw new Error("LOCAL_DESKTOP_GATEWAY_CONTAINER is invalid");
  }
  validateSize(normalized.desktopMemory, "LOCAL_DESKTOP_MEMORY");
  validateSize(normalized.desktopShmSize, "LOCAL_DESKTOP_SHM_SIZE");
  validateSize(normalized.targetMemory, "LOCAL_TARGET_MEMORY");
  validatePositive(normalized.desktopCpus, "LOCAL_DESKTOP_CPUS", 0.1, 64);
  validateInteger(normalized.desktopPidsLimit, "LOCAL_DESKTOP_PIDS_LIMIT", 64, 32768);
  validatePositive(normalized.targetCpus, "LOCAL_TARGET_CPUS", 0.1, 64);
  validateInteger(normalized.targetPidsLimit, "LOCAL_TARGET_PIDS_LIMIT", 32, 32768);
  validateInteger(normalized.cleanupIntervalMs, "LOCAL_RUNTIME_CLEANUP_INTERVAL_MS", 0, 86_400_000);
  return normalized;
}

function commonLabels(
  request: ProvisionRunRequest,
  namespace: string,
  expiresAt: string,
  role: RuntimeRole,
): string[] {
  const values: Record<string, string> = {
    [MANAGED_LABEL]: MANAGED_VALUE,
    [RUN_ID_LABEL]: request.runId,
    [NAMESPACE_LABEL]: namespace,
    [EXPIRES_AT_LABEL]: expiresAt,
    [ACCESS_METHOD_LABEL]: request.accessMethod,
    [ROLE_LABEL]: role,
    ...(request.topology?.team ? { [TEAM_LABEL]: request.topology.team } : {}),
  };
  return Object.entries(values).flatMap(([key, value]) => ["--label", `${key}=${value}`]);
}

function statusFromInspection(runId: string, containers: InspectedContainer[], now: number): RuntimeRunStatus {
  const expectedNamespace = namespaceForRun(runId);
  const relevant = containers.filter((item) => item.labels[RUN_ID_LABEL] === runId);
  const metadataError = relevant.find((item) => (
    item.labels[MANAGED_LABEL] !== MANAGED_VALUE
    || item.labels[NAMESPACE_LABEL] !== expectedNamespace
    || item.labels[ACCESS_METHOD_LABEL] !== "browser_desktop"
  ));
  const expiresAtValues = new Set(relevant.map((item) => item.labels[EXPIRES_AT_LABEL]).filter(Boolean));
  const expiresAt = expiresAtValues.size === 1 ? [...expiresAtValues][0]! : "";
  const parsedExpiry = Date.parse(expiresAt);
  const desktop = relevant.find((item) => item.labels[ROLE_LABEL] === "desktop");
  const target = relevant.find((item) => item.labels[ROLE_LABEL] === "target");
  const team = relevant.find((item) => item.labels[TEAM_LABEL])?.labels[TEAM_LABEL];
  const elasticsearch = relevant.find((item) => item.labels[ROLE_LABEL] === "elasticsearch");
  const kibana = relevant.find((item) => item.labels[ROLE_LABEL] === "kibana");
  const telemetryAgent = relevant.find((item) => item.labels[ROLE_LABEL] === "elastic-agent");
  const scenarioLogs = relevant.find((item) => item.labels[ROLE_LABEL] === "scenario-log-generator");
  const checks: RuntimeReadinessChecks = {
    workstationVmi: containerReady(desktop),
    targetWorkload: containerReady(target),
    desktopEndpoints: containerReady(desktop),
    ...(team === "blue"
      ? {
          elasticsearch: containerReady(elasticsearch),
          kibana: containerReady(kibana),
          telemetryAgent: containerReady(telemetryAgent),
          scenarioLogs: containerReady(scenarioLogs),
        }
      : {}),
  };
  let reason: string | undefined;
  if (metadataError || relevant.length !== containers.length || expiresAtValues.size !== 1 || !Number.isFinite(parsedExpiry)) {
    reason = "Docker runtime container metadata is invalid or inconsistent";
  } else if (parsedExpiry <= now) {
    reason = `Runtime expired at ${expiresAt}`;
  } else if (!hasRequiredRoles(relevant, team === "blue" ? "blue" : team === "red" ? "red" : undefined)) {
    reason = team === "blue"
      ? "Docker blue-team runtime is missing its analyst desktop, ELK, monitored target, agent or scenario log generator"
      : "Docker runtime is missing a desktop or target container";
  } else {
    const required = team === "blue"
      ? [desktop, target, elasticsearch, kibana, telemetryAgent, scenarioLogs]
      : [desktop, target];
    const failed = required.filter((item): item is InspectedContainer => Boolean(item)).find(containerFailed);
    if (failed) {
      const suffix = failed.health === "unhealthy"
        ? "is unhealthy"
        : `stopped with status ${failed.status}${failed.exitCode === undefined ? "" : ` (exit ${failed.exitCode})`}`;
      reason = `Docker ${failed.labels[ROLE_LABEL] ?? "runtime"} container ${suffix}`;
    }
  }
  const status: RuntimeRunStatus["status"] = reason
    ? "failed"
    : Object.values(checks).every(Boolean)
      ? "ready"
      : "provisioning";
  return {
    id: runId,
    status,
    namespace: expectedNamespace,
    expiresAt: expiresAt || new Date(now).toISOString(),
    checks,
    ...(reason ? { reason } : {}),
  };
}

function containerReady(container: InspectedContainer | undefined): boolean {
  if (!container?.running) return false;
  return container.health === undefined || container.health === "healthy";
}

function containerFailed(container: InspectedContainer): boolean {
  return !container.running || container.health === "unhealthy";
}

function hasRequiredRoles(containers: InspectedContainer[], team?: "blue" | "red"): boolean {
  const roles = new Set(containers.map((item) => item.labels[ROLE_LABEL]));
  const base = roles.has("desktop") && roles.has("target");
  return team === "blue"
    ? base
      && roles.has("elasticsearch")
      && roles.has("kibana")
      && roles.has("elastic-agent")
      && roles.has("scenario-log-generator")
    : base;
}

function provisionedResult(
  runId: string,
  namespace: string,
  expiresAt: string,
  status: "provisioning" | "ready" | "failed",
): ProvisionedRun {
  return {
    id: runId,
    status: status === "ready" ? "ready" : "provisioning",
    namespace,
    expiresAt,
    browserDesktop: {
      gatewayPath: `/sessions/${runId}/desktop`,
      protocol: "websocket",
    },
  };
}

function parseInspection(value: unknown): InspectedContainer {
  if (!isRecord(value)) throw new DockerCommandError("Docker container inspection contains an invalid record");
  const record = value as DockerInspectRecord;
  if (typeof record.Id !== "string" || !isRecord(record.Config) || !isRecord(record.State)) {
    throw new DockerCommandError("Docker container inspection is missing required fields");
  }
  const rawLabels = isRecord(record.Config.Labels) ? record.Config.Labels : {};
  const labels: Record<string, string> = {};
  for (const [key, item] of Object.entries(rawLabels)) {
    if (typeof item === "string") labels[key] = item;
  }
  const health = isRecord(record.State.Health) && typeof record.State.Health.Status === "string"
    ? record.State.Health.Status
    : undefined;
  return {
    id: record.Id,
    name: typeof record.Name === "string" ? record.Name.replace(/^\//, "") : record.Id.slice(0, 12),
    labels,
    running: record.State.Running === true,
    status: typeof record.State.Status === "string" ? record.State.Status : "unknown",
    ...(health ? { health } : {}),
    ...(typeof record.State.ExitCode === "number" ? { exitCode: record.State.ExitCode } : {}),
    ...(typeof record.State.Error === "string" && record.State.Error ? { error: record.State.Error } : {}),
  };
}

function parseJsonObject(value: string, name: string): Record<string, unknown> {
  try {
    const result = JSON.parse(value);
    if (!isRecord(result)) throw new Error("not an object");
    return result;
  } catch (error) {
    throw new DockerCommandError(`${name} returned invalid JSON`, String(error));
  }
}

function containerName(role: RuntimeRole, namespace: string): string {
  return `codegate-${role}-${namespace}`;
}

function runNetworkName(prefix: string, runId: string): string {
  const suffix = namespaceForRun(runId).replace(/^range-/, "");
  return `${prefix}-${suffix}`.slice(0, 127);
}

function scenarioLogVolume(namespace: string): string {
  return `zerotop-logs-${namespace}`.slice(0, 127);
}

function telemetryIndexForRun(pattern: string, runId: string): string {
  const suffix = runId.toLowerCase().replace(/[^a-z0-9._-]/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);
  if (!suffix) throw new Error("runId cannot form a telemetry index suffix");
  return pattern.replace(/\*$/, suffix);
}

function validateImage(value: string, name: string): void {
  if (!value || value.length > 512 || /[\s\0]/.test(value) || value.startsWith("-")) {
    throw new Error(`${name} is not a valid container image reference`);
  }
}

function validateSize(value: string, name: string): void {
  if (!/^[1-9][0-9]*(?:\.[0-9]+)?[bkmgBKMG]?$/.test(value)) throw new Error(`${name} is invalid`);
}

function validatePositive(value: number, name: string, minimum: number, maximum: number): void {
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  }
}

function validateInteger(value: number, name: string, minimum: number, maximum: number): void {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

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
const MANAGED_VALUE = "codegate-runtime";

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
  ubuntuDesktopImage?: string;
  kaliDesktopImage?: string;
  localTargetImage?: string;
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
  ubuntuDesktopImage: string;
  kaliDesktopImage: string;
  localTargetImage: string;
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
      await this.assertInternalNetwork();

      const existing = await this.inspectRunContainers(request.runId);
      if (existing.length > 0) {
        const current = statusFromInspection(request.runId, existing, this.options.now());
        if (
          current.namespace === namespaceForRun(request.runId)
          && current.status !== "failed"
          && hasRequiredRoles(existing)
        ) {
          return provisionedResult(request.runId, current.namespace, current.expiresAt, current.status);
        }
        await this.removeRunContainers(request.runId);
      }

      const namespace = namespaceForRun(request.runId);
      const expiresAt = new Date(this.options.now() + request.ttlMinutes * 60_000).toISOString();
      const targetName = containerName("target", namespace);
      const desktopName = containerName("desktop", namespace);
      try {
        await this.options.commandRunner.run(this.targetCreateArgs(request, namespace, expiresAt, targetName));
        await this.options.commandRunner.run(this.desktopCreateArgs(request, namespace, expiresAt, desktopName));
        await this.options.commandRunner.run(["container", "start", targetName]);
        await this.options.commandRunner.run(["container", "start", desktopName]);
      } catch (error) {
        await this.removeRunContainers(request.runId).catch(() => undefined);
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
        await this.removeRunContainers(runId).catch(() => undefined);
      }
      return status;
    });
  }

  async destroy(runId: string): Promise<void> {
    await this.withRunLock(runId, () => this.removeRunContainers(runId));
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
    await this.removeContainerIds([...remove]);
  }

  private async assertInternalNetwork(): Promise<void> {
    let result: DockerCommandResult;
    try {
      result = await this.options.commandRunner.run([
        "network", "inspect", this.options.network, "--format", "{{json .}}",
      ]);
    } catch (error) {
      throw new Error(
        `Docker network ${this.options.network} is unavailable; create it as an internal bridge before starting the runtime`,
        { cause: error },
      );
    }
    const inspection = parseJsonObject(result.stdout, "Docker network inspection");
    if (inspection.Internal !== true) {
      throw new Error(`Docker network ${this.options.network} must be internal`);
    }
  }

  private targetCreateArgs(
    request: ProvisionRunRequest,
    namespace: string,
    expiresAt: string,
    name: string,
  ): string[] {
    return [
      "container", "create",
      "--pull", "never",
      "--name", name,
      "--network", this.options.network,
      "--network-alias", `target.${namespace}.svc.cluster.local`,
      "--network-alias", "target",
      ...commonLabels(request, namespace, expiresAt, "target"),
      "--memory", this.options.targetMemory,
      "--cpus", String(this.options.targetCpus),
      "--pids-limit", String(this.options.targetPidsLimit),
      "--read-only",
      "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864",
      "--cap-drop", "ALL",
      "--security-opt", "no-new-privileges=true",
      "--user", `${request.targetRuntimeContract.uid}:${request.targetRuntimeContract.gid}`,
      "--stop-timeout", "10",
      this.options.localTargetImage,
    ];
  }

  private desktopCreateArgs(
    request: ProvisionRunRequest,
    namespace: string,
    expiresAt: string,
    name: string,
  ): string[] {
    const image = request.desktopImage === "ubuntu"
      ? this.options.ubuntuDesktopImage
      : this.options.kaliDesktopImage;
    return [
      "container", "create",
      "--pull", "missing",
      "--name", name,
      "--network", this.options.network,
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
      "--env", "TITLE=ZeroTOP Training Desktop",
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

  private async removeRunContainers(runId: string): Promise<void> {
    const ids = await this.listContainerIds([`label=${RUN_ID_LABEL}=${runId}`]);
    await this.removeContainerIds(ids);
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
    ubuntuDesktopImage: options.ubuntuDesktopImage ?? "lscr.io/linuxserver/webtop:ubuntu-xfce",
    kaliDesktopImage: options.kaliDesktopImage ?? "lscr.io/linuxserver/kali-linux:latest",
    localTargetImage: options.localTargetImage ?? "codegate/local-target:development",
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
  role: "desktop" | "target",
): string[] {
  const values: Record<string, string> = {
    [MANAGED_LABEL]: MANAGED_VALUE,
    [RUN_ID_LABEL]: request.runId,
    [NAMESPACE_LABEL]: namespace,
    [EXPIRES_AT_LABEL]: expiresAt,
    [ACCESS_METHOD_LABEL]: request.accessMethod,
    [ROLE_LABEL]: role,
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
  const checks: RuntimeReadinessChecks = {
    workstationVmi: containerReady(desktop),
    targetWorkload: containerReady(target),
    desktopEndpoints: containerReady(desktop),
  };
  let reason: string | undefined;
  if (metadataError || relevant.length !== containers.length || expiresAtValues.size !== 1 || !Number.isFinite(parsedExpiry)) {
    reason = "Docker runtime container metadata is invalid or inconsistent";
  } else if (parsedExpiry <= now) {
    reason = `Runtime expired at ${expiresAt}`;
  } else if (!desktop || !target) {
    reason = "Docker runtime is missing a desktop or target container";
  } else {
    const failed = [desktop, target].find(containerFailed);
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

function hasRequiredRoles(containers: InspectedContainer[]): boolean {
  const roles = new Set(containers.map((item) => item.labels[ROLE_LABEL]));
  return roles.has("desktop") && roles.has("target");
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

function containerName(role: "desktop" | "target", namespace: string): string {
  return `codegate-${role}-${namespace}`;
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

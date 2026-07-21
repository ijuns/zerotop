import { execFile, spawn } from "node:child_process";
import { rmSync, writeFileSync } from "node:fs";
import {
  mkdir,
  readFile,
  stat,
  writeFile,
} from "node:fs/promises";
import { join, resolve } from "node:path";

import { parseIpv4Cidr } from "./network.ts";
import type { CommandRunner } from "./pki.ts";
import type { GatewayBundle } from "./types.ts";

interface GatewayEnvironment {
  issuerUrl: string;
  runId: string;
  namespace: string;
  profileId: string;
  bootstrapToken: string;
  runtimeDirectory: string;
  openvpnPath: string;
  iptablesPath: string;
  requireTmpfs: boolean;
}

export async function runGatewayFromEnvironment(): Promise<void> {
  const environment: GatewayEnvironment = {
    issuerUrl: safeIssuerUrl(required("OPENVPN_ISSUER_URL")),
    runId: identifier(required("OPENVPN_RUN_ID"), "OPENVPN_RUN_ID"),
    namespace: namespace(required("OPENVPN_RUN_NAMESPACE")),
    profileId: identifier(required("OPENVPN_PROFILE_ID"), "OPENVPN_PROFILE_ID"),
    bootstrapToken: bootstrapToken(required("GATEWAY_BOOTSTRAP_TOKEN")),
    runtimeDirectory: process.env.OPENVPN_RUNTIME_DIR ?? "/run/openvpn",
    openvpnPath: process.env.OPENVPN_BINARY ?? "/usr/sbin/openvpn",
    iptablesPath: process.env.IPTABLES_BINARY ?? "/usr/sbin/iptables",
    requireTmpfs: process.env.OPENVPN_REQUIRE_TMPFS !== "false",
  };
  await mkdir(environment.runtimeDirectory, { recursive: true, mode: 0o700 });
  rmSync(join(environment.runtimeDirectory, "ready"), { force: true });
  if (environment.requireTmpfs) await assertTmpfs(environment.runtimeDirectory);
  clearGatewayFiles(environment.runtimeDirectory);
  const bundle = await fetchGatewayBundle(environment);
  validateGatewayBundle(bundle, environment);
  await writeGatewayBundle(environment.runtimeDirectory, bundle);
  await ensureIpForwarding();
  await configureFirewall(
    bundle,
    (executable, args) => execute(executable, args),
    environment.iptablesPath,
  );
  delete process.env.GATEWAY_BOOTSTRAP_TOKEN;
  await superviseOpenVpn(
    environment.openvpnPath,
    join(environment.runtimeDirectory, "server.conf"),
    bundle.expiresAt,
  );
}

export async function fetchGatewayBundle(
  environment: Pick<
    GatewayEnvironment,
    "issuerUrl" | "runId" | "profileId" | "bootstrapToken"
  >,
  fetchImpl: typeof fetch = fetch,
): Promise<GatewayBundle> {
  let response: Response;
  try {
    response = await fetchImpl(`${environment.issuerUrl}/v1/gateways/bootstrap`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        runId: environment.runId,
        profileId: environment.profileId,
        bootstrapToken: environment.bootstrapToken,
      }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new Error("OpenVPN gateway bootstrap is unavailable.");
  }
  if (!response.ok) {
    throw new Error(`OpenVPN gateway bootstrap failed with ${response.status}.`);
  }
  const payload = record(await response.json().catch(() => null));
  return payload.bundle as GatewayBundle;
}

export function validateGatewayBundle(
  value: unknown,
  expected: Pick<GatewayEnvironment, "runId" | "profileId" | "namespace">,
): asserts value is GatewayBundle {
  const bundle = record(value);
  const files = record(bundle.files);
  const firewall = record(bundle.firewall);
  if (
    bundle.version !== 1 ||
    bundle.runId !== expected.runId ||
    bundle.profileId !== expected.profileId ||
    bundle.namespace !== expected.namespace ||
    typeof bundle.expiresAt !== "string" ||
    Date.parse(bundle.expiresAt) <= Date.now() ||
    typeof files.caCertificate !== "string" ||
    !files.caCertificate.includes("-----BEGIN CERTIFICATE-----") ||
    typeof files.serverCertificate !== "string" ||
    !files.serverCertificate.includes("-----BEGIN CERTIFICATE-----") ||
    typeof files.serverPrivateKey !== "string" ||
    !files.serverPrivateKey.includes("-----BEGIN PRIVATE KEY-----") ||
    typeof files.tlsCryptKey !== "string" ||
    files.tlsCryptKey.trim().length < 32 ||
    typeof files.serverConfig !== "string" ||
    !files.serverConfig.includes("dev tun\n") ||
    typeof firewall.vpnCidr !== "string" ||
    typeof firewall.allowedCidr !== "string"
  ) {
    throw new Error("The issuer returned an invalid gateway bundle.");
  }
  parseIpv4Cidr(firewall.vpnCidr, "bundle.firewall.vpnCidr");
  parseIpv4Cidr(firewall.allowedCidr, "bundle.firewall.allowedCidr");
}

export async function writeGatewayBundle(
  directory: string,
  bundle: GatewayBundle,
): Promise<void> {
  const files: Array<[string, string]> = [
    ["ca.crt", bundle.files.caCertificate],
    ["server.crt", bundle.files.serverCertificate],
    ["server.key", bundle.files.serverPrivateKey],
    ["tls-crypt.key", bundle.files.tlsCryptKey],
    ["server.conf", bundle.files.serverConfig],
  ];
  await mkdir(directory, { recursive: true, mode: 0o700 });
  for (const [name, contents] of files) {
    await writeFile(join(directory, name), contents, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
  }
}

export async function configureFirewall(
  bundle: Pick<GatewayBundle, "firewall">,
  run: CommandRunner,
  iptablesPath = "/usr/sbin/iptables",
): Promise<void> {
  const vpn = parseIpv4Cidr(bundle.firewall.vpnCidr, "vpnCidr");
  const allowed = parseIpv4Cidr(bundle.firewall.allowedCidr, "allowedCidr");
  await runIgnoringFailure(run, iptablesPath, ["-w", "5", "-N", "CODEGATE_VPN"]);
  await run(iptablesPath, ["-w", "5", "-F", "CODEGATE_VPN"]);
  if (!await commandSucceeds(run, iptablesPath, ["-w", "5", "-C", "FORWARD", "-j", "CODEGATE_VPN"])) {
    await run(iptablesPath, ["-w", "5", "-I", "FORWARD", "1", "-j", "CODEGATE_VPN"]);
  }
  const commands: string[][] = [
    ["-w", "5", "-A", "CODEGATE_VPN", "-i", "tun0", "-s", vpn.cidr, "-d", allowed.cidr, "-j", "ACCEPT"],
    ["-w", "5", "-A", "CODEGATE_VPN", "-o", "tun0", "-s", allowed.cidr, "-d", vpn.cidr, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ["-w", "5", "-A", "CODEGATE_VPN", "-i", "tun0", "-j", "DROP"],
    ["-w", "5", "-A", "CODEGATE_VPN", "-o", "tun0", "-j", "DROP"],
    ["-w", "5", "-A", "CODEGATE_VPN", "-j", "RETURN"],
  ];
  for (const args of commands) await run(iptablesPath, args);
  const natRule = ["-w", "5", "-t", "nat", "-C", "POSTROUTING", "-s", vpn.cidr, "-d", allowed.cidr, "-j", "MASQUERADE"];
  if (!await commandSucceeds(run, iptablesPath, natRule)) {
    await run(iptablesPath, ["-w", "5", "-t", "nat", "-A", "POSTROUTING", "-s", vpn.cidr, "-d", allowed.cidr, "-j", "MASQUERADE"]);
  }
}

function clearGatewayFiles(directory: string): void {
  for (const name of ["ca.crt", "server.crt", "server.key", "tls-crypt.key", "server.conf", "ready"]) {
    rmSync(join(directory, name), { force: true });
  }
}

async function commandSucceeds(run: CommandRunner, executable: string, args: string[]): Promise<boolean> {
  try {
    await run(executable, args);
    return true;
  } catch {
    return false;
  }
}

async function runIgnoringFailure(run: CommandRunner, executable: string, args: string[]): Promise<void> {
  await commandSucceeds(run, executable, args);
}

async function ensureIpForwarding(): Promise<void> {
  const path = "/proc/sys/net/ipv4/ip_forward";
  const current = await readFile(path, "utf8");
  if (current.trim() !== "1") await writeFile(path, "1\n", "utf8");
}

async function assertTmpfs(directory: string): Promise<void> {
  const target = resolve(directory);
  await stat(target);
  const mountInfo = await readFile("/proc/self/mountinfo", "utf8");
  let selected: { path: string; type: string } | null = null;
  for (const line of mountInfo.split("\n")) {
    const separator = line.indexOf(" - ");
    if (separator < 0) continue;
    const left = line.slice(0, separator).split(" ");
    const right = line.slice(separator + 3).split(" ");
    const mountPath = unescapeMount(left[4] ?? "");
    if (
      (target === mountPath || target.startsWith(`${mountPath}/`)) &&
      (!selected || mountPath.length > selected.path.length)
    ) {
      selected = { path: mountPath, type: right[0] ?? "" };
    }
  }
  if (selected?.type !== "tmpfs") {
    throw new Error("OPENVPN_RUNTIME_DIR must be backed by tmpfs.");
  }
}

function superviseOpenVpn(
  executable: string,
  configPath: string,
  expiresAt: string,
): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    const readyMarker = join(resolve(configPath, ".."), "ready");
    rmSync(readyMarker, { force: true });
    const child = spawn(executable, ["--config", configPath], {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      env: process.env,
    });
    let expiring = false;
    let ready = false;
    let readinessError: Error | null = null;
    let logTail = "";
    const inspectOutput = (chunk: Buffer, destination: NodeJS.WriteStream): void => {
      destination.write(chunk);
      if (ready) return;
      logTail = `${logTail}${chunk.toString("utf8")}`.slice(-4096);
      if (logTail.includes("Initialization Sequence Completed")) {
        try {
          writeFileSync(readyMarker, "ready\n", { mode: 0o600, flag: "wx" });
          ready = true;
        } catch (error) {
          readinessError =
            error instanceof Error ? error : new Error("Unable to write readiness marker.");
          child.kill("SIGTERM");
        }
      }
    };
    child.stdout?.on("data", (chunk: Buffer) => inspectOutput(chunk, process.stdout));
    child.stderr?.on("data", (chunk: Buffer) => inspectOutput(chunk, process.stderr));
    const remaining = Math.max(0, Date.parse(expiresAt) - Date.now());
    const expiryTimer = setTimeout(() => {
      expiring = true;
      child.kill("SIGTERM");
    }, remaining);
    const forward = (signal: NodeJS.Signals) => child.kill(signal);
    const onTerm = () => forward("SIGTERM");
    const onInt = () => forward("SIGINT");
    process.once("SIGTERM", onTerm);
    process.once("SIGINT", onInt);
    child.once("error", (error) => {
      cleanup();
      reject(error);
    });
    child.once("exit", (code, signal) => {
      cleanup();
      if (readinessError) {
        reject(readinessError);
      } else if (expiring || code === 0 || signal === "SIGTERM" || signal === "SIGINT") {
        resolvePromise();
      } else {
        reject(new Error(`OpenVPN exited unexpectedly with code ${code}.`));
      }
    });
    function cleanup(): void {
      clearTimeout(expiryTimer);
      rmSync(readyMarker, { force: true });
      process.off("SIGTERM", onTerm);
      process.off("SIGINT", onInt);
    }
  });
}

function execute(executable: string, args: string[]): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    execFile(
      executable,
      args,
      { windowsHide: true, timeout: 10_000, maxBuffer: 1024 * 1024 },
      (error) => (error ? reject(error) : resolvePromise()),
    );
  });
}

function safeIssuerUrl(value: string): string {
  const url = new URL(value);
  const clusterLocal =
    url.hostname.endsWith(".svc.cluster.local") || !url.hostname.includes(".");
  if (url.protocol !== "https:" && !clusterLocal && url.hostname !== "localhost") {
    throw new Error("OPENVPN_ISSUER_URL must use HTTPS outside the cluster.");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("OPENVPN_ISSUER_URL is invalid.");
  }
  return value.replace(/\/$/, "");
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function identifier(value: string, field: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(value)) {
    throw new Error(`${field} is invalid.`);
  }
  return value;
}

function namespace(value: string): string {
  if (!/^range-[a-z0-9](?:[a-z0-9-]{0,55}[a-z0-9])?$/.test(value)) {
    throw new Error("OPENVPN_RUN_NAMESPACE is invalid.");
  }
  return value;
}

function bootstrapToken(value: string): string {
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(value)) {
    throw new Error("GATEWAY_BOOTSTRAP_TOKEN is invalid.");
  }
  return value;
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function unescapeMount(value: string): string {
  return value
    .replace(/\\040/g, " ")
    .replace(/\\011/g, "\t")
    .replace(/\\012/g, "\n")
    .replace(/\\134/g, "\\");
}

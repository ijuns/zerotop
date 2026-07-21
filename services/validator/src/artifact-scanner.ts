import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import type { ArtifactEvidence, LabTarget, TargetRuntimeContract } from "./contracts.ts";

const execFileAsync = promisify(execFile);

export interface ArtifactScanner {
  scan(target: LabTarget): Promise<ArtifactEvidence>;
}

export class CliArtifactScanner implements ArtifactScanner {
  private readonly cosignBin: string;
  private readonly syftBin: string;
  private readonly trivyBin: string;
  private readonly craneBin: string;
  private readonly cosignPublicKeyPath: string;

  constructor(options: {
    cosignBin?: string;
    syftBin?: string;
    trivyBin?: string;
    craneBin?: string;
    cosignPublicKeyPath: string;
  }) {
    this.cosignBin = options.cosignBin ?? "cosign";
    this.syftBin = options.syftBin ?? "syft";
    this.trivyBin = options.trivyBin ?? "trivy";
    this.craneBin = options.craneBin ?? "crane";
    this.cosignPublicKeyPath = options.cosignPublicKeyPath;
  }

  async scan(target: LabTarget): Promise<ArtifactEvidence> {
    const image = `${target.image}@${target.digest}`;
    const workspace = await mkdtemp(join(tmpdir(), "codegate-validation-"));
    const sbomPath = join(workspace, "sbom.spdx.json");
    const trivyPath = join(workspace, "trivy.json");
    try {
      await this.run(this.cosignBin, ["verify", "--key", this.cosignPublicKeyPath, image]);
      const imageConfig = JSON.parse(await this.run(this.craneBin, ["config", image])) as unknown;
      validateOciRuntimeConfig(imageConfig, target.runtimeContract);
      await this.run(this.syftBin, [image, "-o", `spdx-json=${sbomPath}`]);
      const sbomStat = await stat(sbomPath);
      if (sbomStat.size < 2 || sbomStat.size > 25_000_000) throw new Error("SBOM size is invalid");
      await this.run(this.trivyBin, [
        "image",
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--output",
        trivyPath,
        "--severity",
        "HIGH,CRITICAL",
        "--max-image-size",
        "20GB",
        image,
      ]);
      const report = JSON.parse(await readFile(trivyPath, "utf8")) as unknown;
      const unexpectedCriticalIds = unexpectedCriticalVulnerabilities(report, target.expectedCves);
      return {
        imageDigest: target.digest,
        signatureVerified: true,
        ociConfigVerified: true,
        runtimeContractVerified: true,
        sbomGenerated: true,
        scanCompleted: true,
        unexpectedCriticalCount: unexpectedCriticalIds.length,
        unexpectedCriticalIds,
      };
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  }

  private async run(binary: string, args: string[]): Promise<string> {
    const result = await execFileAsync(binary, args, {
      timeout: 120_000,
      maxBuffer: 2_000_000,
      windowsHide: true,
      encoding: "utf8",
      env: scannerProcessEnvironment(process.env),
    });
    return String(result.stdout ?? "");
  }
}

export function scannerProcessEnvironment(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const cacheDirectory = source.VALIDATOR_CACHE_DIR ?? "/var/cache/codegate-validator";
  return {
    PATH: source.PATH,
    XDG_CACHE_HOME: cacheDirectory,
    TRIVY_CACHE_DIR: cacheDirectory,
    SYFT_CHECK_FOR_APP_UPDATE: "false",
    ...optionalEnvironment(source, "DOCKER_CONFIG"),
    ...optionalEnvironment(source, "SSL_CERT_DIR"),
    ...optionalEnvironment(source, "SSL_CERT_FILE"),
    ...optionalEnvironment(source, "COSIGN_REPOSITORY"),
  };
}

function optionalEnvironment(source: NodeJS.ProcessEnv, name: string): NodeJS.ProcessEnv {
  const value = source[name];
  return typeof value === "string" && value.length > 0 ? { [name]: value } : {};
}

export function validateOciRuntimeConfig(value: unknown, contract: TargetRuntimeContract): void {
  if (!isObject(value) || !isObject(value.config)) throw new Error("OCI image config is invalid");
  const config = value.config;
  const acceptedUsers = new Set([String(contract.uid), `${contract.uid}:${contract.gid}`]);
  if (typeof config.User !== "string" || !acceptedUsers.has(config.User)) {
    throw new Error("OCI image user does not match the target runtime contract");
  }
  if (!isObject(config.ExposedPorts) || !Object.hasOwn(config.ExposedPorts, `${contract.port}/tcp`)) {
    throw new Error("OCI image exposed port does not match the target runtime contract");
  }
  if (!isObject(config.Labels)) throw new Error("OCI image runtime labels are missing");
  const labels = config.Labels;
  if (
    labels["io.codegate.runtime.contract"] !== contract.kind
    || labels["io.codegate.runtime.uid"] !== String(contract.uid)
    || labels["io.codegate.runtime.port"] !== String(contract.port)
    || labels["io.codegate.runtime.contract.digest"] !== runtimeContractDigest(contract)
  ) throw new Error("OCI image runtime labels do not match the target runtime contract");
  if (!Array.isArray(config.Env) || !config.Env.includes(`HOST=${contract.bindAddress}`) || !config.Env.includes(`PORT=${contract.port}`)) {
    throw new Error("OCI image bind address or port environment does not match the target runtime contract");
  }
  const hasEntrypoint = Array.isArray(config.Entrypoint) && config.Entrypoint.some((item) => typeof item === "string" && item.length > 0);
  const hasCommand = Array.isArray(config.Cmd) && config.Cmd.some((item) => typeof item === "string" && item.length > 0);
  if (!hasEntrypoint && !hasCommand) throw new Error("OCI image has no executable entrypoint or command");
}

export function runtimeContractDigest(value: TargetRuntimeContract): `sha256:${string}` {
  const canonical = JSON.stringify({
    bindAddress: value.bindAddress,
    fingerprintPath: value.fingerprintPath,
    gid: value.gid,
    healthPath: value.healthPath,
    kind: value.kind,
    port: value.port,
    protocol: value.protocol,
    readOnlyRootFilesystem: value.readOnlyRootFilesystem,
    uid: value.uid,
    writablePaths: value.writablePaths,
  });
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

export function unexpectedCriticalVulnerabilities(value: unknown, expectedCves: string[]): string[] {
  if (!isObject(value) || !Array.isArray(value.Results)) throw new Error("Trivy report is invalid");
  const expected = new Set(expectedCves.map((item) => item.toUpperCase()));
  const unexpected = new Set<string>();
  for (const result of value.Results) {
    if (!isObject(result) || !Array.isArray(result.Vulnerabilities)) continue;
    for (const vulnerability of result.Vulnerabilities) {
      if (!isObject(vulnerability) || vulnerability.Severity !== "CRITICAL") continue;
      if (typeof vulnerability.VulnerabilityID !== "string") throw new Error("Trivy vulnerability ID is invalid");
      const id = vulnerability.VulnerabilityID.toUpperCase();
      if (!expected.has(id)) unexpected.add(id);
    }
  }
  return [...unexpected].sort();
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

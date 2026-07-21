import type { ArtifactCatalogEntry, EnvironmentBuildSpec, PackageCatalogEntry, ResolvedPackage, TargetRuntimeContract } from "./contracts.ts";
import { isIP } from "node:net";
import { BuilderError } from "./errors.ts";
import { isSupportedRuntimeContract, runtimeContractDigest } from "./runtime-contract.ts";

const DIGEST_IMAGE = /^[a-z0-9.-]+(?::\d+)?\/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$/;

export interface BuildCatalogOptions {
  baseImages: string[];
  outputRepositories: string[];
  packages: Record<string, PackageCatalogEntry>;
  artifacts: Record<string, ArtifactCatalogEntry>;
}

export interface CatalogResolution {
  resolvedPackages: ResolvedPackage[];
  runtimeContract: TargetRuntimeContract;
  runtimeContractDigest: `sha256:${string}`;
}

export class BuildCatalog {
  private readonly baseImages: Set<string>;
  private readonly outputRepositories: Set<string>;
  private readonly packages: Readonly<Record<string, PackageCatalogEntry>>;
  private readonly artifacts: Readonly<Record<string, ArtifactCatalogEntry>>;

  constructor(options: BuildCatalogOptions) {
    this.baseImages = new Set(options.baseImages.map((value) => value.toLowerCase()));
    this.outputRepositories = new Set(options.outputRepositories.map((value) => value.toLowerCase()));
    this.packages = Object.freeze({ ...options.packages });
    this.artifacts = Object.freeze({ ...options.artifacts });
    if (this.baseImages.size === 0) throw new Error("At least one base image must be allowlisted");
    if (this.outputRepositories.size === 0) throw new Error("At least one output repository must be allowlisted");
    for (const [key, entry] of Object.entries(this.packages)) validatePackageEntry(key, entry);
    for (const [digest, entry] of Object.entries(this.artifacts)) validateArtifactEntry(digest, entry);
  }

  resolve(spec: EnvironmentBuildSpec): CatalogResolution {
    if (!this.baseImages.has(spec.target.baseImage)) deny("base_image_not_allowlisted", "The requested base image is not allowlisted");
    if (!this.outputRepositories.has(spec.target.outputRepository)) deny("output_repository_not_allowlisted", "The output repository is not allowlisted");
    if (spec.source.cveIds.length > 0 && spec.target.packages.length === 0 && spec.target.artifacts.length === 0) {
      deny("cve_component_required", "CVE builds require an allowlisted package or digest-pinned artifact selection");
    }
    if (!isSupportedRuntimeContract(spec.target.runtimeContract)) {
      deny("runtime_contract_not_supported", "The target runtime contract is not supported by this builder");
    }
    if (
      spec.target.service.protocol !== spec.target.runtimeContract.protocol
      || spec.target.service.port !== spec.target.runtimeContract.port
    ) {
      deny("runtime_contract_mismatch", "The target service does not match the allowlisted runtime contract");
    }
    const resolvedPackages = spec.target.packages.map((selection) => {
      const key = `${selection.name}@${selection.version}`;
      const entry = this.packages[key];
      if (!entry) deny("package_not_allowlisted", `Package ${key} is not allowlisted`);
      return { ...selection, ...entry };
    });
    for (const artifact of spec.target.artifacts) {
      const catalogEntry = this.artifacts[artifact.sha256];
      if (!catalogEntry || catalogEntry.url !== artifact.url) {
        deny("artifact_not_allowlisted", `Artifact ${artifact.sha256} is not allowlisted at the requested URL`);
      }
    }
    return {
      resolvedPackages,
      runtimeContract: spec.target.runtimeContract,
      runtimeContractDigest: runtimeContractDigest(spec.target.runtimeContract),
    };
  }
}

export function catalogFromEnvironment(environment: NodeJS.ProcessEnv = process.env): BuildCatalog {
  return new BuildCatalog({
    baseImages: parseStringArray(environment.BASE_IMAGE_ALLOWLIST_JSON, "BASE_IMAGE_ALLOWLIST_JSON"),
    outputRepositories: parseStringArray(environment.OUTPUT_REPOSITORY_ALLOWLIST_JSON, "OUTPUT_REPOSITORY_ALLOWLIST_JSON"),
    packages: parseObject<PackageCatalogEntry>(environment.PACKAGE_CATALOG_JSON, "PACKAGE_CATALOG_JSON"),
    artifacts: parseObject<ArtifactCatalogEntry>(environment.ARTIFACT_CATALOG_JSON, "ARTIFACT_CATALOG_JSON"),
  });
}

function parseStringArray(value: string | undefined, name: string): string[] {
  const parsed = parseJson(value, name);
  if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string")) throw new Error(`${name} must be a JSON string array`);
  return parsed;
}

function parseObject<T>(value: string | undefined, name: string): Record<string, T> {
  const parsed = parseJson(value, name);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error(`${name} must be a JSON object`);
  return parsed as Record<string, T>;
}

function parseJson(value: string | undefined, name: string): unknown {
  if (!value) throw new Error(`${name} is required`);
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw new Error(`${name} is not valid JSON`);
  }
}

function validatePackageEntry(key: string, entry: PackageCatalogEntry): void {
  if (!/^[a-z0-9][a-z0-9._-]*@[a-z0-9][a-z0-9.+_~-]*$/.test(key)) throw new Error(`Package catalog key ${key} is invalid`);
  if (!entry || typeof entry !== "object" || !DIGEST_IMAGE.test(entry.imageRef)) throw new Error(`Package catalog ${key} imageRef must be digest-pinned`);
  const fields = Object.keys(entry).sort();
  if (fields.join(",") !== "destination,imageRef,runtimeKind,sourcePath") {
    throw new Error(`Package catalog ${key} must contain exactly imageRef, sourcePath, destination, and runtimeKind`);
  }
  if (entry.runtimeKind !== "declarative-http-v1" && entry.runtimeKind !== "signed-node-handler-v1") {
    throw new Error(`Package catalog ${key} runtimeKind is unsupported`);
  }
  if (!safeCatalogPath(entry.sourcePath) || !safeCatalogPath(entry.destination)) throw new Error(`Package catalog ${key} paths are unsafe`);
  const componentId = key.slice(0, key.lastIndexOf("@"));
  if (entry.sourcePath !== "/opt/codegate/package/") {
    throw new Error(`Package catalog ${key} sourcePath must be the reviewed helper export directory`);
  }
  if (entry.destination !== `/opt/codegate/packages/${componentId}/`) {
    throw new Error(`Package catalog ${key} destination must match its component ID`);
  }
}

function validateArtifactEntry(digest: string, entry: ArtifactCatalogEntry): void {
  if (!/^[a-f0-9]{64}$/.test(digest)) throw new Error(`Artifact catalog digest ${digest} is invalid`);
  if (!entry || typeof entry !== "object" || Object.keys(entry).join(",") !== "url" || typeof entry.url !== "string" || !publicHttpsUrl(entry.url)) {
    throw new Error(`Artifact catalog ${digest} URL must be public HTTPS without credentials, query, or fragment`);
  }
}

function publicHttpsUrl(value: string): boolean {
  if (value.length < 12 || value.length > 2_000 || value.trim() !== value || /[\u0000-\u001f\\]/.test(value)) return false;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password || parsed.search || parsed.hash) return false;
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (hostname === "localhost" || hostname.endsWith(".local")) return false;
  if (isIP(hostname) === 4) {
    const octets = hostname.split(".").map(Number);
    const [a = 0, b = 0] = octets;
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19)));
  }
  if (isIP(hostname) === 6) return !/^(?:::|::1|f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:)/i.test(hostname);
  return true;
}

function safeCatalogPath(value: string): boolean {
  return typeof value === "string" && /^\/[a-zA-Z0-9][a-zA-Z0-9._/-]{0,190}\/?$/.test(value) && !value.includes("..") && !value.includes("//");
}

function deny(code: string, message: string): never {
  throw new BuilderError(422, code, message);
}

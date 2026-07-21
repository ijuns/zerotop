import type { HttpProbe, IsolationEndpoint, ProbePlan, TargetProbe, TcpBannerProbe } from "./contracts.ts";

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;
const HOST = /^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\d{1,3}(?:\.\d{1,3}){3})$/;
const CVE = /^CVE-\d{4}-\d{4,7}$/i;

export function parseProbePlan(value: unknown): ProbePlan {
  const root = record(value, "probe plan");
  if (root.schemaVersion !== 1) throw new Error("Unsupported probe plan schemaVersion");
  const target = record(root.target, "target");
  if (target.host !== "target") throw new Error("target.host must be the in-namespace target service");
  const protocol = target.protocol;
  if (protocol !== "http" && protocol !== "tcp") throw new Error("target.protocol must be http or tcp");
  const port = validPort(target.port, "target.port");
  const functionalProbes = probes(root.functionalProbes, "functionalProbes", protocol, false);
  const vulnerabilityProbes = probes(root.vulnerabilityProbes, "vulnerabilityProbes", protocol, true);
  if (functionalProbes.length === 0) throw new Error("At least one functional probe is required");
  if (vulnerabilityProbes.length === 0) throw new Error("At least one vulnerability probe is required");
  const isolation = record(root.isolation, "isolation");
  const requestTimeoutMs = Number(root.requestTimeoutMs);
  if (!Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 250 || requestTimeoutMs > 10_000) {
    throw new Error("requestTimeoutMs must be an integer between 250 and 10000");
  }
  return {
    schemaVersion: 1,
    target: { host: "target", port, protocol },
    functionalProbes,
    vulnerabilityProbes,
    isolation: {
      external: endpoint(isolation.external, "isolation.external"),
      controlPlane: endpoint(isolation.controlPlane, "isolation.controlPlane"),
      crossRun: endpoint(isolation.crossRun, "isolation.crossRun"),
    },
    requestTimeoutMs,
  };
}

function probes(value: unknown, name: string, protocol: "http" | "tcp", requireFinding: boolean): TargetProbe[] {
  if (!Array.isArray(value) || value.length > 20) throw new Error(`${name} must contain at most 20 probes`);
  return value.map((item, index) => {
    const input = record(item, `${name}[${index}]`);
    const id = text(input.id, `${name}[${index}].id`, 80, IDENTIFIER);
    const cveId = input.cveId === undefined
      ? undefined
      : text(input.cveId, `${name}[${index}].cveId`, 24, CVE).toUpperCase();
    const findingId = input.findingId === undefined
      ? undefined
      : text(input.findingId, `${name}[${index}].findingId`, 80, IDENTIFIER);
    if (requireFinding && !cveId && !findingId) {
      throw new Error(`${name}[${index}] requires cveId or findingId`);
    }
    if (protocol === "http" && input.kind === "http") {
      const method = input.method;
      if (method !== "GET" && method !== "HEAD") throw new Error(`${name}[${index}].method is invalid`);
      const path = text(input.path, `${name}[${index}].path`, 500);
      if (!path.startsWith("/") || path.startsWith("//") || path.includes("://") || /[\u0000-\u001f\\]/.test(path)) {
        throw new Error(`${name}[${index}].path must be a safe relative path`);
      }
      if (!Array.isArray(input.expectedStatuses) || input.expectedStatuses.length < 1 || input.expectedStatuses.length > 8) {
        throw new Error(`${name}[${index}].expectedStatuses is invalid`);
      }
      const expectedStatuses = [...new Set(input.expectedStatuses.map((status) => {
        const number = Number(status);
        if (!Number.isInteger(number) || number < 100 || number > 599) throw new Error(`${name}[${index}] has an invalid HTTP status`);
        return number;
      }))];
      const bodyIncludes = markers(input.bodyIncludes, `${name}[${index}].bodyIncludes`);
      return { id, kind: "http", method, path, expectedStatuses, bodyIncludes, ...(cveId ? { cveId } : {}), ...(findingId ? { findingId } : {}) } satisfies HttpProbe;
    }
    if (protocol === "tcp" && input.kind === "tcp_banner") {
      const bannerIncludes = markers(input.bannerIncludes, `${name}[${index}].bannerIncludes`);
      if (bannerIncludes.length === 0) throw new Error(`${name}[${index}] requires a banner marker`);
      return { id, kind: "tcp_banner", bannerIncludes, ...(cveId ? { cveId } : {}), ...(findingId ? { findingId } : {}) } satisfies TcpBannerProbe;
    }
    throw new Error(`${name}[${index}].kind does not match the target protocol`);
  });
}

function markers(value: unknown, name: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 8) throw new Error(`${name} must be an array with at most 8 values`);
  return [...new Set(value.map((item, index) => text(item, `${name}[${index}]`, 200)))];
}

function endpoint(value: unknown, name: string): IsolationEndpoint {
  const input = record(value, name);
  const host = text(input.host, `${name}.host`, 253, HOST);
  return { host, port: validPort(input.port, `${name}.port`) };
}

function validPort(value: unknown, name: string): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`${name} is invalid`);
  return port;
}

function text(value: unknown, name: string, maximum: number, pattern?: RegExp): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || (pattern && !pattern.test(value))) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value as Record<string, unknown>;
}

import type { TargetRuntimeContract } from "./contracts.ts";

export function parseTargetRuntimeContract(value: unknown, name = "targetRuntimeContract"): TargetRuntimeContract {
  if (!isRecord(value)) throw new Error(`${name} must be an object`);
  const expectedKeys = new Set([
    "kind", "uid", "gid", "protocol", "port", "writablePaths",
    "readOnlyRootFilesystem", "bindAddress", "healthPath", "fingerprintPath",
  ]);
  if (Object.keys(value).some((key) => !expectedKeys.has(key))) throw new Error(`${name} contains unsupported fields`);
  if (
    value.kind !== "http-v1"
    || value.uid !== 65_532
    || value.gid !== 65_532
    || value.protocol !== "http"
    || value.port !== 8_080
    || value.readOnlyRootFilesystem !== true
    || value.bindAddress !== "0.0.0.0"
    || value.healthPath !== "/health"
    || value.fingerprintPath !== "/version"
    || !Array.isArray(value.writablePaths)
    || value.writablePaths.length !== 1
    || value.writablePaths[0] !== "/tmp"
  ) throw new Error(`${name} is invalid or unsupported`);
  return {
    kind: "http-v1", uid: 65_532, gid: 65_532, protocol: "http", port: 8_080,
    writablePaths: ["/tmp"], readOnlyRootFilesystem: true, bindAddress: "0.0.0.0",
    healthPath: "/health", fingerprintPath: "/version",
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

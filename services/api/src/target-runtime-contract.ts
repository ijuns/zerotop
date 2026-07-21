export interface TargetRuntimeContract {
  kind: "http-v1";
  uid: 65532;
  gid: 65532;
  protocol: "http";
  port: 8080;
  writablePaths: ["/tmp"];
  readOnlyRootFilesystem: true;
  bindAddress: "0.0.0.0";
  healthPath: "/health";
  fingerprintPath: "/version";
}

const FIELDS = new Set([
  "kind",
  "uid",
  "gid",
  "protocol",
  "port",
  "writablePaths",
  "readOnlyRootFilesystem",
  "bindAddress",
  "healthPath",
  "fingerprintPath",
]);

export function parseTargetRuntimeContract(value: unknown): TargetRuntimeContract | null {
  if (!isObject(value) || Object.keys(value).some((key) => !FIELDS.has(key))) return null;
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
  ) return null;
  return {
    kind: "http-v1",
    uid: 65_532,
    gid: 65_532,
    protocol: "http",
    port: 8_080,
    writablePaths: ["/tmp"],
    readOnlyRootFilesystem: true,
    bindAddress: "0.0.0.0",
    healthPath: "/health",
    fingerprintPath: "/version",
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

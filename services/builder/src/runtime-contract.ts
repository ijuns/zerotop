import { createHash } from "node:crypto";

import type { TargetRuntimeContract } from "./contracts.ts";

export const HTTP_RUNTIME_CONTRACT: TargetRuntimeContract = Object.freeze({
  kind: "http-v1",
  uid: 65_532,
  gid: 65_532,
  protocol: "http",
  port: 8_080,
  writablePaths: ["/tmp"] as ["/tmp"],
  readOnlyRootFilesystem: true,
  bindAddress: "0.0.0.0",
  healthPath: "/health",
  fingerprintPath: "/version",
});

export function isSupportedRuntimeContract(value: TargetRuntimeContract): boolean {
  return value.kind === HTTP_RUNTIME_CONTRACT.kind
    && value.uid === HTTP_RUNTIME_CONTRACT.uid
    && value.gid === HTTP_RUNTIME_CONTRACT.gid
    && value.protocol === HTTP_RUNTIME_CONTRACT.protocol
    && value.port === HTTP_RUNTIME_CONTRACT.port
    && value.readOnlyRootFilesystem === HTTP_RUNTIME_CONTRACT.readOnlyRootFilesystem
    && value.bindAddress === HTTP_RUNTIME_CONTRACT.bindAddress
    && value.healthPath === HTTP_RUNTIME_CONTRACT.healthPath
    && value.fingerprintPath === HTTP_RUNTIME_CONTRACT.fingerprintPath
    && value.writablePaths.length === 1
    && value.writablePaths[0] === "/tmp";
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

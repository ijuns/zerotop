import assert from "node:assert/strict";
import test from "node:test";

import { scannerProcessEnvironment } from "../src/artifact-scanner.ts";

test("scanner tools receive private registry credentials and CA without unrelated secrets", () => {
  const environment = scannerProcessEnvironment({
    PATH: "/usr/bin",
    VALIDATOR_CACHE_DIR: "/cache",
    DOCKER_CONFIG: "/home/validator/.docker",
    SSL_CERT_DIR: "/etc/ssl/certs",
    SSL_CERT_FILE: "/etc/codegate/registry-ca/ca.crt",
    COSIGN_REPOSITORY: "registry.example.invalid/codegate/signatures",
    AI_INTERNAL_TOKEN: "must-not-propagate",
  });
  assert.equal(environment.AI_INTERNAL_TOKEN, undefined);
  assert.deepEqual(environment, {
    PATH: "/usr/bin",
    XDG_CACHE_HOME: "/cache",
    TRIVY_CACHE_DIR: "/cache",
    SYFT_CHECK_FOR_APP_UPDATE: "false",
    DOCKER_CONFIG: "/home/validator/.docker",
    SSL_CERT_DIR: "/etc/ssl/certs",
    SSL_CERT_FILE: "/etc/codegate/registry-ca/ca.crt",
    COSIGN_REPOSITORY: "registry.example.invalid/codegate/signatures",
  });
});

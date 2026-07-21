import assert from "node:assert/strict";
import test from "node:test";

import { registryToolEnvironment } from "../src/signer.ts";

test("Cosign receives only the allowlisted registry trust environment", () => {
  const environment = registryToolEnvironment({
    PATH: "/usr/bin",
    DOCKER_CONFIG: "/untrusted/default",
    SSL_CERT_DIR: "/etc/ssl/certs",
    SSL_CERT_FILE: "/etc/codegate/registry-ca/ca.crt",
    COSIGN_REPOSITORY: "registry.example.invalid/codegate/signatures",
    DATABASE_URL: "must-not-propagate",
  }, "/home/builder/.docker");
  assert.equal(environment.DATABASE_URL, undefined);
  assert.deepEqual(environment, {
    PATH: "/usr/bin",
    HOME: "/tmp/codegate-builder-home",
    DOCKER_CONFIG: "/home/builder/.docker",
    SSL_CERT_DIR: "/etc/ssl/certs",
    SSL_CERT_FILE: "/etc/codegate/registry-ca/ca.crt",
    COSIGN_REPOSITORY: "registry.example.invalid/codegate/signatures",
  });
});

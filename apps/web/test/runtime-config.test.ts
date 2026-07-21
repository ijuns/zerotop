import assert from "node:assert/strict";
import test from "node:test";

import { webRuntimeConfig } from "../lib/runtime-config.ts";

test("loads deployment-time public endpoints without build-time variables", () => {
  const config = webRuntimeConfig({
    CODEGATE_WEB_API_URL: "/api",
    CODEGATE_WEB_KEYCLOAK_URL: "https://identity.example.test/",
    CODEGATE_WEB_KEYCLOAK_REALM: "codegate",
    CODEGATE_WEB_KEYCLOAK_CLIENT_ID: "codegate-web",
    CODEGATE_WEB_DEVELOPMENT_IDENTITY: "false",
    CODEGATE_WEB_DEV_USER_ID: "user-dev",
  });

  assert.equal(config.apiUrl, "/api");
  assert.equal(config.keycloakUrl, "https://identity.example.test");
  assert.equal(config.developmentIdentityEnabled, false);
});

test("allows the explicit local development identity without Keycloak", () => {
  const config = webRuntimeConfig({
    CODEGATE_WEB_API_URL: "http://localhost:18080",
    CODEGATE_WEB_DEVELOPMENT_IDENTITY: "true",
    CODEGATE_WEB_DEV_USER_ID: "user_dev",
  });

  assert.equal(config.keycloakUrl, "");
  assert.equal(config.developmentUserId, "user_dev");
});

test("fails closed for missing production identity or unsafe endpoints", () => {
  assert.throws(() => webRuntimeConfig({ CODEGATE_WEB_DEVELOPMENT_IDENTITY: "false" }));
  assert.throws(() => webRuntimeConfig({
    CODEGATE_WEB_API_URL: "//evil.example/api",
    CODEGATE_WEB_KEYCLOAK_URL: "https://identity.example.test",
    CODEGATE_WEB_DEVELOPMENT_IDENTITY: "false",
  }));
  assert.throws(() => webRuntimeConfig({
    CODEGATE_WEB_API_URL: "/api",
    CODEGATE_WEB_KEYCLOAK_URL: "https://user:secret@identity.example.test",
    CODEGATE_WEB_DEVELOPMENT_IDENTITY: "false",
  }));
});

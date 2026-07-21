import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { authenticateRequest, AuthenticationError, OidcVerifier, requireAnyRole } from "../src/index.ts";

const issuer = "https://id.example/realms/codegate";
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicJwk = publicKey.export({ format: "jwk" });

test("verifies a Keycloak-style RS256 token and extracts platform roles", async () => {
  const verifier = new OidcVerifier({
    issuer,
    audience: "codegate-api",
    clientId: "codegate-web",
    fetchImpl: async () => new Response(JSON.stringify({ keys: [{ ...publicJwk, kid: "key-1", alg: "RS256" }] }), { status: 200 }),
  });
  const token = jwt({
    sub: "user-1",
    iss: issuer,
    aud: "codegate-api",
    exp: Math.floor(Date.now() / 1000) + 300,
    email: "user@example.test",
    org_id: "org-security-lab",
    realm_access: { roles: ["org_member"] },
    resource_access: { "codegate-web": { roles: ["individual"] } },
  });
  const principal = await verifier.verify(token);
  assert.equal(principal.subject, "user-1");
  assert.deepEqual(principal.roles.sort(), ["individual", "org_member"]);
  assert.equal(principal.organizationId, "org-security-lab");
});

test("rejects an expired token", async () => {
  const verifier = new OidcVerifier({
    issuer,
    audience: "codegate-api",
    clientId: "codegate-web",
    clockToleranceSeconds: 0,
    fetchImpl: async () => new Response(JSON.stringify({ keys: [{ ...publicJwk, kid: "key-1", alg: "RS256" }] }), { status: 200 }),
  });
  await assert.rejects(() => verifier.verify(jwt({ sub: "user-1", iss: issuer, aud: "codegate-api", exp: 1 })), AuthenticationError);
});

test("dev identity headers are accepted only in explicit dev mode", async () => {
  const request = new Request("http://localhost", { headers: { "x-user-id": "user-dev", "x-dev-roles": "individual,org_admin" } });
  const principal = await authenticateRequest(request, { mode: "dev" });
  assert.deepEqual(principal.roles, ["individual", "org_admin"]);
  requireAnyRole(principal, ["org_admin"]);
});

function jwt(claims: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "key-1" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), privateKey).toString("base64url");
  return `${header}.${payload}.${signature}`;
}

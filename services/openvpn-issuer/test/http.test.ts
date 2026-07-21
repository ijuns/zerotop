import assert from "node:assert/strict";
import test from "node:test";

import { createIssuerHttpServer } from "../src/http.ts";
import type { GatewayBundle, IssuerOperations } from "../src/types.ts";

const internalToken = "issuer-internal-token-1234567890";
const bootstrapToken = "c".repeat(43);
const downloadTicket = "d".repeat(43);

const bundle: GatewayBundle = {
  version: 1,
  runId: "run-1",
  profileId: "vpn-profile-1",
  namespace: "range-run-1",
  expiresAt: "2026-07-21T02:00:00.000Z",
  files: {
    caCertificate: "ca",
    serverCertificate: "cert",
    serverPrivateKey: "key",
    tlsCryptKey: "tls",
    serverConfig: "config",
  },
  firewall: { vpnCidr: "10.203.0.0/24", allowedCidr: "10.42.0.0/16" },
};

test("HTTP service implements issue, bootstrap, download and revoke contracts", async () => {
  const calls: string[] = [];
  const operations: IssuerOperations = {
    async issue(input) {
      calls.push(`issue:${input.runId}`);
      return {
        profile: {
          profileId: "vpn-profile-1",
          endpoint: input.gatewayEndpoint,
          assignedIp: "10.203.0.2",
          allowedCidr: input.allowedCidr,
          expiresAt: input.expiresAt,
        },
        gatewayBootstrapToken: bootstrapToken,
      };
    },
    async revoke(runId) {
      calls.push(`revoke:${runId}`);
      return true;
    },
    async bootstrap(input) {
      calls.push(`bootstrap:${input.profileId}`);
      assert.equal(input.bootstrapToken, bootstrapToken);
      return bundle;
    },
    async download(ticket) {
      calls.push(`download:${ticket}`);
      return { profileId: "vpn-profile-1", profile: "client\ndev tun\n" };
    },
  };
  const server = createIssuerHttpServer({
    operations,
    issuerToken: internalToken,
    maxTtlMinutes: 240,
    allowedCidr: "10.42.0.0/16",
    clock: () => new Date("2026-07-21T00:00:00.000Z"),
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const base = `http://127.0.0.1:${address.port}`;

  try {
    const unauthorized = await fetch(`${base}/v1/profiles`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(unauthorized.status, 401);

    const issue = await fetch(`${base}/v1/profiles`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${internalToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        runId: "run-1",
        userId: "user-1",
        namespace: "range-run-1",
        expiresAt: "2026-07-21T02:00:00.000Z",
        gatewayEndpoint: "vpn-range-run-1.example.test:1194",
        allowedCidr: "10.42.0.0/16",
        isolationMode: "per_run_gateway",
        routes: [{ namespace: "range-run-1" }],
      }),
    });
    assert.equal(issue.status, 201);
    const issuePayload = (await issue.json()) as Record<string, unknown>;
    assert.equal(issuePayload.gatewayBootstrapToken, bootstrapToken);

    const bootstrap = await fetch(`${base}/v1/gateways/bootstrap`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        runId: "run-1",
        profileId: "vpn-profile-1",
        bootstrapToken,
      }),
    });
    assert.equal(bootstrap.status, 200);
    assert.equal(
      ((await bootstrap.json()) as { bundle: GatewayBundle }).bundle.runId,
      "run-1",
    );

    const download = await fetch(`${base}/download?ticket=${downloadTicket}`);
    assert.equal(download.status, 200);
    assert.equal(
      download.headers.get("content-type"),
      "application/x-openvpn-profile; charset=utf-8",
    );
    assert.match(
      String(download.headers.get("content-disposition")),
      /codegate-vpn-profile-1\.ovpn/,
    );
    assert.equal(await download.text(), "client\ndev tun\n");

    const revoke = await fetch(`${base}/v1/profiles/run-1`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${internalToken}` },
    });
    assert.equal(revoke.status, 204);
    assert.deepEqual(calls, [
      "issue:run-1",
      "bootstrap:vpn-profile-1",
      `download:${downloadTicket}`,
      "revoke:run-1",
    ]);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
});

import assert from "node:assert/strict";
import test from "node:test";

import { configureFirewall, fetchGatewayBundle } from "../src/gateway.ts";
import type { GatewayBundle } from "../src/types.ts";

const bundle: GatewayBundle = {
  version: 1,
  runId: "run-1",
  profileId: "vpn-profile-1",
  namespace: "range-run-1",
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
  files: {
    caCertificate: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
    serverCertificate: "-----BEGIN CERTIFICATE-----\nserver\n-----END CERTIFICATE-----",
    serverPrivateKey: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
    tlsCryptKey: "x".repeat(32),
    serverConfig: "dev tun\n",
  },
  firewall: { vpnCidr: "10.203.0.0/24", allowedCidr: "10.42.0.0/16" },
};

test("gateway bootstrap sends only its run-scoped restart credential", async () => {
  let received: unknown;
  const result = await fetchGatewayBundle(
    {
      issuerUrl: "http://openvpn-issuer:9100",
      runId: "run-1",
      profileId: "vpn-profile-1",
      bootstrapToken: "e".repeat(43),
    },
    async (_request, init) => {
      received = JSON.parse(String(init?.body));
      return Response.json({ bundle });
    },
  );
  assert.deepEqual(received, {
    runId: "run-1",
    profileId: "vpn-profile-1",
    bootstrapToken: "e".repeat(43),
  });
  assert.equal(result.profileId, "vpn-profile-1");
});

test("gateway firewall permits only tunnel-to-runtime traffic and return flow", async () => {
  const calls: Array<{ executable: string; args: string[] }> = [];
  await configureFirewall(
    bundle,
    async (executable, args) => {
      calls.push({ executable, args });
    },
    "/usr/sbin/iptables",
  );
  assert.ok(calls.every((item) => item.executable === "/usr/sbin/iptables"));
  const commands = calls.map((item) => item.args.join(" ")).join("\n");
  assert.match(commands, /-i tun0 -s 10\.203\.0\.0\/24 -d 10\.42\.0\.0\/16 -j ACCEPT/);
  assert.match(commands, /ESTABLISHED,RELATED -j ACCEPT/);
  assert.match(commands, /-i tun0 -j DROP/);
  assert.match(commands, /POSTROUTING[\s\S]+MASQUERADE/);
  assert.doesNotMatch(commands, /0\.0\.0\.0\/0/);
});

test("gateway firewall setup is restart-safe when chains and rules already exist", async () => {
  const calls: string[] = [];
  await configureFirewall(
    bundle,
    async (_executable, args) => {
      calls.push(args.join(" "));
      if (args.includes("-N")) throw new Error("chain exists");
    },
  );
  assert.ok(calls.some((command) => command.includes("-F CODEGATE_VPN")));
  assert.ok(calls.some((command) => command.includes("-C FORWARD")));
  assert.ok(calls.some((command) => command.includes("-t nat -C POSTROUTING")));
});

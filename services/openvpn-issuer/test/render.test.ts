import assert from "node:assert/strict";
import test from "node:test";

import { createGatewayBundle, renderClientProfile } from "../src/render.ts";
import type { CertificateMaterial, OpenVpnProfile } from "../src/types.ts";

const material: CertificateMaterial = {
  caCertificate: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n",
  tlsCryptKey: "-----BEGIN OpenVPN Static key V1-----\ntls-secret-material\n-----END OpenVPN Static key V1-----\n",
  clientCertificate: "-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----\n",
  clientPrivateKey: "-----BEGIN PRIVATE KEY-----\nclient-key\n-----END PRIVATE KEY-----\n",
  clientCommonName: "codegate-client-vpn-profile-1",
  serverCertificate: "-----BEGIN CERTIFICATE-----\nserver\n-----END CERTIFICATE-----\n",
  serverPrivateKey: "-----BEGIN PRIVATE KEY-----\nserver-key\n-----END PRIVATE KEY-----\n",
  serverCommonName: "codegate-server-vpn-profile-1",
};

const profile: OpenVpnProfile = {
  profileId: "vpn-profile-1",
  endpoint: "vpn-range-run-1.example.test:1194",
  assignedIp: "10.203.0.2",
  allowedCidr: "10.42.0.0/16",
  expiresAt: "2026-07-21T02:00:00.000Z",
};

test("client profile pins server identity and embeds all private material", () => {
  const rendered = renderClientProfile(profile, material);
  assert.match(rendered, /^client\n/);
  assert.match(rendered, /remote vpn-range-run-1\.example\.test 1194/);
  assert.match(rendered, /verify-x509-name codegate-server-vpn-profile-1 name/);
  assert.match(rendered, /route 10\.42\.0\.0 255\.255\.0\.0/);
  assert.match(rendered, /<tls-crypt>[\s\S]+OpenVPN Static key V1/);
  assert.doesNotMatch(rendered, /redirect-gateway/);
});

test("server bundle restricts one client certificate and one allowed CIDR", () => {
  const bundle = createGatewayBundle({
    runId: "run-1",
    profile,
    namespace: "range-run-1",
    vpnCidr: "10.203.0.0/24",
    material,
  });
  assert.equal(bundle.firewall.allowedCidr, "10.42.0.0/16");
  assert.match(bundle.files.serverConfig, /mode server\ntls-server/);
  assert.match(bundle.files.serverConfig, /ifconfig-pool 10\.203\.0\.2 10\.203\.0\.2/);
  assert.match(bundle.files.serverConfig, /verify-x509-name codegate-client-vpn-profile-1 name/);
  assert.doesNotMatch(bundle.files.serverConfig, /client-to-client/);
});

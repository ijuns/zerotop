import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";

import { BundleCipher } from "../src/crypto.ts";
import { OpenVpnProfileService, tokenHash } from "../src/service.ts";
import type {
  CertificateAuthority,
  ProfileRepository,
  StoredEncryptedBundle,
  StoredProfileInput,
  TicketExchanger,
} from "../src/types.ts";

const clock = () => new Date("2026-07-21T00:00:00.000Z");
const strongToken = "b".repeat(43);

class MemoryRepository implements ProfileRepository {
  stored: StoredProfileInput | null = null;
  async initialize(): Promise<void> {}
  async close(): Promise<void> {}
  async create(input: StoredProfileInput): Promise<void> {
    this.stored = input;
  }
  async revoke(): Promise<boolean> {
    return this.stored !== null;
  }
  async consumeGatewayBootstrap(
    runId: string,
    profileId: string,
    hash: string,
  ): Promise<StoredEncryptedBundle | null> {
    if (
      !this.stored ||
      this.stored.runId !== runId ||
      this.stored.profileId !== profileId ||
      this.stored.bootstrapTokenHash !== hash
    ) {
      return null;
    }
    return {
      runId,
      profileId,
      encryptedBundle: this.stored.encryptedServerBundle,
    };
  }
  async getActiveClientBundle(
    runId: string,
    profileId: string,
  ): Promise<StoredEncryptedBundle | null> {
    return this.stored?.runId === runId && this.stored.profileId === profileId
      ? {
          runId,
          profileId,
          encryptedBundle: this.stored.encryptedClientBundle,
        }
      : null;
  }
}

const certificateAuthority: CertificateAuthority = {
  async issue() {
    return {
      caCertificate: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
      tlsCryptKey: "-----BEGIN OpenVPN Static key V1-----\nsecret-material-1234567890\n-----END OpenVPN Static key V1-----",
      clientCertificate: "-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----",
      clientPrivateKey: "-----BEGIN PRIVATE KEY-----\nclient-secret\n-----END PRIVATE KEY-----",
      clientCommonName: "codegate-client-vpn-profile-1",
      serverCertificate: "-----BEGIN CERTIFICATE-----\nserver\n-----END CERTIFICATE-----",
      serverPrivateKey: "-----BEGIN PRIVATE KEY-----\nserver-secret\n-----END PRIVATE KEY-----",
      serverCommonName: "codegate-server-vpn-profile-1",
    };
  },
};

test("service stores encrypted bundles and permits a scoped gateway restart bootstrap", async () => {
  const repository = new MemoryRepository();
  const ticketExchanger: TicketExchanger = {
    exchange: async () => ({ runId: "run-1", profileId: "vpn-profile-1" }),
  };
  const service = new OpenVpnProfileService({
    repository,
    certificateAuthority,
    cipher: new BundleCipher(randomBytes(32)),
    ticketExchanger,
    vpnCidr: "10.203.0.0/24",
    clock,
    idFactory: () => "vpn-profile-1",
    tokenFactory: () => strongToken,
  });
  const provision = await service.issue({
    runId: "run-1",
    userId: "user-1",
    namespace: "range-run-1",
    expiresAt: "2026-07-21T02:00:00.000Z",
    gatewayEndpoint: "vpn-range-run-1.example.test:1194",
    isolationMode: "per_run_gateway",
    routes: [{ namespace: "range-run-1" }],
    allowedCidr: "10.42.0.0/16",
  });
  assert.equal(provision.gatewayBootstrapToken, strongToken);
  assert.equal(repository.stored?.bootstrapTokenHash, tokenHash(strongToken));
  assert.notEqual(repository.stored?.bootstrapTokenHash, strongToken);
  assert.doesNotMatch(JSON.stringify(repository.stored), /client-secret|server-secret/);

  const bundle = await service.bootstrap({
    runId: "run-1",
    profileId: "vpn-profile-1",
    bootstrapToken: strongToken,
  });
  assert.equal(bundle.namespace, "range-run-1");
  const restartedBundle = await service.bootstrap({
    runId: "run-1",
    profileId: "vpn-profile-1",
    bootstrapToken: strongToken,
  });
  assert.equal(restartedBundle.profileId, "vpn-profile-1");

  const download = await service.download("download-ticket");
  assert.equal(download.profileId, "vpn-profile-1");
  assert.match(download.profile, /<key>[\s\S]+client-secret/);
});

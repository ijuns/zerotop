import { createHash, randomBytes, randomUUID } from "node:crypto";

import {
  bundleAssociatedData,
  BundleCipher,
} from "./crypto.ts";
import { ServiceError } from "./errors.ts";
import { cidrsOverlap, parseIpv4Cidr } from "./network.ts";
import { createGatewayBundle, renderClientProfile } from "./render.ts";
import type {
  BootstrapRequest,
  CertificateAuthority,
  GatewayBundle,
  IssueProfileRequest,
  IssuerOperations,
  OpenVpnProfile,
  ProfileRepository,
  TicketExchanger,
} from "./types.ts";

interface OpenVpnProfileServiceOptions {
  repository: ProfileRepository;
  certificateAuthority: CertificateAuthority;
  cipher: BundleCipher;
  ticketExchanger: TicketExchanger;
  vpnCidr: string;
  clock?: () => Date;
  idFactory?: () => string;
  tokenFactory?: () => string;
}

export class OpenVpnProfileService implements IssuerOperations {
  private readonly repository: ProfileRepository;
  private readonly certificateAuthority: CertificateAuthority;
  private readonly cipher: BundleCipher;
  private readonly ticketExchanger: TicketExchanger;
  private readonly vpnCidr: string;
  private readonly assignedIp: string;
  private readonly clock: () => Date;
  private readonly idFactory: () => string;
  private readonly tokenFactory: () => string;

  constructor(options: OpenVpnProfileServiceOptions) {
    this.repository = options.repository;
    this.certificateAuthority = options.certificateAuthority;
    this.cipher = options.cipher;
    this.ticketExchanger = options.ticketExchanger;
    const vpn = parseIpv4Cidr(options.vpnCidr, "OPENVPN_CLIENT_CIDR");
    this.vpnCidr = vpn.cidr;
    this.assignedIp = vpn.secondHost;
    this.clock = options.clock ?? (() => new Date());
    this.idFactory = options.idFactory ?? (() => `vpn-${randomUUID()}`);
    this.tokenFactory =
      options.tokenFactory ?? (() => randomBytes(32).toString("base64url"));
  }

  async issue(input: IssueProfileRequest): Promise<{
    profile: OpenVpnProfile;
    gatewayBootstrapToken: string;
  }> {
    const allowed = parseIpv4Cidr(input.allowedCidr, "allowedCidr");
    const vpn = parseIpv4Cidr(this.vpnCidr, "OPENVPN_CLIENT_CIDR");
    if (cidrsOverlap(allowed, vpn)) {
      throw new ServiceError(
        500,
        "network_policy_invalid",
        "The OpenVPN client CIDR overlaps the allowed runtime CIDR.",
      );
    }
    const profileId = this.idFactory();
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(profileId)) {
      throw new Error("The generated profile ID is invalid.");
    }
    const gatewayBootstrapToken = this.tokenFactory();
    if (!/^[A-Za-z0-9_-]{43,128}$/.test(gatewayBootstrapToken)) {
      throw new Error("The generated bootstrap token is invalid.");
    }
    const profile: OpenVpnProfile = {
      profileId,
      endpoint: input.gatewayEndpoint,
      assignedIp: this.assignedIp,
      allowedCidr: allowed.cidr,
      expiresAt: input.expiresAt,
    };
    const material = await this.certificateAuthority.issue(
      profileId,
      input.expiresAt,
    );
    const clientProfile = renderClientProfile(profile, material);
    const gatewayBundle = createGatewayBundle({
      runId: input.runId,
      profile,
      namespace: input.namespace,
      vpnCidr: this.vpnCidr,
      material,
    });
    const createdAt = this.clock().toISOString();
    await this.repository.create({
      runId: input.runId,
      profileId,
      userId: input.userId,
      namespace: input.namespace,
      endpoint: profile.endpoint,
      assignedIp: profile.assignedIp,
      allowedCidr: profile.allowedCidr,
      expiresAt: profile.expiresAt,
      encryptedClientBundle: this.cipher.encrypt(
        { profile: clientProfile },
        bundleAssociatedData("client", input.runId, profileId),
      ),
      encryptedServerBundle: this.cipher.encrypt(
        gatewayBundle,
        bundleAssociatedData("server", input.runId, profileId),
      ),
      bootstrapTokenHash: tokenHash(gatewayBootstrapToken),
      createdAt,
    });
    return { profile, gatewayBootstrapToken };
  }

  revoke(runId: string): Promise<boolean> {
    return this.repository.revoke(runId, this.clock().toISOString());
  }

  async bootstrap(input: BootstrapRequest): Promise<GatewayBundle> {
    const encrypted = await this.repository.consumeGatewayBootstrap(
      input.runId,
      input.profileId,
      tokenHash(input.bootstrapToken),
      this.clock().toISOString(),
    );
    if (!encrypted) {
      throw new ServiceError(
        410,
        "bootstrap_unavailable",
        "The gateway bootstrap credential is invalid, expired or revoked.",
      );
    }
    return this.cipher.decrypt<GatewayBundle>(
      encrypted.encryptedBundle,
      bundleAssociatedData("server", input.runId, input.profileId),
    );
  }

  async download(ticket: string): Promise<{ profileId: string; profile: string }> {
    const access = await this.ticketExchanger.exchange(ticket);
    const encrypted = await this.repository.getActiveClientBundle(
      access.runId,
      access.profileId,
      this.clock().toISOString(),
    );
    if (!encrypted) {
      throw new ServiceError(
        410,
        "profile_unavailable",
        "The OpenVPN profile is revoked, expired or does not match this run.",
      );
    }
    const bundle = this.cipher.decrypt<{ profile: unknown }>(
      encrypted.encryptedBundle,
      bundleAssociatedData("client", access.runId, access.profileId),
    );
    if (typeof bundle.profile !== "string" || !bundle.profile.startsWith("client\n")) {
      throw new ServiceError(
        500,
        "profile_bundle_invalid",
        "The encrypted OpenVPN profile bundle is invalid.",
      );
    }
    return { profileId: access.profileId, profile: bundle.profile };
  }
}

export function tokenHash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

import type { EncryptedPayload } from "./crypto.ts";

export interface OpenVpnProfile {
  profileId: string;
  endpoint: string;
  assignedIp: string;
  allowedCidr: string;
  expiresAt: string;
}

export interface IssueProfileRequest {
  runId: string;
  userId: string;
  namespace: string;
  expiresAt: string;
  gatewayEndpoint: string;
  isolationMode: "per_run_gateway";
  routes: [{ namespace: string }];
  allowedCidr: string;
}

export interface BootstrapRequest {
  runId: string;
  profileId: string;
  bootstrapToken: string;
}

export interface GatewayBundle {
  version: 1;
  runId: string;
  profileId: string;
  namespace: string;
  expiresAt: string;
  files: {
    caCertificate: string;
    serverCertificate: string;
    serverPrivateKey: string;
    tlsCryptKey: string;
    serverConfig: string;
  };
  firewall: {
    vpnCidr: string;
    allowedCidr: string;
  };
}

export interface StoredProfileInput {
  runId: string;
  profileId: string;
  userId: string;
  namespace: string;
  endpoint: string;
  assignedIp: string;
  allowedCidr: string;
  expiresAt: string;
  encryptedClientBundle: EncryptedPayload;
  encryptedServerBundle: EncryptedPayload;
  bootstrapTokenHash: string;
  createdAt: string;
}

export interface StoredEncryptedBundle {
  runId: string;
  profileId: string;
  encryptedBundle: EncryptedPayload;
}

export interface ProfileRepository {
  initialize(): Promise<void>;
  close(): Promise<void>;
  create(input: StoredProfileInput): Promise<void>;
  revoke(runId: string, revokedAt: string): Promise<boolean>;
  consumeGatewayBootstrap(
    runId: string,
    profileId: string,
    bootstrapTokenHash: string,
    consumedAt: string,
  ): Promise<StoredEncryptedBundle | null>;
  getActiveClientBundle(
    runId: string,
    profileId: string,
    accessedAt: string,
  ): Promise<StoredEncryptedBundle | null>;
}

export interface CertificateMaterial {
  caCertificate: string;
  tlsCryptKey: string;
  clientCertificate: string;
  clientPrivateKey: string;
  clientCommonName: string;
  serverCertificate: string;
  serverPrivateKey: string;
  serverCommonName: string;
}

export interface CertificateAuthority {
  issue(profileId: string, expiresAt: string): Promise<CertificateMaterial>;
}

export interface TicketAccess {
  runId: string;
  profileId: string;
}

export interface TicketExchanger {
  exchange(ticket: string): Promise<TicketAccess>;
}

export interface IssuerOperations {
  issue(input: IssueProfileRequest): Promise<{
    profile: OpenVpnProfile;
    gatewayBootstrapToken: string;
  }>;
  revoke(runId: string): Promise<boolean>;
  bootstrap(input: BootstrapRequest): Promise<GatewayBundle>;
  download(ticket: string): Promise<{ profileId: string; profile: string }>;
}

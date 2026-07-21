export type DesktopImage = "ubuntu" | "kali";
export type AccessMethod = "browser_desktop" | "openvpn" | "both";
export type TargetProtocol = "http" | "tcp";

export interface TargetService {
  port: number;
  protocol: TargetProtocol;
}

export interface TargetRuntimeContract {
  kind: "http-v1";
  uid: 65532;
  gid: 65532;
  protocol: "http";
  port: 8080;
  writablePaths: ["/tmp"];
  readOnlyRootFilesystem: true;
  bindAddress: "0.0.0.0";
  healthPath: "/health";
  fingerprintPath: "/version";
}

export interface ProvisionRunRequest {
  runId: string;
  labId: string;
  userId: string;
  desktopImage: DesktopImage;
  accessMethod: AccessMethod;
  ttlMinutes: number;
  targetImage: string;
  targetService: TargetService;
  targetRuntimeContract: TargetRuntimeContract;
}

export interface ProvisionedRun {
  id: string;
  status: "provisioning" | "ready";
  namespace: string;
  expiresAt: string;
  browserDesktop?: {
    gatewayPath: string;
    protocol: "websocket";
  };
  openVpn?: {
    profileId: string;
    endpoint: string;
    assignedIp: string;
    allowedCidr: string;
    expiresAt: string;
  };
}

export interface RuntimeReadinessChecks {
  workstationVmi: boolean;
  targetWorkload: boolean;
  desktopEndpoints?: boolean;
  vpnPod?: boolean;
  vpnService?: boolean;
}

export interface RuntimeRunStatus {
  id: string;
  status: "provisioning" | "ready" | "failed";
  namespace: string;
  expiresAt: string;
  checks: RuntimeReadinessChecks;
  reason?: string;
}

export interface RuntimeAdapter {
  provision(request: ProvisionRunRequest): Promise<ProvisionedRun>;
  get(runId: string): Promise<RuntimeRunStatus>;
  destroy(runId: string): Promise<void>;
}

export type TargetProtocol = "http" | "tcp";

export interface HttpProbe {
  id: string;
  kind: "http";
  method: "GET" | "HEAD";
  path: string;
  expectedStatuses: number[];
  bodyIncludes: string[];
  cveId?: string;
  findingId?: string;
}

export interface TcpBannerProbe {
  id: string;
  kind: "tcp_banner";
  bannerIncludes: string[];
  cveId?: string;
  findingId?: string;
}

export type TargetProbe = HttpProbe | TcpBannerProbe;

export interface IsolationEndpoint {
  host: string;
  port: number;
}

export interface ProbePlan {
  schemaVersion: 1;
  target: {
    host: "target";
    port: number;
    protocol: TargetProtocol;
  };
  functionalProbes: TargetProbe[];
  vulnerabilityProbes: TargetProbe[];
  isolation: {
    external: IsolationEndpoint;
    controlPlane: IsolationEndpoint;
    crossRun: IsolationEndpoint;
  };
  requestTimeoutMs: number;
}

export interface ProbeObservation {
  id: string;
  passed: boolean;
  status?: number;
  matched?: string[];
  missing?: string[];
  error?: string;
  cveId?: string;
  findingId?: string;
}

export interface ProbeResult {
  schemaVersion: 1;
  functional: ProbeObservation[];
  vulnerability: ProbeObservation[];
  network: {
    egressBlocked: boolean;
    controlPlaneBlocked: boolean;
    crossRunBlocked: boolean;
  };
  completedAt: string;
}

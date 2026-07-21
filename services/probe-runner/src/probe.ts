import { createConnection } from "node:net";
import type { ProbeObservation, ProbePlan, ProbeResult, TargetProbe } from "./contracts.ts";

export interface ProbeDependencies {
  fetchImpl?: typeof fetch;
  connect?: (host: string, port: number, timeoutMs: number, readBanner: boolean) => Promise<{ connected: boolean; banner: string }>;
  now?: () => Date;
}

export async function executeProbePlan(plan: ProbePlan, dependencies: ProbeDependencies = {}): Promise<ProbeResult> {
  const fetchImpl = dependencies.fetchImpl ?? fetch;
  const connect = dependencies.connect ?? connectTcp;
  const run = (probe: TargetProbe) => executeTargetProbe(plan, probe, fetchImpl, connect);
  const [functional, vulnerability, external, controlPlane, crossRun] = await Promise.all([
    Promise.all(plan.functionalProbes.map(run)),
    Promise.all(plan.vulnerabilityProbes.map(run)),
    connect(plan.isolation.external.host, plan.isolation.external.port, plan.requestTimeoutMs, false),
    connect(plan.isolation.controlPlane.host, plan.isolation.controlPlane.port, plan.requestTimeoutMs, false),
    connect(plan.isolation.crossRun.host, plan.isolation.crossRun.port, plan.requestTimeoutMs, false),
  ]);
  return {
    schemaVersion: 1,
    functional,
    vulnerability,
    network: {
      egressBlocked: !external.connected,
      controlPlaneBlocked: !controlPlane.connected,
      crossRunBlocked: !crossRun.connected,
    },
    completedAt: (dependencies.now?.() ?? new Date()).toISOString(),
  };
}

async function executeTargetProbe(
  plan: ProbePlan,
  probe: TargetProbe,
  fetchImpl: typeof fetch,
  connect: NonNullable<ProbeDependencies["connect"]>,
): Promise<ProbeObservation> {
  if (probe.kind === "tcp_banner") {
    try {
      const result = await connect(plan.target.host, plan.target.port, plan.requestTimeoutMs, true);
      const matched = probe.bannerIncludes.filter((marker) => result.banner.includes(marker));
      const missing = probe.bannerIncludes.filter((marker) => !result.banner.includes(marker));
      return observation(probe, result.connected && missing.length === 0, { matched, missing });
    } catch (error) {
      return observation(probe, false, { error: safeError(error) });
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), plan.requestTimeoutMs);
  try {
    const response = await fetchImpl(`http://${plan.target.host}:${plan.target.port}${probe.path}`, {
      method: probe.method,
      redirect: "manual",
      signal: controller.signal,
      headers: { accept: "*/*", "user-agent": "CODEGATE-Sandbox-Probe/1.0" },
    });
    const body = probe.method === "HEAD" ? "" : await limitedText(response, 65_536);
    const matched = probe.bodyIncludes.filter((marker) => body.includes(marker));
    const missing = probe.bodyIncludes.filter((marker) => !body.includes(marker));
    const passed = probe.expectedStatuses.includes(response.status) && missing.length === 0;
    return observation(probe, passed, { status: response.status, matched, missing });
  } catch (error) {
    return observation(probe, false, { error: safeError(error) });
  } finally {
    clearTimeout(timer);
  }
}

function observation(
  probe: TargetProbe,
  passed: boolean,
  details: Omit<ProbeObservation, "id" | "passed" | "cveId" | "findingId">,
): ProbeObservation {
  return {
    id: probe.id,
    passed,
    ...(probe.cveId ? { cveId: probe.cveId } : {}),
    ...(probe.findingId ? { findingId: probe.findingId } : {}),
    ...details,
  };
}

async function limitedText(response: Response, maximumBytes: number): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maximumBytes) throw new Error("Target response exceeded the validation limit");
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(body);
}

async function connectTcp(host: string, port: number, timeoutMs: number, readBanner: boolean): Promise<{ connected: boolean; banner: string }> {
  return await new Promise((resolve) => {
    let settled = false;
    let banner = "";
    const socket = createConnection({ host, port });
    const finish = (connected: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ connected, banner });
    };
    socket.setTimeout(timeoutMs);
    socket.on("connect", () => {
      if (!readBanner) return finish(true);
      setTimeout(() => finish(true), Math.min(timeoutMs, 750));
    });
    socket.on("data", (chunk: Buffer) => {
      banner += chunk.toString("utf8");
      if (Buffer.byteLength(banner) >= 8_192) finish(true);
    });
    socket.on("timeout", () => finish(readBanner && socket.readyState === "open"));
    socket.on("error", () => finish(false));
    socket.on("close", () => finish(socket.readyState === "open" || banner.length > 0));
  });
}

function safeError(error: unknown): string {
  const value = error instanceof Error ? error.name : "ProbeError";
  return value.slice(0, 80);
}

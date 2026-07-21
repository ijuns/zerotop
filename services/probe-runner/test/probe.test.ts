import assert from "node:assert/strict";
import test from "node:test";
import { executeProbePlan } from "../src/probe.ts";
import { parseProbePlan } from "../src/validation.ts";

const planValue = {
  schemaVersion: 1,
  target: { host: "target", port: 8080, protocol: "http" },
  functionalProbes: [{ id: "health", kind: "http", method: "GET", path: "/health", expectedStatuses: [200], bodyIncludes: ["ready"] }],
  vulnerabilityProbes: [{ id: "cve-fingerprint", cveId: "CVE-2025-12345", kind: "http", method: "GET", path: "/version", expectedStatuses: [200], bodyIncludes: ["1.2.3"] }],
  isolation: {
    external: { host: "1.1.1.1", port: 443 },
    controlPlane: { host: "10.43.0.1", port: 443 },
    crossRun: { host: "10.43.22.7", port: 8080 },
  },
  requestTimeoutMs: 1000,
};

test("executes bounded target probes and confirms all three blocked paths", async () => {
  const plan = parseProbePlan(planValue);
  const result = await executeProbePlan(plan, {
    fetchImpl: async (input) => {
      const url = String(input);
      return new Response(url.endsWith("/health") ? "ready" : "version=1.2.3", { status: 200 });
    },
    connect: async () => ({ connected: false, banner: "" }),
    now: () => new Date("2026-07-21T00:00:00.000Z"),
  });
  assert.equal(result.functional[0]?.passed, true);
  assert.equal(result.vulnerability[0]?.passed, true);
  assert.deepEqual(result.network, { egressBlocked: true, controlPlaneBlocked: true, crossRunBlocked: true });
});

test("treats any reachable isolation endpoint as a failed isolation check", async () => {
  const plan = parseProbePlan(planValue);
  const result = await executeProbePlan(plan, {
    fetchImpl: async () => new Response("ready 1.2.3", { status: 200 }),
    connect: async (host) => ({ connected: host === "10.43.0.1", banner: "" }),
  });
  assert.equal(result.network.controlPlaneBlocked, false);
});

test("rejects absolute URLs and protocol-changing probes", () => {
  assert.throws(() => parseProbePlan({
    ...planValue,
    functionalProbes: [{ ...planValue.functionalProbes[0], path: "http://attacker.invalid/" }],
  }), /safe relative path/);
  assert.throws(() => parseProbePlan({
    ...planValue,
    target: { ...planValue.target, protocol: "tcp" },
  }), /does not match/);
});

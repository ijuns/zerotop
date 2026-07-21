import assert from "node:assert/strict";
import test from "node:test";

import {
  KubeVirtRuntimeAdapter,
  RuntimeRunNotFoundError,
  type KubernetesApplier,
  type KubernetesRunInspection,
} from "../src/adapter.ts";
import type { KubernetesObject } from "../src/manifests.ts";
import type { OpenVpnIssuer } from "../src/openvpn.ts";

const issuer: OpenVpnIssuer = {
  async issue() {
    throw new Error("not used");
  },
  async revoke() {},
};

test("marks a KubeVirt run ready only when all required checks pass", async () => {
  const adapter = runtimeWithInspection({
    expiresAt: "2026-07-21T12:00:00.000Z",
    readinessDeadline: "2099-07-21T10:10:00.000Z",
    checks: {
      workstationVmi: true,
      targetWorkload: true,
      desktopEndpoints: true,
      vpnPod: true,
      vpnService: true,
    },
  });

  const result = await adapter.get("run-1");
  assert.equal(result.status, "ready");
  assert.equal(result.reason, undefined);
});

test("keeps an incomplete run provisioning before its bounded deadline", async () => {
  const adapter = runtimeWithInspection({
    expiresAt: "2099-07-21T12:00:00.000Z",
    readinessDeadline: "2099-07-21T10:10:00.000Z",
    checks: { workstationVmi: true, targetWorkload: false },
  });

  const result = await adapter.get("run-2");
  assert.equal(result.status, "provisioning");
});

test("fails an incomplete run after its deadline instead of provisioning forever", async () => {
  const adapter = runtimeWithInspection({
    expiresAt: "2026-07-21T12:00:00.000Z",
    readinessDeadline: "2000-01-01T00:00:00.000Z",
    checks: { workstationVmi: false, targetWorkload: false },
  });

  const result = await adapter.get("run-3");
  assert.equal(result.status, "failed");
  assert.match(result.reason ?? "", /deadline/);
});

test("surfaces a missing run namespace as not found", async () => {
  const adapter = runtimeWithInspection(null);
  await assert.rejects(() => adapter.get("run-missing"), RuntimeRunNotFoundError);
});

function runtimeWithInspection(inspection: KubernetesRunInspection | null): KubeVirtRuntimeAdapter {
  const kubernetes: KubernetesApplier = {
    async apply(_resource: KubernetesObject) {},
    async inspectRun() {
      return inspection;
    },
    async deleteNamespace() {},
  };
  return new KubeVirtRuntimeAdapter(
    kubernetes,
    issuer,
    { ubuntuDesktop: "registry.example/ubuntu", kaliDesktop: "registry.example/kali" },
    {
      image: `registry.example/openvpn@sha256:${"a".repeat(64)}`,
      baseDomain: "vpn.example.invalid",
      issuerUrl: "http://issuer:9100",
      allowedCidr: "10.42.0.0/16",
    },
  );
}

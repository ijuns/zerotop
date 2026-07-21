import assert from "node:assert/strict";
import test from "node:test";
import { KubernetesHttpApplier, resourcePath } from "../src/kubernetes-http.ts";

test("builds core and namespaced Kubernetes API paths", () => {
  assert.equal(resourcePath({ apiVersion: "v1", kind: "Namespace", metadata: { name: "range-run-1" } }), "/api/v1/namespaces/range-run-1");
  assert.equal(resourcePath({ apiVersion: "v1", kind: "Service", metadata: { name: "desktop", namespace: "range-run-1" } }), "/api/v1/namespaces/range-run-1/services/desktop");
  assert.equal(resourcePath({ apiVersion: "v1", kind: "ServiceAccount", metadata: { name: "default", namespace: "range-run-1" } }), "/api/v1/namespaces/range-run-1/serviceaccounts/default");
});

test("builds networking and KubeVirt API paths", () => {
  assert.equal(resourcePath({ apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name: "default-deny", namespace: "range-run-1" } }), "/apis/networking.k8s.io/v1/namespaces/range-run-1/networkpolicies/default-deny");
  assert.equal(resourcePath({ apiVersion: "kubevirt.io/v1", kind: "VirtualMachine", metadata: { name: "workstation", namespace: "range-run-1" } }), "/apis/kubevirt.io/v1/namespaces/range-run-1/virtualmachines/workstation");
});

test("builds the per-run gateway Deployment API path", () => {
  assert.equal(
    resourcePath({ apiVersion: "apps/v1", kind: "Deployment", metadata: { name: "openvpn-gateway", namespace: "range-run-1" } }),
    "/apis/apps/v1/namespaces/range-run-1/deployments/openvpn-gateway",
  );
});

test("inspects every access-dependent readiness signal", async () => {
  const responses = new Map<string, unknown>([
    ["/api/v1/namespaces/range-run-1", {
      metadata: { annotations: {
        "codegate.ai/access-method": "both",
        "codegate.ai/expires-at": "2026-07-21T12:00:00.000Z",
        "codegate.ai/readiness-deadline": "2026-07-21T10:10:00.000Z",
      } },
    }],
    ["/apis/kubevirt.io/v1/namespaces/range-run-1/virtualmachineinstances/workstation", readyVmi()],
    ["/apis/apps/v1/namespaces/range-run-1/deployments/target", readyDeployment()],
    ["/api/v1/namespaces/range-run-1/endpoints/desktop", { subsets: [{ addresses: [{ ip: "10.42.1.10" }] }] }],
    ["/api/v1/namespaces/range-run-1/pods?labelSelector=codegate.ai%2Frole%3Dvpn-gateway", {
      items: [{ metadata: {}, status: { phase: "Running", conditions: [{ type: "Ready", status: "True" }] } }],
    }],
    ["/api/v1/namespaces/range-run-1/services/openvpn-gateway", {
      spec: { clusterIP: "10.43.4.12" },
      status: { loadBalancer: { ingress: [{ ip: "192.0.2.44" }] } },
    }],
  ]);
  const requested: string[] = [];
  const client = new KubernetesHttpApplier({
    baseUrl: "https://kubernetes.default.svc",
    bearerToken: "test-token",
    fetchImpl: async (input) => {
      const url = new URL(String(input));
      requested.push(`${url.pathname}${url.search}`);
      const body = responses.get(`${url.pathname}${url.search}`);
      return body
        ? new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } })
        : new Response("not found", { status: 404 });
    },
  });

  const result = await client.inspectRun("range-run-1");
  assert.deepEqual(result?.checks, {
    workstationVmi: true,
    targetWorkload: true,
    desktopEndpoints: true,
    vpnPod: true,
    vpnService: true,
  });
  assert.equal(requested.length, 6);
});

test("inspects validation target Deployment readiness and failure", async () => {
  const responses = new Map<string, unknown>([
    ["/api/v1/namespaces/validation-1", { metadata: {} }],
    ["/apis/apps/v1/namespaces/validation-1/deployments/target", {
      metadata: { generation: 2 },
      status: {
        observedGeneration: 2,
        availableReplicas: 0,
        conditions: [{ type: "Progressing", status: "False", reason: "ProgressDeadlineExceeded" }],
      },
    }],
    ["/apis/batch/v1/namespaces/validation-1/jobs/sandbox-probe", {}],
    ["/api/v1/namespaces/validation-1/pods?labelSelector=job-name%3Dsandbox-probe", { items: [] }],
  ]);
  const client = new KubernetesHttpApplier({
    baseUrl: "https://kubernetes.default.svc",
    bearerToken: "test-token",
    fetchImpl: async (input) => {
      const url = new URL(String(input));
      const body = responses.get(`${url.pathname}${url.search}`);
      return body !== undefined
        ? Response.json(body)
        : new Response("not found", { status: 404 });
    },
  });
  const result = await client.inspectValidation("validation-1");
  assert.equal(result?.targetReady, false);
  assert.equal(result?.targetFailed, true);
  assert.match(result?.failureReason ?? "", /Deployment failed/);
});

test("returns null when the run namespace no longer exists", async () => {
  const client = new KubernetesHttpApplier({
    baseUrl: "https://kubernetes.default.svc",
    bearerToken: "test-token",
    fetchImpl: async () => new Response("not found", { status: 404 }),
  });
  assert.equal(await client.inspectRun("range-missing"), null);
});

test("requires an actual ready endpoint behind the cross-run canary Service", async () => {
  const client = new KubernetesHttpApplier({
    baseUrl: "https://kubernetes.default.svc",
    bearerToken: "test-token",
    fetchImpl: async (input) => {
      const url = new URL(String(input));
      const value = url.pathname.endsWith("/endpoints/validation-canary")
        ? { subsets: [{ addresses: [{ ip: "10.42.8.10" }] }] }
        : {};
      return new Response(JSON.stringify(value), { status: 200 });
    },
  });
  assert.equal(await client.serviceHasReadyEndpoints("codegate-runtime-system", "validation-canary"), true);
});

function readyVmi(): unknown {
  return { status: { phase: "Running", conditions: [{ type: "Ready", status: "True" }] } };
}

function readyDeployment(): unknown {
  return {
    metadata: { generation: 1 },
    status: {
      observedGeneration: 1,
      availableReplicas: 1,
      conditions: [{ type: "Available", status: "True" }],
    },
  };
}

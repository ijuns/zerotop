import assert from "node:assert/strict";
import test from "node:test";
import { buildRunResources } from "../src/manifests.ts";

const request = {
  runId: "run-47a2",
  labId: "lab-webshell",
  userId: "user-1",
  desktopImage: "ubuntu" as const,
  accessMethod: "both" as const,
  ttlMinutes: 70,
  targetImage: `registry.example/targets/webshell@sha256:${"a".repeat(64)}`,
  targetService: { port: 8080, protocol: "http" as const },
  targetRuntimeContract: {
    kind: "http-v1" as const, uid: 65532 as const, gid: 65532 as const,
    protocol: "http" as const, port: 8080 as const, writablePaths: ["/tmp"] as ["/tmp"],
    readOnlyRootFilesystem: true as const, bindAddress: "0.0.0.0" as const,
    healthPath: "/health" as const, fingerprintPath: "/version" as const,
  },
};
const images = { ubuntuDesktop: "registry.example/workstations/ubuntu:24.04", kaliDesktop: "registry.example/workstations/kali:2026.2" };
const openVpnGateway = {
  image: `registry.example/openvpn/gateway@sha256:${"b".repeat(64)}`,
  issuerUrl: "http://openvpn-issuer.codegate-vpn-system.svc.cluster.local:9100",
  hostname: "vpn-range-run-47a2.vpn-runs.example.invalid",
  provision: {
    profile: {
      profileId: "profile-run-47a2",
      endpoint: "vpn-range-run-47a2.vpn-runs.example.invalid:1194",
      assignedIp: "10.203.0.42",
      allowedCidr: "10.42.0.0/16",
      expiresAt: "2026-07-21T10:00:00.000Z",
    },
    gatewayBootstrapToken: "bootstrap-token-that-is-longer-than-thirty-two-characters",
  },
};

test("creates a KubeVirt-compatible namespace without learner API credentials", () => {
  const resources = buildRunResources(request, images, openVpnGateway);
  const namespace = resources.find((item) => item.kind === "Namespace");
  assert.equal(namespace?.metadata.name, "range-run-47a2");
  assert.equal(namespace?.metadata.labels?.["pod-security.kubernetes.io/enforce"], "privileged");
  assert.equal(namespace?.metadata.labels?.["pod-security.kubernetes.io/audit"], "restricted");
  assert.ok(namespace?.metadata.annotations?.["codegate.ai/expires-at"]);
  assert.ok(namespace?.metadata.annotations?.["codegate.ai/readiness-deadline"]);
  assert.equal(namespace?.metadata.annotations?.["codegate.ai/access-method"], "both");
  const serviceAccount = resources.find(
    (item) => item.kind === "ServiceAccount" && item.metadata.name === "default",
  );
  assert.equal((serviceAccount as any)?.automountServiceAccountToken, false);
  assert.equal(resources.some((item) => item.kind === "RoleBinding"), false);
});

test("allows only workstation and VPN clients to the target port and blocks target-initiated egress", () => {
  const resources = buildRunResources(request, images, openVpnGateway);
  const policies = resources.filter((item) => item.kind === "NetworkPolicy");
  assert.deepEqual(policies.map((item) => item.metadata.name).sort(), [
    "allow-desktop-gateway",
    "allow-dns",
    "allow-target-from-clients",
    "allow-vpn-bootstrap",
    "allow-vpn-public",
    "allow-vpn-to-target",
    "allow-workstation-to-target",
    "default-deny",
  ]);
  const deny = policies.find((item) => item.metadata.name === "default-deny");
  assert.deepEqual((deny?.spec as { policyTypes: string[] }).policyTypes, ["Ingress", "Egress"]);
  const targetIngress = policies.find((item) => item.metadata.name === "allow-target-from-clients");
  const ingress = (targetIngress?.spec as any).ingress[0];
  assert.deepEqual(
    ingress.from.map((peer: any) => peer.podSelector.matchLabels["codegate.ai/role"]),
    ["workstation", "vpn-gateway"],
  );
  assert.equal(ingress.ports[0].port, request.targetService.port);
  assert.equal((targetIngress?.spec as any).egress, undefined);
  const targetSelectedEgressPolicies = policies.filter((item) => {
    const spec = item.spec as any;
    return spec.policyTypes?.includes("Egress") &&
      spec.podSelector?.matchLabels?.["codegate.ai/role"] === "target";
  });
  assert.equal(targetSelectedEgressPolicies.length, 0);
  const dns = policies.find((item) => item.metadata.name === "allow-dns");
  assert.deepEqual((dns?.spec as any).podSelector.matchExpressions[0].values, ["workstation", "vpn-gateway"]);
});

test("allows only the selected access gateways into the isolated run", () => {
  const browserResources = buildRunResources(
    { ...request, accessMethod: "browser_desktop" },
    images,
  );
  assert.equal(
    browserResources.some((item) => item.metadata.name === "allow-desktop-gateway"),
    true,
  );
  assert.equal(
    browserResources.some((item) => item.metadata.name === "allow-vpn-gateway"),
    false,
  );

  const vpnResources = buildRunResources(
    { ...request, accessMethod: "openvpn" },
    images,
    openVpnGateway,
  );
  const vpnPolicy = vpnResources.find(
    (item) => item.kind === "NetworkPolicy" && item.metadata.name === "allow-vpn-bootstrap",
  );
  assert.ok(vpnPolicy);
  assert.equal(
    vpnResources.some((item) => item.metadata.name === "allow-desktop-gateway"),
    false,
  );
  const to = (vpnPolicy?.spec as any).egress[0].to[0];
  assert.equal(
    to.namespaceSelector.matchLabels["kubernetes.io/metadata.name"],
    "codegate-vpn-system",
  );
  assert.equal(
    to.podSelector.matchLabels["app.kubernetes.io/name"],
    "codegate-openvpn-issuer",
  );
});

test("creates cloud-init only for the learner workstation VM", () => {
  const resources = buildRunResources(request, images, openVpnGateway);
  const secrets = resources.filter(
    (item) => item.kind === "Secret" && item.metadata.name.endsWith("-cloud-init"),
  );
  assert.deepEqual(
    secrets.map((item) => item.metadata.name).sort(),
    ["workstation-cloud-init"],
  );
  const vm = resources.find(
    (item) => item.kind === "VirtualMachine" && item.metadata.name === "workstation",
  );
  const secret = secrets[0];
  const secretRef = (vm?.spec as any).template.spec.volumes[1].cloudInitNoCloud.secretRef.name;
  assert.equal(secretRef, secret?.metadata.name);
  assert.match(String((secret as any).stringData.userdata), /ssh_pwauth: false/);
  assert.match(String((secret as any).stringData.userdata), /lock_passwd: true/);
  assert.equal(resources.some((item) => item.kind === "VirtualMachine" && item.metadata.name === "target"), false);
});

test("runs the digest-pinned OCI target as a restricted Deployment behind ClusterIP", () => {
  const resources = buildRunResources(request, images, openVpnGateway);
  const deployment = resources.find((item) => item.kind === "Deployment" && item.metadata.name === "target");
  const service = resources.find((item) => item.kind === "Service" && item.metadata.name === "target");
  const pod = (deployment?.spec as any).template.spec;
  const container = pod.containers[0];
  assert.equal(container.image, request.targetImage);
  assert.equal(pod.automountServiceAccountToken, false);
  assert.equal(pod.securityContext.runAsNonRoot, true);
  assert.equal(pod.securityContext.runAsUser, request.targetRuntimeContract.uid);
  assert.equal(pod.securityContext.seccompProfile.type, "RuntimeDefault");
  assert.equal(container.securityContext.allowPrivilegeEscalation, false);
  assert.equal(container.securityContext.readOnlyRootFilesystem, true);
  assert.deepEqual(container.securityContext.capabilities.drop, ["ALL"]);
  assert.deepEqual(container.startupProbe.tcpSocket, { port: "http" });
  assert.deepEqual(container.readinessProbe.tcpSocket, { port: "http" });
  assert.equal(pod.volumes[0].emptyDir.sizeLimit, "64Mi");
  assert.equal((service?.spec as any).type, "ClusterIP");
  assert.equal((service?.spec as any).ports[0].port, 8080);
  assert.equal((service?.spec as any).ports[0].appProtocol, "http");
});

test("uses the selected workstation image and exposes desktop only through ClusterIP", () => {
  const resources = buildRunResources(request, images, openVpnGateway);
  const workstation = resources.find((item) => item.kind === "VirtualMachine" && item.metadata.name === "workstation");
  const spec = workstation?.spec as any;
  assert.equal(spec.template.spec.volumes[0].containerDisk.image, images.ubuntuDesktop);
  const desktop = resources.find((item) => item.kind === "Service" && item.metadata.name === "desktop");
  assert.equal((desktop?.spec as { type: string }).type, "ClusterIP");
});

test("does not create desktop service for VPN-only runs", () => {
  const resources = buildRunResources(
    { ...request, accessMethod: "openvpn" },
    images,
    openVpnGateway,
  );
  assert.equal(resources.some((item) => item.kind === "Service" && item.metadata.name === "desktop"), false);
});

test("creates one isolated VPN data-plane gateway inside the run namespace", () => {
  const resources = buildRunResources(request, images, openVpnGateway);
  const deployment = resources.find(
    (item) => item.kind === "Deployment" && item.metadata.name === "openvpn-gateway",
  );
  const service = resources.find(
    (item) => item.kind === "Service" && item.metadata.name === "openvpn-gateway",
  );
  const secret = resources.find(
    (item) => item.kind === "Secret" && item.metadata.name === "openvpn-gateway-bootstrap",
  );
  assert.equal(deployment?.metadata.namespace, "range-run-47a2");
  assert.equal((deployment?.spec as any).template.spec.automountServiceAccountToken, false);
  const gatewayContainer = (deployment?.spec as any).template.spec.containers[0];
  assert.deepEqual(gatewayContainer.readinessProbe.exec.command, [
    "/usr/bin/test",
    "-f",
    "/run/openvpn/ready",
  ]);
  assert.equal((service?.spec as any).type, "LoadBalancer");
  assert.equal((service?.spec as any).allocateLoadBalancerNodePorts, false);
  assert.equal(
    service?.metadata.annotations?.["external-dns.alpha.kubernetes.io/hostname"],
    "vpn-range-run-47a2.vpn-runs.example.invalid.",
  );
  assert.equal(typeof (secret as any).stringData.GATEWAY_BOOTSTRAP_TOKEN, "string");
  assert.equal(
    resources.some(
      (item) =>
        item.kind === "NetworkPolicy" && item.metadata.name === "allow-vpn-gateway",
    ),
    false,
  );
});

test("builds a blue-team ELK topology with monitored-target telemetry sidecars", () => {
  const blueRequest = {
    ...request,
    accessMethod: "browser_desktop" as const,
    topology: {
      schemaVersion: 1 as const,
      team: "blue" as const,
      isolation: "per_run" as const,
      workstation: { role: "soc_analyst" as const, desktopImage: "ubuntu" as const, entrypoint: "kibana" as const },
      target: { role: "monitored_target" as const, hostname: "target" as const },
      telemetry: {
        stack: "elastic" as const,
        collector: "elastic_agent" as const,
        generator: "scenario_log_generator" as const,
        index: "zerotop-logs-*",
        generation: {
          schemaVersion: 1 as const,
          profile: "powershell_rce_exfiltration" as const,
          totalEvents: 1_200,
          timeRangeMinutes: 60,
          seed: "manifest-test-seed",
          timelineAnchor: "2026-07-22T00:00:00.000Z",
        },
        events: [{
          id: "evidence-1",
          document: {
            "@timestamp": "2026-07-22T00:00:00.000Z",
            event: { dataset: "zerotop.endpoint" },
            threat: { technique: { id: ["T1059.004"] } },
          },
        }],
      },
    },
  };
  const blueImages = {
    ...images,
    elasticsearch: `registry.example/elastic/elasticsearch@sha256:${"c".repeat(64)}`,
    kibana: `registry.example/elastic/kibana@sha256:${"d".repeat(64)}`,
    elasticAgent: `registry.example/elastic/agent@sha256:${"e".repeat(64)}`,
    scenarioLogGenerator: `registry.example/ranges/log-generator@sha256:${"f".repeat(64)}`,
  };

  const resources = buildRunResources(blueRequest, blueImages);

  const names = resources.map((item) => `${item.kind}/${item.metadata.name}`);
  assert.ok(names.includes("Deployment/elasticsearch"));
  assert.ok(names.includes("Deployment/kibana"));
  assert.ok(names.includes("Service/elasticsearch"));
  assert.ok(names.includes("Service/kibana"));
  const target = resources.find((item) => item.kind === "Deployment" && item.metadata.name === "target");
  const containers = (target?.spec as any).template.spec.containers;
  assert.deepEqual(containers.map((item: any) => item.name), ["target", "scenario-log-generator", "elastic-agent"]);
  assert.equal(containers[1].env[0].name, "SCENARIO_EVENTS_BASE64");
  assert.equal(containers[1].env[1].name, "SCENARIO_GENERATION_BASE64");
  assert.equal(containers[2].env[0].value, "http://elasticsearch:9200");
  const policies = resources.filter((item) => item.kind === "NetworkPolicy").map((item) => item.metadata.name);
  for (const name of [
    "allow-workstation-to-kibana",
    "allow-kibana-from-workstation",
    "allow-kibana-to-elasticsearch",
    "allow-target-agent-to-elasticsearch",
    "allow-target-agent-to-kibana",
    "allow-kibana-from-target-agent",
    "allow-elasticsearch-ingest",
  ]) assert.ok(policies.includes(name));
  const namespace = resources.find((item) => item.kind === "Namespace");
  assert.equal(namespace?.metadata.annotations?.["codegate.ai/team"], "blue");
});

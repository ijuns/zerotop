import type { ProvisionRunRequest } from "./contracts.ts";
import type { OpenVpnProvision } from "./openvpn.ts";

export type KubernetesObject = {
  apiVersion: string;
  kind: string;
  metadata: { name: string; namespace?: string; labels?: Record<string, string>; annotations?: Record<string, string> };
  [key: string]: unknown;
};

export interface RuntimeImages {
  ubuntuDesktop: string;
  kaliDesktop: string;
}

export interface OpenVpnRunGateway {
  image: string;
  issuerUrl: string;
  hostname: string;
  provision: OpenVpnProvision;
}

const DNS_NAMESPACE_LABEL = "kubernetes.io/metadata.name";
const VPN_NAMESPACE = "codegate-vpn-system";
const DESKTOP_NAMESPACE = "codegate-desktop-system";

export function namespaceForRun(runId: string): string {
  const safe = runId.toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/^-+|-+$/g, "").slice(0, 42);
  if (!safe) throw new Error("runId must contain a DNS-compatible character");
  return `range-${safe}`;
}

export function buildRunResources(
  request: ProvisionRunRequest,
  images: RuntimeImages,
  openVpnGateway?: OpenVpnRunGateway,
  readinessTimeoutSeconds = 600,
): KubernetesObject[] {
  if (request.ttlMinutes < 10 || request.ttlMinutes > 240) throw new Error("ttlMinutes must be between 10 and 240");
  if (!Number.isInteger(readinessTimeoutSeconds) || readinessTimeoutSeconds < 60 || readinessTimeoutSeconds > 1800) {
    throw new Error("readinessTimeoutSeconds must be between 60 and 1800");
  }
  const namespace = namespaceForRun(request.runId);
  const expiresAt = new Date(Date.now() + request.ttlMinutes * 60_000).toISOString();
  const readinessDeadline = new Date(Date.now() + readinessTimeoutSeconds * 1_000).toISOString();
  const commonLabels = {
    "app.kubernetes.io/managed-by": "codegate-runtime",
    "codegate.ai/run-id": request.runId,
    "codegate.ai/lab-id": request.labId,
  };
  const annotations = {
    "codegate.ai/expires-at": expiresAt,
    "codegate.ai/readiness-deadline": readinessDeadline,
    "codegate.ai/access-method": request.accessMethod,
  };
  const desktopImage = request.desktopImage === "ubuntu" ? images.ubuntuDesktop : images.kaliDesktop;

  const resources: KubernetesObject[] = [
    {
      apiVersion: "v1",
      kind: "Namespace",
      metadata: {
        name: namespace,
        labels: {
          ...commonLabels,
          // KubeVirt's generated virt-launcher pod cannot satisfy Restricted
          // Pod Security. Admission privilege is not learner authorization:
          // the namespace receives no learner RBAC and no mounted API token.
          "pod-security.kubernetes.io/enforce": "privileged",
          "pod-security.kubernetes.io/audit": "restricted",
          "pod-security.kubernetes.io/warn": "restricted",
        },
        annotations,
      },
    },
    {
      apiVersion: "v1",
      kind: "ServiceAccount",
      metadata: { name: "default", namespace, labels: commonLabels, annotations },
      automountServiceAccountToken: false,
    },
    {
      apiVersion: "v1",
      kind: "ResourceQuota",
      metadata: { name: "run-quota", namespace, labels: commonLabels },
      spec: {
        hard: {
          "requests.cpu": "4",
          "requests.memory": "10Gi",
          "limits.cpu": "8",
          "limits.memory": "16Gi",
          pods: "12",
          services: "8",
          "count/secrets": "4",
          "count/deployments.apps": "2",
          "count/virtualmachines.kubevirt.io": "1",
        },
      },
    },
    cloudInitSecret("workstation", namespace, commonLabels, annotations, request),
    {
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: { name: "default-deny", namespace, labels: commonLabels },
      spec: { podSelector: {}, policyTypes: ["Ingress", "Egress"] },
    },
    {
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: { name: "allow-target-from-clients", namespace, labels: commonLabels },
      spec: {
        podSelector: { matchLabels: { "codegate.ai/role": "target" } },
        policyTypes: ["Ingress"],
        ingress: [{
          from: [
            { podSelector: { matchLabels: { "codegate.ai/role": "workstation" } } },
            { podSelector: { matchLabels: { "codegate.ai/role": "vpn-gateway" } } },
          ],
          ports: [{ protocol: "TCP", port: request.targetService.port }],
        }],
      },
    },
    {
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: { name: "allow-workstation-to-target", namespace, labels: commonLabels },
      spec: {
        podSelector: { matchLabels: { "codegate.ai/role": "workstation" } },
        policyTypes: ["Egress"],
        egress: [{
          to: [{ podSelector: { matchLabels: { "codegate.ai/role": "target" } } }],
          ports: [{ protocol: "TCP", port: request.targetService.port }],
        }],
      },
    },
    {
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: { name: "allow-vpn-to-target", namespace, labels: commonLabels },
      spec: {
        podSelector: { matchLabels: { "codegate.ai/role": "vpn-gateway" } },
        policyTypes: ["Egress"],
        egress: [{
          to: [{ podSelector: { matchLabels: { "codegate.ai/role": "target" } } }],
          ports: [{ protocol: "TCP", port: request.targetService.port }],
        }],
      },
    },
    {
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: { name: "allow-dns", namespace, labels: commonLabels },
      spec: {
        podSelector: {
          matchExpressions: [{
            key: "codegate.ai/role",
            operator: "In",
            values: ["workstation", "vpn-gateway"],
          }],
        },
        policyTypes: ["Egress"],
        egress: [{
          to: [{ namespaceSelector: { matchLabels: { [DNS_NAMESPACE_LABEL]: "kube-system" } }, podSelector: { matchLabels: { "k8s-app": "kube-dns" } } }],
          ports: [{ protocol: "UDP", port: 53 }, { protocol: "TCP", port: 53 }],
        }],
      },
    },
    virtualMachine("workstation", namespace, desktopImage, commonLabels, annotations, "4Gi", 2),
    targetDeployment(request, namespace, commonLabels, annotations),
    targetService(request, namespace, commonLabels, annotations),
  ];

  if (request.accessMethod === "browser_desktop" || request.accessMethod === "both") {
    resources.push(gatewayIngressPolicy({
      name: "allow-desktop-gateway",
      namespace,
      commonLabels,
      sourceNamespace: DESKTOP_NAMESPACE,
      sourceApp: "codegate-desktop-gateway",
      destinationRole: "workstation",
      ports: [{ protocol: "TCP", port: 6080 }],
    }));
    resources.push({
      apiVersion: "v1",
      kind: "Service",
      metadata: { name: "desktop", namespace, labels: commonLabels, annotations },
      spec: {
        type: "ClusterIP",
        selector: { "codegate.ai/run-id": request.runId, "codegate.ai/role": "workstation" },
        ports: [{ name: "novnc", protocol: "TCP", port: 6080, targetPort: 6080 }],
      },
    });
  }
  if (request.accessMethod === "openvpn" || request.accessMethod === "both") {
    if (!openVpnGateway) throw new Error("Per-run OpenVPN gateway configuration is required");
    resources.push(...openVpnGatewayResources({
      request,
      namespace,
      commonLabels,
      annotations,
      gateway: openVpnGateway,
    }));
  }
  return resources;
}

function openVpnGatewayResources(input: {
  request: ProvisionRunRequest;
  namespace: string;
  commonLabels: Record<string, string>;
  annotations: Record<string, string>;
  gateway: OpenVpnRunGateway;
}): KubernetesObject[] {
  if (!/@sha256:[a-fA-F0-9]{64}$/.test(input.gateway.image)) {
    throw new Error("OPENVPN_GATEWAY_IMAGE must be pinned by sha256 digest");
  }
  if (!/^[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]$/.test(input.gateway.hostname)) {
    throw new Error("OpenVPN gateway hostname is invalid");
  }
  const labels = { ...input.commonLabels, "codegate.ai/role": "vpn-gateway" };
  return [
    {
      apiVersion: "v1",
      kind: "Secret",
      metadata: {
        name: "openvpn-gateway-bootstrap",
        namespace: input.namespace,
        labels,
        annotations: input.annotations,
      },
      type: "Opaque",
      stringData: {
        GATEWAY_BOOTSTRAP_TOKEN: input.gateway.provision.gatewayBootstrapToken,
      },
    },
    {
      apiVersion: "apps/v1",
      kind: "Deployment",
      metadata: {
        name: "openvpn-gateway",
        namespace: input.namespace,
        labels,
        annotations: input.annotations,
      },
      spec: {
        replicas: 1,
        selector: { matchLabels: labels },
        template: {
          metadata: { labels, annotations: input.annotations },
          spec: {
            serviceAccountName: "default",
            automountServiceAccountToken: false,
            securityContext: { seccompProfile: { type: "RuntimeDefault" } },
            containers: [
              {
                name: "gateway",
                image: input.gateway.image,
                imagePullPolicy: "IfNotPresent",
                ports: [{ name: "openvpn", containerPort: 1194, protocol: "UDP" }],
                env: [
                  { name: "OPENVPN_MODE", value: "gateway" },
                  { name: "OPENVPN_PORT", value: "1194" },
                  { name: "OPENVPN_RUN_ID", value: input.request.runId },
                  { name: "OPENVPN_RUN_NAMESPACE", value: input.namespace },
                  { name: "OPENVPN_PROFILE_ID", value: input.gateway.provision.profile.profileId },
                  { name: "OPENVPN_ISSUER_URL", value: input.gateway.issuerUrl },
                  {
                    name: "GATEWAY_BOOTSTRAP_TOKEN",
                    valueFrom: {
                      secretKeyRef: {
                        name: "openvpn-gateway-bootstrap",
                        key: "GATEWAY_BOOTSTRAP_TOKEN",
                      },
                    },
                  },
                ],
                resources: {
                  requests: {
                    cpu: "100m",
                    memory: "128Mi",
                    "devices.kubevirt.io/tun": "1",
                  },
                  limits: {
                    cpu: "1",
                    memory: "512Mi",
                    "devices.kubevirt.io/tun": "1",
                  },
                },
                readinessProbe: {
                  exec: { command: ["/usr/bin/test", "-f", "/run/openvpn/ready"] },
                  initialDelaySeconds: 2,
                  periodSeconds: 2,
                  timeoutSeconds: 1,
                  failureThreshold: 3,
                },
                securityContext: {
                  runAsUser: 0,
                  allowPrivilegeEscalation: false,
                  capabilities: { drop: ["ALL"], add: ["NET_ADMIN"] },
                  readOnlyRootFilesystem: true,
                },
                volumeMounts: [{ name: "runtime", mountPath: "/run/openvpn" }],
              },
            ],
            volumes: [{ name: "runtime", emptyDir: { medium: "Memory" } }],
          },
        },
      },
    },
    {
      apiVersion: "v1",
      kind: "Service",
      metadata: {
        name: "openvpn-gateway",
        namespace: input.namespace,
        labels,
        annotations: {
          ...input.annotations,
          "external-dns.alpha.kubernetes.io/hostname": `${input.gateway.hostname}.`,
        },
      },
      spec: {
        type: "LoadBalancer",
        allocateLoadBalancerNodePorts: false,
        externalTrafficPolicy: "Local",
        selector: labels,
        ports: [{ name: "openvpn", protocol: "UDP", port: 1194, targetPort: 1194 }],
      },
    },
    {
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: { name: "allow-vpn-public", namespace: input.namespace, labels },
      spec: {
        podSelector: { matchLabels: { "codegate.ai/role": "vpn-gateway" } },
        policyTypes: ["Ingress"],
        ingress: [{ ports: [{ protocol: "UDP", port: 1194 }] }],
      },
    },
    {
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: { name: "allow-vpn-bootstrap", namespace: input.namespace, labels },
      spec: {
        podSelector: { matchLabels: { "codegate.ai/role": "vpn-gateway" } },
        policyTypes: ["Egress"],
        egress: [
          {
            to: [
              {
                namespaceSelector: {
                  matchLabels: { [DNS_NAMESPACE_LABEL]: VPN_NAMESPACE },
                },
                podSelector: {
                  matchLabels: { "app.kubernetes.io/name": "codegate-openvpn-issuer" },
                },
              },
            ],
            ports: [{ protocol: "TCP", port: 9100 }],
          },
        ],
      },
    },
  ];
}

function gatewayIngressPolicy(input: {
  name: string;
  namespace: string;
  commonLabels: Record<string, string>;
  sourceNamespace: string;
  sourceApp: string;
  destinationRole?: string;
  ports?: Array<{ protocol: "TCP" | "UDP"; port: number }>;
}): KubernetesObject {
  return {
    apiVersion: "networking.k8s.io/v1",
    kind: "NetworkPolicy",
    metadata: {
      name: input.name,
      namespace: input.namespace,
      labels: input.commonLabels,
    },
    spec: {
      podSelector: input.destinationRole
        ? { matchLabels: { "codegate.ai/role": input.destinationRole } }
        : {},
      policyTypes: ["Ingress"],
      ingress: [
        {
          from: [
            {
              namespaceSelector: {
                matchLabels: { [DNS_NAMESPACE_LABEL]: input.sourceNamespace },
              },
              podSelector: {
                matchLabels: { "app.kubernetes.io/name": input.sourceApp },
              },
            },
          ],
          ...(input.ports ? { ports: input.ports } : {}),
        },
      ],
    },
  };
}

function cloudInitSecret(
  role: "workstation",
  namespace: string,
  commonLabels: Record<string, string>,
  annotations: Record<string, string>,
  request: ProvisionRunRequest,
): KubernetesObject {
  const runMetadata = JSON.stringify({
    runId: request.runId,
    labId: request.labId,
    role,
  });
  const userData = [
    "#cloud-config",
    "disable_root: true",
    "ssh_pwauth: false",
    "users:",
    "  - name: range",
    "    lock_passwd: true",
    "    shell: /bin/bash",
    "write_files:",
    "  - path: /etc/codegate/run.json",
    "    owner: root:root",
    "    permissions: '0600'",
    `    content: '${runMetadata.replaceAll("'", "''")}'`,
    "runcmd:",
    "  - [systemctl, enable, --now, codegate-workstation.service]",
    "",
  ].join("\n");

  return {
    apiVersion: "v1",
    kind: "Secret",
    metadata: {
      name: `${role}-cloud-init`,
      namespace,
      labels: commonLabels,
      annotations,
    },
    type: "Opaque",
    stringData: { userdata: userData },
  };
}

function virtualMachine(
  role: "workstation",
  namespace: string,
  image: string,
  commonLabels: Record<string, string>,
  annotations: Record<string, string>,
  memory: string,
  cpuCores: number,
): KubernetesObject {
  const labels = { ...commonLabels, "codegate.ai/role": role };
  return {
    apiVersion: "kubevirt.io/v1",
    kind: "VirtualMachine",
    metadata: { name: role, namespace, labels, annotations },
    spec: {
      running: true,
      template: {
        metadata: { labels, annotations },
        spec: {
          terminationGracePeriodSeconds: 30,
          evictionStrategy: "LiveMigrate",
          domain: {
            cpu: { cores: cpuCores },
            resources: { requests: { memory } },
            devices: {
              disks: [{ name: "root", disk: { bus: "virtio" } }, { name: "cloudinit", disk: { bus: "virtio" } }],
              interfaces: [{ name: "default", masquerade: {} }],
            },
          },
          networks: [{ name: "default", pod: {} }],
          volumes: [
            { name: "root", containerDisk: { image, imagePullPolicy: "IfNotPresent" } },
            { name: "cloudinit", cloudInitNoCloud: { secretRef: { name: `${role}-cloud-init` } } },
          ],
        },
      },
    },
  };
}

function targetDeployment(
  request: ProvisionRunRequest,
  namespace: string,
  commonLabels: Record<string, string>,
  annotations: Record<string, string>,
): KubernetesObject {
  const labels = { ...commonLabels, "codegate.ai/role": "target" };
  const portName = request.targetService.protocol === "http" ? "http" : "tcp";
  const tcpProbe = {
    tcpSocket: { port: portName },
    timeoutSeconds: 1,
    periodSeconds: 2,
  };
  return {
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: { name: "target", namespace, labels, annotations },
    spec: {
      replicas: 1,
      revisionHistoryLimit: 0,
      progressDeadlineSeconds: 300,
      selector: { matchLabels: labels },
      template: {
        metadata: { labels, annotations },
        spec: {
          serviceAccountName: "default",
          automountServiceAccountToken: false,
          enableServiceLinks: false,
          terminationGracePeriodSeconds: 10,
          securityContext: {
            runAsNonRoot: true,
            runAsUser: request.targetRuntimeContract.uid,
            runAsGroup: request.targetRuntimeContract.gid,
            fsGroup: request.targetRuntimeContract.gid,
            seccompProfile: { type: "RuntimeDefault" },
          },
          containers: [{
            name: "target",
            image: request.targetImage,
            imagePullPolicy: "IfNotPresent",
            ports: [{ name: portName, containerPort: request.targetService.port, protocol: "TCP" }],
            startupProbe: { ...tcpProbe, failureThreshold: 60 },
            readinessProbe: { ...tcpProbe, failureThreshold: 3 },
            resources: {
              requests: { cpu: "250m", memory: "256Mi" },
              limits: { cpu: "1", memory: "512Mi" },
            },
            securityContext: {
              allowPrivilegeEscalation: false,
              readOnlyRootFilesystem: request.targetRuntimeContract.readOnlyRootFilesystem,
              capabilities: { drop: ["ALL"] },
            },
            volumeMounts: [{ name: "tmp", mountPath: "/tmp" }],
          }],
          volumes: [{ name: "tmp", emptyDir: { medium: "Memory", sizeLimit: "64Mi" } }],
        },
      },
    },
  };
}

function targetService(
  request: ProvisionRunRequest,
  namespace: string,
  commonLabels: Record<string, string>,
  annotations: Record<string, string>,
): KubernetesObject {
  const labels = { ...commonLabels, "codegate.ai/role": "target" };
  const portName = request.targetService.protocol === "http" ? "http" : "tcp";
  return {
    apiVersion: "v1",
    kind: "Service",
    metadata: { name: "target", namespace, labels, annotations },
    spec: {
      type: "ClusterIP",
      selector: labels,
      ports: [{
        name: portName,
        protocol: "TCP",
        port: request.targetService.port,
        targetPort: portName,
        ...(request.targetService.protocol === "http" ? { appProtocol: "http" } : {}),
      }],
    },
  };
}

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
  elasticsearch?: string;
  kibana?: string;
  elasticAgent?: string;
  scenarioLogGenerator?: string;
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
    ...(request.topology?.team ? { "codegate.ai/team": request.topology.team } : {}),
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
          "requests.cpu": request.topology?.team === "blue" ? "6" : "4",
          "requests.memory": request.topology?.team === "blue" ? "14Gi" : "10Gi",
          "limits.cpu": request.topology?.team === "blue" ? "12" : "8",
          "limits.memory": request.topology?.team === "blue" ? "24Gi" : "16Gi",
          pods: request.topology?.team === "blue" ? "18" : "12",
          services: request.topology?.team === "blue" ? "12" : "8",
          "count/secrets": "6",
          "count/deployments.apps": request.topology?.team === "blue" ? "5" : "2",
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
            values: request.topology?.team === "blue"
              ? ["workstation", "target", "kibana", "vpn-gateway"]
              : ["workstation", "vpn-gateway"],
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
    targetDeployment(request, images, namespace, commonLabels, annotations),
    targetService(request, namespace, commonLabels, annotations),
  ];

  if (request.topology?.team === "blue") {
    resources.push(...blueTeamResources(request, images, namespace, commonLabels, annotations));
  }

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

function blueTeamResources(
  request: ProvisionRunRequest,
  images: RuntimeImages,
  namespace: string,
  commonLabels: Record<string, string>,
  annotations: Record<string, string>,
): KubernetesObject[] {
  if (request.topology?.team !== "blue" || !request.topology.telemetry) {
    throw new Error("Blue-team resources require a validated Elastic topology");
  }
  const elasticsearchImage = requiredBlueImage(images.elasticsearch, "ELASTICSEARCH_IMAGE");
  const kibanaImage = requiredBlueImage(images.kibana, "KIBANA_IMAGE");
  const elasticsearchLabels = { ...commonLabels, "codegate.ai/role": "elasticsearch" };
  const kibanaLabels = { ...commonLabels, "codegate.ai/role": "kibana" };
  return [
    {
      apiVersion: "apps/v1",
      kind: "Deployment",
      metadata: { name: "elasticsearch", namespace, labels: elasticsearchLabels, annotations },
      spec: {
        replicas: 1,
        revisionHistoryLimit: 0,
        progressDeadlineSeconds: 600,
        selector: { matchLabels: elasticsearchLabels },
        template: {
          metadata: { labels: elasticsearchLabels, annotations },
          spec: {
            serviceAccountName: "default",
            automountServiceAccountToken: false,
            enableServiceLinks: false,
            securityContext: { seccompProfile: { type: "RuntimeDefault" } },
            containers: [{
              name: "elasticsearch",
              image: elasticsearchImage,
              imagePullPolicy: "IfNotPresent",
              ports: [{ name: "http", containerPort: 9200, protocol: "TCP" }],
              env: [
                { name: "discovery.type", value: "single-node" },
                { name: "xpack.security.enabled", value: "false" },
                { name: "xpack.ml.enabled", value: "false" },
                { name: "ES_JAVA_OPTS", value: "-Xms768m -Xmx768m" },
              ],
              startupProbe: { httpGet: { path: "/_cluster/health", port: "http" }, periodSeconds: 5, failureThreshold: 120 },
              readinessProbe: { httpGet: { path: "/_cluster/health", port: "http" }, periodSeconds: 5, failureThreshold: 6 },
              resources: { requests: { cpu: "500m", memory: "1Gi" }, limits: { cpu: "2", memory: "2Gi" } },
              securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: ["ALL"] } },
              volumeMounts: [{ name: "data", mountPath: "/usr/share/elasticsearch/data" }],
            }],
            volumes: [{ name: "data", emptyDir: { sizeLimit: "4Gi" } }],
          },
        },
      },
    },
    internalService("elasticsearch", namespace, elasticsearchLabels, annotations, 9200, "http"),
    {
      apiVersion: "apps/v1",
      kind: "Deployment",
      metadata: { name: "kibana", namespace, labels: kibanaLabels, annotations },
      spec: {
        replicas: 1,
        revisionHistoryLimit: 0,
        progressDeadlineSeconds: 600,
        selector: { matchLabels: kibanaLabels },
        template: {
          metadata: { labels: kibanaLabels, annotations },
          spec: {
            serviceAccountName: "default",
            automountServiceAccountToken: false,
            enableServiceLinks: false,
            securityContext: { seccompProfile: { type: "RuntimeDefault" } },
            containers: [{
              name: "kibana",
              image: kibanaImage,
              imagePullPolicy: "IfNotPresent",
              ports: [{ name: "http", containerPort: 5601, protocol: "TCP" }],
              env: [
                { name: "ELASTICSEARCH_HOSTS", value: "http://elasticsearch:9200" },
                { name: "SERVER_HOST", value: "0.0.0.0" },
                { name: "TELEMETRY_ENABLED", value: "false" },
              ],
              startupProbe: { httpGet: { path: "/api/status", port: "http" }, periodSeconds: 5, failureThreshold: 120 },
              readinessProbe: { httpGet: { path: "/api/status", port: "http" }, periodSeconds: 5, failureThreshold: 6 },
              resources: { requests: { cpu: "250m", memory: "512Mi" }, limits: { cpu: "1", memory: "1Gi" } },
              securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: ["ALL"] } },
            }],
          },
        },
      },
    },
    internalService("kibana", namespace, kibanaLabels, annotations, 5601, "http"),
    roleNetworkPolicy("allow-workstation-to-kibana", namespace, commonLabels, "workstation", "kibana", 5601, "Egress"),
    roleNetworkPolicy("allow-kibana-from-workstation", namespace, commonLabels, "kibana", "workstation", 5601, "Ingress"),
    roleNetworkPolicy("allow-kibana-to-elasticsearch", namespace, commonLabels, "kibana", "elasticsearch", 9200, "Egress"),
    roleNetworkPolicy("allow-target-agent-to-elasticsearch", namespace, commonLabels, "target", "elasticsearch", 9200, "Egress"),
    roleNetworkPolicy("allow-target-agent-to-kibana", namespace, commonLabels, "target", "kibana", 5601, "Egress"),
    roleNetworkPolicy("allow-kibana-from-target-agent", namespace, commonLabels, "kibana", "target", 5601, "Ingress"),
    {
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: { name: "allow-elasticsearch-ingest", namespace, labels: commonLabels },
      spec: {
        podSelector: { matchLabels: { "codegate.ai/role": "elasticsearch" } },
        policyTypes: ["Ingress"],
        ingress: [{
          from: ["target", "kibana"].map((role) => ({ podSelector: { matchLabels: { "codegate.ai/role": role } } })),
          ports: [{ protocol: "TCP", port: 9200 }],
        }],
      },
    },
  ];
}

function internalService(
  name: string,
  namespace: string,
  labels: Record<string, string>,
  annotations: Record<string, string>,
  port: number,
  appProtocol: "http",
): KubernetesObject {
  return {
    apiVersion: "v1",
    kind: "Service",
    metadata: { name, namespace, labels, annotations },
    spec: {
      type: "ClusterIP",
      selector: labels,
      ports: [{ name: "http", protocol: "TCP", port, targetPort: "http", appProtocol }],
    },
  };
}

function roleNetworkPolicy(
  name: string,
  namespace: string,
  labels: Record<string, string>,
  selectedRole: string,
  peerRole: string,
  port: number,
  direction: "Ingress" | "Egress",
): KubernetesObject {
  const rule = {
    ...(direction === "Ingress"
      ? { from: [{ podSelector: { matchLabels: { "codegate.ai/role": peerRole } } }] }
      : { to: [{ podSelector: { matchLabels: { "codegate.ai/role": peerRole } } }] }),
    ports: [{ protocol: "TCP", port }],
  };
  return {
    apiVersion: "networking.k8s.io/v1",
    kind: "NetworkPolicy",
    metadata: { name, namespace, labels },
    spec: {
      podSelector: { matchLabels: { "codegate.ai/role": selectedRole } },
      policyTypes: [direction],
      ...(direction === "Ingress" ? { ingress: [rule] } : { egress: [rule] }),
    },
  };
}

function requiredBlueImage(value: string | undefined, name: string): string {
  if (!value || !/@sha256:[a-f0-9]{64}$/i.test(value)) {
    throw new Error(`${name} must be configured as a digest-pinned image for blue-team topology`);
  }
  return value;
}

function targetDeployment(
  request: ProvisionRunRequest,
  images: RuntimeImages,
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
  const blue = request.topology?.team === "blue" ? request.topology : undefined;
  const redExercise = request.topology?.team === "red"
    ? request.topology.target.exercise
    : undefined;
  const targetContainer = {
    name: "target",
    image: request.targetImage,
    imagePullPolicy: "IfNotPresent",
    ports: [{ name: portName, containerPort: request.targetService.port, protocol: "TCP" }],
    ...(redExercise ? {
      env: [{
        name: "ZEROTOP_RED_EXERCISE_BASE64",
        value: Buffer.from(JSON.stringify(redExercise), "utf8").toString("base64"),
      }],
    } : {}),
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
    volumeMounts: [
      { name: "tmp", mountPath: "/tmp" },
      ...(blue ? [{ name: "scenario-logs", mountPath: "/var/log/zerotop" }] : []),
    ],
  };
  const sidecars = blue?.telemetry
    ? [
        {
          name: "scenario-log-generator",
          image: requiredBlueImage(images.scenarioLogGenerator, "SCENARIO_LOG_GENERATOR_IMAGE"),
          imagePullPolicy: "IfNotPresent",
          env: [
            { name: "SCENARIO_EVENTS_BASE64", value: Buffer.from(JSON.stringify(blue.telemetry.events), "utf8").toString("base64") },
            ...(blue.telemetry.generation
              ? [{ name: "SCENARIO_GENERATION_BASE64", value: Buffer.from(JSON.stringify(blue.telemetry.generation), "utf8").toString("base64") }]
              : []),
            { name: "SCENARIO_LOG_PATH", value: "/var/log/zerotop/scenario.ndjson" },
          ],
          readinessProbe: { exec: { command: ["/usr/bin/test", "-s", "/var/log/zerotop/scenario.ndjson"] }, periodSeconds: 2, failureThreshold: 30 },
          resources: { requests: { cpu: "25m", memory: "32Mi" }, limits: { cpu: "250m", memory: "128Mi" } },
          securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } },
          volumeMounts: [{ name: "scenario-logs", mountPath: "/var/log/zerotop" }, { name: "generator-tmp", mountPath: "/tmp" }],
        },
        {
          name: "elastic-agent",
          image: requiredBlueImage(images.elasticAgent, "ELASTIC_AGENT_IMAGE"),
          imagePullPolicy: "IfNotPresent",
          env: [
            { name: "ELASTICSEARCH_HOST", value: "http://elasticsearch:9200" },
            { name: "KIBANA_HOST", value: "http://kibana:5601" },
            { name: "ELASTIC_INDEX", value: telemetryIndexForRun(blue.telemetry.index, request.runId) },
          ],
          readinessProbe: { exec: { command: ["/usr/bin/test", "-f", "/tmp/zerotop-agent-ready"] }, periodSeconds: 3, failureThreshold: 60 },
          resources: { requests: { cpu: "50m", memory: "64Mi" }, limits: { cpu: "500m", memory: "512Mi" } },
          securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } },
          volumeMounts: [{ name: "scenario-logs", mountPath: "/var/log/zerotop", readOnly: true }, { name: "agent-tmp", mountPath: "/tmp" }],
        },
      ]
    : [];
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
          containers: [targetContainer, ...sidecars],
          volumes: [
            { name: "tmp", emptyDir: { medium: "Memory", sizeLimit: "64Mi" } },
            ...(blue ? [
              { name: "scenario-logs", emptyDir: { sizeLimit: "128Mi" } },
              { name: "generator-tmp", emptyDir: { medium: "Memory", sizeLimit: "16Mi" } },
              { name: "agent-tmp", emptyDir: { medium: "Memory", sizeLimit: "64Mi" } },
            ] : []),
          ],
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

function telemetryIndexForRun(pattern: string, runId: string): string {
  const suffix = runId.toLowerCase().replace(/[^a-z0-9._-]/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);
  if (!suffix) throw new Error("runId cannot form a telemetry index suffix");
  return pattern.replace(/\*$/, suffix);
}

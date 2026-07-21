import type { KubernetesObject } from "./manifests.ts";
import type { SandboxValidationInput } from "./validation-input.ts";

export interface ValidationManifestOptions {
  namespace: string;
  validationId: string;
  expiresAt: string;
  probeImage: string;
  probePlanBase64Url?: string;
  activeDeadlineSeconds: number;
}

export function buildValidationBaseResources(
  input: SandboxValidationInput,
  options: ValidationManifestOptions,
): KubernetesObject[] {
  const labels = commonLabels(input, options.validationId);
  const annotations = { "codegate.ai/expires-at": options.expiresAt };
  const targetLabels = { ...labels, "codegate.ai/role": "validation-target" };
  return [
    {
      apiVersion: "v1",
      kind: "Namespace",
      metadata: {
        name: options.namespace,
        labels: {
          ...labels,
          "pod-security.kubernetes.io/enforce": "restricted",
          "pod-security.kubernetes.io/audit": "restricted",
          "pod-security.kubernetes.io/warn": "restricted",
        },
        annotations,
      },
    },
    {
      apiVersion: "v1",
      kind: "ServiceAccount",
      metadata: { name: "default", namespace: options.namespace, labels },
      automountServiceAccountToken: false,
    },
    {
      apiVersion: "v1",
      kind: "ResourceQuota",
      metadata: { name: "validation-quota", namespace: options.namespace, labels },
      spec: {
        hard: {
          "requests.cpu": "1",
          "requests.memory": "1Gi",
          "limits.cpu": "2",
          "limits.memory": "2Gi",
          pods: "4",
          services: "2",
          "count/jobs.batch": "1",
          "count/deployments.apps": "1",
        },
      },
    },
    {
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: { name: "default-deny", namespace: options.namespace, labels },
      spec: { podSelector: {}, policyTypes: ["Ingress", "Egress"] },
    },
    {
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: { name: "allow-probe-target", namespace: options.namespace, labels },
      spec: {
        podSelector: { matchLabels: { "codegate.ai/role": "validation-probe" } },
        policyTypes: ["Egress"],
        egress: [{
          to: [{ podSelector: { matchLabels: { "codegate.ai/role": "validation-target" } } }],
          ports: [{ protocol: "TCP", port: input.service.port }],
        }],
      },
    },
    {
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: { name: "allow-probe-dns", namespace: options.namespace, labels },
      spec: {
        podSelector: { matchLabels: { "codegate.ai/role": "validation-probe" } },
        policyTypes: ["Egress"],
        egress: [{
          to: [{
            namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "kube-system" } },
            podSelector: { matchLabels: { "k8s-app": "kube-dns" } },
          }],
          ports: [{ protocol: "UDP", port: 53 }, { protocol: "TCP", port: 53 }],
        }],
      },
    },
    {
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: { name: "allow-target-from-probe", namespace: options.namespace, labels },
      spec: {
        podSelector: { matchLabels: { "codegate.ai/role": "validation-target" } },
        policyTypes: ["Ingress"],
        ingress: [{
          from: [{ podSelector: { matchLabels: { "codegate.ai/role": "validation-probe" } } }],
          ports: [{ protocol: "TCP", port: input.service.port }],
        }],
      },
    },
    targetDeployment(input, options, targetLabels, annotations),
    {
      apiVersion: "v1",
      kind: "Service",
      metadata: { name: "target", namespace: options.namespace, labels: targetLabels, annotations },
      spec: {
        type: "ClusterIP",
        selector: { "codegate.ai/role": "validation-target" },
        ports: [{
          name: input.service.protocol === "http" ? "http" : "tcp",
          protocol: "TCP",
          port: input.service.port,
          targetPort: input.service.protocol === "http" ? "http" : "tcp",
          ...(input.service.protocol === "http" ? { appProtocol: "http" } : {}),
        }],
      },
    },
  ];
}

export function buildValidationProbeJob(
  input: SandboxValidationInput,
  options: ValidationManifestOptions & { probePlanBase64Url: string },
): KubernetesObject {
  if (!/@sha256:[a-f0-9]{64}$/i.test(options.probeImage)) {
    throw new Error("SANDBOX_PROBE_IMAGE must be pinned by sha256 digest");
  }
  const labels = { ...commonLabels(input, options.validationId), "codegate.ai/role": "validation-probe" };
  return {
    apiVersion: "batch/v1",
    kind: "Job",
    metadata: { name: "sandbox-probe", namespace: options.namespace, labels },
    spec: {
      backoffLimit: 0,
      activeDeadlineSeconds: options.activeDeadlineSeconds,
      ttlSecondsAfterFinished: 60,
      template: {
        metadata: { labels },
        spec: {
          restartPolicy: "Never",
          serviceAccountName: "default",
          automountServiceAccountToken: false,
          enableServiceLinks: false,
          securityContext: { runAsNonRoot: true, seccompProfile: { type: "RuntimeDefault" } },
          containers: [{
            name: "probe",
            image: options.probeImage,
            imagePullPolicy: "IfNotPresent",
            env: [{ name: "VALIDATION_PLAN_B64", value: options.probePlanBase64Url }],
            resources: {
              requests: { cpu: "50m", memory: "64Mi" },
              limits: { cpu: "500m", memory: "256Mi" },
            },
            securityContext: {
              allowPrivilegeEscalation: false,
              readOnlyRootFilesystem: true,
              capabilities: { drop: ["ALL"] },
            },
          }],
        },
      },
    },
  };
}

function targetDeployment(
  input: SandboxValidationInput,
  options: ValidationManifestOptions,
  labels: Record<string, string>,
  annotations: Record<string, string>,
): KubernetesObject {
  const portName = input.service.protocol === "http" ? "http" : "tcp";
  const tcpProbe = {
    tcpSocket: { port: portName },
    timeoutSeconds: 1,
    periodSeconds: 2,
  };
  return {
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: { name: "target", namespace: options.namespace, labels, annotations },
    spec: {
      replicas: 1,
      revisionHistoryLimit: 0,
      progressDeadlineSeconds: Math.max(60, Math.min(300, options.activeDeadlineSeconds)),
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
            runAsUser: input.runtimeContract.uid,
            runAsGroup: input.runtimeContract.gid,
            fsGroup: input.runtimeContract.gid,
            seccompProfile: { type: "RuntimeDefault" },
          },
          containers: [{
            name: "target",
            image: input.image,
            imagePullPolicy: "IfNotPresent",
            ports: [{ name: portName, containerPort: input.service.port, protocol: "TCP" }],
            startupProbe: { ...tcpProbe, failureThreshold: 60 },
            readinessProbe: { ...tcpProbe, failureThreshold: 3 },
            resources: {
              requests: { cpu: "250m", memory: "256Mi" },
              limits: { cpu: "1", memory: "512Mi" },
            },
            securityContext: {
              allowPrivilegeEscalation: false,
              readOnlyRootFilesystem: input.runtimeContract.readOnlyRootFilesystem,
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

function commonLabels(input: SandboxValidationInput, validationId: string): Record<string, string> {
  return {
    "app.kubernetes.io/managed-by": "codegate-runtime",
    "codegate.ai/validation-id": validationId,
    "codegate.ai/lab-id": input.labId,
  };
}

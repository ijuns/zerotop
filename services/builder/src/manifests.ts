import { isIP } from "node:net";

import type { BuildRecord } from "./contracts.ts";
import { COMPONENT_POLICY_FILENAME, assertControlledDockerfile, renderComponentPolicy, renderControlledDockerfile } from "./dockerfile.ts";

export const REGISTRY_CA_SECRET_NAME = "codegate-private-registry-ca";

export interface KubernetesObject {
  apiVersion: string;
  kind: string;
  metadata: { name: string; namespace?: string; labels?: Record<string, string>; annotations?: Record<string, string> };
  [key: string]: unknown;
}

export interface BuildManifestOptions {
  buildkitImage: string;
  registrySecretName: string;
  cpuRequest: string;
  cpuLimit: string;
  memoryRequest: string;
  memoryLimit: string;
  ephemeralStorageLimit: string;
  activeDeadlineSeconds: number;
  ttlSecondsAfterFinished: number;
  egressCidrs: string[];
  egressPorts: number[];
}

export function buildResources(record: BuildRecord, options: BuildManifestOptions): KubernetesObject[] {
  validateOptions(options);
  const labels = { "app.kubernetes.io/name": "codegate-builder", "codegate.ai/build-id": record.id };
  const dockerfile = renderControlledDockerfile(record);
  assertControlledDockerfile(dockerfile);
  const imageName = `${record.spec.target.outputRepository}:build-${record.id}`;
  const namespace: KubernetesObject = {
    apiVersion: "v1",
    kind: "Namespace",
    metadata: {
      name: record.namespace,
      labels: {
        ...labels,
        "pod-security.kubernetes.io/enforce": "restricted",
        "pod-security.kubernetes.io/audit": "restricted",
        "pod-security.kubernetes.io/warn": "restricted",
      },
      annotations: { "codegate.ai/deadline-at": record.deadlineAt, "codegate.ai/owner-service": "builder" },
    },
  };
  const quota: KubernetesObject = {
    apiVersion: "v1",
    kind: "ResourceQuota",
    metadata: { name: "build-quota", namespace: record.namespace, labels },
    spec: {
      hard: {
        pods: "2",
        "requests.cpu": options.cpuLimit,
        "limits.cpu": options.cpuLimit,
        "requests.memory": options.memoryLimit,
        "limits.memory": options.memoryLimit,
        "requests.ephemeral-storage": options.ephemeralStorageLimit,
        "limits.ephemeral-storage": options.ephemeralStorageLimit,
      },
    },
  };
  const limitRange: KubernetesObject = {
    apiVersion: "v1",
    kind: "LimitRange",
    metadata: { name: "build-limits", namespace: record.namespace, labels },
    spec: { limits: [{ type: "Container", defaultRequest: { cpu: options.cpuRequest, memory: options.memoryRequest }, default: { cpu: options.cpuLimit, memory: options.memoryLimit, "ephemeral-storage": options.ephemeralStorageLimit } }] },
  };
  const serviceAccount: KubernetesObject = {
    apiVersion: "v1",
    kind: "ServiceAccount",
    metadata: { name: "buildkit", namespace: record.namespace, labels },
    automountServiceAccountToken: false,
  };
  const defaultDeny: KubernetesObject = {
    apiVersion: "networking.k8s.io/v1",
    kind: "NetworkPolicy",
    metadata: { name: "default-deny", namespace: record.namespace, labels },
    spec: { podSelector: {}, policyTypes: ["Ingress", "Egress"] },
  };
  const dnsPolicy: KubernetesObject = {
    apiVersion: "networking.k8s.io/v1",
    kind: "NetworkPolicy",
    metadata: { name: "allow-dns", namespace: record.namespace, labels },
    spec: {
      podSelector: { matchLabels: labels },
      policyTypes: ["Egress"],
      egress: [{
        to: [{
          namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "kube-system" } },
          podSelector: { matchLabels: { "k8s-app": "kube-dns" } },
        }],
        ports: [{ protocol: "UDP", port: 53 }, { protocol: "TCP", port: 53 }],
      }],
    },
  };
  const dependencyPolicy: KubernetesObject = {
    apiVersion: "networking.k8s.io/v1",
    kind: "NetworkPolicy",
    metadata: { name: "allow-build-dependencies", namespace: record.namespace, labels },
    spec: {
      podSelector: { matchLabels: labels },
      policyTypes: ["Egress"],
      egress: [{
        to: options.egressCidrs.map((cidr) => ({ ipBlock: { cidr } })),
        ports: options.egressPorts.map((port) => ({ protocol: "TCP", port })),
      }],
    },
  };
  const dockerfileConfig: KubernetesObject = {
    apiVersion: "v1",
    kind: "ConfigMap",
    metadata: { name: "controlled-build-context", namespace: record.namespace, labels },
    immutable: true,
    data: {
      Dockerfile: dockerfile,
      [COMPONENT_POLICY_FILENAME]: renderComponentPolicy(record.resolvedPackages),
      ".codegate-empty": "controlled context\n",
    },
  };
  const job: KubernetesObject = {
    apiVersion: "batch/v1",
    kind: "Job",
    metadata: { name: record.jobName, namespace: record.namespace, labels },
    spec: {
      backoffLimit: 0,
      activeDeadlineSeconds: options.activeDeadlineSeconds,
      ttlSecondsAfterFinished: options.ttlSecondsAfterFinished,
      template: {
        metadata: { labels, annotations: { "container.apparmor.security.beta.kubernetes.io/buildkit": "runtime/default" } },
        spec: {
          serviceAccountName: "buildkit",
          automountServiceAccountToken: false,
          restartPolicy: "Never",
          enableServiceLinks: false,
          terminationGracePeriodSeconds: 20,
          securityContext: { runAsNonRoot: true, runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000, seccompProfile: { type: "RuntimeDefault" } },
          containers: [{
            name: "buildkit",
            image: options.buildkitImage,
            imagePullPolicy: "IfNotPresent",
            command: ["buildctl-daemonless.sh"],
            args: [
              "build",
              "--frontend=dockerfile.v0",
              "--local=context=/workspace/context",
              "--local=dockerfile=/workspace/dockerfile",
              "--opt=filename=Dockerfile",
              `--output=type=image,name=${imageName},push=true`,
              "--metadata-file=/dev/stdout",
              "--progress=plain",
            ],
            env: [
              { name: "HOME", value: "/home/user" },
              { name: "DOCKER_CONFIG", value: "/home/user/.docker" },
              { name: "BUILDKITD_FLAGS", value: "--oci-worker-snapshotter=native --oci-worker-gc=true" },
              { name: "SOURCE_DATE_EPOCH", value: String(Math.floor(Date.parse(record.createdAt) / 1_000)) },
              { name: "SSL_CERT_DIR", value: "/etc/ssl/certs" },
              { name: "SSL_CERT_FILE", value: "/etc/codegate/registry-ca/ca.crt" },
            ],
            securityContext: { allowPrivilegeEscalation: false, privileged: false, runAsNonRoot: true, readOnlyRootFilesystem: false, capabilities: { drop: ["ALL"] }, seccompProfile: { type: "RuntimeDefault" } },
            resources: {
              requests: { cpu: options.cpuRequest, memory: options.memoryRequest, "ephemeral-storage": "2Gi" },
              limits: { cpu: options.cpuLimit, memory: options.memoryLimit, "ephemeral-storage": options.ephemeralStorageLimit },
            },
            volumeMounts: [
              { name: "dockerfile", mountPath: "/workspace/dockerfile", readOnly: true },
              { name: "empty-context", mountPath: "/workspace/context", readOnly: true },
              { name: "buildkit-state", mountPath: "/home/user/.local/share/buildkit" },
              { name: "temporary", mountPath: "/tmp" },
              { name: "registry-auth", mountPath: "/home/user/.docker", readOnly: true },
              { name: "registry-ca", mountPath: "/etc/codegate/registry-ca", readOnly: true },
            ],
          }],
          volumes: [
            { name: "dockerfile", configMap: { name: "controlled-build-context", items: [{ key: "Dockerfile", path: "Dockerfile" }] } },
            {
              name: "empty-context",
              configMap: {
                name: "controlled-build-context",
                items: [
                  { key: ".codegate-empty", path: ".codegate-empty" },
                  { key: COMPONENT_POLICY_FILENAME, path: COMPONENT_POLICY_FILENAME },
                ],
              },
            },
            { name: "buildkit-state", emptyDir: { sizeLimit: options.ephemeralStorageLimit } },
            { name: "temporary", emptyDir: { sizeLimit: "1Gi" } },
            { name: "registry-auth", secret: { secretName: options.registrySecretName, items: [{ key: ".dockerconfigjson", path: "config.json" }] } },
            { name: "registry-ca", secret: { secretName: REGISTRY_CA_SECRET_NAME, items: [{ key: "ca.crt", path: "ca.crt" }] } },
          ],
        },
      },
    },
  };
  return [namespace, quota, limitRange, serviceAccount, defaultDeny, dnsPolicy, dependencyPolicy, dockerfileConfig, job];
}

export function registryAuthSecret(namespace: string, name: string, dockerConfigJsonBase64: string): KubernetesObject {
  return {
    apiVersion: "v1",
    kind: "Secret",
    metadata: { name, namespace, labels: { "app.kubernetes.io/name": "codegate-builder" } },
    type: "kubernetes.io/dockerconfigjson",
    immutable: true,
    data: { ".dockerconfigjson": dockerConfigJsonBase64 },
  };
}

export function registryCaSecret(namespace: string, caCertificateBase64: string): KubernetesObject {
  return {
    apiVersion: "v1",
    kind: "Secret",
    metadata: { name: REGISTRY_CA_SECRET_NAME, namespace, labels: { "app.kubernetes.io/name": "codegate-builder" } },
    type: "Opaque",
    immutable: true,
    data: { "ca.crt": caCertificateBase64 },
  };
}

function validateOptions(options: BuildManifestOptions): void {
  if (!/^[a-z0-9.-]+(?::\d+)?\/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$/.test(options.buildkitImage)) throw new Error("BuildKit image must be a valid digest-pinned OCI reference");
  if (!/^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/.test(options.registrySecretName)) throw new Error("Registry secret name is invalid");
  if (options.egressCidrs.length === 0 || options.egressCidrs.some((value) => !validCidr(value))) throw new Error("At least one valid build egress CIDR is required");
  if (options.egressPorts.length === 0 || options.egressPorts.some((value) => !Number.isInteger(value) || value < 1 || value > 65_535)) throw new Error("Build egress ports are invalid");
}

function validCidr(value: string): boolean {
  const separator = value.lastIndexOf("/");
  if (separator < 1) return false;
  const address = value.slice(0, separator);
  const prefix = Number(value.slice(separator + 1));
  const version = isIP(address);
  return Number.isInteger(prefix) && ((version === 4 && prefix >= 16 && prefix <= 32) || (version === 6 && prefix >= 32 && prefix <= 128));
}

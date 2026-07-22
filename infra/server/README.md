# Three-node RKE2 production bootstrap

This directory prepares a private, highly available Ubuntu 24.04 cluster for the CODEGATE platform. The initial recommended topology is three identical RKE2 server nodes. Each server participates in embedded etcd, can run workloads, owns a dedicated Longhorn filesystem, and exposes hardware KVM to KubeVirt. Add RKE2 agents later when control-plane and workload capacity need to be separated.

Nothing here contains a real host address, domain, credential, or SSH key. The committed inventory uses RFC 5737 documentation addresses and the playbook refuses to run until every safety value is replaced.

## What the playbook installs

- Ubuntu host hardening, AppArmor, audit rules, time sync, unattended security updates, KVM, iSCSI, and NFS prerequisites;
- a Keepalived private VIP and HAProxy endpoint for RKE2 registration, the Kubernetes API, and ingress traffic;
- pinned RKE2 with embedded-etcd HA, Cilium, WireGuard pod encryption, Multus, secrets encryption, CIS mode, and API audit logging;
- Longhorn with three replicas and a dedicated host path as the default StorageClass;
- cert-manager and External Secrets Operator;
- KubeVirt and CDI from checksum-verified release manifests, with software emulation explicitly disabled;
- the supported RKE2 1.36 Traefik edge as a hardened DaemonSet behind HAProxy and fixed private NodePorts;
- recurring compressed etcd snapshots plus six-hour Longhorn volume backups with mandatory off-node storage configuration;
- root-only RKE2/containerd authentication and private-CA trust for the approved private image registry on every schedulable server and agent;
- node, API, networking, storage, operator, and virtualization readiness validation.

The playbook does not partition disks, create public DNS, provision public IPs, invent a cloud SecretStore, generate production PKI, deploy application credentials, or expose learner VMs directly.

## Required infrastructure

Prepare three physical or virtual machines with:

- Ubuntu Server 24.04 amd64, at least 8 vCPU and 32 GiB RAM per node;
- Intel VT-x or AMD-V enabled, `/dev/kvm` available, and nested virtualization enabled if these hosts are themselves virtual machines;
- one stable private address per node, one unused private VIP on the same L2 network, and an internal DNS record for that VIP;
- a separate, preformatted and persistently mounted filesystem at `/var/lib/longhorn`, with at least 200 GiB free per node;
- SSH key authentication from a Linux or WSL Ansible control host;
- an S3-compatible off-node etcd snapshot bucket and a separate Longhorn backup target;
- outbound HTTPS access to the pinned release and chart sources, container registries, the secret backend, and backup endpoints.

Use a dedicated private cluster network. Do not place RKE2 management, etcd, KubeVirt migration, or Longhorn replication ports on the public internet. See [PORTS.md](PORTS.md).

## Operator workflow

Run Ansible from Linux or WSL with a current `ansible-core`. The roles use only built-in modules.

```bash
cd infra/server
cp inventory.example.yml inventory.yml
cp vars/vault.example.yml vars/vault.yml
ansible-vault encrypt vars/vault.yml
ansible-galaxy install -r requirements.yml
```

Edit the ignored `inventory.yml` with private node addresses. Override the committed `REQUIRED_*` values in an ignored inventory/group-vars file, not in the repository. At minimum, provide:

- `deployment_confirmed: true` only after reviewing the finished inventory;
- the private VIP, prefix, interface, internal registration DNS name, management CIDR, and platform base domain;
- SHA-256 values independently verified against the selected RKE2 installer and KubeVirt/CDI release artifacts;
- the S3 endpoint, region, bucket and Longhorn backup target;
- `rke2_ingress_controller: traefik` and `install_ingress_nginx: false`; the retired controller is rejected by preflight.

Generate unrelated random values for the RKE2 token and Keepalived password, replace the vault placeholders, and retain the encrypted vault in an approved credential escrow. The original RKE2 token is required to decrypt bootstrap data during some disaster-recovery scenarios.

Also set `private_registry_host` in the private inventory and provide `private_registry_pull_username`, `private_registry_pull_password`, and `private_registry_ca_pem` only through the encrypted vault. The robot identity must be pull-only. The playbook renders `/etc/rancher/rke2/registries.yaml` and `/etc/rancher/rke2/private-registry-ca.crt` as root-owned `0600` files with task output suppressed, then restarts server and agent services through the serial deployment handler. The node credential is never reused for BuildKit push or Cosign signing.

Validate inputs before making changes:

```bash
ansible-playbook --syntax-check site.yml --ask-vault-pass -e @vars/vault.yml
ansible-playbook site.yml --check --diff --ask-vault-pass -e @vars/vault.yml
```

Review the diff, then deploy:

```bash
ansible-playbook site.yml --ask-vault-pass -e @vars/vault.yml
```

Run the independent verification playbook after maintenance and upgrades:

```bash
ansible-playbook verify.yml --ask-vault-pass -e @vars/vault.yml
```

The roles are idempotent: configuration files are templated, packages and services declare desired state, operators use server-side apply, and mutable release inputs are pinned. A second run should report only runtime checks and explicitly on-demand operations as changed. Review every version pin and checksum before an upgrade; never replace a pin with an unbounded release channel.

## Supported edge controller

Community ingress-nginx retired in March 2026 and is not installed by this baseline. RKE2 1.36 selects its supported Traefik controller explicitly. A pre-start `HelmChartConfig` disables host ports, exposes fixed NodePorts only to the private HAProxy tier, enables the `traefik` IngressClass and HTTP-to-HTTPS redirect, preserves source addresses with trusted PROXY v2, bounds long-lived browser-desktop connections, disables update checks/telemetry and URL-bearing access logs, and keeps the CRD/Gateway providers off until they receive a separate review. Cluster validation checks the DaemonSet, Service type, exact NodePorts, default IngressClass, and both HA listeners.

## Secret backend boundary

External Secrets Operator is installed, but no `ClusterSecretStore` is guessed. A broad or incorrectly scoped store can expose every production secret to learner workloads. Create a provider-specific store with workload identity, namespace restrictions, and audited remote paths, then apply narrowly scoped `ExternalSecret` resources described in [SECRET-CONTRACTS.md](SECRET-CONTRACTS.md).

The Kubernetes bases include narrowly scoped `ExternalSecret` contracts for every referenced platform/runtime application Secret, builder push authentication, validator pull authentication, the shared registry CA, OpenVPN PKI and encrypted Cosign signing material. Most are provider-neutral; the model-gateway contract is Anthropic-specific and exposes only its internal token plus `ANTHROPIC_API_KEY`. Platform contracts reference `codegate-platform-secrets`; runtime, desktop and VPN contracts use separate namespaced stores. Deployment remains blocked until a private overlay creates those stores with access to only the documented remote paths. Learner namespaces never receive a store.

The Longhorn chart references `longhorn-backup-credentials`; backups remain unready until External Secrets creates that Secret in `longhorn-system`. Application Kubernetes bases similarly reference secrets but contain no secret values. Set `external_secrets_provider_configured=true` in private configuration only after the store and contracts are healthy.

## Backup and recovery

RKE2 takes compressed etcd snapshots every six hours and uploads them off-node when the configured S3 target is reachable. The default Longhorn StorageClass assigns `codegate-volume-backup` to every new volume, while membership in Longhorn's `default` recurring-job group also covers existing volumes without an explicit schedule. The job creates off-node backups every six hours and retains 56 changed restore points (about 14 days). Cluster validation checks both the StorageClass selector and job contract. Longhorn data backups remain separate from etcd snapshots: both are required for complete recovery, and external PostgreSQL/Elasticsearch deployments need their own tested backup plans.

Exercise `backup.yml` after deployment and on a schedule controlled outside this repository:

```bash
ansible-playbook backup.yml --ask-vault-pass -e @vars/vault.yml
```

Perform a restore drill at least quarterly and before risky upgrades. Follow [RESTORE.md](RESTORE.md); never discover the procedure during an incident.

## Applying the CODEGATE workloads

After cluster and secret validation, create environment overlays that replace every `example.invalid`, image placeholder, TLS secret name, and cluster-specific endpoint in `infra/kubernetes`. Render with `kubectl kustomize` and inspect the output before applying. The base allows the default RKE2 Kubernetes Service address only; replace that `/32` together with `rke2_service_cidr` if the environment differs. The OpenVPN gateway needs a cluster-supported TUN device resource. The validator additionally needs a reviewed Cosign public key and narrowly controlled registry, transparency-log, and vulnerability-database mirror egress.

The browser desktop service remains ClusterIP. Only its dedicated Traefik TLS ingress reaches it, and its NetworkPolicy accepts traffic only from the RKE2 Traefik Pods in `kube-system`. The gateway exchanges one-time tickets with the platform API and reaches only the selected run workstation on TCP 6080.

RKE2 registry trust and workload registry trust are separate. `registries.yaml` is consumed by containerd for kubelet image pulls. Rootless BuildKit, Cosign, crane, Syft, and Trivy connect to the registry from inside Pods, so the platform base also mounts the fixed `codegate-private-registry-ca` and least-privilege Docker config Secrets read-only and permits only the reviewed registry CIDR on TCP 443. Keep the CIDR in the platform NetworkPolicy identical to `BUILD_EGRESS_CIDRS`; `scripts/validate-infra-contracts.py` rejects drift.

## Dedicated cluster security boundary

This automation is for a dedicated CODEGATE cyber-range cluster, not a shared enterprise Kubernetes cluster. The runtime and builder controllers must discover Pods and read their logs across short-lived, dynamically named namespaces. Kubernetes RBAC cannot express a namespace-name prefix, so those read verbs remain cluster-scoped even though mutation is constrained by fail-closed admission policies. A node pool does not narrow Kubernetes API authorization. Do not deploy unrelated tenants, production business applications, or broadly readable credentials into this cluster, and enforce secret-redacted workload logs. The stronger future topology is separate runtime/build control planes or per-namespace RoleBindings created by a narrowly privileged bootstrap controller.

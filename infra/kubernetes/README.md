# Kubernetes deployment base

`base/` is a security-oriented starting point for deployed overlays. It is intentionally incomplete until an operator supplies environment-specific images, DNS, TLS, secrets, managed data endpoints, and egress rules.

Before applying an overlay:

1. Replace every `ghcr.io/replace-me` image with an immutable, scanned image digest.
2. Replace `range.example.invalid` and the public OIDC/API URLs.
3. Create the provider-specific namespaced `SecretStore` resources documented in `infra/server/SECRET-CONTRACTS.md`. The base contains provider-neutral `ExternalSecret` resources for all referenced application, runtime, registry and signing Secrets; the private overlay supplies only the restricted store identities and may add the optional NVD API key. Shared peer tokens resolve from canonical remote paths so both consumers rotate together. Do not commit rendered Secret values or expose a store to learner namespaces.
4. Replace every `example.invalid` identity, CORS, registry, and ingress value in an environment overlay. Keep `RUNTIME_ADAPTER=service`; `simulator` is rejected with production OIDC authentication. `TARGET_IMAGE_REGISTRIES` must list only registries allowed to host digest-pinned lab images.
5. Add least-privilege egress policies for the environment's DNS, PostgreSQL, Redis, Keycloak/JWKS, managed Elasticsearch, signature-transparency service, vulnerability database mirror, and telemetry destinations. The base models Elasticsearch as a separately operated `codegate-data` namespace with label `app.kubernetes.io/name=elasticsearch`; it intentionally does not install Elasticsearch or ECK. The checked-in builder/validator registry rule is TCP 443 to the documentation CIDR `192.0.2.10/32`; replace it with the private registry's stable routed CIDR(s) and keep it identical to `BUILD_EGRESS_CIDRS`. AI provider calls go only to the in-cluster `model-gateway:9010`; Cilium FQDN policy permits the AI Pod only `services.nvd.nist.gov:443` and permits the model gateway only the fixed `api.openai.com:443` origin. The base denies all other workload egress; never substitute `0.0.0.0/0`.
6. Retain the `traefik` IngressClass and `kube-system`/`app.kubernetes.io/name=traefik` NetworkPolicy selectors from the RKE2 1.36 edge contract. A different supported controller requires an explicit overlay plus equivalent health, WebSocket, source-address and default-deny tests.
7. Install metrics, disruption budgets, backups, restore tests, and alerting.
8. Deploy the separate KubeVirt/OpenVPN runtime plane in `runtime-plane/base`, replace its zero-digest probe/canary placeholders with reviewed images, pass its security review, and retain `RUNTIME_ADAPTER=service` in production.

Build a candidate manifest without mutating a cluster:

```powershell
kubectl kustomize .\infra\kubernetes\base
```

Create environment overlays under `infra/kubernetes/overlays/<environment>`; do not edit the base with live hostnames or credentials.

The private-registry path has three independent controls: RKE2 `registries.yaml` authenticates node/containerd pulls; the builder push and validator pull Docker configs authenticate user-space registry clients; and `codegate-private-registry-ca` supplies private-CA trust to BuildKit, Cosign, crane, Syft, and Trivy. The rootless dynamic BuildKit Job must mount the copied CA at `/etc/codegate/registry-ca/ca.crt` read-only and set `SSL_CERT_FILE` plus the system `SSL_CERT_DIR`. Admission rejects a Job that omits that shape. `COSIGN_REPOSITORY` is a fixed non-secret repository, while its Docker credential and signing key stay in Secrets.

This base assumes a dedicated CODEGATE cyber-range cluster. Runtime and builder controllers have cluster-scoped Pod/log reads because Kubernetes RBAC cannot restrict a ClusterRole by generated namespace prefix. Their writes are constrained by namespace-boundary and workload-shape admission policies, but a node pool does not reduce API authorization. Do not co-locate unrelated tenants or business workloads; use separate runtime/build control planes or a per-namespace RoleBinding design for a stronger boundary.

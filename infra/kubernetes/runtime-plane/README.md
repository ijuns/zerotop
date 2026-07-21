# KubeVirt and OpenVPN runtime plane

This base defines the controller and gateway trust boundaries for real lab sessions. It is not safe to apply unchanged: image names, PKI, internal tokens, Kubernetes API egress, public addresses, and cluster-specific TUN device resources are deliberate placeholders.

Prerequisites:

- a dedicated CODEGATE cyber-range cluster; a node pool alone does not constrain Kubernetes API authorization;
- KubeVirt and a compatible CNI with enforced NetworkPolicy;
- signed Ubuntu and Kali container-disk images with no embedded credentials;
- digest-pinned probe-runner and validation-canary images built from reviewed source;
- an admission policy that allows the controller to manage only namespaces labelled `app.kubernetes.io/managed-by=codegate-runtime`;
- an External Secrets or equivalent workflow that creates `codegate-runtime-secrets` in `codegate-runtime-system`, `codegate-desktop-secrets` in `codegate-desktop-system`, and `codegate-openvpn-secrets` plus `codegate-openvpn-pki` in `codegate-vpn-system`;
- a cluster-supported `/dev/net/tun` device resource;
- a load-balancer and DNS controller capable of creating and promptly deleting one UDP endpoint per OpenVPN-enabled run;
- wildcard DNS for `OPENVPN_GATEWAY_BASE_DOMAIN`, with quotas and alerts for public address consumption.

For each provisioned run, the runtime controller creates the workstation/target cloud-init Secrets and run-local policies. Browser desktop or `both` sessions admit only `codegate-desktop-system/codegate-desktop-gateway` to workstation TCP 6080. OpenVPN or `both` sessions create a dedicated `openvpn-gateway` Deployment and UDP LoadBalancer inside that run namespace. The gateway can reach pods carrying only the same run label, DNS, and the issuer bootstrap endpoint. No central VPN data-plane Pod can reach every run.

The runtime exposes authenticated `GET /v1/runs/{runId}` readiness. A run is ready only after both KubeVirt VMIs report `Ready`; browser runs also require a populated desktop Endpoint, and VPN runs require a Ready gateway Pod plus a published LoadBalancer address. The run namespace stores a bounded readiness deadline (600 seconds by default), after which the runtime returns `failed` with the failed checks instead of remaining in `provisioning` forever. The checked-in egress policy permits the RKE2 Kubernetes Service at `10.43.0.1/32`; change that CIDR in the same private overlay as `rke2_service_cidr` when using a different Service network.

KubeVirt-generated virt-launcher pods require a Pod Security admission level that a normal application namespace should not receive. Run namespaces therefore enforce `privileged` while auditing and warning against `restricted`. This admission label does not grant Kubernetes authorization: the managed `default` ServiceAccount has token automount disabled, no RoleBinding is created, the runtime controller cannot create RBAC resources, and default-deny egress has no Kubernetes API exception. Learners receive only guest desktop or VPN connectivity and must never receive namespace credentials or `kubectl` access.

Secret contracts:

| Secret | Namespace | Required keys |
|---|---|---|
| `codegate-runtime-secrets` | `codegate-runtime-system` | `RUNTIME_INTERNAL_TOKEN`, `OPENVPN_ISSUER_TOKEN`, `SANDBOX_RUNNER_INTERNAL_TOKEN`, `ELASTICSEARCH_API_KEY` |
| `codegate-desktop-secrets` | `codegate-desktop-system` | `DESKTOP_GATEWAY_INTERNAL_TOKEN`, `DESKTOP_SESSION_SIGNING_KEY` |
| `codegate-openvpn-secrets` | `codegate-vpn-system` | `DATABASE_URL`, `OPENVPN_ISSUER_TOKEN`, `OPENVPN_DOWNLOAD_INTERNAL_TOKEN`, `OPENVPN_MASTER_KEY` (32-byte base64) |
| `codegate-openvpn-pki` | `codegate-vpn-system` | `ca.crt`, `ca.key`, `tls-crypt.key` |

The secret manager must replicate the same desktop internal token into the platform API and desktop namespaces. The runtime token is shared only by the platform API and runtime controller. The OpenVPN issuer token is shared only by the runtime and issuer, while the profile-download token is shared only by the API and issuer. The desktop session signing key stays in the desktop namespace. Rotate these as independent trust relationships; never substitute an end-user token.

The OpenVPN image has two sharply separated modes. The static `codegate-openvpn-issuer` control service signs and stores revocable profiles, serves the one-time authenticated download flow, and never receives NET_ADMIN or a TUN device. Each ephemeral run gateway consumes a strong run-scoped bootstrap token, holds only that run's material in memory, and handles UDP 1194 with NET_ADMIN/TUN inside the run namespace. The central issuer must never forward tunnel packets.

`OPENVPN_ALLOWED_CIDR` is the explicit client route advertised by the issuer and must match the cluster pod CIDR or a narrower dedicated lab CIDR. Advertising a broad route does not grant reachability: default-deny plus the run-label egress selector prevents the run gateway from reaching another namespace, platform service, node network, cloud metadata, or Kubernetes API. The issuer must reject a returned profile whose endpoint or allowed CIDR differs from the runtime request.

Profile download uses the same one-time pattern as desktop access. The browser receives a 60-second opaque ticket from the platform API; the public `/download` handler exchanges it over the internal API, loads the encrypted profile by `profileId`, streams one `.ovpn` response with `Cache-Control: no-store`, and never exposes the CA private key or gateway bootstrap token. Replay and expired tickets must return an error.

The desktop gateway image is built from `services/desktop-gateway/Dockerfile`. It accepts a single-use, run-bound ticket, exchanges that ticket with the platform API over an authenticated internal channel, sets its own signed HttpOnly session cookie, and proxies WebSocket/noVNC traffic only to the assigned run's `desktop:6080` service. Its Service remains ClusterIP-only. The dedicated TLS Ingress is the sole public path and NetworkPolicy admits only the RKE2 Traefik controller in `kube-system`; never expose the Service through NodePort or LoadBalancer.

The base uses the deliberate placeholders `desktop.example.invalid` and `codegate-desktop-tls`. A production overlay must replace the host and bind a certificate issued by cert-manager before deployment. Keep TLS redirect enabled and do not route desktop sessions through the platform API.

The base permits controller egress only to the RKE2 Kubernetes Service address `10.43.0.1/32` on TCP 443, DNS, the OpenVPN issuer, and the modelled TLS-enabled `codegate-data` Elasticsearch service on TCP 9200. The deployment overlay must mount the Elasticsearch CA trust required by its selected client image. An environment with a different Service CIDR or a managed Elasticsearch endpoint must replace those exact destinations in its private overlay; do not solve this by allowing unrestricted egress. The same overlay must replace `devices.kubevirt.io/tun` if its device plugin uses a different resource name, and must replace the per-run gateway image/domain placeholders before enabling OpenVPN.

Keep the Pod Security exception limited to runtime-created namespaces bearing the controller's ownership label. Never weaken the platform or data namespaces to accommodate learner VMs. Admission policy should reject privileged run-namespace Pods that are not KubeVirt-generated virt-launchers, and should reject Role, RoleBinding, or token-bearing ServiceAccount creation from every learner-facing identity.

The runtime controller still needs cluster-scoped Pod, Pod-log, Endpoint, and VMI reads because its namespaces are generated and Kubernetes RBAC has no namespace-prefix selector. Its mutation verbs are the minimum required for server-side apply, Secret reads are absent, and the fail-closed admission policies bind every write to approved `range-*` or `validation-*` object shapes. This read scope is why the base is not supported in a shared enterprise cluster. A strongly isolated node pool limits compute placement but not API reads; separate runtime/build control planes or dynamically created namespaced RoleBindings are the stronger design.

Render without applying:

```powershell
kubectl kustomize .\infra\kubernetes\runtime-plane\base
```

The validator calls authenticated `POST /v1/validation-runs`. In KubeVirt mode the runtime creates a disposable validation namespace, starts the candidate target, runs the digest-pinned probe Job, checks functional and intended-vulnerability probes, proves external/control-plane/cross-run blocking, verifies blue-team telemetry through Elasticsearch, and deletes the namespace before returning evidence. The canary image is built from `services/validation-canary/Dockerfile` and serves only `GET /health` on TCP 8080. Its Service deliberately has no ingress allow policy: successful isolation means a validation probe cannot open that healthy endpoint. Replace both zero-digest image placeholders with reviewed build digests and exercise the complete validation path in a staging cluster before enabling publication.

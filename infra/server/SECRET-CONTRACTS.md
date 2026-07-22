# External secret contracts

The bootstrap installs External Secrets Operator but does not create a cloud-provider identity or a cluster-wide secret store. Create a provider-specific `SecretStore` where possible. If a `ClusterSecretStore` is unavoidable, restrict its namespace selection and remote-path permissions before setting `external_secrets_provider_configured=true`.

No learner-managed namespace may reference a platform or infrastructure store.

## Longhorn backup credentials

Create `longhorn-system/longhorn-backup-credentials` from an audited remote path. For an S3-compatible target, Longhorn commonly expects:

| Kubernetes key | Meaning |
|---|---|
| `AWS_ACCESS_KEY_ID` | Backup-only access key or workload-identity value |
| `AWS_SECRET_ACCESS_KEY` | Backup-only secret, when static credentials are unavoidable |
| `AWS_ENDPOINTS` | S3-compatible endpoint when not using the provider default |
| `AWS_CERT` | Optional private CA certificate |
| `VIRTUAL_HOSTED_STYLE` | Provider-specific addressing switch, if required |

Grant only list/read/write/delete access within the dedicated Longhorn backup prefix. Do not reuse the etcd snapshot credential or an administrator credential.

## Platform and runtime Secrets

The deployment bases expect the following Secrets. Checked-in `ExternalSecret` resources fix their target keys and remote path contracts; a private overlay supplies only namespaced `SecretStore` objects and identities.

| Secret | Namespace | Required keys |
|---|---|---|
| `codegate-api-secrets` | `codegate-platform` | `DATABASE_URL`, `REDIS_URL`, `KEYCLOAK_CLIENT_SECRET`, `RUNTIME_INTERNAL_TOKEN`, `DESKTOP_GATEWAY_INTERNAL_TOKEN`, `GRADER_INTERNAL_TOKEN`, `AI_INTERNAL_TOKEN`, `OPENVPN_DOWNLOAD_INTERNAL_TOKEN`, `VALIDATOR_INTERNAL_TOKEN`, `TELEMETRY_INTERNAL_TOKEN`, `BUILDER_INTERNAL_TOKEN` |
| `codegate-ai-secrets` | `codegate-platform` | `AI_INTERNAL_TOKEN`, `GENERATION_PROVIDER_TOKEN`, `REVIEW_PROVIDER_TOKEN`, `RUBRIC_PROVIDER_TOKEN` (the three provider keys use the same internal model-gateway token); optional `NVD_API_KEY` |
| `codegate-model-gateway-secrets` | `codegate-platform` | `MODEL_GATEWAY_INTERNAL_TOKEN`, `ANTHROPIC_API_KEY` |
| `codegate-builder-secrets` | `codegate-platform` | `BUILDER_INTERNAL_TOKEN`, `DATABASE_URL` |
| `codegate-build-registry` | `codegate-platform` | `.dockerconfigjson` (`kubernetes.io/dockerconfigjson`; pull approved bases/catalog layers and push only target plus Cosign signature repositories) |
| `codegate-validator-registry` | `codegate-platform` | `.dockerconfigjson` (`kubernetes.io/dockerconfigjson`; pull-only access to target and Cosign signature repositories) |
| `codegate-private-registry-ca` | `codegate-platform` | `ca.crt` (registry server trust chain only; no client private key) |
| `codegate-builder-signing` | `codegate-platform` | `cosign.key`, `cosign.pub`, `password` (encrypted key and independent password) |
| `codegate-grader-secrets` | `codegate-platform` | `GRADER_INTERNAL_TOKEN`, `ELASTICSEARCH_API_KEY`, `AI_INTERNAL_TOKEN` |
| `codegate-validator-secrets` | `codegate-platform` | `VALIDATOR_INTERNAL_TOKEN`, `SANDBOX_RUNNER_INTERNAL_TOKEN`, `AI_INTERNAL_TOKEN` |
| `codegate-validator-trust` | `codegate-platform` | `cosign.pub` (reviewed image-signing public key) |
| `codegate-telemetry-secrets` | `codegate-platform` | `TELEMETRY_INTERNAL_TOKEN`, `ELASTICSEARCH_API_KEY` |
| `codegate-runtime-secrets` | `codegate-runtime-system` | `RUNTIME_INTERNAL_TOKEN`, `OPENVPN_ISSUER_TOKEN`, `SANDBOX_RUNNER_INTERNAL_TOKEN`, `ELASTICSEARCH_API_KEY` |
| `codegate-desktop-secrets` | `codegate-desktop-system` | `DESKTOP_GATEWAY_INTERNAL_TOKEN`, `DESKTOP_SESSION_SIGNING_KEY` |
| `codegate-openvpn-secrets` | `codegate-vpn-system` | `DATABASE_URL`, `OPENVPN_ISSUER_TOKEN`, `OPENVPN_DOWNLOAD_INTERNAL_TOKEN`, `OPENVPN_MASTER_KEY` (32-byte base64) |
| `codegate-openvpn-pki` | `codegate-vpn-system` | `ca.crt`, `ca.key`, `tls-crypt.key` |

The same runtime token appears only in the API and runtime Secrets. The same desktop internal token appears only in the API and desktop Secrets. The grading token appears only in the API and grader Secrets. The validator token appears only in the API and validator Secrets. The telemetry token appears only in the API and telemetry Secrets. The builder token appears only in the API and builder Secrets. The sandbox-runner token appears only in the validator and runtime Secrets. The AI token appears only in the API, AI, grader, and validator Secrets. Runtime, grader, and telemetry Elasticsearch API keys should be separate least-privilege credentials; the runtime key needs only temporary validation-index create/write/read/delete privileges, while telemetry is limited to the per-run index prefix. The three AI provider-token keys and `MODEL_GATEWAY_INTERNAL_TOKEN` intentionally resolve from the one canonical AI↔gateway credential and must never reuse `AI_INTERNAL_TOKEN` or `ANTHROPIC_API_KEY`. The source registry credential and CA stay in `codegate-platform`; the builder copies only the Docker config and CA into a short-lived `cg-build-*` namespace as immutable `build-registry-auth` and `codegate-private-registry-ca` Secrets, and namespace deletion removes both. The builder push identity, validator pull identity, and node-level pull identity are distinct. The desktop signing key stays in the desktop namespace. The OpenVPN issuer token appears only in the runtime and VPN Secrets, while the download token appears only in the API and VPN Secrets. Rotate each trust relationship independently.

`infra/kubernetes/base/application-external-secrets.yaml` and `registry-external-secrets.yaml` use the namespaced `codegate-platform-secrets` store. Runtime contracts use one store per trusted system namespace: `codegate-runtime-secret-store`, `codegate-desktop-secret-store`, and `codegate-vpn-secret-store`. No store is created by the public base.

Shared relationship tokens always resolve from `codegate/production/internal/<relationship>` property `token`; the same canonical remote value is projected only into the peer Secrets listed above. Service data credentials use `codegate/production/<service>/postgres`, `/redis`, or `/elasticsearch` as applicable. The AI↔gateway credential is `codegate/production/internal/model-gateway:token`, while the Anthropic API key is isolated at `codegate/production/model-gateway/anthropic:api-key`. The gateway egress policy allows only the exact Anthropic API FQDN. The optional `NVD_API_KEY` is added by a private overlay only when provisioned. Desktop session signing uses `codegate/production/desktop/session-signing`, and OpenVPN encryption/PKI use `codegate/production/openvpn/encryption` and `codegate/production/openvpn/pki`.

Registry and signing contracts use:

| Remote key | Property or properties | Kubernetes target |
|---|---|---|
| `codegate/production/builder/registry-push` | `dockerconfigjson` | `codegate-build-registry/.dockerconfigjson` |
| `codegate/production/validator/registry-pull` | `dockerconfigjson` | `codegate-validator-registry/.dockerconfigjson` |
| `codegate/production/private-registry` | `ca.crt` | `codegate-private-registry-ca/ca.crt` |
| `codegate/production/builder/cosign` | `cosign.key`, `cosign.pub`, `password` | `codegate-builder-signing` |

The RKE2 node pull credential is not an ExternalSecret. It comes from encrypted Ansible Vault variables, is rendered only into root-owned node files, and must have pull-only repository scope. Do not copy it into Kubernetes.

After creating provider-specific stores and applying the checked-in `ExternalSecret` resources, require every `ExternalSecret` to report `Ready=True` before workloads roll out. Verify only key names and ownership metadata; never print or compare secret values in CI logs.

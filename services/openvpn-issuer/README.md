# ZeroTOP OpenVPN issuer and per-run gateway

One production image supports two modes:

- `OPENVPN_MODE=issuer` (default) exposes the private issuer API and public
  one-time profile download on port 9100.
- `OPENVPN_MODE=gateway` (also selected automatically when `OPENVPN_RUN_ID` is
  present) retrieves a run/profile-scoped server bundle, writes it to `/run/openvpn`
  (required to be tmpfs), installs a deny-by-default tunnel forwarding chain,
  and supervises OpenVPN until the run expires.

Gateway readiness is signaled only after OpenVPN emits `Initialization Sequence
Completed`; the process then creates `/run/openvpn/ready` and removes it whenever
OpenVPN exits. The runtime Deployment should probe that marker.

Build with the repository root as context:

```powershell
docker build -f services/openvpn-issuer/Dockerfile .
```

## Issuer configuration

Required:

- `DATABASE_URL`
- `PLATFORM_API_URL`
- `OPENVPN_ISSUER_TOKEN` (24+ characters)
- `OPENVPN_DOWNLOAD_INTERNAL_TOKEN` (24+ characters; must match the API)
- `OPENVPN_MASTER_KEY` (canonical base64 encoding of exactly 32 random bytes)
- `OPENVPN_ALLOWED_CIDR`
- mounted `/etc/openvpn/pki/ca.crt`, `/etc/openvpn/pki/ca.key`, and
  `/etc/openvpn/pki/tls-crypt.key`

Optional: `ISSUER_PORT=9100`, `OPENVPN_PROFILE_TTL_MAX_MINUTES=240`,
`OPENVPN_CLIENT_CIDR=10.203.0.0/24`, and explicit PKI path overrides.

The issuer stores client/server bundles as AES-256-GCM ciphertext in PostgreSQL.
It stores only a SHA-256 bootstrap-credential digest. The credential remains valid
only for the same active run/profile so a Kubernetes container or Pod replacement
can recover; revocation or expiry disables it. NetworkPolicy restricts the endpoint
to runtime gateway Pods. Leaf certificates are generated
and signed with argument-array `openssl` executions; no command shell is used.

## HTTP boundaries

- `GET /health`
- authenticated `POST /v1/profiles`
- authenticated `DELETE /v1/profiles/:runId`
- run/profile-scoped `POST /v1/gateways/bootstrap` for gateway restart recovery
- public `GET /download?ticket=...`, which first consumes the platform API ticket

Expose only `/download` through the public Ingress. `/v1/*` and `/health` remain
cluster-private. NetworkPolicy must allow the issuer to reach PostgreSQL and the
platform API, runtime/gateway pods to reach port 9100, and the public ingress
controller to reach only the download route at the HTTP routing layer.

## Gateway security context

The per-run gateway requires `/dev/net/tun`, `NET_ADMIN`, UID 0, and a memory-backed
`/run/openvpn` volume. The issuer deployment should continue to override the same
image to a non-root UID with a read-only root filesystem.

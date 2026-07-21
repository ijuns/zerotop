# Codegate Declarative Environment Builder 1.0.0

This internal service turns a validated `EnvironmentBuildSpec` into a digest-pinned OCI target for the isolated Kubernetes target runtime. The learner workstation remains an Ubuntu/Kali KubeVirt VM. It is a production control-plane component, not a general-purpose container build API.

## Security boundary

- Requests use one internal bearer credential and a required `Idempotency-Key`.
- The parser rejects unknown fields, mutable image tags, non-HTTPS artifacts, private artifact addresses, unsafe paths, active HTML, answer leakage, unsupported question types, shell commands, and user Dockerfiles.
- Base target images, package helper images, output repositories, and exact artifact URL/digest pairs must exist in server-owned allowlists shared with AI generation.
- The generated Dockerfile has only digest-pinned `FROM`, catalog-controlled `COPY`, checksum-verified `ADD`, and fixed OCI `LABEL` instructions. `RUN`, `CMD`, `ENTRYPOINT`, `SHELL`, `ARG`, `ENV`, and interpolation syntax are prohibited.
- Every build gets a new namespace with restricted Pod Security labels, no inbound network, explicit DNS and CIDR/port egress, quotas, deadline, no service-account token, a rootless BuildKit process, dropped Linux capabilities, and runtime-default seccomp/AppArmor.
- Registry credentials and the registry CA are copied from fixed operator-managed Secrets into the ephemeral namespace, mounted read-only, and removed with that namespace. They are never persisted in PostgreSQL, logs, API responses, or provenance.
- PostgreSQL stores idempotency state, build state, the validated spec, results, and append-only audit events. A database trigger prevents audit update or deletion.
- Success is accepted only when BuildKit logs provide an OCI SHA-256 output digest and the builder signs then verifies that canonical digest through the fixed Cosign repository. The API returns a tag-form `imageRef` and separate `imageDigest`; provenance also records their canonical `imageRef@sha256:...` form.

Package catalog entries are trusted, prebuilt OCI file layers. The builder never runs `apt`, `dnf`, package lifecycle hooks, a user script, or an AI-produced command. The base target and package catalog must implement the same Codegate image composition ABI; preparing that signed catalog is an operator/release-pipeline responsibility.

The current ABI is `http-v1`: the final target runs as UID/GID `65532`, with a read-only root filesystem and `/tmp` as its only writable mount; it listens on `0.0.0.0:8080` and serves `/health` plus `/version`. Helper contents must be readable by UID/GID `65532` after catalog-controlled `COPY`. The runtime and validation sandbox enforce the security context and verify the service through its Pod/Service address, so a loopback-only process cannot pass validation.

The builder performs the first Cosign sign-and-verify gate. The independent validator verifies the signature again, generates the Syft SBOM, runs Trivy, checks the OCI runtime contract, executes the sandbox, and makes the publish/quarantine decision. The builder emits SLSA-style provenance material for that validator; it does not claim the provenance itself is a signed attestation.

## API

All `/v1` routes require `Authorization: Bearer <BUILDER_INTERNAL_TOKEN>`.

### `POST /v1/builds`

Requires `Content-Type: application/json` and an 8-128 character `Idempotency-Key`. The request body is:

```json
{
  "labId": "lab-cve-2026-12345",
  "labVersion": 3,
  "requestedBy": "user-123",
  "spec": {
    "schemaVersion": 1,
    "team": "blue",
    "source": {
      "promptDigest": "sha256:<64 lowercase hex characters>",
      "cveIds": ["CVE-2026-12345"]
    },
    "scenario": {
      "summary": "Investigate controlled authentication abuse.",
      "mitreTechniques": ["T1110"]
    },
    "target": {
      "name": "Authentication telemetry range",
      "baseImage": "registry.example.com/containerdisks/ubuntu@sha256:<digest>",
      "outputRepository": "registry.example.com/codegate/targets",
      "service": { "port": 8080, "protocol": "http" },
      "packages": [{ "name": "nginx-lab", "version": "1.2.3" }],
      "artifacts": [{
        "url": "https://artifacts.example.com/auth.ndjson",
        "sha256": "<64 lowercase hex characters>",
        "destination": "/opt/codegate/artifacts/auth.ndjson"
      }],
      "functionalProbes": [{
        "id": "health",
        "kind": "http",
        "method": "GET",
        "path": "/health",
        "expectedStatuses": [200],
        "bodyIncludes": ["healthy"]
      }],
      "vulnerabilityProbes": [{
        "id": "cve-signal",
        "cveId": "CVE-2026-12345",
        "kind": "http",
        "method": "HEAD",
        "path": "/vulnerable",
        "expectedStatuses": [500],
        "bodyIncludes": []
      }]
    },
    "telemetry": {
      "events": [{
        "id": "event-1",
        "document": {
          "@timestamp": "2026-07-21T10:00:00.000Z",
          "event": { "kind": "alert" },
          "threat": { "technique": { "id": ["T1110"] } }
        }
      }]
    },
    "learning": {
      "title": "Detect authentication abuse",
      "summary": "Investigate the controlled event.",
      "sections": [{ "id": "intro", "title": "Introduction", "markdown": "Search the per-run index." }]
    },
    "questions": [
      { "id": "q-elk", "type": "elk_search", "prompt": "Find the source address.", "points": 50 },
      { "id": "q-mitre", "type": "mitre_attack", "prompt": "Map the ATT&CK technique.", "points": 50 }
    ],
    "grading": {
      "hiddenRefs": [
        { "questionId": "q-elk", "refId": "grading://labs/auth/q-elk", "rubricDigest": "sha256:<digest>" },
        { "questionId": "q-mitre", "refId": "grading://labs/auth/q-mitre", "rubricDigest": "sha256:<digest>" }
      ]
    }
  }
}
```

HTTP probes support only `GET`/`HEAD`, bounded status/marker lists, and target-relative paths; the other probe form is `tcp_banner` with bounded banner markers. Service protocol is `http` or `tcp`, matching the runtime sandbox contract. Blue builds require both `elk_search` and `mitre_attack` questions plus 1-100 inline telemetry events. Each event is at most 32,000 UTF-8 bytes and requires `@timestamp`, `event`, and `threat`. Red builds allow only `single_choice`, `multiple_choice`, `free_text`, and `mitre_attack`.

The response is `202` with `queued`, `running`, or an immediate persisted failure. Reusing the same key and canonical request returns the original build. Reusing it with different content returns `409`.

### `GET /v1/builds/:id`

Returns `queued`, `running`, `succeeded`, `failed`, or `cancelled`. Failures expose a stable top-level `failureCode` for the platform API plus a bounded, credential-redacted `failure` summary. A successful response includes:

- a tag-form `imageRef` without `@`, a separate `imageDigest`, and provenance `canonicalImage=imageRef@imageDigest`;
- SLSA-style `buildProvenance` with builder, invocation, materials, subject, and timestamps;
- `consumable.target` containing `imageRef`, `imageDigest`, `expectedCves`, service data, and `validation` with safe probes and blue telemetry for direct runtime sandbox validation;
- generated learning content, public questions, and opaque hidden grading references. No answer key is accepted or returned by this service.

### `DELETE /v1/builds/:id`

Deletes the isolated namespace and atomically marks an active build `cancelled`. It is idempotent for terminal builds and retries cleanup.

`GET /health` is unauthenticated and reports the service version without exposing dependency or secret details.

## Required configuration

| Variable | Purpose |
| --- | --- |
| `BUILDER_INTERNAL_TOKEN` | At least 32 characters; injected from a Secret. |
| `DATABASE_URL` | PostgreSQL connection URL. Use TLS and a builder-specific role. |
| `BUILDKIT_IMAGE` | Digest-pinned rootless BuildKit image. |
| `BASE_IMAGE_ALLOWLIST_JSON` | JSON array of exact digest-pinned `http-v1` target base images. |
| `OUTPUT_REPOSITORY_ALLOWLIST_JSON` | JSON array of exact writable repository names without tags. |
| `PACKAGE_CATALOG_JSON` | JSON object keyed by `name@version`; each value has digest-pinned `imageRef`, fixed `sourcePath`/`destination`, and an approved `runtimeKind`. |
| `ARTIFACT_CATALOG_JSON` | JSON object keyed by lowercase SHA-256 hex; each value contains the exact HTTPS `url`. |
| `BUILD_REGISTRY_SECRET_NAMESPACE` | Namespace holding the operator-managed source Docker config Secret. |
| `BUILD_REGISTRY_SECRET_NAME` | Source Secret name with `.dockerconfigjson`. |
| `COSIGN_KEY_REF`, `COSIGN_PUBLIC_KEY_PATH`, `COSIGN_PASSWORD_FILE` | Read-only paths supplied by `codegate-builder-signing`. |
| `COSIGN_REPOSITORY` | Fixed non-secret OCI repository for signatures. |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | Private registry CA file and system trust directory used by BuildKit/Cosign. |
| `BUILD_EGRESS_CIDRS` | Unique comma-separated public CIDRs for registries and artifact servers. Hostnames alone are deliberately insufficient. |

Optional controls include `PORT` (9004), `BUILD_TIMEOUT_SECONDS` (900), `BUILD_JOB_TTL_SECONDS` (600), `BUILD_EGRESS_PORTS` (443), CPU/memory/ephemeral-storage request and limit variables, `RECONCILE_INTERVAL_MS` (5000), `BUILD_REGISTRY_TARGET_SECRET`, and stable HTTPS `BUILDER_ID`.

Example catalogs:

```json
BASE_IMAGE_ALLOWLIST_JSON=["registry.example.com/containerdisks/ubuntu@sha256:<digest>"]
OUTPUT_REPOSITORY_ALLOWLIST_JSON=["registry.example.com/codegate/targets"]
PACKAGE_CATALOG_JSON={"nginx-lab@1.2.3":{"imageRef":"registry.example.com/catalog/nginx@sha256:<digest>","sourcePath":"/opt/codegate/package/","destination":"/opt/codegate/packages/nginx-lab/","runtimeKind":"declarative-http-v1"}}
ARTIFACT_CATALOG_JSON={"<64 lowercase hex>":{"url":"https://artifacts.example.com/auth.ndjson"}}
```

The AI service consumes the exact same `PACKAGE_CATALOG_JSON` and `ARTIFACT_CATALOG_JSON`. An external model receives only logical package `{name, version}` selections and approved artifact SHA-256/URL pairs; the builder alone resolves helper image, path, and runtime kind. Registry credentials and provider secrets are never part of that payload. Explicit CVE generation requires at least one selected catalog entry.

## Kubernetes and external dependencies

The service requires a Kubernetes service account that can create/read/delete only its `cg-build-*` namespaces and their ResourceQuota, LimitRange, ServiceAccount, ConfigMap, Secret, NetworkPolicy, Pod, and Job resources; read Pod logs; and read exactly `codegate-build-registry`, `codegate-private-registry-ca`, and the admission parameter ConfigMap in its own namespace. Do not grant workload Pods any Kubernetes API token.

The cluster must provide enforced NetworkPolicy, restricted Pod Security admission, DNS namespace labels, unprivileged user namespaces compatible with rootless BuildKit's native snapshotter, sufficient ephemeral storage, and registry/artifact routes covered by `BUILD_EGRESS_CIDRS`. There is intentionally no privileged or `no-process-sandbox` fallback.

Real operation also requires PostgreSQL, a private OCI registry, release-managed digest catalogs, registry credentials, and the separate validator pipeline. The service cannot be externally proven in a workstation without those dependencies and a Kubernetes cluster.

## Development checks

From the repository root after dependency installation:

```text
pnpm --filter @codegate/builder check
pnpm --filter @codegate/builder test
docker build -f services/builder/Dockerfile .
```

The SQL migration is applied under a PostgreSQL advisory lock at startup. Build state is reconciled every five seconds, including after process restarts; deadlines fail closed and trigger namespace cleanup.

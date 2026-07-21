# Codegate target-base HTTP ABI

`target-base` is the executable base image for dynamically assembled HTTP lab targets. Dynamic builds may copy only operator-approved, digest-pinned and signature-verified component layers plus digest-pinned artifacts. AI selects only catalog `componentId@version` values; it never supplies an image coordinate, Dockerfile, command, entrypoint, environment variable, or response header.

Runtime contract:

- `kind=http-v1`, `0.0.0.0:8080`
- numeric UID/GID `65532`
- read-only root filesystem with `/tmp` as the only writable mount
- fixed `GET|HEAD /health` and `/version` endpoints
- approved component manifests at `/opt/codegate/packages/<componentId>/component.json`
- builder-generated `/opt/codegate/component-policy.json`, binding every selected component ID to its operator-approved runtime kind
- approved artifact bodies below `/opt/codegate/artifacts`

The component schema is [component.schema.json](./component.schema.json). Two reviewed runtime kinds exist:

- `declarative-http-v1` serves bounded static or artifact-backed GET/HEAD responses and executes no component code.
- `signed-node-handler-v1` permits an actual curated application/vulnerability adapter at the fixed `handler.mjs` path. The signed manifest pins the handler SHA-256, the builder verifies the helper OCI signature and digest, and the base invokes only its exported `handle(request, context)` function in a bounded worker. Routes and operation IDs are declarative; no command string or shell is accepted.

The loader rejects unknown fields and path traversal, resolves symlinks, verifies handler bytes, caps request/response/files/routes, fixes security headers, and times out worker calls. Kubernetes still supplies the decisive containment boundary: read-only root, UID/GID 65532, `/tmp` only, all capabilities dropped, seccomp, no service-account token and default-deny egress.

Native or non-Node CVEs require a separately reviewed runtime ABI and digest-pinned component/base image. They must not be smuggled into `signed-node-handler-v1` through a command field.

Production builds must pass a digest-pinned Node 24 parent:

```sh
docker build -f services/target-base/Dockerfile \
  --build-arg NODE_RUNTIME_IMAGE='node@sha256:<verified-multi-arch-digest>' \
  -t registry.example/codegate/target-base:<release> .
```

Sign the pushed digest and place that exact digest in both the AI base-image catalog and `BASE_IMAGE_ALLOWLIST_JSON`. A generated image is not publishable until the validator verifies its signature, OCI runtime labels/config, and the hardened sandbox canary.

TCP targets are not part of `http-v1`; the AI and builder reject them until a separate reviewed TCP ABI and base image are introduced.

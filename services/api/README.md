# ZeroTOP Range API

The API owns identity onboarding, tenant authorization, Lab policy, AI generation,
validation, runtime provisioning, grading, reports, rankings and audited access
tickets. Replaceable boundaries are defined in `src/ports.ts`.

Production defaults are fail-closed:

- PostgreSQL is the default repository and `DATABASE_URL` is required.
- PostgreSQL development fixtures are disabled unless
  `SEED_DEVELOPMENT_DATA=true`; the local Compose stack enables them explicitly.
- `AUTH_MODE=oidc` verifies signed OIDC tokens. `X-User-Id` works only in explicit
  `AUTH_MODE=dev`.
- OIDC users authenticate first and then call `/v1/auth/onboarding`; unauthenticated
  password registration is disabled outside development.
- The AI, runtime and trusted grading HTTP adapters require independent internal
  tokens. The local Lab generator, SQLite, runtime simulator and no-op evidence
  grader are development adapters only.
- `ALLOWED_ORIGINS` is a comma-separated exact origin allowlist; wildcard CORS is
  never enabled.

## Local development

Node.js 24 or later is required. From the repository root:

```powershell
$env:AUTH_MODE = "dev"
$env:CODEGATE_DB_PATH = ".data/codegate.db"
corepack pnpm --filter @codegate/api start
```

Development mode seeds `user_dev` and the `Security Lab` organization and defaults
to the SQLite, local generation and runtime simulator adapters. OpenVPN ticket
downloads default to `http://localhost:9100/download`; override
`OPENVPN_DOWNLOAD_PUBLIC_URL` when running the issuer elsewhere.

Verification commands:

```powershell
corepack pnpm --filter @codegate/api check
corepack pnpm --filter @codegate/api test
```

Build the service image using the repository root as Docker context:

```powershell
docker build -f services/api/Dockerfile .
```

## Production configuration

Required values depend on enabled adapters:

- Identity: `AUTH_MODE=oidc`, `OIDC_ISSUER` (or `KEYCLOAK_ISSUER`),
  `OIDC_AUDIENCE`, `OIDC_CLIENT_ID`, and optionally an internal `OIDC_JWKS_URL`.
- Persistence: `REPOSITORY_MODE=postgres`, `DATABASE_URL`.
- AI: `AI_ADAPTER=http`, `AI_SERVICE_URL`, `AI_INTERNAL_TOKEN`.
- Runtime: `RUNTIME_ADAPTER=service`, `RUNTIME_SERVICE_URL`,
  `RUNTIME_INTERNAL_TOKEN`, `TARGET_IMAGE_REGISTRIES`.
- Trusted grading: `GRADER_ADAPTER=service`, `GRADER_SERVICE_URL`,
  `GRADER_INTERNAL_TOKEN`. The service receives `run`, `lab`, private server
  `questions`, and submitted `answers` at `POST /v1/evidence` and returns
  `{ "data": { "evidence": [...] } }` containing validated ELK/AI-rubric
  evidence. The bundled grader listens on port `9002` by default.
- Access gateways: `DESKTOP_GATEWAY_PUBLIC_URL`,
  `DESKTOP_GATEWAY_INTERNAL_TOKEN`, `DESKTOP_TICKET_TTL_SECONDS`,
  `OPENVPN_DOWNLOAD_PUBLIC_URL`, and `OPENVPN_DOWNLOAD_INTERNAL_TOKEN`.
- Browser access: `ALLOWED_ORIGINS`.

A runtime target is accepted only when the server-side Lab config contains an
allowlisted `target.imageRef` and a `sha256:` `target.imageDigest`. Environment
target images are permitted only as development template fallbacks.

## Main routes

- Identity: `GET /v1/me`, `POST /v1/auth/register` (development),
  `POST /v1/auth/onboarding` (OIDC).
- Labs: `GET /v1/labs`, `POST /v1/labs/generate`, `GET /v1/labs/:id`,
  `POST /v1/labs/:id/validate`, `POST /v1/labs/:id/deploy`.
- Runs and grading: `GET /v1/runs/:id`, `POST /v1/runs/:id/submit`.
- Reports: `GET /v1/reports/me`, `GET /v1/reports/organization`,
  `GET /v1/admin/reports/platform`, `GET /v1/rankings?scope=&period=`.
- Platform administration: `GET /v1/admin/overview`, paginated
  `GET /v1/admin/users|organizations|labs|runs`,
  `POST /v1/admin/organizations`,
  `POST /v1/admin/organizations/:id/rotate-join-code`,
  `POST /v1/admin/labs/:id/quarantine`, and
  `POST /v1/admin/runs/:id/terminate`.
- Organization administration:
  `GET /v1/admin/organization/members` (always scoped to the actor's tenant).
- One-time access: `POST /v1/runs/:id/desktop-ticket`,
  `POST /v1/internal/desktop-tickets/exchange`,
  `POST /v1/runs/:id/openvpn-ticket`,
  `POST /v1/internal/openvpn-tickets/exchange`.

Lab generation, deployment, submission and every administrative mutation
require `Idempotency-Key`. Organization join codes are generated with a CSPRNG,
stored only as SHA-256 hashes, and returned in plaintext only on the first
successful create/rotation response. The blue
policy requires `elk_search` plus `mitre_attack`; red Labs accept any non-empty
combination of `single_choice`, `multiple_choice`, `free_text` and
`mitre_attack`. Answer keys remain in a private grading column and are never
serialized to clients. ELK and free-text grades accept only trusted server-side
evidence fetched by the API; client-supplied evidence is rejected. The trusted
evidence and final grade are stored with the result. Score events are append-only
at the database layer.

Desktop and OpenVPN tickets are opaque, stored only as SHA-256 hashes and
consumed atomically once by an authenticated internal gateway. Desktop tickets
expire after 5 minutes by default (`DESKTOP_TICKET_TTL_SECONDS`, bounded to
60-900 seconds); OpenVPN tickets expire after 60 seconds. The desktop gateway
turns a consumed ticket into a signed HttpOnly cookie bounded by the run expiry.
Every mutation and sensitive administrative/report access is audited.

# 환경 변수 계약

운영 비밀은 `.env` 파일로 배포하지 않고 secret manager에서 서비스별 Kubernetes Secret으로 주입합니다. `.env.example`은 이름과 peer 관계를 설명하기 위한 참고 문서이며 실제 credential을 커밋하지 않습니다.

## 공통 원칙

- `*_INTERNAL_TOKEN`, provider token, API key와 signing key는 서비스 관계마다 별도로 생성합니다.
- 동일한 peer 관계의 양쪽에는 같은 token을 주입합니다. 예를 들어 API와 runtime의 `RUNTIME_INTERNAL_TOKEN`은 같아야 합니다.
- 운영 URL은 외부 endpoint이면 `https://`, cluster 내부 endpoint이면 검토된 `.svc.cluster.local` 주소를 사용합니다.
- 운영 이미지는 tag가 아니라 `@sha256:<64 hex>` digest로 고정합니다.
- `CODEGATE_WEB_*` 값은 Next.js 서버가 runtime에 읽어 브라우저로 직렬화하므로 비밀을 넣지 않습니다.
- `AUTH_MODE=dev`, SQLite, simulator, development/mock adapter와 `AI_*_MODE=dev`는 운영에서 금지합니다.

## Web

| 변수 | 필수 | 설명 |
|---|---:|---|
| `CODEGATE_WEB_API_URL` | 예 | 브라우저가 접근하는 TLS API base URL; same-origin proxy는 `/api` |
| `CODEGATE_WEB_KEYCLOAK_URL` | 예 | 브라우저가 접근하는 Keycloak base URL |
| `CODEGATE_WEB_KEYCLOAK_REALM` | 예 | Keycloak realm, 기본 `codegate` |
| `CODEGATE_WEB_KEYCLOAK_CLIENT_ID` | 예 | PKCE public client, 기본 `codegate-web` |
| `CODEGATE_WEB_DEVELOPMENT_IDENTITY` | 운영 금지 | 개발 header 인증 UI 활성화 |
| `CODEGATE_WEB_DEV_USER_ID` | 개발 전용 | 개발 사용자 ID |

`CODEGATE_WEB_*` 값은 image build에 고정되지 않습니다. 동일한 image를 환경별로 배포하고 container 시작 시 주입할 수 있습니다.

## Platform API

| 변수 | 운영 값/설명 |
|---|---|
| `PORT` | HTTP port, 기본 `8080` |
| `NODE_ENV` | `production` |
| `AUTH_MODE` | `oidc` |
| `REPOSITORY_MODE` | `postgres` |
| `DATABASE_URL` | TLS PostgreSQL DSN |
| `PG_POOL_MAX` | PostgreSQL pool 크기, 기본 `10` |
| `SEED_DEVELOPMENT_DATA` | 운영은 `false` |
| `OIDC_ISSUER` | public issuer URL |
| `OIDC_JWKS_URL` | API가 접근하는 JWKS URL |
| `OIDC_AUDIENCE` | 기본 `codegate-api` |
| `OIDC_CLIENT_ID` | 기본 `codegate-web` |
| `ALLOWED_ORIGINS` | 쉼표로 구분한 정확한 HTTPS origin |
| `RUNTIME_ADAPTER` | 운영은 `service` |
| `RUNTIME_SERVICE_URL` | runtime 내부 URL, 기본 port `9000` |
| `RUNTIME_INTERNAL_TOKEN` | API↔runtime 전용 비밀 |
| `RUNTIME_TARGET_IMAGE` | 개발 template fallback 전용; OIDC 운영 모드는 Lab의 builder imageRef+digest를 요구 |
| `TARGET_IMAGE_REGISTRIES` | 쉼표로 구분한 허용 target registry |
| `AI_ADAPTER` | 운영은 `service` |
| `AI_SERVICE_URL` | AI 내부 URL, 기본 port `8001` |
| `AI_INTERNAL_TOKEN` | API/validator/grader↔AI 비밀 |
| `AI_GENERATION_TIMEOUT_MS` | API의 AI draft 전체 제한, Claude 로컬 구성값 `1260000`(21분); 허용 범위 `30000`~`1800000` |
| `ENVIRONMENT_BUILDER_ADAPTER` | 운영은 `service` |
| `BUILDER_SERVICE_URL` | builder 내부 URL, 기본 port `9004` |
| `BUILDER_INTERNAL_TOKEN` | API↔builder 전용 비밀, 32자 이상 |
| `LAB_VALIDATOR_ADAPTER` | 운영은 `service` |
| `VALIDATOR_SERVICE_URL` | validator 내부 URL, 기본 port `9003` |
| `VALIDATOR_INTERNAL_TOKEN` | API↔validator 전용 비밀 |
| `GRADER_ADAPTER` | 운영은 `service` |
| `GRADER_SERVICE_URL` | grader 내부 URL, 기본 port `9002` |
| `GRADER_INTERNAL_TOKEN` | API↔grader 전용 비밀 |
| `TELEMETRY_ADAPTER` | 운영은 `service` |
| `TELEMETRY_SERVICE_URL` | telemetry 내부 URL, 기본 port `9201` |
| `TELEMETRY_INTERNAL_TOKEN` | API↔telemetry 전용 비밀 |
| `DESKTOP_GATEWAY_PUBLIC_URL` | browser desktop TLS URL |
| `DESKTOP_GATEWAY_INTERNAL_TOKEN` | API↔desktop gateway 비밀 |
| `DESKTOP_TICKET_TTL_SECONDS` | browser desktop 일회용 입장 티켓 수명, 기본 `300`초·허용 범위 `60`~`900`초; 세션 자체의 수명이 아님 |
| `OPENVPN_DOWNLOAD_PUBLIC_URL` | `.ovpn` 일회용 다운로드 TLS URL |
| `OPENVPN_DOWNLOAD_INTERNAL_TOKEN` | API↔OpenVPN issuer 다운로드 비밀 |

`KEYCLOAK_ISSUER`와 `KEYCLOAK_JWKS_URL`은 기존 이름 호환 alias이며 새 overlay는 `OIDC_ISSUER`, `OIDC_JWKS_URL`을 사용합니다.

## AI service

| 변수 | 운영 값/설명 |
|---|---|
| `PORT` | HTTP port, 기본 `8001` |
| `AI_AUTH_MODE` | 운영은 `internal` |
| `AI_INTERNAL_TOKEN` | 호출 peer와 공유하는 내부 비밀 |
| `AI_TARGET_BASE_IMAGE` | learner Ubuntu/Kali desktop과 분리된 digest 고정 `http-v1` target base |
| `AI_OUTPUT_REPOSITORY` | 생성 target을 push할 허용 repository |
| `PACKAGE_CATALOG_JSON` | builder와 공유하는 `name@version` 기반 승인 component catalog |
| `ARTIFACT_CATALOG_JSON` | builder와 공유하는 SHA-256 기반 승인 artifact catalog |
| `AI_GENERATION_MODE` | 운영은 `external` |
| `AI_ALLOW_UNCURATED_CVE_SIMULATION` | 로컬 전용 generic CVE simulation 허용 플래그. 기본 `false`, 운영에서는 설정하지 않음 |
| `GENERATION_PROVIDER_URL` | 내부 `http://model-gateway:9010/v1/generate` |
| `GENERATION_PROVIDER_TIMEOUT_SECONDS` | AI 서비스가 generation provider를 기다리는 제한, Claude 로컬 구성값 `1230`초(20분 30초) |
| `GENERATION_PROVIDER_TOKEN` | `MODEL_GATEWAY_INTERNAL_TOKEN`과 같은 peer token |
| `AI_REVIEW_MODE` | 운영은 `external` |
| `REVIEW_PROVIDER_URL` | 내부 `http://model-gateway:9010/v1/review` |
| `REVIEW_PROVIDER_TOKEN` | `MODEL_GATEWAY_INTERNAL_TOKEN`과 같은 peer token |
| `AI_RUBRIC_MODE` | 운영은 `external` |
| `RUBRIC_PROVIDER_URL` | 내부 `http://model-gateway:9010/v1/rubric` |
| `RUBRIC_PROVIDER_TOKEN` | `MODEL_GATEWAY_INTERNAL_TOKEN`과 같은 peer token |
| `NVD_API_KEY` | 선택, NVD CVE 수집 rate limit 확장 |

Provider 응답은 코드의 엄격한 JSON 계약을 통과해야 합니다. 생성 provider가 요청한 팀·문제 유형·CVE 범위를 변경하거나, 공개 문제에 정답을 포함하거나, 운영자가 정한 build/component catalog 밖의 base·output·package·artifact를 반환하면 요청을 거부합니다. 네 catalog 변수는 external 생성 모드에서 모두 필수이며 `PACKAGE_CATALOG_JSON`과 `ARTIFACT_CATALOG_JSON`은 AI와 builder에 **동일한 문자열 값**으로 주입합니다. 명시적인 CVE 요청은 catalog가 비어 있거나 응답이 승인 component/artifact를 하나도 선택하지 않으면 기본적으로 fail-closed 됩니다. 로컬 Desktop 개발에서만 `AI_ALLOW_UNCURATED_CVE_SIMULATION=true`를 명시하면 빈 catalog와 고정된 로컬 target을 사용하는 generic simulation을 허용할 수 있습니다. 이는 해당 CVE를 실제로 재현하는 환경이라는 보장이 아니므로 운영 설정과 Kubernetes manifest에는 넣지 않습니다. 기존 `AI_UBUNTU_BASE_IMAGE`/`AI_KALI_BASE_IMAGE` alias는 동일 값인 경우에만 개발 모드에서 호환되며 external 모드에서는 설정 자체를 거부합니다.

AI 서비스는 요청된 CVE를 provider 호출 전에 NVD 고정 endpoint로 최대 4개씩 병렬 조회합니다. 정규화된 `cveIntel`만 provider 입력에 포함하며, 누락·불일치·조회 실패 시 Lab 생성을 중단합니다. NVD reference URL의 내용은 가져오지 않고 provider token, NVD API key, registry credential은 모델 입력에 포함하지 않습니다.

각 target catalog 항목은 `http-v1` runtime 계약을 따릅니다. 생성 target은 UID/GID `65532`, 읽기 전용 root filesystem, 유일한 쓰기 경로 `/tmp`, `0.0.0.0:8080` HTTP bind, `/health`, `/version` endpoint를 사용해야 합니다. AI 응답의 `target.service`와 `target.runtimeContract`가 이 값과 정확히 일치하지 않으면 builder로 전달하지 않습니다.

Kubernetes의 `codegate-ai-secrets`에는 `AI_INTERNAL_TOKEN`, `GENERATION_PROVIDER_TOKEN`, `REVIEW_PROVIDER_TOKEN`, `RUBRIC_PROVIDER_TOKEN`을 저장하고 NVD 연동 시 `NVD_API_KEY`를 추가합니다. `AI_GENERATION_MODE=external`, `AI_REVIEW_MODE=external`, `AI_RUBRIC_MODE=external`, 세 provider URL과 네 catalog 값은 ConfigMap으로 주입합니다.

## Model gateway

| 변수 | 운영 값/설명 |
|---|---|
| `PORT` | 내부 HTTP port, 기본 `9010` |
| `MODEL_GATEWAY_INTERNAL_TOKEN` | AI가 세 provider endpoint에 공통으로 사용하는 32자 이상 peer token |
| `MODEL_PROVIDER` | `openai` 또는 `anthropic`, 기본 `openai` |
| `OPENAI_API_KEY` | `MODEL_PROVIDER=openai`일 때 gateway에만 주입하는 OpenAI project API key |
| `OPENAI_BASE_URL` | 고정 `https://api.openai.com/v1`; 다른 origin은 시작 단계에서 거부 |
| `OPENAI_MODEL` | Structured Outputs 호환 비 fine-tuned 모델의 명시적 ID, Compose 기본값 `gpt-5.6-sol` |
| `ANTHROPIC_API_KEY` | `MODEL_PROVIDER=anthropic`일 때 gateway에만 주입하는 Anthropic API key |
| `ANTHROPIC_BASE_URL` | 고정 `https://api.anthropic.com/v1`; 다른 origin은 시작 단계에서 거부 |
| `ANTHROPIC_MODEL` | Structured Outputs 호환 Claude 모델의 명시적 ID |
| `ANTHROPIC_VERSION` | Messages API version header, 기본 `2023-06-01` |
| `MODEL_GATEWAY_GENERATION_TIMEOUT_MS` | 최대·기본 `1200000`(20분); Claude 로컬 구성에서도 `1200000` |
| `MODEL_GATEWAY_GENERATION_MAX_ATTEMPTS` | 생성 provider 호출 횟수, 기본 `1`; 허용값 `1` 또는 `2` |
| `MODEL_GATEWAY_DEBUG_RAW_RESPONSE_CAPTURE` | 기본 미설정. 로컬 단일 요청 진단에서만 정확히 `local-explicit`; 그 외 정의된 값은 시작 시 거부. Anthropic 생성 2xx body만 `/tmp/zerotop-generation-provider-response.json`에 exclusive-create, `0600`으로 저장 |
| `MODEL_GATEWAY_REVIEW_TIMEOUT_MS` | 최대 `29000`, 기본 `25000`; AI review의 30초 budget보다 작음 |
| `MODEL_GATEWAY_RUBRIC_TIMEOUT_MS` | 최대 `11000`, 기본 `9000`; AI rubric의 12초 budget보다 작음 |
| `MODEL_GATEWAY_MAX_CONCURRENCY` | body 수신부터 모델 완료까지 포함하는 동시 요청 상한, 기본 `8` |
| `RUBRIC_CATALOG_JSON` | 서버 소유 rubric ID, policy version, threshold, 가중치 합이 1인 criteria catalog |

OpenAI adapter는 공식 Responses API의 `text.format.type=json_schema`, `strict=true`, `store=false`를 사용하고, Anthropic adapter는 공식 Messages API의 `output_config.format.type=json_schema`를 사용합니다. 두 adapter 모두 tool을 제공하지 않으며 생성 결과를 곧바로 신뢰하지 않고 요청 범위와 승인 catalog를 대조해 LabSpec을 서버에서 재조립합니다. 공개 문제에서는 정답을 제거하고 hidden grading contract만 내부에 유지합니다. refusal, incomplete, 과대 응답, schema 불일치와 rubric catalog 밖 ID는 모두 fail-closed 됩니다. 기존 `OPENAI_*_TIMEOUT_MS` 및 `ANTHROPIC_*_TIMEOUT_MS`도 호환 alias로 읽지만 새 배포에는 provider-neutral timeout 이름을 사용합니다.

Claude 로컬 generation 제한은 바깥 호출부터 `API 1260000ms(21분) > AI service 1230초(20분 30초) > model gateway 1200000ms(20분)` 순서입니다. 안쪽 계층의 실패 응답과 진단 정보가 바깥 계층에 전달될 30초씩의 여유를 확보하기 위한 구성입니다. review와 rubric 제한은 기존 값을 유지합니다.

## Environment builder

| 변수 | 필수/기본값 | 설명 |
|---|---|---|
| `PORT` | `9004` | 내부 HTTP port |
| `BUILDER_INTERNAL_TOKEN` | 필수 | API bearer token, 32자 이상 |
| `DATABASE_URL` | 필수 | build 상태와 멱등 기록 PostgreSQL DSN |
| `BUILDKIT_IMAGE` | 필수 | digest 고정 rootless BuildKit image |
| `BASE_IMAGE_ALLOWLIST_JSON` | 필수 | digest 고정 base image JSON 문자열 배열 |
| `OUTPUT_REPOSITORY_ALLOWLIST_JSON` | 필수 | push 가능한 repository JSON 문자열 배열 |
| `PACKAGE_CATALOG_JSON` | 필수 | `name@version`별 digest helper image와 안전한 경로 JSON 객체 |
| `ARTIFACT_CATALOG_JSON` | 필수 | sha256별 HTTPS URL JSON 객체 |
| `BUILD_REGISTRY_SECRET_NAMESPACE` | 필수 | source registry Secret namespace |
| `BUILD_REGISTRY_SECRET_NAME` | 필수 | 복제할 registry Secret 이름 |
| `BUILD_REGISTRY_TARGET_SECRET` | `build-registry-auth` | build namespace 안의 Secret 이름 |
| `BUILD_EGRESS_CIDRS` | 필수 | registry/artifact mirror의 쉼표 구분 CIDR |
| `BUILD_EGRESS_PORTS` | `443` | 쉼표 구분 허용 port |
| `BUILD_TIMEOUT_SECONDS` | `900` | 60~3600초 build 제한 |
| `BUILD_JOB_TTL_SECONDS` | `600` | 완료 Job 정리 TTL |
| `BUILD_CPU_REQUEST` | `500m` | Job CPU request |
| `BUILD_CPU_LIMIT` | `2` | Job CPU limit |
| `BUILD_MEMORY_REQUEST` | `1Gi` | Job memory request |
| `BUILD_MEMORY_LIMIT` | `4Gi` | Job memory limit |
| `BUILD_EPHEMERAL_STORAGE_LIMIT` | `12Gi` | Job 임시 저장소 제한 |
| `RECONCILE_INTERVAL_MS` | `5000` | active build reconcile 주기 |
| `BUILDER_ID` | `https://codegate.ai/builders/environment-builder/v1` | provenance builder ID |
| `KUBERNETES_TOKEN_FILE` | SA 기본 경로 | in-cluster token 파일 |

`KUBERNETES_SERVICE_HOST`, `KUBERNETES_SERVICE_PORT_HTTPS`는 Kubernetes가 자동으로 주입합니다. builder ServiceAccount는 관리 label이 있는 build namespace와 Job/Secret/NetworkPolicy 범위에만 권한을 가져야 합니다.

Kubernetes에서는 `codegate-api-secrets`와 `codegate-builder-secrets`에 같은 `BUILDER_INTERNAL_TOKEN`을 주입합니다. `codegate-builder-secrets`는 builder용 `DATABASE_URL`도 포함합니다. Registry pull/push credential은 이 Secret에 문자열로 넣지 않고 별도의 `kubernetes.io/dockerconfigjson` Secret으로 관리합니다. Base manifest는 `codegate-platform/codegate-build-registry`를 읽도록 제한되어 있으므로 이름을 변경하면 `Role.resourceNames`도 함께 좁은 범위로 patch해야 합니다.

`PACKAGE_CATALOG_JSON`의 키는 소문자 `name@version`이며 `name`은 component ID입니다. 값은 `imageRef`, `sourcePath`, `destination`, `runtimeKind`만 포함합니다. helper image는 digest로 고정하고 source는 `/opt/codegate/package/`, destination은 `/opt/codegate/packages/<componentId>/`로 고정합니다. `runtimeKind`는 `declarative-http-v1` 또는 별도 서명·handler hash 검증을 거치는 `signed-node-handler-v1`입니다. 모델에는 `{name, version}`만 공개하고 image/path/runtime 좌표는 서버가 resolve합니다. `ARTIFACT_CATALOG_JSON`의 키는 64자리 소문자 SHA-256이고 값은 credential·query·fragment가 없는 public HTTPS `url` 하나만 포함합니다. 중복 JSON key, 알 수 없는 필드, mutable image와 안전하지 않은 경로/URL은 서비스 시작 또는 생성 요청 단계에서 거부됩니다.

## Validator와 probe

| 서비스 | 변수 | 설명 |
|---|---|---|
| validator | `PORT` | 기본 `9003` |
| validator | `VALIDATOR_INTERNAL_TOKEN` | API↔validator 비밀 |
| validator | `COSIGN_PUBLIC_KEY_PATH` | 검토된 image signing public key |
| validator | `COSIGN_BIN`, `SYFT_BIN`, `TRIVY_BIN` | 선택, 실행 파일 경로 override |
| validator | `VALIDATOR_CACHE_DIR` | scan cache, 기본 `/var/cache/codegate-validator` |
| validator | `TARGET_IMAGE_REGISTRIES` | 허용 image registry |
| validator | `SANDBOX_RUNNER_URL` | runtime의 `/v1/validation-runs` endpoint |
| validator | `SANDBOX_RUNNER_INTERNAL_TOKEN` | validator↔runtime validation 비밀 |
| validator | `AI_SERVICE_URL`, `AI_INTERNAL_TOKEN` | AI 자동 검토·판정 연결 |
| probe Job | `VALIDATION_PLAN_B64` | runtime이 생성한 bounded probe plan |

`VALIDATION_PLAN_B64`는 사용자가 설정하는 운영 환경 변수가 아니라 검증 Job에 한 번 주입되는 실행별 값입니다.

## Runtime

| 변수 | 운영 값/설명 |
|---|---|
| `PORT` | 기본 `9000` |
| `RUNTIME_MODE` | `kubevirt` |
| `RUNTIME_INTERNAL_TOKEN` | API↔runtime 비밀 |
| `TARGET_IMAGE_REGISTRIES` | 허용 target image registry |
| `UBUNTU_DESKTOP_IMAGE` | digest 고정 Ubuntu desktop image |
| `KALI_DESKTOP_IMAGE` | digest 고정 Kali desktop image |
| `RANGE_ELASTICSEARCH_IMAGE` | Blue run 전용 Elasticsearch용 digest 고정 image |
| `RANGE_KIBANA_IMAGE` | Blue analyst desktop이 사용하는 Kibana용 digest 고정 image |
| `RANGE_ELASTIC_AGENT_IMAGE` | monitored victim의 Elastic Agent용 digest 고정 image |
| `RANGE_SCENARIO_LOG_GENERATOR_IMAGE` | 승인된 scenario event 생성기용 digest 고정 image |
| `RUNTIME_READY_TIMEOUT_SECONDS` | 준비 제한, 기본 `600` |
| `OPENVPN_GATEWAY_IMAGE` | digest 고정 gateway image |
| `OPENVPN_GATEWAY_BASE_DOMAIN` | 실행별 VPN endpoint base domain |
| `OPENVPN_ISSUER_URL` | issuer 내부 URL |
| `OPENVPN_ISSUER_TOKEN` | runtime↔issuer 비밀 |
| `OPENVPN_ALLOWED_CIDR` | 실행 target으로 제한한 route CIDR |
| `SANDBOX_PROBE_IMAGE` | digest 고정 probe-runner image |
| `SANDBOX_RUNNER_INTERNAL_TOKEN` | validator↔runtime validation 비밀 |
| `SANDBOX_TIMEOUT_SECONDS` | 검증 제한, 기본 `300` |
| `SANDBOX_EXTERNAL_PROBE_HOST/PORT` | 외부 egress 차단 검증 목적지, 기본 `1.1.1.1:443` |
| `SANDBOX_CANARY_NAMESPACE/SERVICE/PORT` | 다른 실행 접근 차단 canary, 기본 `codegate-runtime-system/validation-canary:8080` |
| `ELASTICSEARCH_URL` | TLS Elasticsearch URL |
| `ELASTICSEARCH_API_KEY` | 임시 블루팀 검증 인덱스 전용 최소 권한 key |

Kubernetes API host/port와 token 파일은 in-cluster ServiceAccount에서 자동 주입합니다.

### 로컬 Docker desktop runtime

`RUNTIME_MODE=docker`는 개발 워크스테이션에서만 사용합니다. run마다 internal Docker network를 만들며 `browser_desktop`만 지원합니다.

| 변수 | 기본값/설명 |
|---|---|
| `LOCAL_DESKTOP_NETWORK` | run network 이름 prefix, 기본 `codegate-local-desktops` |
| `LOCAL_DESKTOP_GATEWAY_CONTAINER` | 각 run network에 연결할 loopback gateway container 이름 |
| `LOCAL_UBUNTU_DESKTOP_IMAGE` | Blue analyst desktop 개발 image |
| `LOCAL_KALI_DESKTOP_IMAGE` | Red Kali desktop 개발 image |
| `LOCAL_TARGET_IMAGE` | 운영자가 빌드한 로컬 target image |
| `LOCAL_TARGET_SOURCE_IMAGE` | API 요청의 승인된 논리 target image 좌표; `LOCAL_TARGET_IMAGE`로만 매핑 |
| `LOCAL_ELASTICSEARCH_IMAGE` | Blue run Elasticsearch 개발 image |
| `LOCAL_KIBANA_IMAGE` | Blue run Kibana 개발 image |
| `LOCAL_ELASTIC_AGENT_IMAGE` | Blue run agent collector 개발 image |
| `LOCAL_SCENARIO_LOG_GENERATOR_IMAGE` | 제한된 ECS event generator 개발 image |
| `LOCAL_DESKTOP_MEMORY/CPUS/PIDS_LIMIT/SHM_SIZE` | desktop 자원 제한 |
| `LOCAL_TARGET_MEMORY/CPUS/PIDS_LIMIT` | target 자원 제한 |
| `LOCAL_RUNTIME_CLEANUP_INTERVAL_MS` | 만료 run 정리 주기 |

로컬 image 값도 사용자 프롬프트에서 직접 가져오지 않습니다. 서버 설정의 승인 좌표만 허용하며 Blue telemetry event에는 정답·flag material을 포함할 수 없습니다.

## Telemetry와 grader

| 서비스 | 변수 | 설명 |
|---|---|---|
| telemetry | `PORT` | 기본 `9201` |
| telemetry | `TELEMETRY_INTERNAL_TOKEN` | API bearer token |
| telemetry | `ELASTICSEARCH_URL` | TLS Elasticsearch URL |
| telemetry | `ELASTICSEARCH_API_KEY` | 실행별 index create/search/delete 최소 권한 key |
| grader | `PORT` | 기본 `9002` |
| grader | `GRADER_INTERNAL_TOKEN` | API bearer token |
| grader | `ELASTICSEARCH_URL` | TLS Elasticsearch URL |
| grader | `ELASTICSEARCH_API_KEY` | 실행별 증거 read-only key |
| grader | `AI_SERVICE_URL` | 주관식 rubric endpoint base |
| grader | `AI_INTERNAL_TOKEN` | grader↔AI 비밀 |

Telemetry와 grader에는 서로 다른 Elasticsearch API key를 사용합니다.

## Desktop gateway

| 변수 | 설명 |
|---|---|
| `PORT` | 내부 HTTP port, manifest 기본 `8080` |
| `PLATFORM_API_URL` | API 내부 URL |
| `DESKTOP_UPSTREAM_PORT` | workstation noVNC port, 기본 `6080` |
| `DESKTOP_GATEWAY_INTERNAL_TOKEN` | ticket 교환용 API↔gateway 비밀 |
| `DESKTOP_SESSION_SIGNING_KEY` | HttpOnly session 서명 key, 32자 이상 |
| `DESKTOP_SESSION_MAX_MINUTES` | 티켓 교환 후 desktop session cookie의 최대 수명, 기본·최대 `1440`분; 실제 만료는 run 만료와 이 값 중 더 이른 시각 |

## OpenVPN issuer와 실행별 gateway

Issuer의 운영 변수는 다음과 같습니다.

| 변수 | 설명 |
|---|---|
| `OPENVPN_MODE` | `issuer` |
| `PORT` 또는 `ISSUER_PORT` | 기본 `9100` |
| `DATABASE_URL` | profile metadata PostgreSQL DSN |
| `PLATFORM_API_URL` | ticket 교환 API 내부 URL |
| `OPENVPN_ISSUER_TOKEN` | runtime↔issuer 비밀 |
| `OPENVPN_DOWNLOAD_INTERNAL_TOKEN` | API↔issuer download 비밀 |
| `OPENVPN_MASTER_KEY` | profile 암호화용 32-byte base64 key |
| `OPENVPN_ALLOWED_CIDR` | 학습자에게 광고하는 제한된 lab route |
| `OPENVPN_CLIENT_CIDR` | client pool, 기본 `10.203.0.0/24` |
| `OPENVPN_PROFILE_TTL_MAX_MINUTES` | 최대 profile 수명, 기본 `240` |
| `OPENVPN_CA_CERT_PATH` | CA certificate mount 경로 |
| `OPENVPN_CA_KEY_PATH` | CA private key mount 경로 |
| `OPENVPN_TLS_CRYPT_PATH` | tls-crypt key mount 경로 |
| `OPENVPN_CA_KEY_PASSPHRASE_FILE` | 선택, CA key passphrase 파일 |
| `OPENVPN_WORK_DIR` | tmpfs 작업 경로, 기본 `/run/openvpn` |
| `OPENSSL_BINARY` | 기본 `openssl` |

실행별 gateway의 `OPENVPN_RUN_ID`, `OPENVPN_RUN_NAMESPACE`, `OPENVPN_PROFILE_ID`, `GATEWAY_BOOTSTRAP_TOKEN`은 runtime이 생성합니다. gateway에는 `OPENVPN_ISSUER_URL`, tmpfs `OPENVPN_RUNTIME_DIR`, `OPENVPN_BINARY`, `IPTABLES_BINARY`와 `OPENVPN_REQUIRE_TMPFS=true`가 적용됩니다. bootstrap token은 활성 run/profile에만 유효하며 재시작 시 동일한 실행 범위 안에서 다시 가져올 수 있고, 만료·폐기된 credential은 거부됩니다.

## Secret peer 매핑

| 비밀 | 공유 peer |
|---|---|
| `AI_INTERNAL_TOKEN` | API, validator, grader ↔ AI |
| `BUILDER_INTERNAL_TOKEN` | API ↔ builder |
| `RUNTIME_INTERNAL_TOKEN` | API ↔ runtime |
| `SANDBOX_RUNNER_INTERNAL_TOKEN` | validator ↔ runtime |
| `VALIDATOR_INTERNAL_TOKEN` | API ↔ validator |
| `GRADER_INTERNAL_TOKEN` | API ↔ grader |
| `TELEMETRY_INTERNAL_TOKEN` | API ↔ telemetry |
| `DESKTOP_GATEWAY_INTERNAL_TOKEN` | API ↔ desktop gateway |
| `OPENVPN_ISSUER_TOKEN` | runtime ↔ OpenVPN issuer |
| `OPENVPN_DOWNLOAD_INTERNAL_TOKEN` | API ↔ OpenVPN issuer |

한 token을 모든 서비스에 재사용하지 않습니다. 각 관계를 독립적으로 회전하고 audit에서 secret 값 자체는 기록하지 않습니다.

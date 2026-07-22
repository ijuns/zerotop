# 로컬 개발

로컬 실행은 Docker 통합 모드와 Docker가 필요 없는 시뮬레이터 모드로 구분됩니다. 두 모드 모두 외부에 노출하지 않는 개발 전용 구성입니다.

> `infra/.env.example`, Keycloak 개발 계정, 고정 내부 토큰, HTTP endpoint와 보안이 비활성화된 Elasticsearch는 격리된 개발 PC에서만 사용하세요. 운영 자격 증명으로 재사용하거나 공유 네트워크에 공개하면 안 됩니다.

## 준비 사항

- Node.js 24 이상
- Corepack과 pnpm 11.9.0
- AI 서비스 또는 전체 테스트를 실행할 때 Python 3.12 이상
- 통합 모드를 실행할 때 Docker Desktop과 실행 중인 Docker Engine

저장소 루트에서 의존성을 설치합니다.

```powershell
corepack enable
corepack prepare pnpm@11.9.0 --activate
pnpm install --frozen-lockfile
python -m pip install -r .\services\ai\requirements.txt
```

## Docker 없는 시뮬레이터 모드

```powershell
.\scripts\local-dev.ps1 -Mode Local
```

Burp Suite 등 다른 도구가 기본 API 포트 `8080`을 사용 중이면 충돌하지 않는 포트를 지정합니다.

```powershell
.\scripts\local-dev.ps1 -Mode Local -ApiPort 18080 -WebPort 13000
```

PowerShell 실행 정책이 현재 shell에서 스크립트를 막을 때만 process 범위 예외를 적용합니다.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\local-dev.ps1 -Mode Local
```

이 모드는 숨김 창에서 Next.js 웹과 Node API를 시작하고 `scripts/.runtime/`에 SQLite, 로그와 PID metadata를 저장합니다. 실제 Keycloak, Elasticsearch, VM, BuildKit 또는 VPN을 만들지 않습니다. Lab 설계, 팀별 문제 규칙, 제출, 점수, 리포트와 랭킹을 빠르게 확인하는 용도입니다.

시작한 프로세스만 안전하게 종료합니다.

```powershell
.\scripts\stop-local.ps1
```

종료 스크립트는 기록한 PID와 시작 시각을 함께 확인해 PID가 재사용된 다른 프로세스를 종료하지 않습니다.

## Docker 통합 모드

```powershell
.\scripts\local-dev.ps1 -Mode Docker
```

현재 Compose 구성은 다음을 실행합니다.

- Next.js 웹과 Node API
- PostgreSQL과 Redis
- 개발 realm을 import한 Keycloak
- 보안이 비활성화된 단일 노드 Elasticsearch와 Kibana
- 로컬 runtime adapter와 실행별 텔레메트리 서비스
- `-IncludeAi`를 지정한 경우 FastAPI AI 컨테이너

Compose API는 의도적으로 `AUTH_MODE=dev`를 사용하므로 Keycloak을 띄우더라도 웹 요청은 개발 사용자 header를 사용합니다. OIDC 전체 흐름은 운영과 동일한 OIDC 설정으로 별도 통합 환경에서 검증해야 합니다.

```powershell
.\scripts\local-dev.ps1 -Mode Docker -IncludeAi
```

`-IncludeAi`를 지정하면 실행 스크립트가 API를 AI HTTP adapter에 연결하고, 로컬 전용 결정론적 생성·검토·루브릭 모드로 강의 자료와 문제 계약까지 통합 검증합니다. 옵션을 생략하면 API 내부 local adapter를 사용합니다. 이 두 경로 모두 외부 모델 공급자를 대신하는 개발 동작이며, 실제 외부 모델 호출은 [환경 변수 문서](environment-variables.md)의 provider endpoint와 token을 설정한 배포에서만 사용합니다.

실제 Anthropic Claude Messages API 연결을 로컬에서 별도로 검증할 때만 `external-ai` profile을 사용합니다. 기본 Docker/AI 모드는 계속 결정론적으로 동작합니다. External 생성에는 검토된 `AI_TARGET_BASE_IMAGE`, `AI_OUTPUT_REPOSITORY`, `PACKAGE_CATALOG_JSON`, `ARTIFACT_CATALOG_JSON`도 필요합니다. Claude 로컬 개발에서는 키를 콘솔 명령에 직접 넣지 않고, Git에서 제외되는 `.env.claude.local`을 초기화 스크립트로 생성합니다.

Desktop 모드를 한 번 시작해 로컬 target 이미지를 만든 뒤 다음을 실행합니다. 초기화 스크립트는 현재 프로세스/사용자 범위의 `ANTHROPIC_API_KEY`를 읽거나 비공개 입력으로 받고, 서로 다른 내부 token과 실제 로컬 image digest를 기록합니다. 값은 출력하지 않습니다.

```powershell
.\scripts\init-claude-config.ps1
.\scripts\check-claude-config.ps1
.\scripts\start-desktop-claude.ps1
```

전체 Compose topology를 새로 시작하는 경우에만 마지막 명령 대신 `.\scripts\start-claude-ai.ps1`을 사용합니다. `.env.claude.local`은 `.gitignore`와 검사 스크립트가 이중으로 보호하지만 평문 로컬 개발 secret이므로 공유·첨부·커밋하지 않습니다. 운영에서는 Kubernetes Secret 또는 별도 secret manager를 사용합니다.

선택한 API key가 비어 있거나 model ID·catalog·rubric catalog·내부 token이 잘못되면 model-gateway 또는 AI 컨테이너는 시작/요청 단계에서 fail-closed 됩니다. 이 profile은 Kubernetes builder/runtime를 추가하지 않으므로 외부 모델 경계의 계약 검증용이며 완전한 운영 배포를 대체하지 않습니다.

기본 `Docker` 통합 모드는 API lifecycle용 runtime adapter를 사용합니다. 실제 브라우저 GUI와 팀별 로컬 topology를 확인하려면 `-Mode Desktop`을 사용합니다. Desktop 모드는 Blue의 Ubuntu 분석 desktop·ELK·별도 monitored target·agent·scenario log generator와 Red의 Kali·별도 target을 run별 internal Docker network에 구성합니다. 자세한 차이와 실행법은 [로컬 데스크톱 런타임 문서](local-desktop-runtime.md)를 따릅니다.

Kubernetes가 필요한 공급망 검증, KubeVirt VM, 실제 CVE target, 승인된 행위 재생과 실행별 OpenVPN gateway는 로컬 Docker가 대신하지 않습니다. 이 기능들은 [운영 배포 문서](production-deployment.md)의 runtime plane에서 검증합니다.

## 로컬 URL

| 컴포넌트 | URL | Docker 통합 | 시뮬레이터 |
|---|---|---:|---:|
| 웹 | `http://localhost:3000` | 예 | 예 |
| API health | `http://localhost:8080/health` | 예 | 예 |
| Runtime health | `http://localhost:9000/health` | 예 | API 내부 시뮬레이터 |
| Telemetry health | `http://localhost:9201/health` | 예 | 개발 adapter |
| Keycloak | `http://localhost:8081` | 예 | 아니요 |
| Kibana | `http://localhost:5601` | 예 | 아니요 |
| AI health | `http://localhost:8001/health` | 선택 | 아니요 |

PostgreSQL, Redis와 Elasticsearch는 host interface에 공개하지 않습니다. 진단은 `docker compose exec`를 사용합니다.

표의 `http://localhost:5601`은 기본 `Docker` 통합 모드의 공용 개발 Kibana입니다. `Desktop` 모드에서 Blue run마다 생성되는 Kibana는 host에 공개되지 않으며, **실습 워크스페이스 → 워크스페이스 열기**로 들어간 Ubuntu SOC 데스크톱의 브라우저에서만 `http://kibana:5601`로 접속합니다. 자세한 메뉴 순서와 PowerShell 진단 명령은 [로컬 데스크톱 런타임 문서](local-desktop-runtime.md)를 참고합니다.

## 개발 계정

`codegate` realm import에는 다음 고정 사용자가 있습니다.

| 사용자명 | 비밀번호 | Realm 역할 |
|---|---|---|
| `individual` | `Individual123!` | `individual` |
| `org-member` | `Member123!` | `org_member` |
| `org-admin` | `OrgAdmin123!` | `org_admin` |
| `platform-admin` | `PlatformAdmin123!` | `platform_admin` |

이 계정은 예측 가능하므로 운영 realm에 import하지 않습니다. 웹 OIDC 클라이언트는 authorization code flow와 PKCE를 사용합니다. `X-User-Id`와 `X-Dev-Roles`는 `AUTH_MODE=dev`에서만 허용됩니다.

## 상태와 로그 확인

```powershell
docker compose -f .\infra\docker-compose.yml ps
docker compose -f .\infra\docker-compose.yml logs --tail 100 api web runtime telemetry
docker compose -f .\infra\docker-compose.yml exec postgres psql -U codegate -d codegate
docker compose -f .\infra\docker-compose.yml down
```

`down`은 named volume을 보존합니다. 데이터 전체 폐기가 명시적으로 필요한 경우가 아니면 volume 삭제 옵션을 사용하지 않습니다. PostgreSQL 초기화 파일은 빈 volume에서만 적용되므로 보존 환경에는 버전 migration을 사용합니다.

## 검사와 테스트

```powershell
pnpm check
pnpm test
pnpm build
```

`pnpm check`는 각 TypeScript 프로젝트를 검사합니다. `pnpm test`는 Node 테스트와 `services/ai/tests`의 Python unittest를 실행합니다. `pnpm build`는 빌드 스크립트가 있는 workspace를 빌드하며 Next.js production build를 포함합니다.

개별 범위를 빠르게 확인할 수도 있습니다.

```powershell
pnpm --filter @codegate/api test
pnpm --filter @codegate/runtime test
pnpm --filter @codegate/builder test
python -m unittest discover -s services/ai/tests -p "test_*.py"
```

## 시뮬레이터 표시 원칙

`Local`/기본 `Docker` 시뮬레이터가 반환하는 Ubuntu/Kali/ELK 식별자는 lifecycle과 권한 계약을 시험하기 위한 값이며 실제 가상 머신이나 네트워크 접근 권한이 아닙니다. 반면 `Desktop` 모드는 실제 Docker GUI와 run별 컨테이너·network를 만들지만 KubeVirt VM 또는 운영 보안 경계를 의미하지 않습니다. UI는 현재 adapter의 종류와 제한을 구분해 표시해야 합니다.

어떤 로컬 모드도 OpenVPN을 실제 발급하지 않으며, 한 run에 `browser_desktop`과 `openvpn`을 동시에 선택하는 `both` 상태를 허용하지 않습니다. 개발 채점기는 서버가 보관한 ELK fixture ID만 신뢰하고 주관식에는 길이 기반의 결정론적 rubric을 적용합니다. 이 adapter는 OIDC 운영 모드에서 시작 단계부터 거부되며 운영 채점 결과로 사용할 수 없습니다.

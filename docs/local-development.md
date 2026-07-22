# 로컬 개발

로컬에서 돌리는 방법은 두 가지입니다. Docker 없이 시뮬레이터로 빠르게 확인하는 모드, 그리고 Docker Compose로 실제 스택 전체를 띄우는 통합 모드. 둘 다 외부에 노출하면 안 되는 개발 전용 구성이라는 건 똑같습니다.

> `infra/.env.example`, Keycloak 개발 계정, 고정된 내부 토큰, HTTP 엔드포인트, 보안을 꺼둔 로컬 Elasticsearch — 이런 값들은 격리된 개발 PC 밖으로 절대 나가면 안 됩니다. 운영 자격 증명으로 재사용하거나 공유 네트워크에 올리는 순간 그날로 사고입니다.

## 준비물

- Node.js 24 이상
- Corepack과 pnpm 11.9.0
- AI 서비스나 전체 테스트를 돌릴 거면 Python 3.12 이상
- 통합 모드를 쓸 거면 Docker Desktop과 실행 중인 Docker Engine

저장소 루트에서 의존성부터 설치합니다.

```powershell
corepack enable
corepack prepare pnpm@11.9.0 --activate
pnpm install --frozen-lockfile
python -m pip install -r .\services\ai\requirements.txt
```

## Docker 없이, 시뮬레이터 모드

```powershell
.\scripts\local-dev.ps1 -Mode Local
```

Burp Suite 같은 다른 도구가 기본 API 포트 `8080`을 쓰고 있으면 겹치지 않게 포트를 지정하면 됩니다.

```powershell
.\scripts\local-dev.ps1 -Mode Local -ApiPort 18080 -WebPort 13000
```

PowerShell 실행 정책 때문에 스크립트가 막히면, 그때만 프로세스 범위로 예외를 걸어줍니다.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\local-dev.ps1 -Mode Local
```

이 모드는 숨김 창에서 Next.js 웹과 Node API를 띄우고, `scripts/.runtime/`에 SQLite 파일과 로그, PID 정보를 남깁니다. 실제 Keycloak이나 Elasticsearch, VM, BuildKit, VPN은 아무것도 안 만듭니다. Lab 설계부터 팀별 문제 규칙, 제출, 채점, 리포트, 랭킹까지 제품 흐름만 빠르게 확인하고 싶을 때 쓰는 모드라고 보면 됩니다.

띄운 프로세스만 안전하게 정리하려면 이렇게 합니다.

```powershell
.\scripts\stop-local.ps1
```

종료 스크립트는 기록해둔 PID와 시작 시각을 같이 확인합니다. 혹시 PID가 재사용돼서 다른 프로세스로 넘어갔어도 그건 건드리지 않습니다.

## Docker로 통합 모드

```powershell
.\scripts\local-dev.ps1 -Mode Docker
```

지금 Compose 구성이 띄우는 건 다음과 같습니다.

- Next.js 웹과 Node API
- PostgreSQL과 Redis
- 개발용 realm을 import한 Keycloak
- 보안을 꺼둔 단일 노드 Elasticsearch와 Kibana
- 로컬 런타임 어댑터와 실행별 텔레메트리 서비스
- `-IncludeAi`를 붙였으면 FastAPI AI 컨테이너까지

Compose API는 일부러 `AUTH_MODE=dev`로 띄웁니다. 그래서 Keycloak이 떠있어도 웹 요청은 개발용 사용자 헤더로 처리됩니다. OIDC 전체 흐름을 제대로 확인하려면 운영과 똑같은 OIDC 설정을 넣은 별도 통합 환경에서 검증해야 합니다.

```powershell
.\scripts\local-dev.ps1 -Mode Docker -IncludeAi
```

`-IncludeAi`를 넣으면 API가 AI HTTP 어댑터에 연결되고, 로컬 전용 결정론적 생성·검토·루브릭 모드로 강의 자료와 문제 계약까지 통합해서 확인할 수 있습니다. 안 넣으면 API 내부의 local 어댑터를 씁니다. 두 경로 다 외부 모델 공급자를 대신하는 개발용 동작일 뿐이고, 실제로 외부 모델을 부르려면 [환경 변수 문서](environment-variables.md)에 있는 provider 엔드포인트와 토큰을 설정한 배포에서만 됩니다.

실제 Anthropic Claude Messages API 연결을 로컬에서 따로 확인하고 싶을 때만 `external-ai` profile을 씁니다. 기본 Docker/AI 모드는 여전히 결정론적으로 동작하니 걱정 안 해도 됩니다. External 생성을 쓰려면 검토된 `AI_TARGET_BASE_IMAGE`, `AI_OUTPUT_REPOSITORY`, `PACKAGE_CATALOG_JSON`, `ARTIFACT_CATALOG_JSON`도 같이 있어야 합니다. Claude 로컬 개발에서는 키를 콘솔 명령에 직접 박아넣지 않고, Git에서 제외되는 `.env.claude.local`을 초기화 스크립트로 만들어서 씁니다.

Desktop 모드를 한 번 먼저 띄워서 로컬 타깃 이미지를 만들어놓고 다음을 실행합니다. 초기화 스크립트는 현재 프로세스나 사용자 범위의 `ANTHROPIC_API_KEY`를 읽어가거나, 없으면 비공개 입력으로 받습니다. 서로 다른 내부 토큰과 실제 로컬 이미지 digest도 같이 기록해줍니다. 값은 화면에 출력하지 않습니다.

```powershell
.\scripts\init-claude-config.ps1
.\scripts\check-claude-config.ps1
.\scripts\start-desktop-claude.ps1
```

Compose topology를 아예 처음부터 새로 띄우는 경우에만 마지막 명령 대신 `.\scripts\start-claude-ai.ps1`을 씁니다. `.env.claude.local`은 `.gitignore`와 검사 스크립트가 이중으로 막아주긴 하지만, 어쨌든 평문 로컬 개발 시크릿이니 공유하거나 첨부하거나 커밋하면 안 됩니다. 운영에서는 Kubernetes Secret이나 별도 secret manager를 씁니다.

API 키가 비어 있거나 model ID, catalog, rubric catalog, 내부 토큰 중 하나라도 잘못되면 model-gateway나 AI 컨테이너는 시작하거나 요청받는 단계에서 바로 막힙니다. 이 profile은 Kubernetes builder/runtime을 추가하지 않으니, 외부 모델 경계의 계약을 확인하는 용도지 완전한 운영 배포를 대체하는 건 아닙니다.

기본 `Docker` 통합 모드는 API 라이프사이클용 런타임 어댑터를 씁니다. 실제 브라우저 GUI와 팀별 로컬 topology를 눈으로 보고 싶으면 `-Mode Desktop`을 쓰세요. Desktop 모드는 블루팀의 Ubuntu 분석 데스크톱·ELK·별도 관측 대상·에이전트·시나리오 로그 생성기와 레드팀의 Kali·별도 타깃을 실행별 내부 Docker 네트워크에 구성해줍니다. 자세한 차이와 사용법은 [로컬 데스크톱 런타임 문서](local-desktop-runtime.md)에 정리해뒀습니다.

Kubernetes가 있어야만 되는 공급망 검증, KubeVirt VM, 실제 CVE 타깃, 승인된 행위 재생, 실행별 OpenVPN 게이트웨이는 로컬 Docker로는 흉내낼 수 없습니다. 이런 것들은 [운영 배포 문서](production-deployment.md)의 runtime plane에서 확인합니다.

## 로컬 접속 주소

| 컴포넌트 | URL | Docker 통합 | 시뮬레이터 |
|---|---|---:|---:|
| 웹 | `http://localhost:3000` | 예 | 예 |
| API health | `http://localhost:8080/health` | 예 | 예 |
| Runtime health | `http://localhost:9000/health` | 예 | API 내부 시뮬레이터 |
| Telemetry health | `http://localhost:9201/health` | 예 | 개발 어댑터 |
| Keycloak | `http://localhost:8081` | 예 | 아니요 |
| Kibana | `http://localhost:5601` | 예 | 아니요 |
| AI health | `http://localhost:8001/health` | 선택 | 아니요 |

PostgreSQL, Redis, Elasticsearch는 host 인터페이스에 공개하지 않습니다. 뭔가 확인하고 싶으면 `docker compose exec`로 들어가서 봅니다.

위 표의 `http://localhost:5601`은 기본 `Docker` 통합 모드에서 공용으로 쓰는 개발 Kibana입니다. `Desktop` 모드에서 블루팀 실행마다 새로 생기는 Kibana는 host에 노출되지 않고, **실습 워크스페이스 → 워크스페이스 열기**로 들어간 Ubuntu SOC 데스크톱 안의 브라우저에서만 `http://kibana:5601`로 접속됩니다. 메뉴 순서와 PowerShell 진단 명령은 [로컬 데스크톱 런타임 문서](local-desktop-runtime.md)를 참고하세요.

## 개발용 계정

`codegate` realm에는 다음 고정 사용자가 들어 있습니다.

| 사용자명 | 비밀번호 | Realm 역할 |
|---|---|---|
| `individual` | `Individual123!` | `individual` |
| `org-member` | `Member123!` | `org_member` |
| `org-admin` | `OrgAdmin123!` | `org_admin` |
| `platform-admin` | `PlatformAdmin123!` | `platform_admin` |

이 계정들은 비밀번호가 예측 가능해서 운영 realm에는 절대 import하지 않습니다. 웹 OIDC 클라이언트는 authorization code flow에 PKCE를 씁니다. `X-User-Id`와 `X-Dev-Roles` 헤더는 `AUTH_MODE=dev`일 때만 통합니다.

## 상태와 로그 확인

```powershell
docker compose -f .\infra\docker-compose.yml ps
docker compose -f .\infra\docker-compose.yml logs --tail 100 api web runtime telemetry
docker compose -f .\infra\docker-compose.yml exec postgres psql -U codegate -d codegate
docker compose -f .\infra\docker-compose.yml down
```

`down`은 named volume을 지우지 않고 남겨둡니다. 데이터를 완전히 날려야 할 명확한 이유가 없다면 volume 삭제 옵션은 쓰지 않는 게 좋습니다. PostgreSQL 초기화 파일은 빈 volume에만 적용되니, 데이터를 유지하는 환경에서는 버전 마이그레이션으로 갑니다.

## 검사와 테스트

```powershell
pnpm check
pnpm test
pnpm build
```

`pnpm check`는 TypeScript 프로젝트를 전부 훑습니다. `pnpm test`는 Node 테스트와 `services/ai/tests`의 Python unittest를 같이 돌립니다. `pnpm build`는 빌드 스크립트가 있는 워크스페이스를 전부 빌드하는데, Next.js production 빌드도 여기 포함됩니다.

범위를 좁혀서 빠르게 확인하고 싶으면 이렇게도 됩니다.

```powershell
pnpm --filter @codegate/api test
pnpm --filter @codegate/runtime test
pnpm --filter @codegate/builder test
python -m unittest discover -s services/ai/tests -p "test_*.py"
```

## 시뮬레이터라는 걸 화면에서 알 수 있어야 한다

`Local` 모드나 기본 `Docker` 모드의 시뮬레이터가 돌려주는 Ubuntu/Kali/ELK 식별자는 라이프사이클과 권한 계약을 시험해보기 위한 값일 뿐, 진짜 가상 머신이나 네트워크 접근 권한이 아닙니다. `Desktop` 모드는 한 발 더 나가서 실제 Docker GUI와 실행별 컨테이너·네트워크를 진짜로 만들지만, 그렇다고 KubeVirt VM이나 운영 수준의 보안 경계를 의미하지는 않습니다. UI는 지금 어떤 어댑터가 돌고 있고 뭐가 한계인지 구분해서 보여줘야 합니다. 시뮬레이터를 진짜처럼 보이게 만드는 건 개발 편의를 위한 함정이 될 수 있으니까요.

어떤 로컬 모드도 OpenVPN을 실제로 발급하지는 않고, 한 실행에서 `browser_desktop`과 `openvpn`을 동시에 켜는 `both` 상태도 허용하지 않습니다. 개발용 채점기는 서버가 갖고 있는 ELK fixture ID만 신뢰하고, 주관식에는 길이 기반의 결정론적 루브릭을 씁니다. 이 어댑터는 OIDC 운영 모드에서는 시작 단계부터 거부되고, 당연히 운영 채점 결과로 쓸 수 없습니다.

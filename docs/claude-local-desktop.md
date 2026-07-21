# Desktop 모드에서 Claude 연결하기

이 절차는 이미 실행 중인 `local-dev.ps1 -Mode Desktop`의 Runtime, Desktop Gateway, 웹, 개인 Lab 컨테이너를 유지하면서 AI 서비스만 추가하고 API만 짧게 재시작합니다. 시작 과정에서는 Anthropic에 요청을 보내지 않습니다. 실제 모델 호출은 사용자가 AI Lab 생성, AI 검토 또는 주관식 채점을 요청할 때만 발생합니다.

## 1. 비밀 설정 파일

저장소 루트의 `.env.claude.local`을 사용합니다. 이 이름은 저장소의 `.gitignore`에 있는 `.env.*` 규칙으로 제외됩니다. 스크립트도 저장소 내부 설정 파일이 Git ignore 대상인지 확인하고, 그렇지 않으면 실행을 거부합니다.

설정 파일은 다음 경계를 지킵니다.

- `ANTHROPIC_API_KEY`는 `model-gateway` 컨테이너에만 전달합니다.
- Platform API에는 `AI_INTERNAL_TOKEN`만 전달합니다.
- API 프로세스를 만들 때 Anthropic/OpenAI key와 model-gateway token을 환경에서 제거하여 불필요하게 상속하지 않게 합니다.
- 설정값과 API key는 콘솔이나 로그에 출력하지 않습니다.
- Compose 컨테이너 환경은 로컬 관리자에게 보일 수 있으므로 이 방식은 로컬 개발 전용입니다. 운영에서는 Kubernetes Secret 또는 별도 secret manager를 사용합니다.

필수 변수는 다음과 같습니다.

```dotenv
MODEL_PROVIDER=anthropic
ANTHROPIC_API_KEY=YOUR_KEY
ANTHROPIC_MODEL=YOUR_STRUCTURED_OUTPUTS_COMPATIBLE_MODEL
ANTHROPIC_VERSION=2023-06-01

AI_INTERNAL_TOKEN=RANDOM_INTERNAL_TOKEN_AT_LEAST_24_CHARACTERS
MODEL_GATEWAY_INTERNAL_TOKEN=RANDOM_GATEWAY_TOKEN_AT_LEAST_32_CHARACTERS

AI_GENERATION_MODE=external
AI_ALLOW_UNCURATED_CVE_SIMULATION=true
AI_REVIEW_MODE=external
AI_RUBRIC_MODE=external
AI_GENERATION_TIMEOUT_MS=1260000
GENERATION_PROVIDER_TIMEOUT_SECONDS=1230
MODEL_GATEWAY_GENERATION_TIMEOUT_MS=1200000
MODEL_GATEWAY_GENERATION_MAX_ATTEMPTS=1

AI_TARGET_BASE_IMAGE=REVIEWED_IMAGE@sha256:REQUIRED_64_CHARACTER_DIGEST
AI_OUTPUT_REPOSITORY=REVIEWED_OUTPUT_REPOSITORY
PACKAGE_CATALOG_JSON={}
ARTIFACT_CATALOG_JSON={}
RUBRIC_CATALOG_JSON={"incident-analysis-v1":{"policyVersion":"incident-analysis-2026.07","passThreshold":0.7,"criteria":[{"id":"evidence","description":"격리된 실습 데이터의 구체적인 증거를 사용한다.","weight":0.6},{"id":"mitigation","description":"비례적인 탐지 또는 완화 조치를 설명한다.","weight":0.4}]}}
```

Generation timeout은 `API 1260000ms(21분) > AI service 1230초(20분 30초) > model gateway 1200000ms(20분)` 순서로 설정합니다. Claude에는 최대 20분을 제공하고, 바깥 계층에는 gateway의 실제 오류가 전달될 30초씩의 여유를 둡니다. review와 rubric timeout은 기존 값을 사용합니다.

`PACKAGE_CATALOG_JSON`과 `ARTIFACT_CATALOG_JSON`은 모델이 임의 이미지나 파일을 선택하지 못하게 하는 운영자 소유 allowlist입니다. 로컬 기본값 `{}`는 일반 프롬프트 기반 강의·시나리오 생성을 위한 값입니다. 이 로컬 helper는 `AI_ALLOW_UNCURATED_CVE_SIMULATION=true`를 설정하므로 catalog에 없는 CVE도 고정된 `codegate/local-target` 위에서 generic simulation으로 생성할 수 있습니다. 이 결과는 해당 CVE의 실제 취약 구현을 보장하지 않으며 운영 배포에서는 반드시 플래그를 끄고 검토된 package 또는 artifact를 사용해야 합니다.

## 2. 연결

먼저 Desktop 모드가 실행 중이어야 합니다.

```powershell
Invoke-RestMethod http://localhost:18080/health
Invoke-RestMethod http://localhost:9000/health
Invoke-RestMethod http://localhost:9001/health
```

처음 한 번은 저장소 루트에서 Git 제외 설정 파일을 생성하고 확인합니다. 키는 현재 프로세스/사용자 환경 변수에서 읽거나 비공개 입력으로 받으며 화면에 출력하지 않습니다.

```powershell
.\scripts\init-claude-config.ps1
.\scripts\check-claude-config.ps1
```

`codegate/local-target:development` 이미지를 다시 빌드해 digest가 바뀌면 `.\scripts\init-claude-config.ps1 -Force`로 로컬 설정을 갱신합니다. 시작 helper는 catalog digest와 실제 이미지가 다르면 실행을 거부합니다.

그 다음 Desktop 연결 helper를 실행합니다.

```powershell
.\scripts\start-desktop-claude.ps1
```

이미 AI 이미지를 빌드한 경우에는 다음처럼 재사용할 수 있습니다.

```powershell
.\scripts\start-desktop-claude.ps1 -SkipBuild
```

다른 포트로 Desktop 모드를 시작했다면 같은 값을 전달합니다.

```powershell
.\scripts\start-desktop-claude.ps1 -ApiPort 18080 -WebPort 3000
```

스크립트는 다음 순서로 동작합니다.

1. `.env.claude.local`의 형식, 필수값, JSON catalog와 Git ignore 상태를 검사합니다.
2. Compose의 `postgres`, `redis`, `elasticsearch`, `ai`, `model-gateway`만 시작합니다.
3. AI health가 정상일 때 기존 Platform API 프로세스만 종료합니다.
4. 로컬 `codegate/local-target:development` 이미지의 실제 Docker content digest를 조회해 runtime fallback 좌표에 사용합니다. 0으로 채운 가짜 digest는 사용하지 않습니다.
5. 동일한 SQLite DB와 Runtime/Gateway 설정을 유지하면서 `AI_ADAPTER=http`, `AI_SERVICE_URL=http://localhost:8001`로 API를 다시 시작합니다.
6. API health가 실패하면 결정론적 local AI adapter로 API를 복구합니다.

Runtime, Desktop Gateway, 웹 프로세스와 이미 배포된 개인 Lab 컨테이너는 중지하거나 삭제하지 않습니다.

## 3. 시작 상태만 확인

다음 health 요청은 외부 모델을 호출하지 않습니다.

```powershell
Invoke-RestMethod http://localhost:8001/health
Invoke-RestMethod http://localhost:18080/health

docker compose --env-file .\.env.claude.local `
  -f .\infra\docker-compose.yml `
  --profile ai --profile external-ai ps ai model-gateway
```

Anthropic 호출과 비용 발생 여부는 이후 사용자가 직접 AI Lab 생성으로 확인합니다. API key가 대화, 화면 공유 또는 로그에 노출되었다면 Anthropic Console에서 기존 key를 폐기하고 새 key를 설정 파일에 넣어야 합니다.

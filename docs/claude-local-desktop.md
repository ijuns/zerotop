# Desktop 모드에서 Claude 연결하기

이 절차는 이미 떠 있는 `local-dev.ps1 -Mode Desktop`의 Runtime, Desktop Gateway, 웹, 개인 Lab 컨테이너는 그대로 두고 AI 서비스만 새로 추가한 다음 API만 짧게 재시작합니다. 시작하는 과정 자체는 Anthropic에 아무 요청도 안 보냅니다. 실제 모델 호출은 사용자가 AI Lab 생성, AI 검토, 주관식 채점을 요청할 때만 일어납니다.

## 1. 비밀 설정 파일

저장소 루트의 `.env.claude.local`을 씁니다. 이 이름은 저장소 `.gitignore`의 `.env.*` 규칙에 이미 걸려 있어서 자동으로 제외됩니다. 스크립트도 시작하기 전에 이 파일이 Git ignore 대상인지 한 번 더 확인하고, 아니면 그냥 실행을 거부합니다.

설정 파일은 이런 경계를 지킵니다.

- `ANTHROPIC_API_KEY`는 `model-gateway` 컨테이너에만 넘깁니다.
- Platform API에는 `AI_INTERNAL_TOKEN`만 넘깁니다.
- API 프로세스를 새로 띄울 때는 Anthropic 키와 model-gateway 토큰을 환경에서 지워서, 굳이 필요 없는 프로세스가 상속받는 일이 없게 합니다.
- 설정값과 API 키는 콘솔이나 로그에 절대 찍지 않습니다.
- Compose 컨테이너 환경은 로컬 관리자 눈에 보일 수 있으니, 이 방식은 어디까지나 로컬 개발 전용입니다. 운영에서는 Kubernetes Secret이나 별도 secret manager를 씁니다.

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

Generation timeout은 바깥에서 안쪽으로 갈수록 짧아지게 잡습니다: API 1260000ms(21분) > AI service 1230초(20분 30초) > model gateway 1200000ms(20분). Claude에는 최대 20분을 주고, 바깥 계층들에는 gateway가 실제로 낸 오류가 제대로 전달될 수 있도록 30초씩 여유를 둔 겁니다. review와 rubric timeout은 기존 값 그대로 씁니다.

`PACKAGE_CATALOG_JSON`과 `ARTIFACT_CATALOG_JSON`은 모델이 아무 이미지나 파일을 마음대로 고르지 못하게 막는, 운영자가 소유한 allowlist입니다. 로컬 기본값 `{}`는 그냥 일반 프롬프트 기반 강의·시나리오 생성용입니다. 이 로컬 헬퍼는 `AI_ALLOW_UNCURATED_CVE_SIMULATION=true`를 켜두기 때문에, 카탈로그에 없는 CVE도 고정된 `codegate/local-target` 위에서 generic simulation으로 만들어낼 수 있습니다. 다만 이 결과가 해당 CVE를 실제로 재현한다는 보장은 전혀 없습니다. 운영 배포에서는 이 플래그를 반드시 끄고, 검토된 패키지나 아티팩트를 써야 합니다.

## 2. 연결하기

먼저 Desktop 모드가 떠 있어야 합니다.

```powershell
Invoke-RestMethod http://localhost:18080/health
Invoke-RestMethod http://localhost:9000/health
Invoke-RestMethod http://localhost:9001/health
```

처음 한 번은 저장소 루트에서 Git 제외 설정 파일을 만들고 확인합니다. 키는 현재 프로세스/사용자 환경 변수에서 읽거나 비공개 입력으로 받고, 화면에는 출력하지 않습니다.

```powershell
.\scripts\init-claude-config.ps1
.\scripts\check-claude-config.ps1
```

`codegate/local-target:development` 이미지를 다시 빌드해서 digest가 바뀌었다면 `.\scripts\init-claude-config.ps1 -Force`로 로컬 설정을 갱신합니다. 시작 헬퍼는 카탈로그 digest와 실제 이미지가 다르면 실행을 거부합니다.

그다음 Desktop 연결 헬퍼를 실행합니다.

```powershell
.\scripts\start-desktop-claude.ps1
```

이미 AI 이미지를 빌드해뒀다면 이렇게 재사용할 수 있습니다.

```powershell
.\scripts\start-desktop-claude.ps1 -SkipBuild
```

Desktop 모드를 다른 포트로 띄웠다면 같은 값을 넘겨줍니다.

```powershell
.\scripts\start-desktop-claude.ps1 -ApiPort 18080 -WebPort 3000
```

스크립트는 이 순서로 움직입니다.

1. `.env.claude.local`의 형식, 필수값, JSON 카탈로그, Git ignore 상태를 검사합니다.
2. Compose의 `postgres`, `redis`, `elasticsearch`, `ai`, `model-gateway`만 띄웁니다.
3. AI health가 정상이면 기존 Platform API 프로세스만 종료합니다.
4. 로컬 `codegate/local-target:development` 이미지의 실제 Docker content digest를 조회해서 runtime fallback 좌표로 씁니다. 0으로 채운 가짜 digest는 여기서 쓰지 않습니다.
5. 같은 SQLite DB와 Runtime/Gateway 설정을 그대로 유지한 채, `AI_ADAPTER=http`, `AI_SERVICE_URL=http://localhost:8001`로 API를 다시 띄웁니다.
6. API health가 실패하면 결정론적 local AI 어댑터로 다시 되돌립니다.

Runtime, Desktop Gateway, 웹 프로세스와 이미 배포해둔 개인 Lab 컨테이너는 건드리지 않습니다.

## 3. 시작 상태만 확인하기

아래 헬스 체크는 외부 모델을 전혀 호출하지 않습니다.

```powershell
Invoke-RestMethod http://localhost:8001/health
Invoke-RestMethod http://localhost:18080/health

docker compose --env-file .\.env.claude.local `
  -f .\infra\docker-compose.yml `
  --profile ai --profile external-ai ps ai model-gateway
```

실제로 Anthropic을 호출해서 비용이 발생하는지는 이후에 사용자가 직접 AI Lab 생성을 해봐야 확인됩니다. 혹시 API 키가 대화나 화면 공유, 로그에 노출됐다면 바로 Anthropic Console에서 기존 키를 폐기하고 새 키를 설정 파일에 넣어야 합니다.

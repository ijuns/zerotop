# Render 무료 데모 배포

제출·시연용 라이브 링크를 Render 무료 티어에 올리는 절차입니다. 실 서비스가
아니라 **데모 배포**입니다: 로그인은 Keycloak 없이 자체 세션(`AUTH_MODE=local`)을
쓰고, 데이터는 재시작마다 초기화되며 부팅 시 데모 데이터가 다시 채워집니다.

## 구성

`render.yaml` 블루프린트가 두 서비스를 정의합니다.

- **zerotop-api** — Node API (`infra/docker/api.Dockerfile`), SQLite, `AUTH_MODE=local`
- **zerotop-web** — Next.js 웹 (`apps/web/Dockerfile`)

웹이 `/api/*`를 API로 프록시하므로 브라우저는 웹 도메인 하나만 사용합니다.
**CORS가 개입하지 않습니다.**

## 절차

1. Render 대시보드 → **New → Blueprint** → 이 저장소 연결. `render.yaml`이
   자동으로 두 서비스를 만듭니다.
2. 첫 배포 후, **zerotop-api** 서비스의 환경변수에서 `sync: false`로 표시된 값을
   설정합니다.
   - `SEED_FIXTURE_PASSWORD` — 시드 계정 전체(관리자 `admin@zerotop.local` 포함)의
     로그인 비밀번호. **직접 정하세요.** 저장소에 있는 기본값(`ZeroTOP!2026`)은
     이 값을 설정하면 더 이상 통하지 않습니다.
3. 두 서비스가 `Live` 상태가 되면 **zerotop-web**의 `.onrender.com` 주소가
   라이브 링크입니다.

`SESSION_SIGNING_SECRET`은 Render가 자동 생성하고, `API_PROXY_TARGET`은 API
서비스 주소로 자동 연결됩니다.

## 시연 흐름

1. 웹 링크 방문 → 로그인 화면
2. 회원가입(이메일·이름·소속·비밀번호 8자 이상·필수 동의) → 자동 로그인 → 앱 진입
3. 로그아웃 → 이메일·비밀번호로 재로그인
4. 시즌 랭킹 → 개인 전체 / 조직 종합 모두 데이터 표시
5. 관리자 기능: `admin@zerotop.local` / `SEED_FIXTURE_PASSWORD`로 로그인

## 한계 (데모이므로)

- **재시작 시 초기화** — 무료 티어는 디스크가 휘발성입니다. 부팅 시 랭킹 데이터는
  다시 채워지지만, **방문자가 만든 계정은 사라집니다.**
- **콜드 스타트** — 15분 미사용 시 잠들어 첫 접속이 ~50초 걸립니다.
- **데모 인증** — `AUTH_MODE=local`은 자체 구현 세션입니다. 검증된 인증
  인프라(Keycloak OIDC)가 아니므로 실 서비스에는 부적합합니다.

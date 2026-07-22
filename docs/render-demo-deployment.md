# Render 무료 데모 배포

제출·시연용 라이브 링크가 필요할 때 Render 무료 티어에 올리는 절차입니다. 미리 말해두면 이건 실 서비스가 아니라 **데모 배포**입니다. 로그인은 Keycloak 없이 자체 세션(`AUTH_MODE=local`)을 쓰고, 데이터는 재시작할 때마다 초기화되지만 부팅 시점에 데모 데이터를 다시 채워 넣습니다.

## 구성

`render.yaml` 블루프린트 하나가 서비스 두 개를 정의합니다.

- **zerotop-api** — Node API (`infra/docker/api.Dockerfile`), SQLite, `AUTH_MODE=local`
- **zerotop-web** — Next.js 웹 (`apps/web/Dockerfile`)

웹이 `/api/*`를 API로 프록시해주기 때문에 브라우저는 웹 도메인 하나만 보면 됩니다. **CORS가 아예 개입할 일이 없습니다.**

## 배포 절차

1. Render 대시보드에서 **New → Blueprint**로 이 저장소를 연결합니다. `render.yaml`이 알아서 두 서비스를 만들어줍니다.
2. 첫 배포가 끝나면, **zerotop-api** 서비스 환경변수에서 `sync: false`로 표시된 값을 채웁니다.
   - `SEED_FIXTURE_PASSWORD` — 시드 계정 전체(관리자 `admin@zerotop.local` 포함)의 로그인 비밀번호입니다. **직접 정하세요.** 저장소에 있는 기본값(`ZeroTOP!2026`)은 이 값을 설정하는 순간 더 이상 안 먹힙니다.
3. 두 서비스가 `Live` 상태로 바뀌면 **zerotop-web**의 `.onrender.com` 주소가 그대로 라이브 링크입니다.

`SESSION_SIGNING_SECRET`은 Render가 자동으로 만들어주고, `API_PROXY_TARGET`도 API 서비스 주소로 자동 연결되니 따로 손댈 게 없습니다.

## 시연할 때 이렇게 흘러갑니다

1. 웹 링크 방문 → 로그인 화면
2. 회원가입(이메일·이름·소속·비밀번호 8자 이상·필수 동의) → 자동 로그인 → 앱 진입
3. 로그아웃 → 이메일·비밀번호로 재로그인
4. 시즌 랭킹 → 개인 전체와 조직 종합 모두 데이터가 채워진 상태로 표시
5. 관리자 기능은 `admin@zerotop.local` / `SEED_FIXTURE_PASSWORD`로 로그인해서 확인

## 데모라서 감안해야 할 한계

- **재시작하면 초기화됩니다.** 무료 티어는 디스크가 휘발성이라, 부팅할 때 랭킹 데이터는 다시 채워지지만 **방문자가 그동안 만든 계정은 사라집니다.**
- **콜드 스타트가 있습니다.** 15분 동안 아무도 안 쓰면 잠들고, 다시 깨어나는 첫 접속에는 50초 정도 걸립니다.
- **인증은 데모 수준입니다.** `AUTH_MODE=local`은 자체 구현한 세션이지, 검증된 인증 인프라(Keycloak OIDC)가 아닙니다. 실 서비스로 그대로 쓰기엔 부족합니다.

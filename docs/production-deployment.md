# 운영 배포

이 문서는 저장소에 들어 있는 운영 구성을 실제 인프라에 얹는 순서를 다룹니다. Ubuntu/RKE2 서버 부트스트랩, Kubernetes 플랫폼 plane, KubeVirt/OpenVPN runtime plane 베이스까지 다 저장소에 있지만, 그렇다고 이 코드가 알아서 클라우드 계정을 만들거나 물리 서버를 구매해주지는 않습니다.

## 지금 배포 상태

애플리케이션과 인프라 코드는 로컬 저장소에 다 준비돼 있습니다. 실제로 운영에 올리려면 클라우드 계정, 서버 주소, SSH 키, 도메인과 DNS/TLS 권한, 이미지 레지스트리, 외부 모델·데이터 서비스 자격 증명이 필요합니다. 이 값들이 채워지지 않은 상태에서는 공개 URL도, 운영 클러스터도 생기지 않습니다. 체크아웃만으로는 아무 일도 안 일어난다는 뜻입니다.

## 외부에서 미리 준비해야 할 것

### 컴퓨팅과 네트워크

- 권장 시작 구성은 KVM을 노출하는 Ubuntu Server 24.04 amd64 3대입니다.
- 노드당 최소 8 vCPU, 32 GiB RAM, `/var/lib/longhorn` 전용 200 GiB 이상을 기준으로 삼되, 실제 동시 실행 수에 맞춰 늘리세요.
- 관리·etcd·storage·KubeVirt migration 트래픽은 사설망에 두고, private VIP와 내부 DNS를 준비합니다.
- 플랫폼, Identity, 데스크톱, VPN 다운로드와 실행별 VPN 게이트웨이용 DNS를 준비합니다.
- TLS 인증서 발급 경로와, 실행별 UDP 1194 LoadBalancer를 감당할 수용량·quota를 확보합니다.
- etcd snapshot용 S3 호환 저장소, Longhorn backup target, PostgreSQL과 Elasticsearch의 독립 백업을 준비합니다.

### 데이터, Identity, AI

- PostgreSQL은 플랫폼 API, 빌더, OpenVPN issuer가 TLS로 접근하도록 하고, 서비스별로 최소 권한 계정을 나눠 씁니다.
- Keycloak에는 운영 realm과 public web client, API audience를 만들고 운영 redirect URI만 허용합니다.
- Elasticsearch/Kibana는 실행별 인덱스 lifecycle, TLS trust, telemetry/grader/runtime별로 분리한 API 키를 발급합니다.
- AI 생성·검토·주관식 루브릭 요청은 네트워크로 격리된 내부 `model-gateway:9010`으로만 보냅니다. 게이트웨이는 고정된 `https://api.anthropic.com/v1` 주소만 호출하고, Anthropic API 키와 AI↔게이트웨이 내부 토큰은 비밀 관리 시스템에 넣어둡니다.
- AI 서비스의 `AI_TARGET_BASE_IMAGE`와 `AI_OUTPUT_REPOSITORY`는 빌더 허용 목록과 같은 운영 카탈로그를 가리켜야 합니다. 학습자용 Ubuntu/Kali 데스크톱 이미지는 이것과 완전히 별개입니다. `PACKAGE_CATALOG_JSON`과 `ARTIFACT_CATALOG_JSON`도 AI와 빌더에 같은 값으로 주입합니다. 외부 모델은 논리적인 `{name, version}`만 고르고, 실제 digest나 경로는 서버가 알아서 resolve합니다. 모델이 좌표를 임의로 바꾸거나 카탈로그 밖 컴포넌트/아티팩트를 고른 응답은 그냥 거부됩니다.
- CVE를 지정한 생성 요청은 AI가 NVD 원문을 고정 엔드포인트에서 조회·정규화한 `cveIntel`을 provider에 넘긴 뒤에야 진행됩니다. NVD 조회가 실패하거나, 응답 ID가 요청과 다르거나, 승인된 컴포넌트/아티팩트를 하나도 안 골랐다면 그 자리에서 막힙니다.
- 베이스는 AI egress를 기본적으로 다 막아둡니다. AI Pod은 Cilium FQDN 정책으로 `services.nvd.nist.gov:443`만 직접 부를 수 있고, 생성·검토·루브릭 요청은 NetworkPolicy가 허용한 내부 model gateway로만 나갑니다. 게이트웨이는 `api.anthropic.com:443`만 호출할 수 있고, `0.0.0.0/0`이나 다른 모델 공급자 주소는 애초에 열려 있지 않습니다.
- Redis를 쓰는 확장 기능이 있다면 TLS/인증 엔드포인트를 붙이되, 플랫폼 정합성의 기준점은 여전히 PostgreSQL로 둡니다.

### 이미지 공급망

- 플랫폼 서비스, Ubuntu/Kali 데스크톱, 취약 타깃, BuildKit, probe runner, validation canary, OpenVPN 게이트웨이 이미지를 전부 사설 레지스트리에 push합니다.
- 배포하는 모든 이미지는 불변 digest로 고정하고, SBOM을 만들고, 취약점 스캔과 Cosign 서명까지 끝냅니다.
- 빌더의 베이스 이미지, 출력 저장소, 패키지 헬퍼 이미지, 다운로드 아티팩트는 운영자가 검토한 allowlist JSON으로 관리합니다.
- 승인된 베이스/헬퍼 이미지는 `http-v1` ABI로 release 검증을 거칩니다. 최종 타깃은 UID/GID `65532`, read-only root, `/tmp`만 쓰기 가능, `0.0.0.0:8080` bind, `/health`와 `/version` 엔드포인트를 제공해야 하고, runtime과 validation sandbox도 같은 security context를 강제로 적용합니다.
- 빌더의 egress는 레지스트리와 검토된 아티팩트 미러의 고정 CIDR/포트로만 열어둡니다.

### 비밀과 정책

- External Secrets Operator나 그에 준하는 secret manager를 연동하고, 소스 컨트롤에는 평문 Kubernetes Secret을 절대 넣지 않습니다.
- peer 서비스끼리 공유하는 내부 토큰은 관계마다 다른 값을 씁니다. runtime, builder, grader, telemetry, validator, desktop, VPN — 각 관계가 다 별도 토큰입니다.
- `codegate-api-secrets`와 `codegate-builder-secrets`에는 같은 `BUILDER_INTERNAL_TOKEN`을 주입하고, builder 전용 Secret에는 `DATABASE_URL`도 같이 넣습니다.
- `codegate-ai-secrets`에는 `AI_INTERNAL_TOKEN`과 내부 게이트웨이용 `GENERATION_PROVIDER_TOKEN`, `REVIEW_PROVIDER_TOKEN`, `RUBRIC_PROVIDER_TOKEN`(다 같은 bearer 값), 쓴다면 `NVD_API_KEY`까지 넣습니다. `codegate-model-gateway-secrets`에는 그 canonical `MODEL_GATEWAY_INTERNAL_TOKEN`과 `ANTHROPIC_API_KEY`만 넣습니다. 내부 provider URL, 세 AI 모드의 `external` 값, 빌드 카탈로그 좌표는 비밀이 아니니 ConfigMap으로 따로 뺍니다.
- registry 인증은 일반 환경 변수 Secret과 섞지 않습니다. 검토된 `kubernetes.io/dockerconfigjson` source Secret을 builder system namespace에 두고, build namespace에는 필요한 시간만큼만 `BUILD_REGISTRY_TARGET_SECRET` 이름으로 복제합니다.
- 조직별 데이터 보존 기간, 최대 동시 실행 수, VM 리소스 quota, Lab 최대 수명, 허용 CVE와 예상 취약점 정책을 미리 확정해둡니다.
- CNI NetworkPolicy, Pod Security, admission policy, audit 수집을 운영 정책에 연결합니다.

## 배포 순서

### 1. RKE2 서버 준비

`infra/server`의 예제 inventory와 vault를 복사하고, `REQUIRED_*` 값을 전부 실제 사설 주소와 독립적인 random secret으로 바꿉니다.

```bash
cd infra/server
cp inventory.example.yml inventory.yml
cp vars/vault.example.yml vars/vault.yml
ansible-vault encrypt vars/vault.yml
ansible-galaxy install -r requirements.yml
ansible-playbook --syntax-check site.yml --ask-vault-pass -e @vars/vault.yml
ansible-playbook site.yml --check --diff --ask-vault-pass -e @vars/vault.yml
ansible-playbook site.yml --ask-vault-pass -e @vars/vault.yml
ansible-playbook verify.yml --ask-vault-pass -e @vars/vault.yml
```

이 playbook이 RKE2 HA, Cilium, Longhorn, cert-manager, External Secrets, KubeVirt/CDI, audit와 백업 기반까지 구성해줍니다. 실제 디스크 파티션, DNS, 공인 IP, SecretStore, 운영 PKI, 애플리케이션 credential은 운영자가 직접 채워 넣어야 합니다.

### 2. 이미지 빌드·서명

CI에서 workspace 검사와 테스트를 통과한 커밋으로 각 Dockerfile을 빌드합니다. 나온 digest는 SBOM·스캔·서명 증거와 함께 release metadata에 기록하고, 운영 overlay는 tag가 아니라 digest를 참조하게 합니다.

검증용 `probe-runner`와 `validation-canary`도 일반 서비스와 똑같이 검토하고 서명합니다. 취약 타깃 이미지의 예상 CVE는 허용된 의도적 취약점으로 따로 기록해두고, 예상하지 못한 critical 취약점이 나오면 검증 실패로 처리합니다.

### 3. 데이터와 Identity 연결

PostgreSQL 마이그레이션을 적용하고 API가 `REPOSITORY_MODE=postgres`로 뜨도록 맞춥니다. Keycloak issuer/JWKS/audience/client 값, Elasticsearch CA와 서비스별 API 키, CORS origin을 실제 TLS 호스트명으로 설정합니다. 개발용 시드 데이터와 개발 인증은 운영에서 전부 끕니다.

### 4. 환경별 Kubernetes overlay 작성

`infra/kubernetes/base`와 `infra/kubernetes/runtime-plane/base`는 직접 건드리지 않고, `infra/kubernetes/overlays/<environment>`에 private patch를 작성합니다.

- `ghcr.io/replace-me`, `replace-with-digest`, zero digest를 실제 서명된 digest로 교체
- `example.invalid` 호스트명과 TLS Secret 이름을 전부 교체
- ExternalSecret, SecretStore, CA mount 연결
- 실제 Service/Pod CIDR, Kubernetes API `/32`, registry·Elasticsearch egress 목적지를 지정. AI→내부 게이트웨이, AI→NVD, 게이트웨이→Anthropic API 외에는 egress를 열지 않기
- builder registry pull/push Secret과 카탈로그 JSON 연결
- ingress controller label, Gateway/Ingress class, WebSocket timeout 확인
- OpenVPN TUN 디바이스 리소스, wildcard DNS, UDP LoadBalancer 연결
- 블루 실행의 분석 데스크톱→Kibana, 시나리오 러너→피해 시스템, 피해 시스템 Elastic Agent→텔레메트리만 허용하고, 레드 실행은 Kali/VPN→타깃 선언 포트만 허용하는 기본 차단 NetworkPolicy 연결
- `browser_desktop`과 `openvpn` 중 선택한 ingress만 만들고, 전환 시 이전 티켓/인증서를 폐기하는 정책 연결

적용 전에 렌더링 결과를 저장해서 검토합니다.

```bash
kubectl kustomize infra/kubernetes/overlays/production > rendered-platform.yaml
kubectl kustomize infra/kubernetes/runtime-plane/overlays/production > rendered-runtime.yaml
```

placeholder 값, 평문 Secret, mutable 이미지 태그, 과도한 ClusterRole, 지나치게 넓은 `0.0.0.0/0` egress가 없는지 확인한 다음 server-side apply를 씁니다.

### 5. 배포 후 수용 검증

다음 항목을 전부 통과해야 실제 사용자 트래픽을 엽니다.

1. OIDC 로그인과 개인/조직 온보딩, 잘못된 가입 코드 거부, 두 번째 조직 가입 차단
2. 블루/레드 AI 생성, 선언형 환경 스키마와 공개 문제에서 정답 자료가 제거되는지
3. 빌더의 허용 목록 성공과, 임의 이미지/패키지/아티팩트/egress 거부
4. 서명·SBOM·Trivy·기능·AI 판정·격리 점검이 자동 통과하고, 실패 시 사람 승인 없이 자동 격리되는지
5. 외부 인터넷, Kubernetes API, 클라우드 메타데이터, 다른 실행 canary 접근이 막히는지
6. 블루팀 Ubuntu 분석 데스크톱과 레드팀 Kali 데스크톱의 일회용 티켓·WebSocket 연결, 실행별 Kibana/타깃 진입점
7. OpenVPN 프로필 일회용 다운로드, 같은 실행 타깃 접근, 다른 실행·플랫폼 접근 차단, browser/OpenVPN 동시 활성화 거부
8. 블루팀의 별도 피해 시스템, Elastic Agent 등록, 승인된 시나리오 행위, 실행별 Elasticsearch 인덱스/Kibana space 검색·증거 선택·MITRE 채점
9. 레드팀의 별도 취약 타깃, Kali/VPN에서만 허용된 서비스·취약점 재현과 네 가지 문제 유형 채점
10. 실행 만료나 관리자 강제 종료 후 VM, 네임스페이스, 데스크톱/VPN 자격 증명, Elastic Agent 토큰, Elasticsearch 인덱스/Kibana space가 정리되는지
11. 개인·조직·플랫폼 리포트, 조직/전체 랭킹의 권한과 개인정보 공개 동의
12. 감사 로그, 메트릭, 알림, rate/resource quota
13. etcd, Longhorn, PostgreSQL, Elasticsearch 백업과 격리 환경 restore drill

## 운영 전환 기준

- 모든 public endpoint에 유효한 TLS와 필요한 보안 헤더가 적용돼 있어야 합니다.
- 개발 계정, `AUTH_MODE=dev`, SQLite, 시뮬레이터, deterministic AI mode는 운영 워크로드에 하나도 남아있으면 안 됩니다.
- 모든 내부 토큰과 API 키에 대해 소유자, 회전 주기, 폐기 절차가 문서로 남아 있어야 합니다.
- 자동 검증 증거와 정리 증거가 보존되고, 격리된 Lab은 절대 실행되지 않아야 합니다.
- 동시 실행 수와 VM 리소스 사용량에 대한 용량 테스트, 장애 시 강제 정리, 비용 경보를 다 통과해야 합니다.
- 백업이 성공했다는 것만으로는 부족하고, 별도 환경에서 실제로 복구가 성공한 시각과 RTO/RPO를 기록해야 합니다.

서버별 상세 값과 포트는 `infra/server/README.md`와 `infra/server/PORTS.md`, Kubernetes 비밀 계약은 `infra/server/SECRET-CONTRACTS.md`를 같이 참고하세요.

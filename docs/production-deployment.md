# 운영 배포

이 문서는 저장소에 포함된 운영 구성을 실제 인프라에 적용하기 위한 순서를 설명합니다. 저장소에는 Ubuntu/RKE2 서버 부트스트랩, Kubernetes 플랫폼 plane과 KubeVirt/OpenVPN runtime plane 베이스가 있지만 클라우드 계정이나 물리 서버를 자동으로 구매하지는 않습니다.

## 현재 배포 상태

애플리케이션과 인프라 코드는 로컬 저장소에 구성되어 있습니다. 실제 운영 배포에는 공급자 계정, 서버 주소, SSH key, 도메인과 DNS/TLS 권한, 이미지 레지스트리, 외부 모델·데이터 서비스 자격 증명이 필요합니다. 이 값이 제공되지 않은 상태에서는 공개 URL이나 운영 cluster가 생성되지 않습니다.

## 외부 선결 조건

### 컴퓨팅과 네트워크

- 권장 시작 토폴로지는 KVM을 노출하는 Ubuntu Server 24.04 amd64 3대입니다.
- 노드당 최소 8 vCPU, 32 GiB RAM, `/var/lib/longhorn` 전용 200 GiB 이상을 기준으로 실제 동시 실행 수에 맞춰 산정합니다.
- 관리·etcd·storage·KubeVirt migration 트래픽은 사설망에 두고, private VIP와 내부 DNS를 준비합니다.
- 플랫폼, Identity, 데스크톱, VPN 다운로드와 실행별 VPN gateway용 DNS를 준비합니다.
- TLS 인증서 발급 경로와 실행별 UDP 1194 LoadBalancer 수용량·quota를 확보합니다.
- etcd snapshot용 S3 호환 저장소, Longhorn backup target, PostgreSQL과 Elasticsearch의 별도 백업을 준비합니다.

### 데이터, Identity와 AI

- PostgreSQL은 플랫폼 API, 빌더와 OpenVPN issuer가 접근할 수 있도록 TLS와 서비스별 최소 권한 계정을 구성합니다.
- Keycloak에는 운영 realm, public web client와 API audience를 구성하고 운영 redirect URI만 허용합니다.
- Elasticsearch/Kibana에는 실행별 인덱스 lifecycle, TLS trust와 telemetry/grader/runtime별로 분리한 API key를 발급합니다.
- AI 생성·검토·주관식 루브릭 요청은 네트워크로 격리된 내부 `model-gateway:9010`으로만 전달합니다. 게이트웨이는 선택한 제공자에 따라 고정된 `https://api.openai.com/v1` 또는 `https://api.anthropic.com/v1` origin만 호출하며 선택한 API key와 AI↔gateway 내부 token은 비밀 관리 시스템에 저장합니다.
- AI 서비스의 단일 `AI_TARGET_BASE_IMAGE`와 `AI_OUTPUT_REPOSITORY`는 builder 허용 목록과 동일한 운영 catalog를 가리키도록 설정합니다. learner의 Ubuntu/Kali desktop image는 이 target base와 별도입니다. `PACKAGE_CATALOG_JSON`과 `ARTIFACT_CATALOG_JSON`도 AI와 builder에 같은 값으로 주입합니다. 외부 모델은 logical `{name, version}`만 선택하며 서버가 digest/path를 resolve합니다. 모델이 좌표를 바꾸거나 catalog 밖 component/artifact를 선택한 응답은 거부됩니다.
- CVE 지정 생성은 AI가 NVD 원문을 고정 endpoint에서 조회·정규화한 `cveIntel`을 provider에 전달한 뒤 수행합니다. NVD 조회가 실패하거나 응답 ID가 요청과 다르거나 승인 component/artifact를 선택하지 않으면 생성은 fail-closed 됩니다.
- base는 AI egress를 기본 차단합니다. AI Pod은 Cilium FQDN 정책으로 `services.nvd.nist.gov:443`만 직접 호출하고, 생성·검토·루브릭은 NetworkPolicy가 허용한 내부 model gateway로만 보냅니다. 기본 게이트웨이는 `api.openai.com:443`만 호출하며 Anthropic overlay는 이를 `api.anthropic.com:443`으로 교체합니다. 두 제공자를 동시에 열거나 일반 `0.0.0.0/0`을 허용하지 않습니다.
- Redis를 사용하는 확장 기능은 TLS/인증 endpoint를 사용하되 플랫폼 정합성의 source of truth는 PostgreSQL로 유지합니다.

### 이미지 공급망

- 플랫폼 서비스, Ubuntu/Kali desktop, 취약 target, BuildKit, probe runner, validation canary와 OpenVPN gateway 이미지를 사설 registry에 push합니다.
- 모든 배포 이미지는 immutable digest로 고정하고 SBOM을 생성하며 취약점 scan과 Cosign 서명을 완료합니다.
- 빌더의 base image, 출력 repository, package helper image와 다운로드 artifact를 운영자가 검토한 allowlist JSON으로 관리합니다.
- 승인 base/helper image는 `http-v1` ABI로 release 검증합니다. 최종 target은 UID/GID `65532`, read-only root, `/tmp`만 writable, `0.0.0.0:8080` bind, `/health` 및 `/version` endpoint를 제공해야 하며 runtime과 validation sandbox도 같은 security context를 강제합니다.
- 빌더 egress는 registry와 검토된 artifact mirror의 고정 CIDR/port로만 제한합니다.

### 비밀과 정책

- External Secrets Operator 또는 동등한 secret manager 연동을 구성하고 source control에는 평문 Kubernetes Secret을 저장하지 않습니다.
- peer 서비스가 공유하는 내부 token은 동일한 값을 받되 runtime, builder, grader, telemetry, validator, desktop, VPN 관계마다 서로 다른 token을 사용합니다.
- `codegate-api-secrets`와 `codegate-builder-secrets`에는 동일한 `BUILDER_INTERNAL_TOKEN`을 주입하고, builder 전용 Secret에는 `DATABASE_URL`도 포함합니다.
- `codegate-ai-secrets`에는 `AI_INTERNAL_TOKEN`과 내부 gateway의 동일한 bearer 값을 갖는 `GENERATION_PROVIDER_TOKEN`, `REVIEW_PROVIDER_TOKEN`, `RUBRIC_PROVIDER_TOKEN`, 사용하는 경우 `NVD_API_KEY`를 주입합니다. `codegate-model-gateway-secrets`에는 그 canonical `MODEL_GATEWAY_INTERNAL_TOKEN`과 선택한 `OPENAI_API_KEY` 또는 `ANTHROPIC_API_KEY` 하나만 주입합니다. 내부 provider URL, 세 AI mode의 `external` 값과 build catalog 좌표는 비밀이 아닌 ConfigMap으로 분리합니다.
- registry 인증은 일반 환경 변수 Secret과 섞지 않습니다. 검토된 `kubernetes.io/dockerconfigjson` source Secret을 builder system namespace에 두고 build namespace에는 필요한 수명 동안만 `BUILD_REGISTRY_TARGET_SECRET` 이름으로 복제합니다.
- 조직별 데이터 보존 기간, 최대 동시 실행, VM resource quota, Lab 최대 수명, 허용 CVE와 예상 취약점 정책을 확정합니다.
- CNI NetworkPolicy, Pod Security, admission policy와 audit 수집을 운영 정책에 연결합니다.

## 배포 순서

### 1. RKE2 서버 준비

`infra/server`의 예제 inventory와 vault를 복사하고 모든 `REQUIRED_*` 값을 실제 사설 주소와 독립적인 random secret으로 교체합니다.

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

playbook은 RKE2 HA, Cilium, Longhorn, cert-manager, External Secrets, KubeVirt/CDI, audit와 백업 기반을 구성합니다. 실제 disk partition, DNS, 공인 IP, SecretStore, 운영 PKI와 애플리케이션 credential은 운영자가 제공합니다.

### 2. 이미지 빌드·서명

CI에서 workspace 검사와 테스트를 통과한 commit으로 각 Dockerfile을 빌드합니다. 결과 digest를 SBOM·scan·서명 증거와 함께 release metadata에 기록하고 운영 overlay는 tag가 아니라 digest를 참조합니다.

검증용 `probe-runner`와 `validation-canary`도 일반 서비스와 동일하게 검토·서명합니다. 취약 target image의 예상 CVE는 허용된 의도적 취약점으로 별도 기록하며 예상하지 않은 critical 취약점은 검증 실패로 처리합니다.

### 3. 데이터와 Identity 연결

PostgreSQL migration을 적용하고 API가 `REPOSITORY_MODE=postgres`로 시작하도록 구성합니다. Keycloak issuer/JWKS/audience/client 값, Elasticsearch CA와 서비스별 API key, CORS origin을 실제 TLS hostname으로 설정합니다. 개발 seed와 개발 인증은 운영에서 비활성화합니다.

### 4. 환경별 Kubernetes overlay 작성

`infra/kubernetes/base`와 `infra/kubernetes/runtime-plane/base`를 직접 수정하지 않고 `infra/kubernetes/overlays/<environment>`에 private patch를 작성합니다.

- `ghcr.io/replace-me`, `replace-with-digest`, zero digest를 실제 서명 digest로 교체
- 모든 `example.invalid` hostname과 TLS Secret 이름 교체
- ExternalSecret, SecretStore와 CA mount 연결
- 실제 Service/Pod CIDR, Kubernetes API `/32`, registry·Elasticsearch egress 목적지 지정. AI→내부 gateway와 AI→NVD, gateway→선택한 OpenAI 또는 Anthropic API 외에는 egress를 열지 않음
- builder registry pull/push Secret과 catalog JSON 연결
- ingress controller label, Gateway/Ingress class와 WebSocket timeout 검증
- OpenVPN TUN device resource, wildcard DNS와 UDP LoadBalancer 연결
- Blue run의 analyst→Kibana, scenario runner→victim, victim Elastic Agent→telemetry만 허용하고 Red run의 Kali/VPN→target 선언 포트만 허용하는 기본 차단 NetworkPolicy 연결
- `browser_desktop`과 `openvpn` 중 선택한 ingress만 생성하고 전환 시 이전 ticket/certificate를 폐기하는 정책 연결

적용 전 렌더링 결과를 저장해 검토합니다.

```bash
kubectl kustomize infra/kubernetes/overlays/production > rendered-platform.yaml
kubectl kustomize infra/kubernetes/runtime-plane/overlays/production > rendered-runtime.yaml
```

placeholder 차단 값, 평문 Secret, mutable image tag, 과도한 ClusterRole과 광범위한 `0.0.0.0/0` egress가 없는지 검사한 뒤 server-side apply를 사용합니다.

### 5. 배포 후 수용 검증

다음 항목을 모두 통과해야 사용자 트래픽을 엽니다.

1. OIDC 로그인과 개인/조직 onboarding, 잘못된 가입 코드 거부, 두 번째 조직 가입 차단
2. 블루/레드 AI 생성, 선언형 topology schema와 공개 문제에서 정답 material이 제거되는지 확인
3. builder의 허용 목록 성공과 임의 image/package/artifact/egress 거부
4. 서명·SBOM·Trivy·기능·AI 판정·격리 probe의 자동 통과 및 실패 시 사람 승인 대기 없이 자동 격리
5. 외부 인터넷, Kubernetes API, cloud metadata, 다른 실행 canary 접근 차단
6. Blue Ubuntu analyst desktop과 Red Kali desktop의 일회용 티켓·WebSocket 연결, 실행별 Kibana/target 진입점 확인
7. OpenVPN 프로필 일회용 다운로드, 같은 실행 target 접근, 다른 실행·플랫폼 접근 차단, browser/OpenVPN 동시 활성화 거부
8. Blue의 별도 monitored victim, Elastic Agent enrollment, 승인된 시나리오 행위, 실행별 Elasticsearch index/Kibana space 검색·증거 선택·MITRE 채점 확인
9. Red의 별도 vulnerable target, Kali/VPN에서만 허용된 서비스·취약점 재현과 네 가지 문제 유형 채점 확인
10. 실행 만료·관리자 강제 종료 후 VM, namespace, desktop/VPN 자격 증명, Elastic Agent token과 Elasticsearch index/Kibana space 정리
11. 개인·조직·플랫폼 리포트, 조직/전체 랭킹의 권한과 개인정보 공개 동의 확인
12. 감사 로그, metric, alert와 rate/resource quota 확인
13. etcd, Longhorn, PostgreSQL, Elasticsearch 백업과 격리 환경 restore drill

## 운영 전환 기준

- 모든 public endpoint에 유효한 TLS와 필요한 보안 header가 적용되어야 합니다.
- 개발 계정, `AUTH_MODE=dev`, SQLite, simulator와 deterministic AI mode가 운영 workload에 존재하면 안 됩니다.
- 모든 내부 token과 API key의 소유자, 회전 주기와 폐기 절차가 기록되어야 합니다.
- 자동 검증 증거와 cleanup evidence가 보존되고 격리된 Lab은 실행할 수 없어야 합니다.
- 동시 실행 수와 VM resource 사용량에 대한 capacity test, 장애 시 강제 정리와 비용 경보를 통과해야 합니다.
- 백업 성공만이 아니라 별도 환경 복구 성공 시각과 RTO/RPO를 기록해야 합니다.

서버별 상세 값과 포트는 `infra/server/README.md` 및 `infra/server/PORTS.md`, Kubernetes 비밀 계약은 `infra/server/SECRET-CONTRACTS.md`를 함께 확인하세요.

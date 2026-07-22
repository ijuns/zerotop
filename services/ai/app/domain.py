from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any
from uuid import uuid4

from app.build_catalog import BuildCatalogError, load_build_catalog

BLUE_QUESTIONS = {"elk_search", "mitre_attack"}
RED_QUESTIONS = {"single_choice", "multiple_choice", "free_text", "mitre_attack"}
ALLOWED_ACCESS = {"browser_desktop", "openvpn", "both"}
ALLOWED_IMAGES = {"ubuntu", "kali"}


class DomainError(ValueError):
    """Raised when a Lab request violates the product contract."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _question_types(team: str, raw: list[str]) -> list[str]:
    selected = list(dict.fromkeys(raw))
    if team == "blue":
        if set(selected) != BLUE_QUESTIONS:
            raise DomainError("블루팀 Lab은 ELK 검색형과 MITRE ATT&CK 유형을 모두 포함해야 합니다.")
        return ["elk_search", "mitre_attack"]
    if team == "red":
        if not selected or not set(selected).issubset(RED_QUESTIONS):
            raise DomainError("레드팀 Lab은 허용된 문제 유형을 하나 이상 선택해야 합니다.")
        return selected
    raise DomainError("team은 blue 또는 red여야 합니다.")


def generate_lab_draft(request: dict[str, Any]) -> dict[str, Any]:
    """Create a defensive, isolated LabSpec without producing executable exploit code."""
    title = str(request.get("title", "")).strip()
    prompt = str(request.get("prompt", "")).strip()
    team = str(request.get("team", "")).strip().lower()
    if len(title) < 3:
        raise DomainError("title은 3자 이상이어야 합니다.")
    if len(prompt) < 10:
        raise DomainError("prompt는 10자 이상이어야 합니다.")

    desktop_image = str(request.get("desktopImage") or ("ubuntu" if team == "blue" else "kali"))
    access_method = str(request.get("accessMethod") or "browser_desktop")
    if desktop_image not in ALLOWED_IMAGES:
        raise DomainError("지원하지 않는 desktopImage입니다.")
    if access_method not in ALLOWED_ACCESS:
        raise DomainError("지원하지 않는 accessMethod입니다.")
    question_types = _question_types(team, list(request.get("questionTypes") or []))
    try:
        build_target = load_build_catalog(require_environment=False).target
    except BuildCatalogError as exc:
        raise DomainError(f"Build catalog is invalid: {exc}") from exc

    cve_ids = [
        str(item).upper()
        for item in request.get("cveIds", [])
        if isinstance(item, str) and item.upper().startswith("CVE-")
    ]
    blue_profile = _blue_scenario_profile(title, prompt, cve_ids) if team == "blue" else None
    red_profile = _red_scenario_profile(title, prompt, cve_ids) if team == "red" else None
    if team == "blue":
        assert blue_profile is not None
        log_sources = list(blue_profile["logSources"])
        attack_chain = list(blue_profile["attackChain"])
        assessment = {
            "elk": {"languages": ["kql", "esql", "eql"], "evidenceWeight": 70},
            "mitre": {"selection": "multiple", "weight": 30},
        }
    else:
        assert red_profile is not None
        log_sources = list(red_profile["logSources"])
        attack_chain = list(red_profile["attackChain"])
        assessment = {
            "questionTypes": question_types,
            "commandMasking": "required",
            "explanationFlow": ["intent", "detection", "blocking"],
        }

    learning = _generated_learning(
        team=team,
        title=title,
        prompt=prompt,
        log_sources=log_sources,
        profile=blue_profile if team == "blue" else red_profile,
        cve_ids=cve_ids,
    )
    telemetry_events = (
        _blue_signal_events(attack_chain, prompt, blue_profile) if team == "blue" else []
    )
    topology: dict[str, Any] = {
        "schemaVersion": 1,
        "team": team,
        "isolation": "per_run",
        "workstation": {
            "role": "soc_analyst" if team == "blue" else "attack_operator",
            "desktopImage": "ubuntu" if team == "blue" else "kali",
            "entrypoint": "kibana" if team == "blue" else "target",
        },
        "target": {
            "role": "monitored_target" if team == "blue" else "vulnerable_target",
            "hostname": "target",
        },
        **(
            {
                "telemetry": {
                    "stack": "elastic",
                    "collector": "elastic_agent",
                    "generator": "scenario_log_generator",
                    "index": "zerotop-logs-*",
                    "events": telemetry_events,
                    "generation": {
                        "schemaVersion": 1,
                        "profile": (
                            "powershell_rce_exfiltration"
                            if blue_profile is None
                            else str(blue_profile["id"])
                        ),
                        "totalEvents": 1200,
                        "timeRangeMinutes": 60,
                        "seed": hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:32],
                        "timelineAnchor": _now(),
                    },
                }
            }
            if team == "blue"
            else {}
        ),
    }
    questions, grading_questions = _generated_questions(
        team, question_types, attack_chain, telemetry_events,
        blue_profile if team == "blue" else red_profile,
    )
    functional_probes = [
        {
            "id": "target-health",
            "kind": "http",
            "method": "GET",
            "path": "/health",
            "expectedStatuses": [200],
            "bodyIncludes": ["ready"],
        }
    ]
    vulnerability_probes = [
        {
            "id": f"fingerprint-{index + 1}",
            "kind": "http",
            "method": "GET",
            "path": "/version",
            "expectedStatuses": [200],
            "bodyIncludes": [cve_id],
            "cveId": cve_id,
        }
        for index, cve_id in enumerate(cve_ids)
    ] or [
        {
            "id": "scenario-fingerprint",
            "kind": "http",
            "method": "GET",
            "path": "/version",
            "expectedStatuses": [200],
            "bodyIncludes": ["codegate-vulnerable-target"],
            "findingId": "scenario-fingerprint",
        }
    ]
    prompt_hash = f"sha256:{hashlib.sha256(prompt.encode('utf-8')).hexdigest()}"
    build_learning = {
        "title": learning["title"],
        "summary": learning["summary"],
        "sections": [
            {
                "id": section["id"],
                "title": section["title"],
                "markdown": section["bodyMarkdown"],
            }
            for section in learning["sections"]
        ],
    }
    environment_build_spec = {
        "schemaVersion": 1,
        "team": team,
        "source": {"promptDigest": prompt_hash, "cveIds": cve_ids},
        "scenario": {
            "summary": learning["summary"],
            "mitreTechniques": [item["id"] for item in attack_chain],
        },
        "target": {
            "name": "generated-target",
            "baseImage": build_target.base_image,
            "outputRepository": build_target.output_repository,
            "service": {"port": 8080, "protocol": "http"},
            "runtimeContract": build_target.runtime_contract.provider_value(),
            "packages": [],
            "artifacts": [],
            "functionalProbes": functional_probes,
            "vulnerabilityProbes": vulnerability_probes,
        },
        "topology": topology,
        **({"telemetry": {"events": telemetry_events}} if team == "blue" else {}),
        "learning": build_learning,
        "questions": questions,
        "grading": {
            "hiddenRefs": [
                {
                    "questionId": question["id"],
                    "refId": f"grading://{question['id']}",
                    "rubricDigest": f"sha256:{hashlib.sha256(question['id'].encode('utf-8')).hexdigest()}",
                }
                for question in questions
            ]
        },
    }

    return {
        "id": f"lab-{uuid4().hex[:12]}",
        "version": 1,
        "title": title,
        "prompt": prompt,
        "team": team,
        "desktopImage": desktop_image,
        "accessMethod": access_method,
        "questionTypes": question_types,
        "status": "draft",
        "network": {"egress": "deny", "isolation": "per_run", "controlPlaneAccess": "deny"},
        "scenario": {
            "summary": learning["summary"],
            "logSources": log_sources,
            "attackChain": attack_chain,
            "assessment": assessment,
        },
        "topology": topology,
        "learning": learning,
        "questions": questions,
        "gradingQuestions": grading_questions,
        "environmentBuildSpec": environment_build_spec,
        "safety": {
            "weaponizedPayloads": "forbidden",
            "externalTargets": "forbidden",
            "secrets": "none",
        },
        "createdAt": _now(),
    }


def _blue_scenario_profile(
    title: str, prompt: str, cve_ids: list[str]
) -> dict[str, Any]:
    value = f"{title} {prompt} {' '.join(cve_ids)}".lower()
    if any(marker in value for marker in ("ransomware", "랜섬", "암호화", "encrypt", "shadow copy")):
        return {
            "id": "ransomware",
            "summary": "초기 계정 접근 이후 복구 기능 방해와 대량 파일 암호화로 이어지는 랜섬웨어 행위를 엔드포인트·인증·파일 로그로 추적하는 시나리오입니다.",
            "logSources": ["windows.security", "windows.sysmon", "powershell", "edr", "file_integrity", "firewall"],
            "attackChain": [
                {"id": "T1078", "name": "Valid Accounts", "tactic": "initial-access"},
                {"id": "T1059.001", "name": "PowerShell", "tactic": "execution"},
                {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "impact"},
                {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "impact"},
            ],
            "executionLabel": "복구 방해 명령과 프로세스 실행",
            "impactLabel": "대량 파일 암호화 및 복구 방해",
        }
    if any(marker in value for marker in ("credential", "identity", "impossible travel", "valid account", "아이덴티티", "계정", "인증 이상", "로그인 이상", "brute force", "무차별 대입")):
        return {
            "id": "credential_abuse",
            "summary": "반복된 인증 실패 이후 성공한 비정상 로그인과 권한·원격접속 변화를 연계해 계정 탈취 및 악용 범위를 조사하는 시나리오입니다.",
            "logSources": ["windows.security", "authentication", "vpn", "edr", "active_directory", "firewall"],
            "attackChain": [
                {"id": "T1110", "name": "Brute Force", "tactic": "credential-access"},
                {"id": "T1078", "name": "Valid Accounts", "tactic": "initial-access"},
                {"id": "T1098", "name": "Account Manipulation", "tactic": "persistence"},
                {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactic": "lateral-movement"},
            ],
            "executionLabel": "비정상 계정 사용과 권한 변경",
            "impactLabel": "원격접속 및 내부 자원 접근 확대",
        }
    if any(marker in value for marker in ("webshell", "web shell", "웹셸", "웹쉘")):
        return {
            "id": "webshell",
            "summary": "공개 웹 서비스 악용 이후 웹셸 파일 생성과 서버 명령 실행, 추가 도구 전송으로 이어지는 침해 흐름을 조사하는 시나리오입니다.",
            "logSources": ["waf", "web.access", "linux.audit", "process", "file_integrity", "firewall"],
            "attackChain": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
                {"id": "T1505.003", "name": "Web Shell", "tactic": "persistence"},
                {"id": "T1059.004", "name": "Unix Shell", "tactic": "execution"},
                {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "command-and-control"},
            ],
            "executionLabel": "웹셸 기반 명령 실행",
            "impactLabel": "추가 도구 반입과 외부 통신",
        }
    # A CVE identifier or generic RCE request does not imply a Windows host.
    # Use this Windows-specific profile only when the prompt explicitly asks
    # for PowerShell; other CVEs remain in the generic/dynamic scenario path.
    if any(marker in value for marker in ("powershell", "power shell", "파워쉘", "파워셸")):
        return {
            "id": "powershell_rce_exfiltration",
            "summary": "웹 서비스의 원격 코드 실행 가능성이 악용된 뒤 PowerShell 실행, 민감정보 수집·압축과 외부 반출로 이어지는 침해 흐름을 조사하는 시나리오입니다.",
            "logSources": ["waf", "web.access", "windows.sysmon", "powershell", "file_integrity", "firewall", "dns"],
            "attackChain": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
                {"id": "T1059.001", "name": "PowerShell", "tactic": "execution"},
                {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
                {"id": "T1560.001", "name": "Archive via Utility", "tactic": "collection"},
                {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
            ],
            "executionLabel": "PowerShell 실행과 시스템 정찰",
            "impactLabel": "민감정보 수집·압축 및 외부 반출",
        }
    return {
        "id": "generic_intrusion",
        "summary": "공개 서비스의 이상 요청 이후 명령 실행, 파일 탐색, 외부 통신으로 이어지는 일반 침해 흐름을 다중 로그로 재구성하는 시나리오입니다.",
        "logSources": ["waf", "web.access", "process", "linux.audit", "file_integrity", "firewall", "dns"],
        "attackChain": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
            {"id": "T1059.004", "name": "Unix Shell", "tactic": "execution"},
            {"id": "T1083", "name": "File and Directory Discovery", "tactic": "discovery"},
            {"id": "T1071.001", "name": "Web Protocols", "tactic": "command-and-control"},
        ],
        "executionLabel": "명령 실행과 파일 탐색",
        "impactLabel": "외부 통신 및 후속 접근",
    }


def _red_scenario_profile(
    title: str, prompt: str, cve_ids: list[str]
) -> dict[str, Any]:
    value = f"{title} {prompt}".lower()
    # CVE identifiers alone do not identify a product or weakness family in the
    # deterministic fallback. Production uses the trusted CVE records.
    profiles = [
        (
            ("container", "docker", "kubernetes", "k8s", "escape", "컨테이너", "도커", "쿠버네티스"),
            {
                "id": "container_escape",
                "summary": "격리된 컨테이너 서비스의 노출 구성과 런타임 경계를 확인하고 제한된 권한 검증으로 호스트 영향 가능성을 평가하는 레드팀 시나리오입니다.",
                "logSources": ["container.runtime", "kubernetes.audit", "linux.audit", "process", "firewall"],
                "attackChain": [
                    {"id": "T1610", "name": "Deploy Container", "tactic": "defense-evasion"},
                    {"id": "T1611", "name": "Escape to Host", "tactic": "privilege-escalation"},
                    {"id": "T1059.004", "name": "Unix Shell", "tactic": "execution"},
                    {"id": "T1082", "name": "System Information Discovery", "tactic": "discovery"},
                ],
                "surfaceLabel": "컨테이너 런타임과 오케스트레이션 경계",
                "validationFocus": "과도한 권한, 위험한 마운트와 런타임 격리 실패 가능성",
                "defenderSignals": "컨테이너 생성·권한 변경·프로세스·감사 로그",
                "mitigationFocus": "최소 권한 보안 컨텍스트와 런타임 정책 강화",
            },
        ),
        (
            ("credential", "password", "brute force", "ssh", "login", "계정", "자격 증명", "비밀번호", "로그인", "인증"),
            {
                "id": "credential_access",
                "summary": "노출된 원격 접근 서비스의 인증 정책과 계정 보호 상태를 확인하고 제한된 자격 증명 검증으로 계정 악용 가능성을 평가하는 레드팀 시나리오입니다.",
                "logSources": ["authentication", "linux.audit", "sshd", "pam", "firewall"],
                "attackChain": [
                    {"id": "T1046", "name": "Network Service Discovery", "tactic": "discovery"},
                    {"id": "T1110", "name": "Brute Force", "tactic": "credential-access"},
                    {"id": "T1078", "name": "Valid Accounts", "tactic": "initial-access"},
                    {"id": "T1021.004", "name": "SSH", "tactic": "lateral-movement"},
                ],
                "surfaceLabel": "원격 인증 및 계정 접근 서비스",
                "validationFocus": "인증 정책, 계정 잠금과 제한 계정의 접근 범위",
                "defenderSignals": "인증 성공·실패, 세션, 권한 변경과 원격 접속 로그",
                "mitigationFocus": "다중 인증, 계정 잠금과 원격 접근 허용 목록",
            },
        ),
        (
            ("path traversal", "directory traversal", "file read", "lfi", "upload", "경로 조작", "디렉터리 순회", "파일 읽기", "파일 업로드"),
            {
                "id": "file_exposure",
                "summary": "웹 애플리케이션의 파일 처리 기능과 경로 검증 경계를 확인하고 제공된 표식 파일만 사용해 비인가 파일 접근 가능성을 평가하는 레드팀 시나리오입니다.",
                "logSources": ["waf", "web.access", "application", "file_integrity", "linux.audit"],
                "attackChain": [
                    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
                    {"id": "T1083", "name": "File and Directory Discovery", "tactic": "discovery"},
                    {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
                    {"id": "T1074.001", "name": "Local Data Staging", "tactic": "collection"},
                ],
                "surfaceLabel": "웹 파일 처리와 경로 검증 기능",
                "validationFocus": "경로 정규화, 파일 권한 검사와 비인가 접근 가능성",
                "defenderSignals": "웹 요청·응답, 애플리케이션 오류와 파일 접근 로그",
                "mitigationFocus": "허용 목록 기반 경로 검증과 저장소 격리",
            },
        ),
        (
            ("web", "http", "api", "rce", "sqli", "sql injection", "ssrf", "deserial", "log4j", "웹", "원격 코드", "인젝션", "역직렬화"),
            {
                "id": "web_application",
                "summary": "격리된 웹 애플리케이션의 노출 기능과 입력 처리 경계를 식별하고 비파괴 검증으로 서버 측 영향 가능성을 평가하는 레드팀 시나리오입니다.",
                "logSources": ["waf", "web.access", "application", "linux.audit", "process", "firewall"],
                "attackChain": [
                    {"id": "T1595.002", "name": "Vulnerability Scanning", "tactic": "reconnaissance"},
                    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
                    {"id": "T1059.004", "name": "Unix Shell", "tactic": "execution"},
                    {"id": "T1083", "name": "File and Directory Discovery", "tactic": "discovery"},
                ],
                "surfaceLabel": "공개 웹 애플리케이션과 API 입력 경계",
                "validationFocus": "노출 기능, 입력 처리와 서버 측 동작의 취약 조건",
                "defenderSignals": "WAF·웹 접근·애플리케이션·프로세스 로그",
                "mitigationFocus": "영향 버전 패치, 입력 검증과 서비스 계정 최소 권한",
            },
        ),
    ]
    for markers, profile in profiles:
        if any(marker in value for marker in markers):
            return profile
    return {
        "id": "generic_validation",
        "summary": "프롬프트에 제시된 격리 대상을 먼저 식별하고 확인된 서비스와 기능에만 근거한 비파괴 검증으로 취약 조건을 평가하는 일반 레드팀 시나리오입니다.",
        "logSources": ["network", "service", "authentication", "linux.audit", "firewall"],
        "attackChain": [
            {"id": "T1595.002", "name": "Vulnerability Scanning", "tactic": "reconnaissance"},
            {"id": "T1046", "name": "Network Service Discovery", "tactic": "discovery"},
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
            {"id": "T1059.004", "name": "Unix Shell", "tactic": "execution"},
        ],
        "surfaceLabel": "프롬프트로 지정된 격리 대상의 서비스 표면",
        "validationFocus": "대상에서 확인된 제품·버전·기능과 취약 전제 조건",
        "defenderSignals": "서비스 요청, 인증, 프로세스, 감사와 네트워크 로그",
        "mitigationFocus": "확인된 영향 조건에 맞는 패치·구성 변경과 최소 권한",
    }


def _generated_learning(
    *,
    team: str,
    title: str,
    prompt: str,
    log_sources: list[str],
    profile: dict[str, Any] | None,
    cve_ids: list[str],
) -> dict[str, Any]:
    if team == "blue":
        assert profile is not None
        summary = str(profile["summary"])
        cve_context = (
            f"\n\n학습 대상 취약점: **{', '.join(cve_ids)}**. 공개 식별자는 조사 범위를 정하는 참고 정보이며 실제 영향 조건은 제공 환경의 서비스·로그 증거로 검증해야 합니다."
            if cve_ids
            else ""
        )
        return {
            "title": title,
            "summary": summary,
            "prerequisites": [
                "침해사고 대응 절차 기초",
                "Windows 및 Linux 이벤트·프로세스 개념",
                "Kibana Discover 기본 사용법",
            ],
            "objectives": [
                "정상 운영 로그와 공격 신호를 구분하고 시간순 사건 흐름을 재구성합니다.",
                "ELK와 KQL을 사용해 인증·프로세스·파일·네트워크 증거를 교차 검증합니다.",
                "관찰 행위를 MITRE ATT&CK 전술과 기법 후보에 근거 기반으로 매핑합니다.",
                "초동 격리, 자격 증명 조치, 탐지 개선과 재발 방지 방안을 제안합니다.",
            ],
            "sections": [
                {
                    "id": "threat-context",
                    "title": "시나리오 브리핑과 조사 범위",
                    "bodyMarkdown": f"## {title}\n\n{prompt}\n\n{summary}{cve_context}\n\n분석 범위는 제공된 격리 환경으로 제한합니다. 문제의 정답을 추측하기보다 서로 다른 로그에서 동일한 사용자·호스트·프로세스·네트워크 흐름이 이어지는지 검증하세요.",
                },
                {
                    "id": "evidence-model",
                    "title": "증거 모델과 타임라인 상관분석",
                    "bodyMarkdown": f"이번 실습에는 {', '.join(log_sources)} 계열 로그가 섞여 있습니다. `@timestamp`로 정렬한 뒤 `host.name`, `user.name`, `process.entity_id`, `source.ip`, `destination.ip`, `file.path`를 연결 키로 사용합니다. 단일 이벤트만으로 결론을 내리지 말고 앞뒤 이벤트와 정상 기준선을 비교하세요.",
                },
                {
                    "id": "investigation-workflow",
                    "title": "SOC 조사 워크플로",
                    "bodyMarkdown": f"1. 전체 시간 범위와 데이터 수집 상태를 확인합니다.\n2. 인증 또는 외부 노출 지점에서 최초 이상 징후 후보를 찾습니다.\n3. 같은 호스트와 사용자에서 이어진 {profile['executionLabel']} 관련 이벤트를 확인합니다.\n4. {profile['impactLabel']} 전후의 파일·프로세스·네트워크 증거를 교차 검증합니다.\n5. 사용한 쿼리와 증거를 기록하고 반증 가능한 정상 행위도 함께 검토합니다.",
                },
                {
                    "id": "elk-kql-guidance",
                    "title": "ELK Discover와 KQL 검색 가이드",
                    "bodyMarkdown": "Kibana의 **Analytics → Discover**에서 실습 데이터 뷰를 선택합니다. 먼저 넓은 조건으로 후보를 찾고 필드를 추가해 범위를 좁히세요. 예: `event.category:process AND host.name:*`, `event.category:authentication AND event.outcome:*`, `file.path:* AND user.name:*`. 결과가 적으면 시간 범위와 필드 존재 여부를, 많으면 호스트·사용자·프로세스 식별자 조합을 확인합니다. 예시는 검색 방법만 설명하며 특정 증거 ID나 정답을 제공하지 않습니다.",
                },
                {
                    "id": "mitre-context",
                    "title": "MITRE ATT&CK 근거 기반 매핑",
                    "bodyMarkdown": "ATT&CK 매핑은 도구 이름이 아니라 관찰한 행위와 목적을 기준으로 수행합니다. 인증, 명령 실행, 수집, 압축, 외부 전송처럼 단계별 증거를 먼저 기술하고 해당 전술의 기법 후보를 비교하세요. 하나의 이벤트가 여러 후보와 연관될 수 있으므로 타임라인 전체를 근거로 최종 선택합니다.",
                },
                {
                    "id": "response-remediation",
                    "title": "초동 대응과 재발 방지",
                    "bodyMarkdown": "영향을 받은 계정과 호스트를 우선 격리하고 활성 세션과 자격 증명을 재검토합니다. 의심 프로세스·파일·네트워크 지표를 탐지 규칙으로 전환해 과거 로그에 소급 적용합니다. 취약 서비스 패치, 최소 권한, 스크립트 로깅 강화, 외부 통신 통제를 적용한 뒤 동일 시나리오가 재현되지 않는지 검증합니다.",
                },
            ],
        }

    assert profile is not None
    red_cve_context = (
        f"\n\n학습 대상 취약점: **{', '.join(cve_ids)}**. 제공 환경에서 실제 영향 조건을 검증하세요."
        if cve_ids
        else ""
    )
    return {
        "title": title,
        "summary": str(profile["summary"]),
        "prerequisites": ["TCP/IP 및 HTTP 기초", "Linux 명령행 기초", "격리 환경의 범위 통제 원칙"],
        "objectives": [
            f"{profile['surfaceLabel']}의 공격 표면과 취약 조건을 식별합니다.",
            f"{profile['validationFocus']} 검증 과정이 남기는 {profile['defenderSignals']}을 설명합니다.",
            "발견 사항을 MITRE ATT&CK 및 완화 권고와 연결합니다.",
        ],
        "sections": [
            {
                "id": "threat-context",
                "title": "시나리오와 허용 범위",
                "bodyMarkdown": f"## {title}\n\n{prompt}{red_cve_context}\n\n{profile['summary']}\n\n제공된 대상과 허용된 접근 방식만 사용하며 외부 시스템으로 범위를 확장하지 않습니다.",
            },
            {
                "id": "attack-workflow",
                "title": "공격 표면 검증 절차",
                "bodyMarkdown": f"서비스 식별, 취약 조건 확인, 제한된 검증, 영향 분석 순서로 진행합니다. 이번 시나리오의 핵심은 {profile['validationFocus']}입니다. 각 단계의 가정과 관찰 결과를 기록하고 불필요한 파괴 행위는 수행하지 않습니다.",
            },
            {
                "id": "defender-visibility",
                "title": "방어 관점의 관측 지점",
                "bodyMarkdown": "웹 요청, 인증, 프로세스 실행, 파일 변경, 네트워크 연결 중 어떤 지점에서 행위가 관찰되는지 정리합니다. 공격 성공 여부뿐 아니라 탐지와 차단이 가능한 통제 지점을 함께 설명합니다.",
            },
            {
                "id": "mitre-context",
                "title": "MITRE ATT&CK 매핑 원칙",
                "bodyMarkdown": "도구 이름만으로 기법을 선택하지 말고 실제 행위, 대상, 목적을 근거로 전술과 기법 후보를 비교합니다. 특정 정답 ID는 강의에서 제공하지 않습니다.",
            },
            {
                "id": "remediation",
                "title": "완화와 재검증",
                "bodyMarkdown": f"{profile['mitigationFocus']}을 우선 검토합니다. 변경 전후에 동일한 안전 검증 절차를 수행해 취약 조건 제거와 정상 기능 유지를 함께 확인합니다.",
            },
        ],
    }


def _blue_signal_events(
    attack_chain: list[dict[str, str]], prompt: str, profile: dict[str, Any] | None
) -> list[dict[str, Any]]:
    anchor = datetime.now(timezone.utc)
    first = attack_chain[0]["id"]
    execution = attack_chain[1]["id"] if len(attack_chain) > 1 else first
    technique = lambda index: attack_chain[min(index, len(attack_chain) - 1)]["id"]

    def timestamp(minutes_before: int) -> str:
        return (anchor - timedelta(minutes=minutes_before)).isoformat()

    signals: list[tuple[str, int, str, str, dict[str, Any], str]] = [
        (
            "signal-web-rce-probe",
            18,
            "비정상 웹 요청 이후 애플리케이션 계정의 인증 컨텍스트가 변경되었습니다.",
            "web",
            {"host": {"name": "web-01"}, "source": {"ip": "192.0.2.44"}, "url": {"path": "/api/export"}},
            technique(0),
        ),
        (
            "signal-webshell-powershell",
            16,
            "웹 서비스 프로세스에서 PowerShell 자식 프로세스가 생성되었습니다.",
            "process",
            {"host": {"name": "web-01"}, "user": {"name": "svc_web"}, "process": {"name": "powershell.exe", "parent": {"name": "w3wp.exe"}, "entity_id": "proc-ps-001"}},
            technique(1),
        ),
        (
            "signal-powershell-recon",
            14,
            "PowerShell 프로세스가 시스템 및 계정 정보를 열람했습니다.",
            "process",
            {"host": {"name": "web-01"}, "user": {"name": "svc_web"}, "process": {"name": "powershell.exe", "entity_id": "proc-ps-001"}},
            technique(1),
        ),
        (
            "signal-sensitive-file-read",
            11,
            "서비스 계정이 평소 접근하지 않던 민감 데이터 파일을 연속으로 읽었습니다.",
            "file",
            {"host": {"name": "web-01"}, "user": {"name": "svc_web"}, "file": {"path": "C:\\Data\\customer-export.csv"}},
            technique(2),
        ),
        (
            "signal-archive-created",
            8,
            "민감 데이터 디렉터리에서 새 압축 파일이 생성되었습니다.",
            "file",
            {"host": {"name": "web-01"}, "user": {"name": "svc_web"}, "file": {"path": "C:\\ProgramData\\cache\\export.zip"}},
            technique(3),
        ),
        (
            "signal-outbound-exfiltration",
            5,
            "침해 호스트에서 드물게 관찰되는 외부 목적지로 대용량 연결이 발생했습니다.",
            "network",
            {"host": {"name": "web-01"}, "user": {"name": "svc_web"}, "source": {"ip": "10.20.30.15", "bytes": 18642771}, "destination": {"ip": "198.51.100.77", "port": 443}, "network": {"direction": "egress", "transport": "tcp"}},
            technique(4),
        ),
    ]
    if profile is not None and profile.get("id") != "powershell_rce_exfiltration":
        execution_label = str(profile["executionLabel"])
        impact_label = str(profile["impactLabel"])
        signals = [
            ("signal-initial-anomaly", 18, "정상 기준선과 다른 최초 접근 이벤트가 관찰되었습니다.", "authentication", {}, technique(0)),
            ("signal-execution-start", 15, f"최초 접근 이후 {execution_label} 관련 이벤트가 시작되었습니다.", "process", {}, technique(1)),
            ("signal-followup-activity", 12, f"동일 사용자와 호스트에서 {execution_label} 후속 행위가 이어졌습니다.", "process", {}, technique(1)),
            ("signal-impact-stage-one", 9, f"{impact_label}의 첫 번째 영향 신호가 확인되었습니다.", "file", {}, technique(2)),
            ("signal-impact-stage-two", 6, f"{impact_label}와 연관된 추가 시스템 변화가 확인되었습니다.", "file", {}, technique(3)),
            ("signal-impact-stage-three", 3, f"{impact_label}의 최종 네트워크 또는 세션 흔적이 확인되었습니다.", "network", {}, technique(3)),
        ]
    events: list[dict[str, Any]] = []
    for signal_id, minutes, message, category, fields, technique_id in signals:
        document = {
            "@timestamp": timestamp(minutes),
            "message": message,
            "event": {
                "id": signal_id,
                "kind": "alert",
                "category": category,
                "dataset": "zerotop.scenario",
            },
            **fields,
            "threat": {
                "framework": "MITRE ATT&CK",
                "technique": {"id": [technique_id]},
            },
        }
        events.append({"id": signal_id, "document": document})
    return events


def _generated_questions(
    team: str,
    question_types: list[str],
    attack_chain: list[dict[str, str]],
    telemetry_events: list[dict[str, Any]],
    profile: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if team == "blue":
        assert profile is not None
        technique_ids = [item["id"] for item in attack_chain]
        evidence_ids = [str(item["id"]) for item in telemetry_events]
        definitions = [
            ("blue-elk-entry", "elk_search", "정상 운영 로그와 구분되는 최초 침해 징후를 찾으세요. 인증 또는 외부 노출 지점의 이벤트를 시간순으로 비교하고 최초 진입 정황을 직접 뒷받침하는 증거를 선택한 뒤 사용한 KQL을 제출하세요.", 20, {"expectedEvidenceIds": evidence_ids[:2]}),
            ("blue-elk-execution", "elk_search", f"최초 침해 이후 {profile['executionLabel']} 흐름을 재구성하세요. 동일한 사용자·호스트·프로세스 계보를 연결해 실행 단계와 후속 행위를 입증하는 증거를 선택하세요.", 20, {"expectedEvidenceIds": evidence_ids[1:3]}),
            ("blue-elk-impact", "elk_search", f"{profile['impactLabel']} 단계의 타임라인을 완성하세요. 앞선 실행 흐름과 같은 사용자 또는 호스트에서 이어진 사건임을 보여주는 증거를 모두 선택하고 검색 쿼리를 제출하세요.", 20, {"expectedEvidenceIds": evidence_ids[3:6]}),
            ("blue-mitre-entry", "mitre_attack", "최초 침해 단계에서 관찰된 인증 또는 접근 행위를 가장 잘 설명하는 MITRE ATT&CK 기법을 후보 목록에서 선택하세요. 도구명이 아닌 인증 맥락과 접근 목적을 기준으로 판단하세요.", 15, {"techniqueIds": [technique_ids[0]]}),
            ("blue-mitre-execution", "mitre_attack", "명령 실행과 후속 정찰 행위를 설명하는 MITRE ATT&CK 기법을 선택하세요. 프로세스 계보와 명령행 증거를 함께 고려하세요.", 15, {"techniqueIds": [technique_ids[1] if len(technique_ids) > 1 else technique_ids[0]]}),
            ("blue-mitre-chain", "mitre_attack", "전체 공격 타임라인을 구성하는 핵심 MITRE ATT&CK 기법을 모두 선택하세요. 서로 다른 단계가 포함되어야 하며 ELK에서 확인한 증거 흐름을 기준으로 선택하세요.", 10, {"techniqueIds": technique_ids[:3]}),
        ]
        public = [
            {"id": item[0], "type": item[1], "prompt": item[2], "points": item[3]}
            for item in definitions
        ]
        hidden = [
            {**question, "answerKey": definitions[index][4]}
            for index, question in enumerate(public)
        ]
        return public, hidden

    red_question_types = list(question_types)
    while len(red_question_types) < 4:
        red_question_types.append(
            question_types[len(red_question_types) % len(question_types)]
        )
    prompts = {
        "single_choice": "격리된 대상의 공격 표면을 확인한 뒤 다음 단계로 가장 적절한 검증 행동을 선택하세요. 범위 통제와 증거 보존을 함께 고려해야 합니다.",
        "multiple_choice": "시뮬레이션 공격 흐름을 입증하면서 방어팀의 탐지 개선에도 직접 활용할 수 있는 관측 증거를 모두 선택하세요.",
        "free_text": "발견한 공격 경로를 초기 조건, 실행 단계, 영향, 방어 관측 지점 순서로 설명하고 이를 차단할 완화 조치와 재검증 방법을 근거와 함께 작성하세요.",
        "mitre_attack": "격리 환경에서 실제로 관찰한 공격 행위를 가장 잘 설명하는 MITRE ATT&CK 기법을 선택하세요. 사용 도구가 아니라 행위의 목적과 대상에 근거해야 합니다.",
    }
    public: list[dict[str, Any]] = []
    hidden: list[dict[str, Any]] = []
    for index, question_type in enumerate(red_question_types):
        question_id = f"{team}-q{index + 1}"
        points = 20 if question_type == "mitre_attack" else 30
        options = None
        if question_type == "single_choice":
            options = [
                {"id": "safe-enumeration", "label": "허용된 대상과 포트 범위에서 서비스와 버전을 식별한다."},
                {"id": "disable-audit", "label": "탐지를 피하기 위해 대상의 감사 로그를 비활성화한다."},
                {"id": "external-scan", "label": "유사 시스템을 찾기 위해 인터넷 대역으로 스캔 범위를 확장한다."},
                {"id": "destructive-test", "label": "영향 확인을 위해 데이터 삭제 동작부터 실행한다."},
            ]
            answer_key = {"optionIds": ["safe-enumeration"]}
        elif question_type == "multiple_choice":
            options = [
                {"id": "process-event", "label": "부모·자식 프로세스 관계와 명령행"},
                {"id": "auth-event", "label": "인증 주체, 출발지, 성공 여부가 포함된 이벤트"},
                {"id": "network-event", "label": "대상 서비스와 연계된 네트워크 연결 기록"},
                {"id": "marketing-cookie", "label": "공격 흐름과 무관한 마케팅 쿠키"},
            ]
            answer_key = {"optionIds": ["process-event", "auth-event", "network-event"]}
        elif question_type == "mitre_attack":
            answer_key = {"techniqueIds": [attack_chain[0]["id"]]}
        else:
            answer_key = {"rubricId": f"{question_id}-analysis-v2"}
        question = {
            "id": question_id,
            "type": question_type,
            "prompt": prompts[question_type],
            "points": points,
            **({"options": options} if options else {}),
        }
        public.append(question)
        hidden.append({**question, "answerKey": answer_key})
    return public, hidden


def validate_lab_draft(lab: dict[str, Any]) -> dict[str, Any]:
    """Apply deterministic mandatory checks. Any failure results in quarantine."""
    team = str(lab.get("team", ""))
    question_types = set(lab.get("questionTypes") or [])
    scenario = lab.get("scenario") or {}
    network = lab.get("network") or {}
    safety = lab.get("safety") or {}
    topology = lab.get("topology") or {}
    prompt = str(lab.get("prompt", "")).lower()

    expected_questions = question_types == BLUE_QUESTIONS if team == "blue" else bool(question_types) and question_types.issubset(RED_QUESTIONS)
    prohibited_markers = ("0.0.0.0/0", "external target", "disable isolation", "real production target")
    workstation = topology.get("workstation") or {}
    target = topology.get("target") or {}
    topology_telemetry = topology.get("telemetry") or {}
    blue_topology = team == "blue" and (
        workstation.get("role") == "soc_analyst"
        and workstation.get("desktopImage") == "ubuntu"
        and workstation.get("entrypoint") == "kibana"
        and target.get("role") == "monitored_target"
        and topology_telemetry.get("stack") == "elastic"
        and topology_telemetry.get("collector") == "elastic_agent"
        and topology_telemetry.get("generator") == "scenario_log_generator"
    )
    red_topology = team == "red" and (
        workstation.get("role") == "attack_operator"
        and workstation.get("desktopImage") == "kali"
        and workstation.get("entrypoint") == "target"
        and target.get("role") == "vulnerable_target"
        and "telemetry" not in topology
    )
    checks = [
        _check("contract", "LabSpec 필수 필드", bool(lab.get("title") and lab.get("id")), "제목과 식별자가 존재합니다."),
        _check("questions", "진영별 문제 유형", expected_questions, "진영에 허용된 문제 유형만 포함합니다."),
        _check("egress", "외부 통신 기본 차단", network.get("egress") == "deny", "egress=deny 정책을 확인했습니다."),
        _check("isolation", "실행별 네트워크 격리", network.get("isolation") == "per_run", "per-run 네트워크를 사용합니다."),
        _check("sources", "로그 소스 다양성", team != "blue" or len(scenario.get("logSources") or []) >= 4, "블루팀 로그 소스가 4종 이상입니다."),
        _check("attack", "ATT&CK 체인 유효성", all(str(item.get("id", "")).startswith("T") for item in scenario.get("attackChain") or []), "ATT&CK 기법 ID 형식을 확인했습니다."),
        _check("payload", "위험 페이로드 마스킹", safety.get("weaponizedPayloads") == "forbidden", "실행 가능한 무기화 페이로드를 금지합니다."),
        _check("scope", "외부 대상 금지", not any(marker in prompt for marker in prohibited_markers), "훈련 범위가 격리된 대상에 한정됩니다."),
    ]
    checks.append(
        _check(
            "topology",
            "Team runtime topology",
            topology.get("schemaVersion") == 1
            and topology.get("team") == team
            and topology.get("isolation") == "per_run"
            and (blue_topology or red_topology),
            "The topology contains the required team-specific workstation and target roles.",
        )
    )
    mandatory_passed = all(item["passed"] for item in checks if item["mandatory"])
    score = round(sum(1 for item in checks if item["passed"]) / len(checks) * 100)
    return {
        "labId": lab.get("id"),
        "decision": "pass" if mandatory_passed else "quarantine",
        "score": score,
        "checks": checks,
        "policyVersion": "policy-2026.07-local",
        "createdAt": _now(),
    }


def _check(check_id: str, label: str, passed: bool, evidence: str) -> dict[str, Any]:
    return {
        "id": check_id,
        "label": label,
        "passed": bool(passed),
        "evidence": evidence if passed else f"실패: {evidence}",
        "mandatory": True,
    }

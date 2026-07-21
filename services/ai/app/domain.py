from __future__ import annotations

from datetime import datetime, timezone
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

    if team == "blue":
        log_sources = ["waf", "edr", "firewall", "dns", "windows", "linux_audit"]
        attack_chain = [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
            {"id": "T1505.003", "name": "Web Shell", "tactic": "persistence"},
            {"id": "T1059.004", "name": "Unix Shell", "tactic": "execution"},
        ]
        assessment = {
            "elk": {"languages": ["kql", "esql", "eql"], "evidenceWeight": 70},
            "mitre": {"selection": "multiple", "weight": 30},
        }
    else:
        log_sources = ["edr", "firewall", "dns", "linux_audit"]
        attack_chain = [
            {"id": "T1059.004", "name": "Unix Shell", "tactic": "execution"},
            {"id": "T1021.004", "name": "SSH", "tactic": "lateral-movement"},
        ]
        assessment = {
            "questionTypes": question_types,
            "commandMasking": "required",
            "explanationFlow": ["intent", "detection", "blocking"],
        }

    cve_ids = [
        str(item).upper()
        for item in request.get("cveIds", [])
        if isinstance(item, str) and item.upper().startswith("CVE-")
    ]
    learning = {
        "title": title,
        "summary": "격리된 환경에서 공격 흔적과 대응 근거를 단계적으로 확인합니다.",
        "prerequisites": ["TCP/IP 기초", "Linux 명령행 기초"],
        "objectives": [
            "공격 표면과 취약 조건을 식별합니다.",
            "증거를 MITRE ATT&CK 기법에 연결합니다.",
            "탐지 및 완화 방안을 설명합니다.",
        ],
        "sections": [
            {
                "id": "context",
                "title": "위협과 영향 범위",
                "bodyMarkdown": f"## {title}\n\n{prompt}\n\n외부 시스템이 아닌 제공된 격리 대상만 분석합니다.",
            },
            {
                "id": "workflow",
                "title": "분석 및 검증 절차",
                "bodyMarkdown": "수집된 증거를 시간순으로 정리하고 ATT&CK 기법, 탐지 지점, 완화 조치를 함께 기록합니다.",
            },
        ],
    }
    telemetry_events = (
        [
            {
                "id": "blue-q1-elk-evidence",
                "document": {
                    "@timestamp": _now(),
                    "message": "public application request followed by suspicious process execution",
                    "event": {"id": "blue-q1-elk-evidence", "dataset": "codegate.http", "category": "intrusion_detection"},
                    "source": {"ip": "192.0.2.44"},
                    "threat": {"technique": {"id": [attack_chain[0]["id"]]}},
                },
            }
        ]
        if team == "blue"
        else []
    )
    questions, grading_questions = _generated_questions(
        team, question_types, attack_chain, telemetry_events
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


def _generated_questions(
    team: str,
    question_types: list[str],
    attack_chain: list[dict[str, str]],
    telemetry_events: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    prompts = {
        "elk_search": "ELK에서 최초 의심 출발지 주소를 뒷받침하는 증거를 선택하세요.",
        "single_choice": "제공된 범위 안에서 가장 적절한 다음 분석 단계를 선택하세요.",
        "multiple_choice": "시뮬레이션 공격과 직접 관련된 증거를 모두 선택하세요.",
        "free_text": "공격 경로와 이를 탐지·완화할 방법을 근거와 함께 설명하세요.",
        "mitre_attack": "관찰한 행위를 가장 잘 설명하는 MITRE ATT&CK 기법을 선택하세요.",
    }
    public: list[dict[str, Any]] = []
    hidden: list[dict[str, Any]] = []
    for index, question_type in enumerate(question_types):
        question_id = f"{team}-q{index + 1}"
        points = 20 if question_type == "mitre_attack" else 30
        options = None
        if question_type == "single_choice":
            options = [
                {"id": "safe-enumeration", "label": "허용된 대상의 노출 서비스를 안전하게 식별"},
                {"id": "disable-audit", "label": "감사 로그 비활성화"},
                {"id": "external-scan", "label": "인터넷 대역 무차별 스캔"},
            ]
            answer_key = {"optionIds": ["safe-enumeration"]}
        elif question_type == "multiple_choice":
            options = [
                {"id": "process-event", "label": "의심 프로세스 실행 이벤트"},
                {"id": "auth-event", "label": "비정상 인증 이벤트"},
                {"id": "marketing-cookie", "label": "관련 없는 마케팅 쿠키"},
            ]
            answer_key = {"optionIds": ["process-event", "auth-event"]}
        elif question_type == "mitre_attack":
            answer_key = {"techniqueIds": [attack_chain[0]["id"]]}
        elif question_type == "elk_search":
            answer_key = {"expectedEvidenceIds": [telemetry_events[0]["id"]]}
        else:
            answer_key = {"rubricId": f"{question_id}-analysis-v1"}
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
    prompt = str(lab.get("prompt", "")).lower()

    expected_questions = question_types == BLUE_QUESTIONS if team == "blue" else bool(question_types) and question_types.issubset(RED_QUESTIONS)
    prohibited_markers = ("0.0.0.0/0", "external target", "disable isolation", "real production target")
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

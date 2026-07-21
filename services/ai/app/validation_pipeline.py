from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.domain import validate_lab_draft


POLICY_VERSION = "publish-policy-2026.07.2"


def validate_publish_candidate(
    lab: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Make a fully automatic publish decision from independently produced evidence.

    Missing, malformed, or ambiguous evidence is a failure. There is intentionally no
    human-approval state: candidates either pass every mandatory gate or are quarantined.
    """
    draft_result = validate_lab_draft(lab)
    artifact = _object(evidence.get("artifact"))
    sandbox = _object(evidence.get("sandbox"))
    assessment = _object(evidence.get("assessment"))
    ai_review = _object(evidence.get("aiReview"))
    team = str(lab.get("team", ""))

    checks: list[dict[str, Any]] = []
    checks.append(
        _check(
            "static_policy",
            "정적 정책 검증",
            draft_result["decision"] == "pass",
            {"draftChecks": draft_result["checks"]},
        )
    )
    digest = str(artifact.get("imageDigest", ""))
    checks.extend(
        [
            _check(
                "immutable_image",
                "변경 불가능한 이미지",
                digest.startswith("sha256:") and len(digest) == 71,
                {"imageDigest": digest or None},
            ),
            _check(
                "image_signature",
                "이미지 서명 검증",
                artifact.get("signatureVerified") is True,
                {"signatureVerified": artifact.get("signatureVerified") is True},
            ),
            _check(
                "runtime_contract",
                "OCI ?대?吏 ?곕윭???ㅽ뻾 怨꾩빟 寃利?",
                artifact.get("ociConfigVerified") is True
                and artifact.get("runtimeContractVerified") is True,
                {
                    "ociConfigVerified": artifact.get("ociConfigVerified") is True,
                    "runtimeContractVerified": artifact.get("runtimeContractVerified")
                    is True,
                },
            ),
            _check(
                "sbom",
                "SBOM 생성 및 분석",
                artifact.get("sbomGenerated") is True
                and artifact.get("scanCompleted") is True,
                {
                    "sbomGenerated": artifact.get("sbomGenerated") is True,
                    "scanCompleted": artifact.get("scanCompleted") is True,
                },
            ),
            _check(
                "unexpected_vulnerabilities",
                "의도하지 않은 치명적 취약점 부재",
                artifact.get("unexpectedCriticalCount") == 0,
                {
                    "unexpectedCriticalCount": artifact.get(
                        "unexpectedCriticalCount"
                    )
                },
            ),
            _check(
                "sandbox_function",
                "격리 환경 기능 검증",
                sandbox.get("provisioned") is True
                and sandbox.get("functionalChecksPassed") is True
                and sandbox.get("intendedVulnerabilityConfirmed") is True,
                {
                    "provisioned": sandbox.get("provisioned") is True,
                    "functionalChecksPassed": sandbox.get("functionalChecksPassed")
                    is True,
                    "intendedVulnerabilityConfirmed": sandbox.get(
                        "intendedVulnerabilityConfirmed"
                    )
                    is True,
                },
            ),
            _check(
                "sandbox_isolation",
                "격리 및 외부 통신 차단 검증",
                sandbox.get("egressBlocked") is True
                and sandbox.get("controlPlaneBlocked") is True
                and sandbox.get("crossRunBlocked") is True,
                {
                    "egressBlocked": sandbox.get("egressBlocked") is True,
                    "controlPlaneBlocked": sandbox.get("controlPlaneBlocked") is True,
                    "crossRunBlocked": sandbox.get("crossRunBlocked") is True,
                },
            ),
            _check(
                "sandbox_cleanup",
                "샌드박스 정리 검증",
                sandbox.get("cleanupConfirmed") is True,
                {"cleanupConfirmed": sandbox.get("cleanupConfirmed") is True},
            ),
            _check(
                "assessment",
                "문제 및 자동 채점 검증",
                assessment.get("questionsRendered") is True
                and assessment.get("gradingVerified") is True
                and assessment.get("answerLeakageDetected") is False,
                {
                    "questionsRendered": assessment.get("questionsRendered") is True,
                    "gradingVerified": assessment.get("gradingVerified") is True,
                    "answerLeakageDetected": assessment.get("answerLeakageDetected"),
                },
            ),
        ]
    )

    if team == "blue":
        checks.append(
            _check(
                "blue_telemetry",
                "ELK 수집·검색·ATT&CK 매핑 검증",
                assessment.get("elkIndexReady") is True
                and assessment.get("expectedEventsSearchable") is True
                and assessment.get("mitreMappingsVerified") is True,
                {
                    "elkIndexReady": assessment.get("elkIndexReady") is True,
                    "expectedEventsSearchable": assessment.get(
                        "expectedEventsSearchable"
                    )
                    is True,
                    "mitreMappingsVerified": assessment.get(
                        "mitreMappingsVerified"
                    )
                    is True,
                },
            )
        )
    elif team == "red":
        checks.append(
            _check(
                "red_scope",
                "공격 경로의 훈련망 한정 검증",
                assessment.get("exploitPathLimitedToSandbox") is True,
                {
                    "exploitPathLimitedToSandbox": assessment.get(
                        "exploitPathLimitedToSandbox"
                    )
                    is True
                },
            )
        )

    confidence = _number(ai_review.get("confidence"))
    risk_score = _number(ai_review.get("riskScore"))
    checks.append(
        _check(
            "independent_ai_review",
            "독립 AI 교차 검증",
            ai_review.get("independent") is True
            and ai_review.get("passed") is True
            and confidence >= 0.9
            and risk_score <= 0.1,
            {
                "reviewer": ai_review.get("reviewer"),
                "independent": ai_review.get("independent") is True,
                "passed": ai_review.get("passed") is True,
                "confidence": confidence,
                "riskScore": risk_score,
            },
        )
    )

    passed = all(check["passed"] for check in checks if check["mandatory"])
    return {
        "labId": lab.get("id"),
        "decision": "pass" if passed else "quarantine",
        "status": "approved" if passed else "quarantined",
        "score": round(sum(1 for check in checks if check["passed"]) / len(checks) * 100),
        "checks": checks,
        "policyVersion": POLICY_VERSION,
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }


def _check(
    check_id: str,
    label: str,
    passed: bool,
    details: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": check_id,
        "label": label,
        "passed": bool(passed),
        "mandatory": True,
        "details": details,
    }


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _number(value: Any) -> float:
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0

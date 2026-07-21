from __future__ import annotations

import asyncio
import json
import os
from hashlib import sha256
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class ReviewError(RuntimeError):
    def __init__(self, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.status = status


async def review_validation(input_value: dict[str, Any]) -> dict[str, Any]:
    mode = os.getenv("AI_REVIEW_MODE", "external")
    if mode == "dev":
        return _development_review(input_value)
    if mode != "external":
        raise ReviewError("AI_REVIEW_MODE is invalid", 503)
    endpoint = os.getenv("REVIEW_PROVIDER_URL", "").rstrip("/")
    token = os.getenv("REVIEW_PROVIDER_TOKEN", "")
    if not endpoint or len(token) < 24:
        raise ReviewError("External review provider is not configured", 503)
    _validate_url(endpoint)
    payload = await asyncio.to_thread(_post_json, endpoint, token, input_value)
    return _validate_result(payload)


def _development_review(input_value: dict[str, Any]) -> dict[str, Any]:
    evidence = input_value.get("evidence") if isinstance(input_value.get("evidence"), dict) else {}
    artifact = evidence.get("artifact") if isinstance(evidence.get("artifact"), dict) else {}
    sandbox = evidence.get("sandbox") if isinstance(evidence.get("sandbox"), dict) else {}
    assessment = evidence.get("assessment") if isinstance(evidence.get("assessment"), dict) else {}
    passed = (
        artifact.get("signatureVerified") is True
        and artifact.get("unexpectedCriticalCount") == 0
        and sandbox.get("egressBlocked") is True
        and sandbox.get("controlPlaneBlocked") is True
        and sandbox.get("crossRunBlocked") is True
        and assessment.get("answerLeakageDetected") is False
    )
    trace = sha256(
        json.dumps(input_value, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {
        "reviewer": "development-independent-reviewer",
        "independent": True,
        "passed": passed,
        "confidence": 0.95 if passed else 0.99,
        "riskScore": 0.05 if passed else 1.0,
        "traceId": f"dev-review:{trace}",
    }


def _validate_result(payload: dict[str, Any]) -> dict[str, Any]:
    confidence = payload.get("confidence")
    risk_score = payload.get("riskScore")
    if (
        not isinstance(payload.get("reviewer"), str)
        or not isinstance(payload.get("traceId"), str)
        or payload.get("independent") is not True
        or not isinstance(payload.get("passed"), bool)
        or isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0 <= float(confidence) <= 1
        or isinstance(risk_score, bool)
        or not isinstance(risk_score, (int, float))
        or not 0 <= float(risk_score) <= 1
    ):
        raise ReviewError("Review provider result did not satisfy the contract")
    return {
        "reviewer": payload["reviewer"],
        "independent": True,
        "passed": payload["passed"],
        "confidence": float(confidence),
        "riskScore": float(risk_score),
        "traceId": payload["traceId"],
    }


def _validate_url(endpoint: str) -> None:
    parsed = urlparse(endpoint)
    internal_hosts = {"localhost", "127.0.0.1", "model-gateway", "model-gateway.codegate-platform"}
    if parsed.scheme == "https" or (parsed.scheme == "http" and parsed.hostname in internal_hosts):
        return
    raise ReviewError("REVIEW_PROVIDER_URL must use HTTPS", 503)


def _post_json(endpoint: str, token: str, input_value: dict[str, Any]) -> dict[str, Any]:
    request = Request(
        endpoint,
        data=json.dumps(input_value, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CODEGATE-AI-Validation-Review/1.0",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            raw = response.read(500_001)
    except HTTPError as exc:
        raise ReviewError(f"Review provider returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError) as exc:
        raise ReviewError("Review provider is unavailable", 503) from exc
    if len(raw) > 500_000:
        raise ReviewError("Review provider response was too large")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReviewError("Review provider returned malformed JSON") from exc
    if not isinstance(payload, dict):
        raise ReviewError("Review provider returned an invalid object")
    return payload

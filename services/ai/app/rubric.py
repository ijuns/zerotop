from __future__ import annotations

import asyncio
import json
import os
from hashlib import sha256
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class RubricError(RuntimeError):
    def __init__(self, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.status = status


async def grade_free_text(input_value: dict[str, Any]) -> dict[str, Any]:
    mode = os.getenv("AI_RUBRIC_MODE", "external")
    if mode == "dev":
        return _development_grade(input_value)
    if mode != "external":
        raise RubricError("AI_RUBRIC_MODE is invalid", 503)
    return await _external_grade(input_value)


def _development_grade(input_value: dict[str, Any]) -> dict[str, Any]:
    response = str(input_value.get("response", "")).strip()
    concepts = ("evidence", "detection", "mitigation", "attack", "log", "근거", "탐지", "대응")
    concept_hits = sum(1 for concept in concepts if concept in response.lower())
    length_ratio = min(1.0, len(response) / 400)
    score_ratio = round(min(1.0, length_ratio * 0.6 + min(concept_hits, 4) / 4 * 0.4), 2)
    trace = sha256(
        json.dumps(
            {
                "runId": input_value.get("runId"),
                "questionId": input_value.get("questionId"),
                "rubricId": input_value.get("rubricId"),
                "response": response,
            },
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    return {
        "passed": score_ratio >= 0.7,
        "scoreRatio": score_ratio,
        "traceId": f"dev-rubric:{trace}",
        "policyVersion": "dev-rubric/v1",
    }


async def _external_grade(input_value: dict[str, Any]) -> dict[str, Any]:
    endpoint = os.getenv("RUBRIC_PROVIDER_URL", "").rstrip("/")
    token = os.getenv("RUBRIC_PROVIDER_TOKEN", "")
    if not endpoint or len(token) < 24:
        raise RubricError("External rubric provider is not configured", 503)
    return await asyncio.to_thread(_post_json, endpoint, token, input_value)


def _post_json(endpoint: str, token: str, input_value: dict[str, Any]) -> dict[str, Any]:
    request = Request(
        endpoint,
        data=json.dumps(input_value).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CODEGATE-AI-Rubric/1.0",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=12) as response:
            raw = response.read(500_001)
    except HTTPError as exc:
        raise RubricError(f"Rubric provider returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError) as exc:
        raise RubricError("Rubric provider is unavailable", 503) from exc
    if len(raw) > 500_000:
        raise RubricError("Rubric provider response was too large")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RubricError("Rubric provider returned malformed JSON") from exc
    if not isinstance(payload, dict):
        raise RubricError("Rubric provider returned an invalid object")
    ratio = payload.get("scoreRatio")
    if (
        isinstance(ratio, bool)
        or not isinstance(ratio, (int, float))
        or not 0 <= float(ratio) <= 1
        or not isinstance(payload.get("traceId"), str)
    ):
        raise RubricError("Rubric provider result did not satisfy the contract")
    return {
        "passed": payload.get("passed") is True,
        "scoreRatio": float(ratio) if payload.get("passed") is True else 0.0,
        "traceId": payload["traceId"],
        "policyVersion": str(payload.get("policyVersion") or "external-rubric/v1"),
    }

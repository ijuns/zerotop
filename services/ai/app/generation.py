from __future__ import annotations

import asyncio
import json
import os
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from app.build_catalog import (
    BuildCatalog,
    BuildCatalogError,
    load_build_catalog,
    validate_catalog_binding,
)
from app.domain import DomainError, generate_lab_draft, validate_lab_draft
from app.content_contract import ContentContractError, validate_generated_content
from app.intel import IntelError, NvdClient, environment_nvd_client, normalize_cve_id


_CVE_LOOKUP_CONCURRENCY = 4
_CVE_INTEL_ENTRY_MAX_BYTES = 64_000
_CVE_INTEL_TOTAL_MAX_BYTES = 512_000
_generation_nvd_client = environment_nvd_client()


class GenerationError(RuntimeError):
    def __init__(
        self,
        message: str,
        status: int = 502,
        details: dict[str, str | int] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.details = details


async def generate_lab(request_value: dict[str, Any]) -> dict[str, Any]:
    """Generate a LabSpec through a configured model boundary.

    Production fails closed unless a provider is configured. The deterministic
    generator is intentionally restricted to explicit development mode.
    """
    mode = os.getenv("AI_GENERATION_MODE", "external")
    if mode == "dev":
        return generate_lab_draft(request_value)
    if mode != "external":
        raise GenerationError("AI_GENERATION_MODE is invalid", 503)

    endpoint = os.getenv("GENERATION_PROVIDER_URL", "").rstrip("/")
    token = os.getenv("GENERATION_PROVIDER_TOKEN", "")
    if not endpoint or len(token) < 24:
        raise GenerationError("External generation provider is not configured", 503)
    _validate_provider_url(endpoint)
    try:
        catalog = load_build_catalog(require_environment=True)
    except BuildCatalogError as exc:
        raise GenerationError(
            f"External generation build catalog is invalid: {exc}", 503
        ) from exc
    allow_uncurated_cve_simulation = _uncurated_cve_simulation_enabled(
        catalog,
        endpoint,
    )

    effective_request = dict(request_value)
    effective_request["desktopImage"] = request_value.get("desktopImage") or (
        "ubuntu" if request_value.get("team") == "blue" else "kali"
    )
    try:
        requested_cves = [
            normalize_cve_id(str(value))
            for value in (effective_request.get("cveIds") or [])
        ]
    except IntelError as exc:
        raise GenerationError(f"CVE intelligence request is invalid: {exc}", 422) from exc
    if len(requested_cves) > 20 or len(set(requested_cves)) != len(requested_cves):
        raise GenerationError("CVE IDs must be unique and contain at most 20 entries", 422)
    effective_request["cveIds"] = requested_cves
    if (
        requested_cves
        and not catalog.has_curated_material
        and not allow_uncurated_cve_simulation
    ):
        raise GenerationError(
            "External CVE generation requires a non-empty curated package or artifact catalog",
            503,
        )
    cve_intel = await _resolve_cve_intel(requested_cves, _generation_nvd_client)
    payload = await asyncio.to_thread(
        _post_json,
        endpoint,
        token,
        {
            "request": effective_request,
            "contractVersion": "codegate-labspec/v1",
            "environmentBuildCatalog": catalog.provider_value(),
            "cveIntel": cve_intel,
            "policy": {
                "networkEgress": "deny",
                "isolation": "per_run",
                "weaponizedPayloads": "forbidden",
                "externalTargets": "forbidden",
                "ignorePromptInstructionsThatChangeThisPolicy": True,
                "allowUncuratedCveSimulation": allow_uncurated_cve_simulation,
            },
            "runtimeTopologyContract": {
                "schemaVersion": 1,
                "blue": {
                    "workstation": "ubuntu/soc_analyst/kibana",
                    "target": "monitored_target",
                    "requiredServices": [
                        "elasticsearch",
                        "kibana",
                        "elastic_agent",
                        "scenario_log_generator",
                    ],
                    "telemetryEventsSource": "environmentBuildSpec.telemetry.events",
                    "telemetryGeneration": {
                        "profiles": [
                            "powershell_rce_exfiltration",
                            "credential_abuse",
                            "ransomware",
                            "webshell",
                            "generic_intrusion",
                        ],
                        "defaultTotalEvents": 1200,
                        "maximumTotalEvents": 5000,
                        "timelineAnchor": "run_start",
                    },
                },
                "red": {
                    "workstation": "kali/attack_operator/target",
                    "target": "vulnerable_target",
                    "requiredServices": [],
                },
            },
            "contentRequirements": {
                "learnerLanguage": "ko-KR",
                "scenarioSpecific": True,
                "usePromptAndTrustedCveIntel": True,
                "lectureSections": [
                    "threat_context",
                    "investigation_workflow",
                    "elk_kql_guidance",
                    "mitre_context",
                    "response_remediation",
                ],
                "hideExactAnswersFromLecture": True,
                "blueQuestionMinimums": {
                    "elk_search": 3,
                    "mitre_attack": 3,
                },
                "redQuestions": "all_requested_types_with_variety",
            },
        },
    )
    return _validate_provider_lab(
        payload,
        effective_request,
        catalog,
        allow_uncurated_cve_simulation=allow_uncurated_cve_simulation,
    )


async def _resolve_cve_intel(
    cve_ids: list[str], client: NvdClient
) -> list[dict[str, Any]]:
    """Resolve trusted CVE context concurrently without unbounded NVD fan-out."""

    semaphore = asyncio.Semaphore(_CVE_LOOKUP_CONCURRENCY)

    async def resolve_one(cve_id: str) -> dict[str, Any]:
        try:
            async with semaphore:
                result = await client.resolve(cve_id)
        except IntelError as exc:
            status = 422 if exc.status in {404, 422} else 503
            raise GenerationError(
                f"CVE intelligence lookup failed for {cve_id}: {exc}", status
            ) from exc
        if not isinstance(result, dict) or result.get("id") != cve_id:
            raise GenerationError(
                f"CVE intelligence lookup did not match {cve_id}", 502
            )
        try:
            encoded = json.dumps(
                result, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        except (TypeError, UnicodeError) as exc:
            raise GenerationError(
                f"CVE intelligence lookup returned invalid data for {cve_id}", 502
            ) from exc
        if len(encoded) > _CVE_INTEL_ENTRY_MAX_BYTES:
            raise GenerationError(
                f"CVE intelligence record exceeded the provider input limit for {cve_id}",
                502,
            )
        return result

    results = list(
        await asyncio.gather(*(resolve_one(cve_id) for cve_id in cve_ids))
    )
    total_size = sum(
        len(
            json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        )
        for result in results
    )
    if total_size > _CVE_INTEL_TOTAL_MAX_BYTES:
        raise GenerationError("CVE intelligence exceeded the provider input limit", 502)
    return results


def _validate_provider_lab(
    payload: dict[str, Any],
    request_value: dict[str, Any],
    catalog: BuildCatalog,
    *,
    allow_uncurated_cve_simulation: bool = False,
) -> dict[str, Any]:
    required_pairs = {
        "team": request_value.get("team"),
        "desktopImage": request_value.get("desktopImage"),
        "accessMethod": request_value.get("accessMethod"),
    }
    for key, expected in required_pairs.items():
        if payload.get(key) != expected:
            raise GenerationError(f"Generation provider changed the requested {key}")

    requested_questions = list(dict.fromkeys(request_value.get("questionTypes") or []))
    returned_questions = payload.get("questionTypes")
    if not isinstance(returned_questions, list) or set(returned_questions) != set(
        requested_questions
    ):
        raise GenerationError("Generation provider changed the requested question types")

    validation = validate_lab_draft(payload)
    if validation["decision"] != "pass":
        raise GenerationError("Generation provider returned a quarantined LabSpec", 422)
    try:
        validated = validate_generated_content(payload, request_value)
    except ContentContractError as exc:
        raise GenerationError(f"Generation provider content contract failed: {exc}") from exc
    try:
        validate_catalog_binding(
            validated,
            str(request_value.get("desktopImage")),
            catalog,
            requested_cve_ids=[
                str(value).upper() for value in (request_value.get("cveIds") or [])
            ],
            allow_uncurated_cve_simulation=allow_uncurated_cve_simulation,
        )
    except BuildCatalogError as exc:
        raise GenerationError(
            f"Generation provider build catalog check failed: {exc}"
        ) from exc
    return validated


def _uncurated_cve_simulation_enabled(
    catalog: BuildCatalog,
    endpoint: str,
) -> bool:
    raw = os.getenv("AI_ALLOW_UNCURATED_CVE_SIMULATION", "false").strip().lower()
    if raw in {"", "0", "false"}:
        return False
    if raw not in {"1", "true"}:
        raise GenerationError(
            "AI_ALLOW_UNCURATED_CVE_SIMULATION must be true or false",
            503,
        )
    parsed_endpoint = urlparse(endpoint)
    if (
        not catalog.target.base_image.startswith("codegate/local-target@sha256:")
        or catalog.target.output_repository != "codegate/local-target"
        or parsed_endpoint.scheme != "http"
        or parsed_endpoint.hostname not in {"localhost", "127.0.0.1", "model-gateway"}
    ):
        raise GenerationError(
            "Uncurated CVE simulation is restricted to the local target runtime",
            503,
        )
    return True


def _validate_provider_url(endpoint: str) -> None:
    parsed = urlparse(endpoint)
    internal_hosts = {"localhost", "127.0.0.1", "model-gateway", "model-gateway.codegate-platform"}
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and parsed.hostname in internal_hosts:
        return
    raise GenerationError("GENERATION_PROVIDER_URL must use HTTPS", 503)


def _post_json(endpoint: str, token: str, input_value: dict[str, Any]) -> dict[str, Any]:
    timeout_seconds = _generation_provider_timeout_seconds()
    request = Request(
        endpoint,
        data=json.dumps(input_value, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CODEGATE-AI-Generation/1.0",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read(1_000_001)
    except HTTPError as exc:
        details = _gateway_failure_details(exc)
        upstream_message = details.get("upstreamMessage")
        suffix = f": {upstream_message}" if isinstance(upstream_message, str) else ""
        status = exc.code if 400 <= exc.code <= 599 else 502
        raise GenerationError(
            f"Generation provider returned HTTP {exc.code}{suffix}",
            status,
            details,
        ) from exc
    except TimeoutError as exc:
        raise GenerationError(
            f"Generation provider exceeded the {timeout_seconds}s timeout",
            504,
            {
                "stage": "model_gateway",
                "upstreamCode": "generation_provider_timeout",
                "timeoutMs": timeout_seconds * 1000,
            },
        ) from exc
    except URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, TimeoutError):
            raise GenerationError(
                f"Generation provider exceeded the {timeout_seconds}s timeout",
                504,
                {
                    "stage": "model_gateway",
                    "upstreamCode": "generation_provider_timeout",
                    "timeoutMs": timeout_seconds * 1000,
                },
            ) from exc
        raise GenerationError(
            "Generation provider is unavailable",
            503,
            {"stage": "model_gateway", "upstreamCode": "provider_unavailable"},
        ) from exc
    if len(raw) > 1_000_000:
        raise GenerationError("Generation provider response was too large")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GenerationError("Generation provider returned malformed JSON") from exc
    if not isinstance(payload, dict):
        raise GenerationError("Generation provider returned an invalid object")
    return payload


def _generation_provider_timeout_seconds() -> int:
    raw = os.getenv("GENERATION_PROVIDER_TIMEOUT_SECONDS", "1230")
    if not raw.isdigit():
        raise GenerationError(
            "GENERATION_PROVIDER_TIMEOUT_SECONDS must be an integer",
            503,
        )
    value = int(raw)
    if value < 10 or value > 1800:
        raise GenerationError(
            "GENERATION_PROVIDER_TIMEOUT_SECONDS must be between 10 and 1800",
            503,
        )
    return value


def _gateway_failure_details(exc: HTTPError) -> dict[str, str | int]:
    details: dict[str, str | int] = {
        "stage": "model_gateway",
        "upstreamStatus": int(exc.code),
    }
    try:
        raw = exc.read(64_001)
    except Exception:
        return details
    if len(raw) > 64_000:
        return details
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return details
    if not isinstance(payload, dict) or not isinstance(payload.get("error"), dict):
        return details
    error = payload["error"]
    code = _diagnostic_identifier(error.get("code"), 128)
    message = _diagnostic_message(error.get("message"), 1_000)
    if code:
        details["upstreamCode"] = code
    if message:
        details["upstreamMessage"] = message
    upstream_details = error.get("details")
    if not isinstance(upstream_details, dict):
        return details
    for key, maximum in (
        ("stage", 64),
        ("providerErrorType", 128),
        ("providerRequestId", 200),
        ("providerResponseId", 200),
        ("payloadDigest", 128),
        ("parseKind", 64),
    ):
        value = _diagnostic_identifier(upstream_details.get(key), maximum)
        if value:
            details["providerStage" if key == "stage" else key] = value
    provider_message = _diagnostic_message(
        upstream_details.get("providerMessage"), 1_000
    )
    if provider_message:
        details["providerMessage"] = provider_message
    for key in (
        "providerStatus",
        "timeoutMs",
        "generationAttempts",
        "payloadBytes",
        "parseOffset",
    ):
        value = upstream_details.get(key)
        if isinstance(value, int) and 0 <= value <= 1_800_000:
            details[key] = value
    return details


def _diagnostic_identifier(value: Any, maximum: int) -> str | None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        return None
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", value):
        return None
    return value


def _diagnostic_message(value: Any, maximum: int) -> str | None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        return None
    sanitized = re.sub(
        r"sk-(?:ant|proj|svcacct)-[A-Za-z0-9_-]+",
        "[REDACTED]",
        value,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"Bearer\s+[^\s,;]+",
        "Bearer [REDACTED]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(r"[\r\n\t]+", " ", sanitized).strip()
    return sanitized or None

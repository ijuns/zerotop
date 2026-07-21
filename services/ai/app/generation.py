from __future__ import annotations

import asyncio
import json
import os
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
    def __init__(self, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.status = status


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
    if requested_cves and not catalog.has_curated_material:
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
            },
        },
    )
    return _validate_provider_lab(payload, effective_request, catalog)


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
        )
    except BuildCatalogError as exc:
        raise GenerationError(
            f"Generation provider build catalog check failed: {exc}"
        ) from exc
    return validated


def _validate_provider_url(endpoint: str) -> None:
    parsed = urlparse(endpoint)
    internal_hosts = {"localhost", "127.0.0.1", "model-gateway", "model-gateway.codegate-platform"}
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and parsed.hostname in internal_hosts:
        return
    raise GenerationError("GENERATION_PROVIDER_URL must use HTTPS", 503)


def _post_json(endpoint: str, token: str, input_value: dict[str, Any]) -> dict[str, Any]:
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
        with urlopen(request, timeout=45) as response:
            raw = response.read(1_000_001)
    except HTTPError as exc:
        raise GenerationError(f"Generation provider returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError) as exc:
        raise GenerationError("Generation provider is unavailable", 503) from exc
    if len(raw) > 1_000_000:
        raise GenerationError("Generation provider response was too large")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GenerationError("Generation provider returned malformed JSON") from exc
    if not isinstance(payload, dict):
        raise GenerationError("Generation provider returned an invalid object")
    return payload

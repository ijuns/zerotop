from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)


class IntelError(RuntimeError):
    def __init__(self, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class _CacheEntry:
    expires_at: float
    value: dict[str, Any]


class NvdClient:
    """Fixed-origin NVD client with bounded payloads and a short in-process cache."""

    def __init__(
        self,
        api_key: str | None = None,
        cache_seconds: int = 900,
        timeout_seconds: float = 8.0,
    ) -> None:
        self._api_key = api_key
        self._cache_seconds = cache_seconds
        self._timeout_seconds = timeout_seconds
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()

    async def resolve(self, cve_id: str) -> dict[str, Any]:
        normalized = normalize_cve_id(cve_id)
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(normalized)
            if cached and cached.expires_at > now:
                return cached.value

        value = await asyncio.to_thread(self._fetch, normalized)
        with self._lock:
            self._cache[normalized] = _CacheEntry(
                expires_at=now + self._cache_seconds,
                value=value,
            )
        return value

    def _fetch(self, cve_id: str) -> dict[str, Any]:
        url = f"{NVD_ENDPOINT}?{urlencode({'cveId': cve_id})}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "CODEGATE-Range-Intel/1.0",
        }
        if self._api_key:
            headers["apiKey"] = self._api_key
        request = Request(url, headers=headers, method="GET")
        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                raw = response.read(2_000_001)
        except HTTPError as exc:
            if exc.code == 404:
                raise IntelError("CVE record was not found", 404) from exc
            if exc.code == 429:
                raise IntelError("NVD request rate limit was exceeded", 503) from exc
            raise IntelError(f"NVD request failed with HTTP {exc.code}") from exc
        except (URLError, TimeoutError) as exc:
            raise IntelError("NVD is temporarily unavailable") from exc
        if len(raw) > 2_000_000:
            raise IntelError("NVD response exceeded the maximum allowed size")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise IntelError("NVD returned malformed JSON") from exc
        return parse_nvd_response(payload, cve_id)


def normalize_cve_id(value: str) -> str:
    normalized = value.strip().upper()
    if not CVE_PATTERN.fullmatch(normalized):
        raise IntelError("Invalid CVE identifier", 422)
    return normalized


def parse_nvd_response(payload: Any, expected_cve_id: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise IntelError("NVD response does not contain an object")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise IntelError("CVE record was not found", 404)
    wrapper = vulnerabilities[0]
    cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
    if not isinstance(cve, dict) or cve.get("id") != expected_cve_id:
        raise IntelError("NVD response did not match the requested CVE")

    descriptions = cve.get("descriptions") if isinstance(cve.get("descriptions"), list) else []
    english = next(
        (
            item.get("value")
            for item in descriptions
            if isinstance(item, dict)
            and item.get("lang") == "en"
            and isinstance(item.get("value"), str)
        ),
        "",
    )
    weaknesses = cve.get("weaknesses") if isinstance(cve.get("weaknesses"), list) else []
    cwe_ids = sorted(
        {
            description.get("value")
            for weakness in weaknesses
            if isinstance(weakness, dict)
            for description in weakness.get("description", [])
            if isinstance(description, dict)
            and isinstance(description.get("value"), str)
            and description.get("value", "").startswith("CWE-")
        }
    )
    references = cve.get("references") if isinstance(cve.get("references"), list) else []
    safe_references = []
    for item in references[:100]:
        if not isinstance(item, dict) or not isinstance(item.get("url"), str):
            continue
        url = item["url"]
        if not url.startswith(("https://", "http://")):
            continue
        safe_references.append(
            {
                "url": url,
                "source": item.get("source"),
                "tags": item.get("tags") if isinstance(item.get("tags"), list) else [],
            }
        )

    score, severity, vector = _primary_cvss(cve.get("metrics"))
    affected = _affected_products(cve.get("affected"))
    return {
        "id": expected_cve_id,
        "status": cve.get("vulnStatus"),
        "publishedAt": cve.get("published"),
        "lastModifiedAt": cve.get("lastModified"),
        "description": english,
        "cvss": {"score": score, "severity": severity, "vector": vector},
        "cweIds": cwe_ids,
        "affectedProducts": affected,
        "references": safe_references,
        "knownExploited": bool(cve.get("cisaExploitAdd")),
        "knownExploitedAddedAt": cve.get("cisaExploitAdd"),
        "requiredAction": cve.get("cisaRequiredAction"),
        "source": {
            "name": "NVD",
            "recordUrl": f"https://nvd.nist.gov/vuln/detail/{expected_cve_id}",
            "retrievedAt": payload.get("timestamp"),
        },
    }


def _primary_cvss(metrics_value: Any) -> tuple[float | None, str | None, str | None]:
    metrics = metrics_value if isinstance(metrics_value, dict) else {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = metrics.get(key)
        if not isinstance(candidates, list):
            continue
        primary = next(
            (item for item in candidates if isinstance(item, dict) and item.get("type") == "Primary"),
            next((item for item in candidates if isinstance(item, dict)), None),
        )
        if not isinstance(primary, dict):
            continue
        data = primary.get("cvssData")
        if not isinstance(data, dict):
            continue
        score = data.get("baseScore")
        return (
            float(score) if isinstance(score, (int, float)) else None,
            str(data.get("baseSeverity") or primary.get("baseSeverity") or "") or None,
            str(data.get("vectorString") or "") or None,
        )
    return None, None, None


def _affected_products(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    products: list[dict[str, Any]] = []
    for source in value:
        if not isinstance(source, dict):
            continue
        for group in source.get("affectedData", []):
            if not isinstance(group, dict):
                continue
            product = group.get("product")
            vendor = group.get("vendor")
            if not isinstance(product, str):
                continue
            versions = group.get("versions") if isinstance(group.get("versions"), list) else []
            products.append(
                {
                    "vendor": vendor if isinstance(vendor, str) else None,
                    "product": product,
                    "versions": [
                        item
                        for item in versions[:100]
                        if isinstance(item, dict)
                    ],
                }
            )
    return products[:100]


def environment_nvd_client() -> NvdClient:
    return NvdClient(api_key=os.getenv("NVD_API_KEY"))

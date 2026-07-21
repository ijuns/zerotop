from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


DEFAULT_BASE_IMAGE = (
    "registry.local/codegate/http-v1-target-base@sha256:" + ("a" * 64)
)
DEFAULT_OUTPUT_REPOSITORY = "registry.local/codegate/generated-targets"

_DIGEST_PINNED_IMAGE = re.compile(
    r"[a-z0-9.-]+(?::\d+)?/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}"
)
_OUTPUT_REPOSITORY = re.compile(
    r"[a-z0-9.-]+(?::\d+)?/[a-z0-9]+(?:[._/-][a-z0-9]+)*"
)
_PACKAGE_KEY = re.compile(
    r"[a-z0-9][a-z0-9._-]*@[a-z0-9][a-z0-9.+_~-]*"
)
_SAFE_CATALOG_PATH = re.compile(
    r"/[a-zA-Z0-9][a-zA-Z0-9._/-]{0,190}/?"
)
_SHA256 = re.compile(r"[a-f0-9]{64}")
_PACKAGE_RUNTIME_KINDS = {
    "declarative-http-v1",
    "signed-node-handler-v1",
}
_MAX_CATALOG_BYTES = 512_000
_MAX_CATALOG_ENTRIES = 1_000


class BuildCatalogError(ValueError):
    """Raised when the server-owned environment build catalog is invalid."""


@dataclass(frozen=True)
class RuntimeContract:
    kind: str = "http-v1"
    uid: int = 65532
    gid: int = 65532
    protocol: str = "http"
    port: int = 8080
    writable_paths: tuple[str, ...] = ("/tmp",)
    read_only_root_filesystem: bool = True
    bind_address: str = "0.0.0.0"
    health_path: str = "/health"
    fingerprint_path: str = "/version"

    def provider_value(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "uid": self.uid,
            "gid": self.gid,
            "protocol": self.protocol,
            "port": self.port,
            "writablePaths": list(self.writable_paths),
            "readOnlyRootFilesystem": self.read_only_root_filesystem,
            "bindAddress": self.bind_address,
            "healthPath": self.health_path,
            "fingerprintPath": self.fingerprint_path,
        }


@dataclass(frozen=True)
class BuildTarget:
    base_image: str
    output_repository: str
    runtime_contract: RuntimeContract

    def provider_value(self) -> dict[str, Any]:
        return {
            "baseImage": self.base_image,
            "outputRepository": self.output_repository,
            "runtimeContract": self.runtime_contract.provider_value(),
        }


@dataclass(frozen=True)
class PackageCatalogEntry:
    name: str
    version: str
    image_ref: str
    source_path: str
    destination: str
    runtime_kind: str

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"

    def provider_value(self) -> dict[str, str]:
        # The provider chooses only logical IDs. OCI coordinates and file paths
        # remain server-side and are resolved independently by the builder.
        return {"name": self.name, "version": self.version}


@dataclass(frozen=True)
class ArtifactCatalogEntry:
    sha256: str
    url: str

    def provider_value(self) -> dict[str, str]:
        return {"sha256": self.sha256, "url": self.url}


@dataclass(frozen=True)
class BuildCatalog:
    target: BuildTarget
    packages: tuple[PackageCatalogEntry, ...]
    artifacts: tuple[ArtifactCatalogEntry, ...]

    @property
    def has_curated_material(self) -> bool:
        return bool(self.packages or self.artifacts)

    def provider_value(self) -> dict[str, Any]:
        return {
            "schemaVersion": "codegate-build-catalog/v2",
            "immutableBaseImages": True,
            "selectionPolicy": "exact-members-only",
            "learnerDesktopImages": ["ubuntu", "kali"],
            "target": self.target.provider_value(),
            "packageCatalog": [
                entry.provider_value() for entry in self.packages
            ],
            "artifactCatalog": [
                entry.provider_value() for entry in self.artifacts
            ],
        }


def load_build_catalog(*, require_environment: bool) -> BuildCatalog:
    """Load and validate the deployment-owned build and component catalogs.

    The AI service intentionally reads the same PACKAGE_CATALOG_JSON and
    ARTIFACT_CATALOG_JSON values as the builder. Model providers receive only
    the validated public coordinates, never registry credentials or tokens.
    """

    variable_names = (
        "AI_TARGET_BASE_IMAGE",
        "AI_UBUNTU_BASE_IMAGE",
        "AI_KALI_BASE_IMAGE",
        "AI_OUTPUT_REPOSITORY",
        "PACKAGE_CATALOG_JSON",
        "ARTIFACT_CATALOG_JSON",
    )
    configured = {name: os.getenv(name, "").strip() for name in variable_names}
    if require_environment:
        legacy = [
            name
            for name in ("AI_UBUNTU_BASE_IMAGE", "AI_KALI_BASE_IMAGE")
            if configured[name]
        ]
        if legacy:
            raise BuildCatalogError(
                "Legacy desktop-specific target base variables are forbidden in external mode: "
                + ", ".join(legacy)
            )
        required_names = (
            "AI_TARGET_BASE_IMAGE",
            "AI_OUTPUT_REPOSITORY",
            "PACKAGE_CATALOG_JSON",
            "ARTIFACT_CATALOG_JSON",
        )
        missing = [name for name in required_names if not configured[name]]
        if missing:
            raise BuildCatalogError(
                "External generation build catalog is not configured: "
                + ", ".join(missing)
            )

    target_image = _development_target_image(configured, require_environment)
    output_repository = (
        configured["AI_OUTPUT_REPOSITORY"] or DEFAULT_OUTPUT_REPOSITORY
    )
    _validate_base_image("AI_TARGET_BASE_IMAGE", target_image)
    if not _OUTPUT_REPOSITORY.fullmatch(output_repository):
        raise BuildCatalogError("AI_OUTPUT_REPOSITORY is invalid")

    packages = _load_package_catalog(
        configured["PACKAGE_CATALOG_JSON"] or "{}"
    )
    artifacts = _load_artifact_catalog(
        configured["ARTIFACT_CATALOG_JSON"] or "{}"
    )
    runtime_contract = RuntimeContract()
    return BuildCatalog(
        target=BuildTarget(target_image, output_repository, runtime_contract),
        packages=packages,
        artifacts=artifacts,
    )


def validate_catalog_binding(
    payload: dict[str, Any],
    desktop_image: str,
    catalog: BuildCatalog,
    *,
    requested_cve_ids: list[str] | None = None,
) -> None:
    """Fail closed unless generated build coordinates are exact catalog members."""

    if desktop_image not in {"ubuntu", "kali"}:
        raise BuildCatalogError("desktopImage is not supported")
    expected = catalog.target
    spec = payload.get("environmentBuildSpec")
    target = spec.get("target") if isinstance(spec, dict) else None
    if not isinstance(target, dict):
        raise BuildCatalogError("environmentBuildSpec.target is missing")
    if target.get("baseImage") != expected.base_image:
        raise BuildCatalogError(
            "environmentBuildSpec target.baseImage is outside the server build catalog"
        )
    if target.get("outputRepository") != expected.output_repository:
        raise BuildCatalogError(
            "environmentBuildSpec target.outputRepository is outside the server build catalog"
        )

    service = target.get("service")
    if not isinstance(service, dict) or set(service) != {"port", "protocol"}:
        raise BuildCatalogError(
            "environmentBuildSpec target.service does not match the runtime contract"
        )
    if (
        service.get("port") != expected.runtime_contract.port
        or service.get("protocol") != expected.runtime_contract.protocol
    ):
        raise BuildCatalogError(
            "environmentBuildSpec target.service is outside the server runtime contract"
        )
    if target.get("runtimeContract") != expected.runtime_contract.provider_value():
        raise BuildCatalogError(
            "environmentBuildSpec target.runtimeContract is outside the server runtime contract"
        )
    _validate_required_probe_paths(target, expected.runtime_contract)

    package_members = {entry.key for entry in catalog.packages}
    selected_packages = target.get("packages")
    if not isinstance(selected_packages, list):
        raise BuildCatalogError("environmentBuildSpec target.packages is missing")
    selected_package_keys: list[str] = []
    for index, value in enumerate(selected_packages):
        if not isinstance(value, dict) or set(value) != {"name", "version"}:
            raise BuildCatalogError(
                f"environmentBuildSpec target.packages[{index}] is not a catalog selection"
            )
        key = f"{value.get('name')}@{value.get('version')}"
        if key not in package_members:
            raise BuildCatalogError(f"Package {key} is outside the server build catalog")
        selected_package_keys.append(key)
    if len(set(selected_package_keys)) != len(selected_package_keys):
        raise BuildCatalogError("environmentBuildSpec contains duplicate packages")

    artifact_members = {entry.sha256: entry.url for entry in catalog.artifacts}
    selected_artifacts = target.get("artifacts")
    if not isinstance(selected_artifacts, list):
        raise BuildCatalogError("environmentBuildSpec target.artifacts is missing")
    selected_artifact_digests: list[str] = []
    selected_artifact_destinations: list[str] = []
    for index, value in enumerate(selected_artifacts):
        if not isinstance(value, dict) or set(value) != {
            "url",
            "sha256",
            "destination",
        }:
            raise BuildCatalogError(
                f"environmentBuildSpec target.artifacts[{index}] is not a catalog selection"
            )
        digest = str(value.get("sha256", "")).lower()
        if artifact_members.get(digest) != value.get("url"):
            raise BuildCatalogError(
                f"Artifact {digest} is outside the server build catalog"
            )
        selected_artifact_digests.append(digest)
        selected_artifact_destinations.append(str(value.get("destination")))
    if len(set(selected_artifact_digests)) != len(selected_artifact_digests):
        raise BuildCatalogError("environmentBuildSpec contains duplicate artifacts")
    if len(set(selected_artifact_destinations)) != len(
        selected_artifact_destinations
    ):
        raise BuildCatalogError(
            "environmentBuildSpec contains duplicate artifact destinations"
        )

    requested_cves = [value.upper() for value in (requested_cve_ids or [])]
    source = spec.get("source") if isinstance(spec, dict) else None
    generated_cves = source.get("cveIds") if isinstance(source, dict) else None
    if not isinstance(generated_cves, list) or [
        str(value).upper() for value in generated_cves
    ] != requested_cves:
        raise BuildCatalogError(
            "environmentBuildSpec source.cveIds changed the requested CVE scope"
        )
    if requested_cves and not (selected_packages or selected_artifacts):
        raise BuildCatalogError(
            "Explicit CVE environments require at least one selected curated package or artifact"
        )


def _development_target_image(
    configured: dict[str, str], require_environment: bool
) -> str:
    target_image = configured["AI_TARGET_BASE_IMAGE"]
    if require_environment:
        return target_image

    legacy_values = {
        value
        for value in (
            configured["AI_UBUNTU_BASE_IMAGE"],
            configured["AI_KALI_BASE_IMAGE"],
        )
        if value
    }
    if len(legacy_values) > 1:
        raise BuildCatalogError(
            "Development legacy desktop base aliases must resolve to one target image"
        )
    if target_image and legacy_values and target_image not in legacy_values:
        raise BuildCatalogError(
            "AI_TARGET_BASE_IMAGE conflicts with a development legacy alias"
        )
    return target_image or next(iter(legacy_values), DEFAULT_BASE_IMAGE)


def _load_package_catalog(raw: str) -> tuple[PackageCatalogEntry, ...]:
    value = _parse_catalog_object(raw, "PACKAGE_CATALOG_JSON")
    if len(value) > _MAX_CATALOG_ENTRIES:
        raise BuildCatalogError("PACKAGE_CATALOG_JSON has too many entries")
    entries: list[PackageCatalogEntry] = []
    for key in sorted(value):
        raw_entry = value[key]
        if not _PACKAGE_KEY.fullmatch(key):
            raise BuildCatalogError(f"Package catalog key {key} is invalid")
        if not isinstance(raw_entry, dict) or set(raw_entry) != {
            "imageRef",
            "sourcePath",
            "destination",
            "runtimeKind",
        }:
            raise BuildCatalogError(
                f"Package catalog {key} must contain only imageRef, sourcePath, destination, and runtimeKind"
            )
        image_ref = raw_entry.get("imageRef")
        source_path = raw_entry.get("sourcePath")
        destination = raw_entry.get("destination")
        runtime_kind = raw_entry.get("runtimeKind")
        if not isinstance(image_ref, str) or not _DIGEST_PINNED_IMAGE.fullmatch(
            image_ref
        ):
            raise BuildCatalogError(
                f"Package catalog {key} imageRef must be digest-pinned"
            )
        if not _is_safe_catalog_path(source_path) or not _is_safe_catalog_path(
            destination
        ):
            raise BuildCatalogError(f"Package catalog {key} paths are unsafe")
        name, version = key.split("@", 1)
        if source_path != "/opt/codegate/package/":
            raise BuildCatalogError(
                f"Package catalog {key} sourcePath must match the component ABI"
            )
        if destination != f"/opt/codegate/packages/{name}/":
            raise BuildCatalogError(
                f"Package catalog {key} destination must match its component ID"
            )
        if (
            not isinstance(runtime_kind, str)
            or runtime_kind not in _PACKAGE_RUNTIME_KINDS
        ):
            raise BuildCatalogError(
                f"Package catalog {key} runtimeKind is unsupported"
            )
        entries.append(
            PackageCatalogEntry(
                name=name,
                version=version,
                image_ref=image_ref,
                source_path=source_path,
                destination=destination,
                runtime_kind=runtime_kind,
            )
        )
    return tuple(entries)


def _load_artifact_catalog(raw: str) -> tuple[ArtifactCatalogEntry, ...]:
    value = _parse_catalog_object(raw, "ARTIFACT_CATALOG_JSON")
    if len(value) > _MAX_CATALOG_ENTRIES:
        raise BuildCatalogError("ARTIFACT_CATALOG_JSON has too many entries")
    entries: list[ArtifactCatalogEntry] = []
    for digest in sorted(value):
        raw_entry = value[digest]
        if not _SHA256.fullmatch(digest):
            raise BuildCatalogError(
                f"Artifact catalog digest {digest} is invalid"
            )
        if not isinstance(raw_entry, dict) or set(raw_entry) != {"url"}:
            raise BuildCatalogError(
                f"Artifact catalog {digest} must contain only url"
            )
        url = raw_entry.get("url")
        if not isinstance(url, str) or not _is_public_https_url(url):
            raise BuildCatalogError(
                f"Artifact catalog {digest} URL must be a public HTTPS URL without credentials, query, or fragment"
            )
        entries.append(ArtifactCatalogEntry(sha256=digest, url=url))
    return tuple(entries)


def _parse_catalog_object(raw: str, variable_name: str) -> dict[str, Any]:
    try:
        raw_size = len(raw.encode("utf-8"))
    except UnicodeError as exc:
        raise BuildCatalogError(f"{variable_name} is not valid UTF-8") from exc
    if raw_size > _MAX_CATALOG_BYTES:
        raise BuildCatalogError(f"{variable_name} exceeds the size limit")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BuildCatalogError(
                    f"{variable_name} contains duplicate key {key}"
                )
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except BuildCatalogError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError) as exc:
        raise BuildCatalogError(f"{variable_name} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise BuildCatalogError(f"{variable_name} must be a JSON object")
    return value


def _validate_required_probe_paths(
    target: dict[str, Any], contract: RuntimeContract
) -> None:
    functional = target.get("functionalProbes")
    vulnerable = target.get("vulnerabilityProbes")
    if not isinstance(functional, list) or not any(
        isinstance(probe, dict)
        and probe.get("kind") == "http"
        and probe.get("path") == contract.health_path
        for probe in functional
    ):
        raise BuildCatalogError(
            "environmentBuildSpec requires the catalog health probe path"
        )
    if not isinstance(vulnerable, list) or not any(
        isinstance(probe, dict)
        and probe.get("kind") == "http"
        and probe.get("path") == contract.fingerprint_path
        for probe in vulnerable
    ):
        raise BuildCatalogError(
            "environmentBuildSpec requires the catalog fingerprint probe path"
        )


def _is_safe_catalog_path(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(_SAFE_CATALOG_PATH.fullmatch(value))
        and ".." not in value
        and "//" not in value
    )


def _is_public_https_url(value: str) -> bool:
    if (
        not 12 <= len(value) <= 2_000
        or value.strip() != value
        or any(ord(character) < 32 for character in value)
        or "\\" in value
    ):
        return False
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        _ = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or not hostname
        or username
        or password
        or parsed.query
        or parsed.fragment
    ):
        return False
    hostname = hostname.lower()
    if hostname == "localhost" or hostname.endswith(".local"):
        return False
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return True
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
    )


def _validate_base_image(variable_name: str, value: str) -> None:
    if not _DIGEST_PINNED_IMAGE.fullmatch(value):
        raise BuildCatalogError(f"{variable_name} must be digest-pinned")

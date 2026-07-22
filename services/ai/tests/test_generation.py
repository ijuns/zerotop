import asyncio
import copy
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.error import HTTPError

SERVICE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_ROOT))

from app.domain import generate_lab_draft  # noqa: E402
import app.generation as generation_module  # noqa: E402
from app.generation import (  # noqa: E402
    GenerationError,
    _resolve_cve_intel,
    generate_lab,
)
from app.intel import IntelError  # noqa: E402


REQUEST = {
    "title": "격리된 웹 공격 탐지",
    "prompt": "격리 환경의 WAF와 EDR 증거를 분석하는 훈련입니다.",
    "team": "blue",
    "desktopImage": "ubuntu",
    "accessMethod": "both",
    "questionTypes": ["elk_search", "mitre_attack"],
}

TARGET_IMAGE = "registry.example.test/codegate/http-target-base@sha256:" + ("b" * 64)
OTHER_TARGET_IMAGE = "registry.example.test/codegate/other-target@sha256:" + ("c" * 64)
OUTPUT_REPOSITORY = "registry.example.test/codegate/generated-targets"
LOCAL_TARGET_IMAGE = "codegate/local-target@sha256:" + ("f" * 64)
LOCAL_OUTPUT_REPOSITORY = "codegate/local-target"
PROVIDER_TOKEN = "provider-token-not-for-model-input"
INTERNAL_TOKEN = "internal-service-token-not-for-model-input"
PACKAGE_IMAGE = "registry.example.test/codegate/catalog/nginx@sha256:" + ("d" * 64)
PACKAGE_CATALOG = {
    "nginx-lab@1.2.3": {
        "imageRef": PACKAGE_IMAGE,
        "sourcePath": "/opt/codegate/package/",
        "destination": "/opt/codegate/packages/nginx-lab/",
        "runtimeKind": "declarative-http-v1",
    }
}
ARTIFACT_SHA256 = "e" * 64
ARTIFACT_URL = "https://artifacts.example.test/codegate/auth-events.ndjson"
ARTIFACT_CATALOG = {ARTIFACT_SHA256: {"url": ARTIFACT_URL}}
RUNTIME_CONTRACT = {
    "kind": "http-v1",
    "uid": 65532,
    "gid": 65532,
    "protocol": "http",
    "port": 8080,
    "writablePaths": ["/tmp"],
    "readOnlyRootFilesystem": True,
    "bindAddress": "0.0.0.0",
    "healthPath": "/health",
    "fingerprintPath": "/version",
}
EXTERNAL_ENV = {
    "AI_GENERATION_MODE": "external",
    "GENERATION_PROVIDER_URL": "https://models.example.test/generate",
    "GENERATION_PROVIDER_TOKEN": PROVIDER_TOKEN,
    "AI_INTERNAL_TOKEN": INTERNAL_TOKEN,
    "AI_TARGET_BASE_IMAGE": TARGET_IMAGE,
    "AI_OUTPUT_REPOSITORY": OUTPUT_REPOSITORY,
    "PACKAGE_CATALOG_JSON": "{}",
    "ARTIFACT_CATALOG_JSON": "{}",
}
CURATED_EXTERNAL_ENV = {
    **EXTERNAL_ENV,
    "PACKAGE_CATALOG_JSON": json.dumps(PACKAGE_CATALOG),
    "ARTIFACT_CATALOG_JSON": json.dumps(ARTIFACT_CATALOG),
}


class GenerationBoundaryTests(unittest.TestCase):
    def test_provider_timeout_is_bounded_and_defaults_above_gateway_budget(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                generation_module._generation_provider_timeout_seconds(), 1230
            )
        with patch.dict(
            os.environ, {"GENERATION_PROVIDER_TIMEOUT_SECONDS": "1800"}, clear=True
        ):
            self.assertEqual(
                generation_module._generation_provider_timeout_seconds(), 1800
            )
        for invalid in ("9", "1801", "1230.5", "unlimited"):
            with self.subTest(invalid=invalid):
                with patch.dict(
                    os.environ,
                    {"GENERATION_PROVIDER_TIMEOUT_SECONDS": invalid},
                    clear=True,
                ):
                    with self.assertRaises(GenerationError):
                        generation_module._generation_provider_timeout_seconds()

    def test_gateway_error_metadata_is_allowlisted_and_secrets_are_redacted(self) -> None:
        body = json.dumps(
            {
                "error": {
                    "code": "model_provider_timeout",
                    "message": "Anthropic exceeded timeout sk-ant-secret-value",
                    "details": {
                        "stage": "anthropic",
                        "timeoutMs": 1200000,
                        "providerStatus": 504,
                        "providerErrorType": "timeout_error",
                        "providerRequestId": "req_debug_123",
                        "providerResponseId": "msg_debug_123",
                        "providerMessage": "Bearer sensitive-token timed out",
                        "generationAttempts": 2,
                        "payloadBytes": 65432,
                        "payloadDigest": "sha256:abcdef0123456789",
                        "parseKind": "syntax_error",
                        "parseOffset": 321,
                        "rawBody": "must-not-propagate",
                    },
                }
            }
        ).encode("utf-8")
        failure = HTTPError(
            "http://model-gateway:9010/v1/generate",
            504,
            "Gateway Timeout",
            {},
            io.BytesIO(body),
        )
        with patch.dict(
            os.environ,
            {"GENERATION_PROVIDER_TIMEOUT_SECONDS": "1230"},
            clear=True,
        ):
            with patch("app.generation.urlopen", side_effect=failure):
                with self.assertRaises(GenerationError) as raised:
                    generation_module._post_json(
                        "http://model-gateway:9010/v1/generate",
                        PROVIDER_TOKEN,
                        {"request": {}},
                    )
        error = raised.exception
        self.assertEqual(error.status, 504)
        self.assertEqual(error.details["upstreamCode"], "model_provider_timeout")
        self.assertEqual(error.details["providerStage"], "anthropic")
        self.assertEqual(error.details["providerResponseId"], "msg_debug_123")
        self.assertEqual(error.details["timeoutMs"], 1200000)
        self.assertEqual(error.details["generationAttempts"], 2)
        self.assertEqual(error.details["payloadBytes"], 65432)
        self.assertEqual(error.details["payloadDigest"], "sha256:abcdef0123456789")
        self.assertEqual(error.details["parseKind"], "syntax_error")
        self.assertEqual(error.details["parseOffset"], 321)
        self.assertNotIn("rawBody", error.details)
        self.assertNotIn("secret-value", json.dumps(error.details))
        self.assertNotIn("sensitive-token", json.dumps(error.details))

    def test_external_mode_fails_closed_without_credentials(self) -> None:
        with patch.dict(os.environ, {"AI_GENERATION_MODE": "external"}, clear=True):
            with self.assertRaises(GenerationError):
                asyncio.run(generate_lab(REQUEST))

    def test_dev_mode_is_explicit(self) -> None:
        with patch.dict(os.environ, {"AI_GENERATION_MODE": "dev"}, clear=True):
            lab = asyncio.run(generate_lab(REQUEST))
        self.assertEqual(lab["team"], "blue")
        self.assertEqual(
            lab["environmentBuildSpec"]["target"]["baseImage"],
            "registry.local/codegate/http-v1-target-base@sha256:" + ("a" * 64),
        )
        self.assertEqual(
            lab["environmentBuildSpec"]["target"]["runtimeContract"],
            RUNTIME_CONTRACT,
        )

    def test_dev_mode_accepts_server_owned_catalog_overrides(self) -> None:
        env = {
            "AI_GENERATION_MODE": "dev",
            "AI_TARGET_BASE_IMAGE": TARGET_IMAGE,
            "AI_OUTPUT_REPOSITORY": OUTPUT_REPOSITORY,
        }
        with patch.dict(os.environ, env, clear=True):
            lab = asyncio.run(generate_lab(REQUEST))
        target = lab["environmentBuildSpec"]["target"]
        self.assertEqual(target["baseImage"], TARGET_IMAGE)
        self.assertEqual(target["outputRepository"], OUTPUT_REPOSITORY)

    def test_dev_mode_accepts_only_a_single_legacy_target_base_alias(self) -> None:
        env = {
            "AI_GENERATION_MODE": "dev",
            "AI_UBUNTU_BASE_IMAGE": TARGET_IMAGE,
            "AI_KALI_BASE_IMAGE": TARGET_IMAGE,
            "AI_OUTPUT_REPOSITORY": OUTPUT_REPOSITORY,
        }
        with patch.dict(os.environ, env, clear=True):
            lab = asyncio.run(generate_lab(REQUEST))
        self.assertEqual(
            lab["environmentBuildSpec"]["target"]["baseImage"], TARGET_IMAGE
        )

    def test_external_mode_rejects_legacy_desktop_target_aliases(self) -> None:
        env = {**EXTERNAL_ENV, "AI_UBUNTU_BASE_IMAGE": TARGET_IMAGE}
        with patch.dict(os.environ, env, clear=True):
            with patch("app.generation._post_json") as post_json:
                with self.assertRaisesRegex(
                    GenerationError, "Legacy desktop-specific"
                ) as raised:
                    asyncio.run(generate_lab(REQUEST))
        self.assertEqual(raised.exception.status, 503)
        post_json.assert_not_called()

    def test_external_mode_requires_complete_build_catalog(self) -> None:
        env = {
            "AI_GENERATION_MODE": "external",
            "GENERATION_PROVIDER_URL": "https://models.example.test/generate",
            "GENERATION_PROVIDER_TOKEN": PROVIDER_TOKEN,
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(GenerationError, "build catalog") as raised:
                asyncio.run(generate_lab(REQUEST))
        self.assertEqual(raised.exception.status, 503)

    def test_external_mode_rejects_mutable_base_image_tag(self) -> None:
        env = {**EXTERNAL_ENV, "AI_TARGET_BASE_IMAGE": "ubuntu:24.04"}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(GenerationError, "digest-pinned") as raised:
                asyncio.run(generate_lab(REQUEST))
        self.assertEqual(raised.exception.status, 503)

    def test_external_lab_cannot_change_requested_scope(self) -> None:
        with patch.dict(os.environ, EXTERNAL_ENV, clear=True):
            malicious = generate_lab_draft(REQUEST)
            malicious["accessMethod"] = "openvpn"
            with patch("app.generation._post_json", return_value=malicious):
                with self.assertRaises(GenerationError):
                    asyncio.run(generate_lab(REQUEST))

    def test_external_training_package_requires_build_learning_and_hidden_grading_contracts(self) -> None:
        with patch.dict(os.environ, EXTERNAL_ENV, clear=True):
            generated = generate_lab_draft(REQUEST)
            with patch("app.generation._post_json", return_value=generated):
                result = asyncio.run(generate_lab(REQUEST))
        self.assertEqual(len(result["learning"]["sections"]), 6)
        self.assertEqual(
            [question["type"] for question in result["questions"]].count("elk_search"),
            3,
        )
        self.assertEqual(
            [question["type"] for question in result["questions"]].count("mitre_attack"),
            3,
        )
        self.assertEqual(
            result["gradingQuestions"][0]["id"], result["questions"][0]["id"]
        )

    def test_external_training_package_rejects_answer_leakage(self) -> None:
        with patch.dict(os.environ, EXTERNAL_ENV, clear=True):
            generated = generate_lab_draft(REQUEST)
            generated["questions"][0]["answerKey"] = {"expectedEvidenceIds": ["x"]}
            with patch("app.generation._post_json", return_value=generated):
                with self.assertRaises(GenerationError):
                    asyncio.run(generate_lab(REQUEST))

    def test_provider_receives_immutable_catalog_without_provider_secret(self) -> None:
        with patch.dict(os.environ, CURATED_EXTERNAL_ENV, clear=True):
            generated = generate_lab_draft(REQUEST)
            with patch(
                "app.generation._post_json", return_value=generated
            ) as post_json:
                asyncio.run(generate_lab(REQUEST))

        endpoint, token, provider_input = post_json.call_args.args
        self.assertEqual(endpoint, EXTERNAL_ENV["GENERATION_PROVIDER_URL"])
        self.assertEqual(token, PROVIDER_TOKEN)
        self.assertEqual(
            provider_input["environmentBuildCatalog"],
            {
                "schemaVersion": "codegate-build-catalog/v2",
                "immutableBaseImages": True,
                "learnerDesktopImages": ["ubuntu", "kali"],
                "target": {
                    "baseImage": TARGET_IMAGE,
                    "outputRepository": OUTPUT_REPOSITORY,
                    "runtimeContract": RUNTIME_CONTRACT,
                },
                "selectionPolicy": "exact-members-only",
                "packageCatalog": [
                    {"name": "nginx-lab", "version": "1.2.3"}
                ],
                "artifactCatalog": [
                    {"sha256": ARTIFACT_SHA256, "url": ARTIFACT_URL}
                ],
            },
        )
        self.assertEqual(provider_input["cveIntel"], [])
        self.assertNotIn(PROVIDER_TOKEN, json.dumps(provider_input))
        self.assertNotIn(INTERNAL_TOKEN, json.dumps(provider_input))
        self.assertNotIn("GENERATION_PROVIDER_TOKEN", json.dumps(provider_input))
        self.assertNotIn(PACKAGE_IMAGE, json.dumps(provider_input))
        self.assertNotIn("sourcePath", json.dumps(provider_input))
        self.assertNotIn("runtimeKind", json.dumps(provider_input))

    def test_external_result_must_match_the_target_catalog_entry(self) -> None:
        with patch.dict(os.environ, EXTERNAL_ENV, clear=True):
            generated = generate_lab_draft(REQUEST)
            mismatches = [
                ("baseImage", OTHER_TARGET_IMAGE),
                ("outputRepository", "registry.example.test/other/generated"),
            ]
            for field, value in mismatches:
                with self.subTest(field=field):
                    malicious = copy.deepcopy(generated)
                    malicious["environmentBuildSpec"]["target"][field] = value
                    with patch("app.generation._post_json", return_value=malicious):
                        with self.assertRaisesRegex(
                            GenerationError, "build catalog check failed"
                        ):
                            asyncio.run(generate_lab(REQUEST))

    def test_external_request_defaults_to_team_catalog_desktop(self) -> None:
        red_request = {
            "title": "Isolated red-team analysis",
            "prompt": "Analyze a contained target and document defensive evidence.",
            "team": "red",
            "desktopImage": None,
            "accessMethod": "browser_desktop",
            "questionTypes": ["single_choice"],
        }
        with patch.dict(os.environ, EXTERNAL_ENV, clear=True):
            generated = generate_lab_draft(red_request)
            with patch(
                "app.generation._post_json", return_value=generated
            ) as post_json:
                result = asyncio.run(generate_lab(red_request))

        self.assertEqual(post_json.call_args.args[2]["request"]["desktopImage"], "kali")
        self.assertEqual(result["desktopImage"], "kali")
        self.assertEqual(
            result["environmentBuildSpec"]["target"]["baseImage"], TARGET_IMAGE
        )

    def test_external_catalog_rejects_mutable_helper_image_and_unsafe_paths(self) -> None:
        invalid_entries = [
            {
                "imageRef": "registry.example.test/codegate/catalog/nginx:latest",
                "sourcePath": "/opt/codegate/package/",
                "destination": "/opt/codegate/packages/nginx-lab/",
                "runtimeKind": "declarative-http-v1",
            },
            {
                "imageRef": PACKAGE_IMAGE,
                "sourcePath": "/opt/codegate/../secrets/",
                "destination": "/opt/codegate/packages/nginx-lab/",
                "runtimeKind": "declarative-http-v1",
            },
            {
                "imageRef": PACKAGE_IMAGE,
                "sourcePath": "/opt/codegate/package/",
                "destination": "/opt/codegate/packages/nginx-lab/",
                "runtimeKind": "arbitrary-executable-v1",
            },
        ]
        for entry in invalid_entries:
            with self.subTest(entry=entry):
                env = {
                    **EXTERNAL_ENV,
                    "PACKAGE_CATALOG_JSON": json.dumps(
                        {"nginx-lab@1.2.3": entry}
                    ),
                }
                with patch.dict(os.environ, env, clear=True):
                    with patch("app.generation._post_json") as post_json:
                        with self.assertRaisesRegex(
                            GenerationError, "build catalog is invalid"
                        ) as raised:
                            asyncio.run(generate_lab(REQUEST))
                self.assertEqual(raised.exception.status, 503)
                post_json.assert_not_called()

    def test_external_catalog_rejects_non_https_or_unkeyed_artifacts(self) -> None:
        invalid_catalogs = [
            {ARTIFACT_SHA256: {"url": "http://artifacts.example.test/file"}},
            {"not-a-sha256": {"url": ARTIFACT_URL}},
        ]
        for catalog in invalid_catalogs:
            with self.subTest(catalog=catalog):
                env = {
                    **EXTERNAL_ENV,
                    "ARTIFACT_CATALOG_JSON": json.dumps(catalog),
                }
                with patch.dict(os.environ, env, clear=True):
                    with patch("app.generation._post_json") as post_json:
                        with self.assertRaisesRegex(
                            GenerationError, "build catalog is invalid"
                        ):
                            asyncio.run(generate_lab(REQUEST))
                post_json.assert_not_called()

    def test_provider_cannot_select_uncurated_package_or_artifact(self) -> None:
        generated = generate_lab_draft(REQUEST)
        mutations = [
            (
                "packages",
                [{"name": "unreviewed", "version": "9.9.9"}],
            ),
            (
                "artifacts",
                [
                    {
                        "url": "https://attacker.example.test/payload",
                        "sha256": ARTIFACT_SHA256,
                        "destination": "/opt/codegate/artifacts/payload",
                    }
                ],
            ),
        ]
        with patch.dict(os.environ, CURATED_EXTERNAL_ENV, clear=True):
            for field, value in mutations:
                with self.subTest(field=field):
                    malicious = copy.deepcopy(generated)
                    malicious["environmentBuildSpec"]["target"][field] = value
                    with patch("app.generation._post_json", return_value=malicious):
                        with self.assertRaisesRegex(
                            GenerationError, "build catalog check failed"
                        ):
                            asyncio.run(generate_lab(REQUEST))

    def test_runtime_contract_binds_service_and_required_probe_paths(self) -> None:
        generated = generate_lab_draft(REQUEST)
        mutations = [
            ("service", {"port": 9090, "protocol": "http"}),
            ("runtimeContract", {**RUNTIME_CONTRACT, "uid": 1000}),
            (
                "functionalProbes",
                [
                    {
                        "id": "other-health",
                        "kind": "http",
                        "method": "GET",
                        "path": "/ready",
                        "expectedStatuses": [200],
                        "bodyIncludes": ["ready"],
                    }
                ],
            ),
            (
                "vulnerabilityProbes",
                [
                    {
                        "id": "other-fingerprint",
                        "kind": "http",
                        "method": "GET",
                        "path": "/about",
                        "expectedStatuses": [200],
                        "bodyIncludes": ["codegate-vulnerable-target"],
                        "findingId": "scenario-fingerprint",
                    }
                ],
            ),
        ]
        with patch.dict(os.environ, EXTERNAL_ENV, clear=True):
            for field, value in mutations:
                with self.subTest(field=field):
                    malicious = copy.deepcopy(generated)
                    malicious["environmentBuildSpec"]["target"][field] = value
                    with patch("app.generation._post_json", return_value=malicious):
                        with self.assertRaisesRegex(
                            GenerationError, "build catalog check failed"
                        ):
                            asyncio.run(generate_lab(REQUEST))

    def test_external_cve_requires_selected_curated_material_and_trusted_intel(self) -> None:
        cve_id = "CVE-2026-12345"
        cve_request = {**REQUEST, "cveIds": [cve_id]}
        intel = {
            "id": cve_id,
            "description": "A server-owned normalized NVD record.",
            "references": [],
        }

        with patch.dict(os.environ, EXTERNAL_ENV, clear=True):
            with patch("app.generation._post_json") as post_json:
                with self.assertRaisesRegex(
                    GenerationError, "non-empty curated"
                ) as raised:
                    asyncio.run(generate_lab(cve_request))
        self.assertEqual(raised.exception.status, 503)
        post_json.assert_not_called()

        with patch.dict(os.environ, CURATED_EXTERNAL_ENV, clear=True):
            generated = generate_lab_draft(cve_request)
            with patch.object(
                generation_module._generation_nvd_client,
                "resolve",
                new=AsyncMock(return_value=intel),
            ):
                with patch("app.generation._post_json", return_value=generated):
                    with self.assertRaisesRegex(
                        GenerationError, "selected curated"
                    ):
                        asyncio.run(generate_lab(cve_request))

                selected = copy.deepcopy(generated)
                selected["environmentBuildSpec"]["target"]["packages"] = [
                    {"name": "nginx-lab", "version": "1.2.3"}
                ]
                with patch(
                    "app.generation._post_json", return_value=selected
                ) as post_json:
                    result = asyncio.run(generate_lab(cve_request))

        self.assertEqual(result["environmentBuildSpec"]["source"]["cveIds"], [cve_id])
        provider_input = post_json.call_args.args[2]
        self.assertEqual(provider_input["cveIntel"], [intel])
        self.assertNotIn("NVD_API_KEY", json.dumps(provider_input))

    def test_external_cve_allows_explicit_local_uncurated_simulation(self) -> None:
        cve_id = "CVE-2026-12345"
        cve_request = {**REQUEST, "cveIds": [cve_id]}
        intel = {
            "id": cve_id,
            "description": "A server-owned normalized NVD record.",
            "references": [],
        }
        local_env = {
            **EXTERNAL_ENV,
            "GENERATION_PROVIDER_URL": "http://model-gateway:9010/v1/generate",
            "AI_TARGET_BASE_IMAGE": LOCAL_TARGET_IMAGE,
            "AI_OUTPUT_REPOSITORY": LOCAL_OUTPUT_REPOSITORY,
            "AI_ALLOW_UNCURATED_CVE_SIMULATION": "true",
        }

        with patch.dict(os.environ, local_env, clear=True):
            generated = generate_lab_draft(cve_request)
            with patch.object(
                generation_module._generation_nvd_client,
                "resolve",
                new=AsyncMock(return_value=intel),
            ):
                with patch(
                    "app.generation._post_json", return_value=generated
                ) as post_json:
                    result = asyncio.run(generate_lab(cve_request))

        self.assertEqual(result["environmentBuildSpec"]["source"]["cveIds"], [cve_id])
        target = result["environmentBuildSpec"]["target"]
        self.assertEqual(target["packages"], [])
        self.assertEqual(target["artifacts"], [])
        provider_input = post_json.call_args.args[2]
        self.assertEqual(provider_input["cveIntel"], [intel])
        self.assertTrue(provider_input["policy"]["allowUncuratedCveSimulation"])

    def test_uncurated_cve_simulation_rejects_non_local_build_coordinates(self) -> None:
        cve_request = {**REQUEST, "cveIds": ["CVE-2026-12345"]}
        env = {
            **EXTERNAL_ENV,
            "AI_ALLOW_UNCURATED_CVE_SIMULATION": "true",
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("app.generation._post_json") as post_json:
                with self.assertRaisesRegex(
                    GenerationError, "restricted to the local target runtime"
                ):
                    asyncio.run(generate_lab(cve_request))
        post_json.assert_not_called()

    def test_uncurated_cve_simulation_does_not_bypass_catalog_membership(self) -> None:
        cve_id = "CVE-2026-12345"
        cve_request = {**REQUEST, "cveIds": [cve_id]}
        local_env = {
            **EXTERNAL_ENV,
            "GENERATION_PROVIDER_URL": "http://model-gateway:9010/v1/generate",
            "AI_TARGET_BASE_IMAGE": LOCAL_TARGET_IMAGE,
            "AI_OUTPUT_REPOSITORY": LOCAL_OUTPUT_REPOSITORY,
            "AI_ALLOW_UNCURATED_CVE_SIMULATION": "true",
        }
        generated = generate_lab_draft(cve_request)
        generated["environmentBuildSpec"]["target"]["packages"] = [
            {"name": "invented-package", "version": "1.0.0"}
        ]

        with patch.dict(os.environ, local_env, clear=True):
            with patch.object(
                generation_module._generation_nvd_client,
                "resolve",
                new=AsyncMock(return_value={"id": cve_id}),
            ):
                with patch("app.generation._post_json", return_value=generated):
                    with self.assertRaisesRegex(
                        GenerationError, "outside the server build catalog"
                    ):
                        asyncio.run(generate_lab(cve_request))

    def test_uncurated_cve_simulation_flag_is_strictly_opt_in(self) -> None:
        cve_request = {**REQUEST, "cveIds": ["CVE-2026-12345"]}
        for configured in ("", "false", "0"):
            with self.subTest(configured=configured):
                env = {
                    **EXTERNAL_ENV,
                    "AI_ALLOW_UNCURATED_CVE_SIMULATION": configured,
                }
                with patch.dict(os.environ, env, clear=True):
                    with patch("app.generation._post_json") as post_json:
                        with self.assertRaisesRegex(
                            GenerationError, "non-empty curated"
                        ):
                            asyncio.run(generate_lab(cve_request))
                post_json.assert_not_called()

    def test_uncurated_cve_simulation_rejects_an_invalid_flag_value(self) -> None:
        cve_request = {**REQUEST, "cveIds": ["CVE-2026-12345"]}
        env = {
            **EXTERNAL_ENV,
            "AI_ALLOW_UNCURATED_CVE_SIMULATION": "yes",
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("app.generation._post_json") as post_json:
                with self.assertRaisesRegex(
                    GenerationError,
                    "AI_ALLOW_UNCURATED_CVE_SIMULATION must be true or false",
                ):
                    asyncio.run(generate_lab(cve_request))
        post_json.assert_not_called()

    def test_cve_intel_fails_closed_on_mismatched_record(self) -> None:
        cve_id = "CVE-2026-12345"
        cve_request = {**REQUEST, "cveIds": [cve_id]}
        with patch.dict(os.environ, CURATED_EXTERNAL_ENV, clear=True):
            with patch.object(
                generation_module._generation_nvd_client,
                "resolve",
                new=AsyncMock(return_value={"id": "CVE-2026-99999"}),
            ):
                with patch("app.generation._post_json") as post_json:
                    with self.assertRaisesRegex(
                        GenerationError, "did not match"
                    ):
                        asyncio.run(generate_lab(cve_request))
        post_json.assert_not_called()

    def test_external_cve_accepts_an_exact_curated_artifact_selection(self) -> None:
        cve_id = "CVE-2026-12345"
        cve_request = {**REQUEST, "cveIds": [cve_id]}
        with patch.dict(os.environ, CURATED_EXTERNAL_ENV, clear=True):
            generated = generate_lab_draft(cve_request)
            generated["environmentBuildSpec"]["target"]["artifacts"] = [
                {
                    "url": ARTIFACT_URL,
                    "sha256": ARTIFACT_SHA256,
                    "destination": "/opt/codegate/artifacts/auth-events.ndjson",
                }
            ]
            with patch.object(
                generation_module._generation_nvd_client,
                "resolve",
                new=AsyncMock(return_value={"id": cve_id}),
            ):
                with patch("app.generation._post_json", return_value=generated):
                    result = asyncio.run(generate_lab(cve_request))
        self.assertEqual(
            result["environmentBuildSpec"]["target"]["artifacts"][0]["sha256"],
            ARTIFACT_SHA256,
        )

    def test_cve_intel_provider_failure_is_fail_closed(self) -> None:
        cve_id = "CVE-2026-12345"
        cve_request = {**REQUEST, "cveIds": [cve_id]}
        with patch.dict(os.environ, CURATED_EXTERNAL_ENV, clear=True):
            with patch.object(
                generation_module._generation_nvd_client,
                "resolve",
                new=AsyncMock(side_effect=IntelError("NVD unavailable", 502)),
            ):
                with patch("app.generation._post_json") as post_json:
                    with self.assertRaisesRegex(
                        GenerationError, "lookup failed"
                    ) as raised:
                        asyncio.run(generate_lab(cve_request))
        self.assertEqual(raised.exception.status, 503)
        post_json.assert_not_called()

    def test_cve_intel_lookups_are_concurrent_and_bounded(self) -> None:
        class TrackingClient:
            def __init__(self) -> None:
                self.active = 0
                self.maximum = 0

            async def resolve(self, cve_id: str) -> dict[str, str]:
                self.active += 1
                self.maximum = max(self.maximum, self.active)
                await asyncio.sleep(0.005)
                self.active -= 1
                return {"id": cve_id}

        client = TrackingClient()
        identifiers = [f"CVE-2026-{10000 + index}" for index in range(10)]
        results = asyncio.run(_resolve_cve_intel(identifiers, client))  # type: ignore[arg-type]
        self.assertEqual([item["id"] for item in results], identifiers)
        self.assertGreater(client.maximum, 1)
        self.assertLessEqual(client.maximum, 4)


if __name__ == "__main__":
    unittest.main()

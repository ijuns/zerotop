from __future__ import annotations

import unittest

from app.intel import IntelError, normalize_cve_id, parse_nvd_response


class IntelTests(unittest.TestCase):
    def test_rejects_invalid_cve_ids_before_network_access(self) -> None:
        with self.assertRaises(IntelError):
            normalize_cve_id("https://attacker.invalid/metadata")
        self.assertEqual(normalize_cve_id("cve-2026-12345"), "CVE-2026-12345")

    def test_parses_nvd_record_without_fetching_reference_content(self) -> None:
        payload = {
            "timestamp": "2026-07-21T00:00:00Z",
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-12345",
                        "vulnStatus": "Analyzed",
                        "published": "2026-07-20T00:00:00Z",
                        "lastModified": "2026-07-21T00:00:00Z",
                        "descriptions": [{"lang": "en", "value": "Example vulnerability"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "type": "Primary",
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    },
                                }
                            ]
                        },
                        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
                        "references": [
                            {"url": "https://vendor.example/advisory", "tags": ["Vendor Advisory"]},
                            {"url": "file:///etc/passwd", "tags": ["Exploit"]},
                        ],
                        "affected": [
                            {
                                "affectedData": [
                                    {
                                        "vendor": "Example",
                                        "product": "Server",
                                        "versions": [{"version": "1.0", "status": "affected"}],
                                    }
                                ]
                            }
                        ],
                        "cisaExploitAdd": "2026-07-21",
                    }
                }
            ],
        }
        result = parse_nvd_response(payload, "CVE-2026-12345")
        self.assertEqual(result["cvss"]["score"], 9.8)
        self.assertEqual(result["cweIds"], ["CWE-78"])
        self.assertEqual(len(result["references"]), 1)
        self.assertTrue(result["knownExploited"])


if __name__ == "__main__":
    unittest.main()

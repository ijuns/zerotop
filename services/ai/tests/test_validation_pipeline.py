from __future__ import annotations

import copy
import unittest

from app.domain import generate_lab_draft
from app.validation_pipeline import validate_publish_candidate


def evidence(team: str) -> dict:
    assessment = {
        "questionsRendered": True,
        "gradingVerified": True,
        "answerLeakageDetected": False,
    }
    if team == "blue":
        assessment.update(
            {
                "elkIndexReady": True,
                "expectedEventsSearchable": True,
                "mitreMappingsVerified": True,
            }
        )
    else:
        assessment["exploitPathLimitedToSandbox"] = True
    return {
        "artifact": {
            "imageDigest": "sha256:" + "a" * 64,
            "signatureVerified": True,
            "ociConfigVerified": True,
            "runtimeContractVerified": True,
            "sbomGenerated": True,
            "scanCompleted": True,
            "unexpectedCriticalCount": 0,
        },
        "sandbox": {
            "provisioned": True,
            "functionalChecksPassed": True,
            "intendedVulnerabilityConfirmed": True,
            "egressBlocked": True,
            "controlPlaneBlocked": True,
            "crossRunBlocked": True,
            "cleanupConfirmed": True,
        },
        "assessment": assessment,
        "aiReview": {
            "reviewer": "independent-policy-model",
            "independent": True,
            "passed": True,
            "confidence": 0.96,
            "riskScore": 0.02,
        },
    }


class PublishValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = generate_lab_draft(
            {
                "title": "CVE investigation",
                "prompt": "Investigate a safely isolated vulnerable application.",
                "team": "blue",
                "desktopImage": "ubuntu",
                "accessMethod": "browser_desktop",
                "questionTypes": ["elk_search", "mitre_attack"],
            }
        )

    def test_all_mandatory_evidence_automatically_approves(self) -> None:
        result = validate_publish_candidate(self.lab, evidence("blue"))
        self.assertEqual(result["decision"], "pass")
        self.assertEqual(result["status"], "approved")

    def test_missing_or_failed_isolation_evidence_quarantines(self) -> None:
        failed = evidence("blue")
        failed["sandbox"]["egressBlocked"] = False
        result = validate_publish_candidate(self.lab, failed)
        self.assertEqual(result["decision"], "quarantine")
        self.assertTrue(
            any(
                check["id"] == "sandbox_isolation" and not check["passed"]
                for check in result["checks"]
            )
        )

    def test_ai_review_cannot_override_a_mandatory_failure(self) -> None:
        failed = copy.deepcopy(evidence("blue"))
        failed["artifact"]["signatureVerified"] = False
        failed["aiReview"]["confidence"] = 1.0
        failed["aiReview"]["riskScore"] = 0.0
        result = validate_publish_candidate(self.lab, failed)
        self.assertEqual(result["decision"], "quarantine")

    def test_runtime_contract_mismatch_is_quarantined(self) -> None:
        failed = evidence("blue")
        failed["artifact"]["runtimeContractVerified"] = False
        result = validate_publish_candidate(self.lab, failed)
        self.assertEqual(result["decision"], "quarantine")
        self.assertTrue(
            any(
                check["id"] == "runtime_contract" and not check["passed"]
                for check in result["checks"]
            )
        )


if __name__ == "__main__":
    unittest.main()

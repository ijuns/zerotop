import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SERVICE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_ROOT))

from app.review import ReviewError, review_validation  # noqa: E402


SAFE_INPUT = {
    "lab": {"id": "lab-safe", "team": "blue"},
    "evidence": {
        "artifact": {"signatureVerified": True, "unexpectedCriticalCount": 0},
        "sandbox": {"egressBlocked": True, "controlPlaneBlocked": True, "crossRunBlocked": True},
        "assessment": {"answerLeakageDetected": False},
    },
}


class ValidationReviewTests(unittest.TestCase):
    def test_external_mode_fails_closed_without_provider(self) -> None:
        with patch.dict(os.environ, {"AI_REVIEW_MODE": "external"}, clear=True):
            with self.assertRaises(ReviewError):
                asyncio.run(review_validation(SAFE_INPUT))

    def test_development_review_is_deterministic(self) -> None:
        with patch.dict(os.environ, {"AI_REVIEW_MODE": "dev"}, clear=True):
            result = asyncio.run(review_validation(SAFE_INPUT))
        self.assertTrue(result["passed"])
        self.assertTrue(result["independent"])
        self.assertLessEqual(result["riskScore"], 0.1)

    def test_provider_must_claim_independent_review(self) -> None:
        env = {
            "AI_REVIEW_MODE": "external",
            "REVIEW_PROVIDER_URL": "https://models.example.test/review",
            "REVIEW_PROVIDER_TOKEN": "x" * 32,
        }
        with patch.dict(os.environ, env, clear=True), patch(
            "app.review._post_json",
            return_value={
                "reviewer": "same-generator",
                "independent": False,
                "passed": True,
                "confidence": 0.99,
                "riskScore": 0.01,
                "traceId": "trace-not-independent",
            },
        ):
            with self.assertRaises(ReviewError):
                asyncio.run(review_validation(SAFE_INPUT))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from app.rubric import RubricError, _development_grade, grade_free_text


class RubricTests(unittest.IsolatedAsyncioTestCase):
    def test_development_grade_is_traceable_and_bounded(self) -> None:
        result = _development_grade(
            {
                "runId": "run-1",
                "questionId": "q-1",
                "rubricId": "rubric-1",
                "response": "Evidence from the log supports detection and mitigation. " * 12,
            }
        )
        self.assertGreaterEqual(result["scoreRatio"], 0.7)
        self.assertTrue(result["traceId"].startswith("dev-rubric:"))

    async def test_external_mode_fails_closed_without_provider_secret(self) -> None:
        with patch.dict(os.environ, {"AI_RUBRIC_MODE": "external"}, clear=True):
            with self.assertRaises(RubricError):
                await grade_free_text(
                    {
                        "runId": "run-1",
                        "questionId": "q-1",
                        "rubricId": "rubric-1",
                        "response": "A detailed response that is long enough.",
                    }
                )


if __name__ == "__main__":
    unittest.main()

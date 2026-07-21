import sys
import unittest
from pathlib import Path

SERVICE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_ROOT))

from app.domain import DomainError, generate_lab_draft, validate_lab_draft  # noqa: E402


class LabAuthoringTests(unittest.TestCase):
    def test_blue_lab_requires_elk_and_mitre(self) -> None:
        lab = generate_lab_draft(
            {
                "title": "웹셸 침투 탐지",
                "prompt": "WAF와 EDR 로그를 분석하는 격리 훈련을 생성합니다.",
                "team": "blue",
                "desktopImage": "ubuntu",
                "accessMethod": "browser_desktop",
                "questionTypes": ["elk_search", "mitre_attack"],
            }
        )
        self.assertEqual(lab["questionTypes"], ["elk_search", "mitre_attack"])
        self.assertEqual(validate_lab_draft(lab)["decision"], "pass")

    def test_blue_lab_rejects_red_question_type(self) -> None:
        with self.assertRaises(DomainError):
            generate_lab_draft(
                {
                    "title": "잘못된 블루팀 Lab",
                    "prompt": "허용되지 않은 문제 유형이 포함된 요청입니다.",
                    "team": "blue",
                    "questionTypes": ["elk_search", "free_text"],
                }
            )

    def test_red_lab_allows_selected_question_mix(self) -> None:
        lab = generate_lab_draft(
            {
                "title": "격리 레드팀 검증",
                "prompt": "Kali 환경에서 공격 흐름과 방어 지점을 분석합니다.",
                "team": "red",
                "desktopImage": "kali",
                "accessMethod": "both",
                "questionTypes": ["single_choice", "free_text", "mitre_attack"],
            }
        )
        self.assertEqual(lab["desktopImage"], "kali")
        self.assertEqual(validate_lab_draft(lab)["decision"], "pass")

    def test_validation_quarantines_unsafe_network(self) -> None:
        lab = generate_lab_draft(
            {
                "title": "네트워크 검증",
                "prompt": "격리된 로그 분석 훈련을 생성합니다.",
                "team": "blue",
                "questionTypes": ["elk_search", "mitre_attack"],
            }
        )
        lab["network"]["egress"] = "allow"
        result = validate_lab_draft(lab)
        self.assertEqual(result["decision"], "quarantine")
        self.assertFalse(next(item for item in result["checks"] if item["id"] == "egress")["passed"])


if __name__ == "__main__":
    unittest.main()

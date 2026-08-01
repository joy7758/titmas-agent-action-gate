from __future__ import annotations

import json
import unittest

from scripts.validate_milestone import ROOT, reference_decision


class ContractFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        registry = json.loads((ROOT / "evaluations/case-registry.json").read_text(encoding="utf-8"))
        self.cases = {
            item["id"]: json.loads(
                (ROOT / "evaluations" / item["path"]).read_text(encoding="utf-8")
            )
            for item in registry["cases"]
        }

    def test_required_outcomes(self) -> None:
        expected = {
            "valid-execution": ("ALLOW", "ALL_BOUNDARIES_SATISFIED", True),
            "missing-evidence": ("BLOCK", "EVIDENCE_MISSING", False),
            "tampered-evidence": ("BLOCK", "EVIDENCE_TAMPERED", False),
            "high-risk-approval": ("REQUIRE_APPROVAL", "HUMAN_APPROVAL_REQUIRED", False),
        }
        self.assertEqual({name: reference_decision(case) for name, case in self.cases.items()}, expected)

    def test_tampered_evidence_precedes_approval(self) -> None:
        case = json.loads(json.dumps(self.cases["tampered-evidence"]))
        case["policy_evaluation"]["effect"] = "REQUIRE_HUMAN_APPROVAL"
        case["human_approval"] = {
            "status": "GRANTED",
            "request_id": case["action_request"]["request_id"],
            "request_binding": case["policy_evaluation"]["request_binding"],
            "policy_id": case["policy_evaluation"]["policy_id"],
            "policy_version": case["policy_evaluation"]["policy_version"],
        }
        self.assertEqual(reference_decision(case), ("BLOCK", "EVIDENCE_TAMPERED", False))

    def test_policy_deny_precedes_valid_evidence(self) -> None:
        case = json.loads(json.dumps(self.cases["valid-execution"]))
        case["policy_evaluation"]["effect"] = "DENY"
        self.assertEqual(reference_decision(case), ("BLOCK", "POLICY_DENY", False))


if __name__ == "__main__":
    unittest.main()

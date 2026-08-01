from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from titmas_action_gate.approval import ApprovalAuthority
from titmas_action_gate.gate import ActionGate

ROOT = Path(__file__).resolve().parents[1]
CHECKED_AT = datetime(2026, 8, 2, 0, 0, tzinfo=UTC)


class GateRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = ApprovalAuthority(b"runtime-test-approval-key-material-at-least-32-bytes")
        self.gate = ActionGate(self.authority)
        registry = json.loads((ROOT / "evaluations/case-registry.json").read_text(encoding="utf-8"))
        self.cases = {
            item["id"]: json.loads((ROOT / "evaluations" / item["path"]).read_text(encoding="utf-8"))
            for item in registry["cases"]
        }

    def evaluate(self, case_name: str, approval: dict | None = None) -> dict:
        case = self.cases[case_name]
        return self.gate.evaluate(
            case["action_request"],
            case["policy_evaluation"],
            case["evidence_verification_result"],
            approval if approval is not None else case["human_approval"],
            decided_at=CHECKED_AT,
        )

    def test_four_contract_cases_use_runtime_engine(self) -> None:
        for name, case in self.cases.items():
            decision = self.evaluate(name)
            self.assertEqual(decision["outcome"], case["expected_decision"]["outcome"], name)
            self.assertEqual(decision["reason_codes"], case["expected_decision"]["reason_codes"], name)
            self.assertEqual(decision["may_execute"], case["expected_decision"]["may_execute"], name)

    def test_decision_id_is_deterministic_across_evaluation_time(self) -> None:
        case = self.cases["valid-execution"]
        first = self.gate.evaluate(
            case["action_request"], case["policy_evaluation"], case["evidence_verification_result"], decided_at=CHECKED_AT
        )
        second = self.gate.evaluate(
            case["action_request"], case["policy_evaluation"], case["evidence_verification_result"], decided_at=CHECKED_AT + timedelta(seconds=20)
        )
        self.assertEqual(first["decision_id"], second["decision_id"])
        self.assertNotEqual(first["expires_at"], second["expires_at"])

    def test_valid_scoped_approval_allows_high_risk_request(self) -> None:
        case = self.cases["high-risk-approval"]
        approval = self.authority.create(
            case["action_request"],
            case["policy_evaluation"],
            subject="human:test-reviewer",
            identity_provider="test-idp",
            decided_at=CHECKED_AT - timedelta(seconds=1),
        )
        decision = self.evaluate("high-risk-approval", approval)
        self.assertEqual(decision["outcome"], "ALLOW")

    def test_spoofed_or_expired_approval_blocks(self) -> None:
        case = self.cases["high-risk-approval"]
        approval = self.authority.create(
            case["action_request"],
            case["policy_evaluation"],
            subject="human:test-reviewer",
            identity_provider="test-idp",
            decided_at=CHECKED_AT - timedelta(minutes=20),
            ttl=timedelta(minutes=1),
        )
        self.assertEqual(self.evaluate("high-risk-approval", approval)["reason_codes"], ["APPROVAL_INVALID"])
        approval["signature_ref"] = approval["signature_ref"][:-1] + "0"
        self.assertEqual(self.evaluate("high-risk-approval", approval)["reason_codes"], ["APPROVAL_INVALID"])

    def test_parameters_mutation_fails_closed(self) -> None:
        case = json.loads(json.dumps(self.cases["valid-execution"]))
        case["action_request"]["parameters"]["title"] = "Expanded scope"
        decision = self.gate.evaluate(
            case["action_request"], case["policy_evaluation"], case["evidence_verification_result"], decided_at=CHECKED_AT
        )
        self.assertEqual(decision["outcome"], "BLOCK")
        self.assertEqual(decision["reason_codes"], ["INPUT_MISMATCH"])

    def test_policy_deny_precedes_missing_evidence(self) -> None:
        case = json.loads(json.dumps(self.cases["missing-evidence"]))
        case["policy_evaluation"]["effect"] = "DENY"
        decision = self.gate.evaluate(
            case["action_request"], case["policy_evaluation"], case["evidence_verification_result"], decided_at=CHECKED_AT
        )
        self.assertEqual(decision["reason_codes"], ["POLICY_DENY"])


if __name__ == "__main__":
    unittest.main()

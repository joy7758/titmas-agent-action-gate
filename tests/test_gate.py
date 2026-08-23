import unittest
from unittest.mock import patch
from datetime import timedelta

from titmas_action_gate.approval import ApprovalAuthority
from titmas_action_gate.gate import ActionGate
from titmas_action_gate.errors import ContractValidationError

class ActionGateTests(unittest.TestCase):
    def setUp(self):
        self.authority = ApprovalAuthority(b"test-approval-key-material-at-least-32-bytes-long")
        self.gate = ActionGate(self.authority, allow_ttl=timedelta(minutes=10))

    def test_initialization(self):
        self.assertEqual(self.gate.allow_ttl, timedelta(minutes=10))
        self.assertIs(self.gate.approval_authority, self.authority)

    @patch("titmas_action_gate.gate.validate_contract")
    @patch("titmas_action_gate.gate.validate_action_request")
    def test_evaluate_input_invalid_on_exception(self, mock_validate_action_request, mock_validate_contract):
        mock_validate_action_request.side_effect = Exception("Invalid")
        result = self.gate.evaluate({"request_id": "aar-req-1"}, {}, {})
        self.assertEqual(result["outcome"], "BLOCK")
        self.assertEqual(result["reason_codes"], ["INPUT_INVALID"])
        self.assertFalse(result["may_execute"])

    @patch("titmas_action_gate.gate.validate_contract")
    @patch("titmas_action_gate.gate.validate_action_request")
    def test_evaluate_input_mismatch_on_contract_validation_error(self, mock_validate_action_request, mock_validate_contract):
        exc = ContractValidationError("DIGEST_MISMATCH", "Invalid")
        mock_validate_action_request.side_effect = exc
        result = self.gate.evaluate({"request_id": "aar-req-1"}, {}, {})
        self.assertEqual(result["outcome"], "BLOCK")
        self.assertEqual(result["reason_codes"], ["INPUT_MISMATCH"])
        self.assertFalse(result["may_execute"])

    @patch("titmas_action_gate.gate.validate_contract")
    @patch("titmas_action_gate.gate.validate_action_request")
    @patch("titmas_action_gate.gate.request_binding")
    @patch("titmas_action_gate.gate.validate_bound_input")
    def test_evaluate_policy_deny(self, mock_validate_bound_input, mock_request_binding, mock_validate_action_request, mock_validate_contract):
        mock_request_binding.return_value = "test-binding"
        action_request = {"request_id": "aar-req-1"}
        policy_evaluation = {"effect": "DENY"}
        evidence_result = {"status": "VALID", "evidence_types": [], "checks": []}
        result = self.gate.evaluate(action_request, policy_evaluation, evidence_result)
        self.assertEqual(result["outcome"], "BLOCK")
        self.assertEqual(result["reason_codes"], ["POLICY_DENY"])

    @patch("titmas_action_gate.gate.validate_contract")
    @patch("titmas_action_gate.gate.validate_action_request")
    @patch("titmas_action_gate.gate.request_binding")
    @patch("titmas_action_gate.gate.validate_bound_input")
    def test_evaluate_allow_without_approval(self, mock_validate_bound_input, mock_request_binding, mock_validate_action_request, mock_validate_contract):
        mock_request_binding.return_value = "test-binding"
        action_request = {"request_id": "aar-req-1"}
        policy_evaluation = {"effect": "ALLOW_WITHOUT_APPROVAL", "required_evidence_types": ["type-a"]}
        evidence_result = {"status": "VALID", "evidence_types": ["type-a"], "checks": [{"passed": True}]}
        result = self.gate.evaluate(action_request, policy_evaluation, evidence_result)
        self.assertEqual(result["outcome"], "ALLOW")
        self.assertEqual(result["reason_codes"], ["ALL_BOUNDARIES_SATISFIED"])
        self.assertTrue(result["may_execute"])

    @patch("titmas_action_gate.gate.validate_contract")
    @patch("titmas_action_gate.gate.validate_action_request")
    @patch("titmas_action_gate.gate.request_binding")
    @patch("titmas_action_gate.gate.validate_bound_input")
    def test_evaluate_evidence_missing(self, mock_validate_bound_input, mock_request_binding, mock_validate_action_request, mock_validate_contract):
        mock_request_binding.return_value = "test-binding"
        action_request = {"request_id": "aar-req-1"}
        policy_evaluation = {"effect": "ALLOW_WITHOUT_APPROVAL"}
        evidence_result = {"status": "MISSING"}
        result = self.gate.evaluate(action_request, policy_evaluation, evidence_result)
        self.assertEqual(result["outcome"], "BLOCK")
        self.assertEqual(result["reason_codes"], ["EVIDENCE_MISSING"])

if __name__ == "__main__":
    unittest.main()

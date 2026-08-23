from __future__ import annotations

import unittest
from datetime import timedelta
from unittest.mock import patch

from titmas_action_gate.approval import ApprovalAuthority
from titmas_action_gate.canonical import parse_datetime


class ApprovalAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = b"0123456789abcdef0123456789abcdef"
        self.auth = ApprovalAuthority(self.key)
        self.request = {
            "request_id": "req-123",
            "action": "read",
            "target": {"provider": "github", "repository": "org/repo", "resource_ref": "issue-1"},
            "parameters": {"a": 1},
            "parameters_sha256": "fake-hash",
        }
        self.policy = {
            "policy_id": "pol-123",
            "policy_version": "1.0",
            "ruleset_sha256": "ruleset-hash-123",
        }

    def test_init_key_too_short(self) -> None:
        with self.assertRaises(ValueError):
            ApprovalAuthority(b"short")

    @patch("titmas_action_gate.approval.request_binding")
    @patch("titmas_action_gate.approval.validate_action_request")
    @patch("titmas_action_gate.approval.validate_bound_input")
    def test_create_and_verify_success(self, mock_bound, mock_req, mock_binding) -> None:
        mock_binding.return_value = {"action": "read"}
        approval = self.auth.create(request=self.request, policy=self.policy, subject="user1", identity_provider="github")
        self.assertEqual(approval["status"], "GRANTED")
        self.assertTrue(approval["approved_by"]["human_verified"])

        # Verify success
        result = self.auth.verify(approval, self.request, self.policy)
        self.assertTrue(result)

    @patch("titmas_action_gate.approval.request_binding")
    @patch("titmas_action_gate.approval.validate_action_request")
    @patch("titmas_action_gate.approval.validate_bound_input")
    def test_verify_tampered_signature(self, mock_bound, mock_req, mock_binding) -> None:
        mock_binding.return_value = {"action": "read"}
        approval = self.auth.create(request=self.request, policy=self.policy, subject="user1", identity_provider="github")
        # Tamper signature
        approval["signature_ref"] = "hmac-sha256:demo:wrong"
        self.assertFalse(self.auth.verify(approval, self.request, self.policy))

    @patch("titmas_action_gate.approval.request_binding")
    @patch("titmas_action_gate.approval.validate_action_request")
    @patch("titmas_action_gate.approval.validate_bound_input")
    def test_verify_expired(self, mock_bound, mock_req, mock_binding) -> None:
        mock_binding.return_value = {"action": "read"}
        approval = self.auth.create(
            request=self.request,
            policy=self.policy,
            subject="user1",
            identity_provider="github",
            ttl=timedelta(minutes=-1),  # Already expired
        )
        self.assertFalse(self.auth.verify(approval, self.request, self.policy))

        # Test valid initially, but expired later
        approval2 = self.auth.create(request=self.request, policy=self.policy, subject="user1", identity_provider="github", ttl=timedelta(minutes=15))
        future_time = parse_datetime(approval2["expires_at"]) + timedelta(minutes=1)
        self.assertFalse(self.auth.verify(approval2, self.request, self.policy, now=future_time))

        # Test checked before decided_at
        past_time = parse_datetime(approval2["decided_at"]) - timedelta(minutes=1)
        self.assertFalse(self.auth.verify(approval2, self.request, self.policy, now=past_time))

    @patch("titmas_action_gate.approval.request_binding")
    @patch("titmas_action_gate.approval.validate_action_request")
    @patch("titmas_action_gate.approval.validate_bound_input")
    def test_verify_tampered_status(self, mock_bound, mock_req, mock_binding) -> None:
        mock_binding.return_value = {"action": "read"}
        approval = self.auth.create(request=self.request, policy=self.policy, subject="user1", identity_provider="github")
        approval["status"] = "DENIED"
        self.assertFalse(self.auth.verify(approval, self.request, self.policy))

    @patch("titmas_action_gate.approval.request_binding")
    @patch("titmas_action_gate.approval.validate_action_request")
    @patch("titmas_action_gate.approval.validate_bound_input")
    def test_verify_policy_mismatch(self, mock_bound, mock_req, mock_binding) -> None:
        mock_binding.return_value = {"action": "read"}
        approval = self.auth.create(request=self.request, policy=self.policy, subject="user1", identity_provider="github")
        wrong_policy = {**self.policy, "policy_id": "wrong-id"}
        self.assertFalse(self.auth.verify(approval, self.request, wrong_policy))

    @patch("titmas_action_gate.approval.request_binding")
    @patch("titmas_action_gate.approval.validate_action_request")
    @patch("titmas_action_gate.approval.validate_bound_input")
    def test_verify_validation_exception(self, mock_bound, mock_req, mock_binding) -> None:
        mock_binding.return_value = {"action": "read"}
        approval = self.auth.create(request=self.request, policy=self.policy, subject="user1", identity_provider="github")
        # Make validate_bound_input raise an exception
        mock_bound.side_effect = Exception("Validation failed")
        self.assertFalse(self.auth.verify(approval, self.request, self.policy))


if __name__ == "__main__":
    unittest.main()

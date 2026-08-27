from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from titmas_action_gate.errors import AuthenticationError
from titmas_action_gate.service import ActionGateService


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="titmas-service-tests-")
        self.state_dir = self.tempdir.name
        self.caller_token = "valid-caller-token"
        self.approver_token = "valid-approver-token"
        self.approval_key = b"dummy-approval-key-must-be-at-least-32-bytes"
        self.record_signing_key = b"dummy-record-signing-key-must-be-at-least-32-bytes"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_init_success(self) -> None:
        service = ActionGateService(
            self.state_dir,
            caller_token=self.caller_token,
            approver_token=self.approver_token,
            approval_key=self.approval_key,
            record_signing_key=self.record_signing_key,
        )
        self.assertTrue(Path(self.state_dir).exists())
        self.assertIsNotNone(service.store)
        self.assertIsNotNone(service.policy)
        self.assertIsNotNone(service.approvals)
        self.assertIsNotNone(service.signer)
        self.assertIsNotNone(service.gate)
        self.assertIsNotNone(service.evidence)

    def test_init_short_caller_token(self) -> None:
        with self.assertRaisesRegex(ValueError, "caller token must be at least 16 characters"):
            ActionGateService(
                self.state_dir,
                caller_token="short",
                approver_token=self.approver_token,
                approval_key=self.approval_key,
                record_signing_key=self.record_signing_key,
            )

    def test_init_short_approver_token(self) -> None:
        with self.assertRaisesRegex(ValueError, "approver token must be distinct and at least 16 characters"):
            ActionGateService(
                self.state_dir,
                caller_token=self.caller_token,
                approver_token="short",
                approval_key=self.approval_key,
                record_signing_key=self.record_signing_key,
            )

    def test_init_identical_tokens(self) -> None:
        with self.assertRaisesRegex(ValueError, "approver token must be distinct and at least 16 characters"):
            ActionGateService(
                self.state_dir,
                caller_token=self.caller_token,
                approver_token=self.caller_token,
                approval_key=self.approval_key,
                record_signing_key=self.record_signing_key,
            )

    @patch.dict(os.environ, {}, clear=True)
    def test_demo_missing_approval_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "Explicit approval_key or TITMAS_APPROVAL_KEY environment variable is required."):
            ActionGateService.demo(
                self.state_dir,
                caller_token=self.caller_token,
                approver_token=self.approver_token,
                record_signing_key=self.record_signing_key,
            )

    @patch.dict(os.environ, {"TITMAS_APPROVAL_KEY": "env-approval-key"}, clear=True)
    def test_demo_missing_record_signing_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "Explicit record_signing_key or TITMAS_RECORD_SIGNING_KEY environment variable is required."):
            ActionGateService.demo(
                self.state_dir,
                caller_token=self.caller_token,
                approver_token=self.approver_token,
            )

    @patch.dict(
        os.environ,
        {
            "TITMAS_APPROVAL_KEY": "env-approval-key",
            "TITMAS_RECORD_SIGNING_KEY": "env-record-signing-key",
        },
        clear=True,
    )
    def test_demo_from_env(self) -> None:
        service = ActionGateService.demo(
            self.state_dir,
            caller_token=self.caller_token,
            approver_token=self.approver_token,
        )
        self.assertIsNotNone(service)

    def test_authenticate_success(self) -> None:
        service = ActionGateService(
            self.state_dir,
            caller_token=self.caller_token,
            approver_token=self.approver_token,
            approval_key=self.approval_key,
            record_signing_key=self.record_signing_key,
        )
        # Should not raise
        service.authenticate(self.caller_token)

    def test_authenticate_failure(self) -> None:
        service = ActionGateService(
            self.state_dir,
            caller_token=self.caller_token,
            approver_token=self.approver_token,
            approval_key=self.approval_key,
            record_signing_key=self.record_signing_key,
        )
        with self.assertRaises(AuthenticationError) as ctx:
            service.authenticate("invalid-caller-token")
        self.assertEqual(ctx.exception.code, "AUTHENTICATION_FAILED")
        self.assertEqual(ctx.exception.message, "Caller token is invalid.")

    def test_authenticate_approver_success(self) -> None:
        service = ActionGateService(
            self.state_dir,
            caller_token=self.caller_token,
            approver_token=self.approver_token,
            approval_key=self.approval_key,
            record_signing_key=self.record_signing_key,
        )
        # Should not raise
        service.authenticate_approver(self.approver_token)

    def test_authenticate_approver_failure(self) -> None:
        service = ActionGateService(
            self.state_dir,
            caller_token=self.caller_token,
            approver_token=self.approver_token,
            approval_key=self.approval_key,
            record_signing_key=self.record_signing_key,
        )
        with self.assertRaises(AuthenticationError) as ctx:
            service.authenticate_approver("invalid-approver-token")
        self.assertEqual(ctx.exception.code, "APPROVER_AUTHENTICATION_FAILED")
        self.assertEqual(ctx.exception.message, "Approver token is invalid.")

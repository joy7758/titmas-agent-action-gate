import unittest
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from titmas_action_gate.agents import (
    EvidenceVerifier,
    GitHubOperator,
    HandoffLog,
    ReleaseSteward,
    RequestAnalyst,
    WorkflowLead,
)
from titmas_action_gate.provider import GitHubProvider
from titmas_action_gate.service import ActionGateService, ExecuteAllowedRequest


class TestAgents(unittest.TestCase):
    def test_handoff_log(self):
        log = HandoffLog()
        payload = {"test": "data"}
        log.add("sender1", "rec1", "req1", "resp1", payload)

        self.assertEqual(len(log.entries), 1)
        handoff = log.entries[0]
        self.assertEqual(handoff.sender, "sender1")

        dicts = log.as_dicts()
        self.assertEqual(len(dicts), 1)
        self.assertEqual(dicts[0]["sender"], "sender1")
        self.assertIn("payload_sha256", dicts[0])

    @patch("titmas_action_gate.agents.validate_action_request")
    def test_request_analyst(self, mock_validate):
        analyst = RequestAnalyst()
        dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

        req = analyst.analyze(
            action="test.action",
            repository="test/repo",
            resource_ref="ref/123",
            parameters={"p1": "v1"},
            evidence_requirements=["REQ1"],
            uncertainty=["UNC1"],
            created_at=dt,
        )

        self.assertEqual(req["action"], "test.action")
        self.assertEqual(req["requested_by"]["agent_id"], "request-analyst")
        mock_validate.assert_called_once_with(req)

    def test_evidence_verifier(self):
        verifier = EvidenceVerifier()
        mock_service = MagicMock(spec=ActionGateService)
        mock_service.verify_evidence.return_value = {"status": "ok"}

        result = verifier.verify(mock_service, "req-123", caller_token="token123")

        mock_service.verify_evidence.assert_called_once_with("req-123", caller_token="token123")
        self.assertEqual(result, {"status": "ok"})

    def test_workflow_lead(self):
        lead = WorkflowLead()
        mock_service = MagicMock(spec=ActionGateService)
        mock_service.evaluate_action_gate.return_value = {"decision": "allow"}
        dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

        result = lead.decide(mock_service, "req-123", caller_token="token123", decided_at=dt)

        mock_service.evaluate_action_gate.assert_called_once_with("req-123", caller_token="token123", decided_at=dt)
        self.assertEqual(result, {"decision": "allow"})

    def test_github_operator(self):
        operator = GitHubOperator()
        mock_service = MagicMock(spec=ActionGateService)
        mock_service.execute_allowed.return_value = {"executed": True}
        mock_provider = MagicMock(spec=GitHubProvider)
        dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

        result = operator.execute(mock_service, "req-123", "dec-123", mock_provider, caller_token="token123", consumed_at=dt)

        self.assertTrue(mock_service.execute_allowed.called)
        args = mock_service.execute_allowed.call_args[0]
        req_obj = args[0]
        self.assertIsInstance(req_obj, ExecuteAllowedRequest)
        self.assertEqual(req_obj.request_id, "req-123")
        self.assertEqual(result, {"executed": True})

    @patch("titmas_action_gate.agents.validate_action_request")
    def test_release_steward(self, mock_validate):
        steward = ReleaseSteward()
        analyst = RequestAnalyst()
        dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

        req = steward.build_release_request(
            analyst,
            repository="test/repo",
            pull_number=42,
            created_at=dt,
        )

        self.assertEqual(req["action"], "github.pull_request.merge")
        self.assertEqual(req["requested_by"]["agent_id"], "release-steward")
        self.assertEqual(mock_validate.call_count, 2)  # Called by analyst.analyze, then steward itself

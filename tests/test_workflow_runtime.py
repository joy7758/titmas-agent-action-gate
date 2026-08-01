from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime

from titmas_action_gate.service import ActionGateService
from titmas_action_gate.workflow import AgentTeamsWorkflow


class WorkflowRuntimeTests(unittest.TestCase):
    def test_complete_reference_workflow(self) -> None:
        with tempfile.TemporaryDirectory(prefix="titmas-aag-workflow-") as state_dir:
            service = ActionGateService.demo(state_dir)
            report = AgentTeamsWorkflow(service, caller_token="titmas-demo-caller-token").run(
                repository="joy7758/action-gate-demo",
                base_time=datetime(2026, 8, 2, 2, 0, tzinfo=UTC),
            )
        self.assertEqual(report["orchestration"]["layer"], "AgentTeams")
        self.assertFalse(report["orchestration"]["live_agentteams_deployment_claimed"])
        self.assertEqual(report["initial_evidence_status"], "VALID")
        self.assertEqual(report["initial_decision"]["outcome"], "ALLOW")
        self.assertEqual(report["execution_receipt"]["status"], "SUCCEEDED")
        self.assertEqual(report["post_execution_evidence_status"], "VALID")
        self.assertEqual(report["release_decision_before_approval"]["outcome"], "REQUIRE_APPROVAL")
        self.assertEqual(report["release_decision_after_approval"]["outcome"], "ALLOW")
        self.assertGreaterEqual(len(report["handoffs"]), 7)
        self.assertEqual(report["action_store_chain_issues"], [])
        self.assertEqual(report["agent_evidence_chain_issues"], [])
        self.assertFalse(report["provider"]["external_write"])


if __name__ == "__main__":
    unittest.main()

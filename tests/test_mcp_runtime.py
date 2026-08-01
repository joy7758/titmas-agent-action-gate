from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from titmas_action_gate.mcp_server import configure_service, get_action_state, mcp, record_human_approval, submit_action_request
from titmas_action_gate.service import ActionGateService

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TOOLS = {
    "submit_action_request",
    "attach_evidence",
    "verify_evidence",
    "evaluate_action_gate",
    "record_human_approval",
    "get_action_state",
}


class McpRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="titmas-aag-mcp-")
        self.service = ActionGateService.demo(self.tempdir.name)
        configure_service(self.service)
        self.request = json.loads((ROOT / "evaluations/cases/valid-execution/case.json").read_text(encoding="utf-8"))["action_request"]

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_exact_six_tools_are_callable(self) -> None:
        self.assertEqual({tool.name for tool in mcp._tool_manager.list_tools()}, EXPECTED_TOOLS)

    def test_tool_authentication_fails_closed(self) -> None:
        result = submit_action_request(self.request, "wrong-token-value")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "AUTHENTICATION_FAILED")

    def test_submit_and_read_state(self) -> None:
        submitted = submit_action_request(self.request, "titmas-demo-caller-token")
        self.assertTrue(submitted["ok"])
        state = get_action_state(self.request["request_id"], "titmas-demo-caller-token")
        self.assertTrue(state["ok"])
        self.assertEqual(state["result"]["chain_issues"], [])

    def test_agent_caller_token_cannot_issue_human_approval(self) -> None:
        result = record_human_approval(
            "aar-auth-boundary-001",
            "human:reviewer",
            "test-idp",
            "GRANTED",
            "titmas-demo-caller-token",
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "APPROVER_AUTHENTICATION_FAILED")


if __name__ == "__main__":
    unittest.main()

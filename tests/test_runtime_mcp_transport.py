from __future__ import annotations

import tempfile
import unittest
import warnings

from starlette.testclient import TestClient

from titmas_action_gate.runtime import HUMAN_PRINCIPAL_ID, RuntimePrincipalRegistry
from titmas_action_gate.runtime_mcp_server import NativeRuntimeMcp
from titmas_action_gate.service import ActionGateService


def credentials() -> dict[str, str]:
    principals = {
        "workflow-lead",
        "request-analyst",
        "evidence-verifier",
        "github-operator",
        "cloud-context-inspector",
        "release-steward",
        HUMAN_PRINCIPAL_ID,
    }
    return {principal: f"transport-test-{index:02d}-" + (chr(97 + index) * 32) for index, principal in enumerate(sorted(principals))}


class RuntimeMcpTransportTests(unittest.TestCase):
    def test_transport_derives_identity_and_denies_before_business_state(self) -> None:
        values = credentials()
        scope = {
            "schema_version": "0.1.0",
            "run_id": "run-native-transport-001",
            "correlation_id": "corr-native-transport-001",
            "task_id": "task-native-transport-001",
            "repository": "joy7758/action-gate-demo",
            "commit": "a" * 40,
        }
        with tempfile.TemporaryDirectory(prefix="titmas-runtime-transport-") as state_dir:
            service = ActionGateService.demo(state_dir)
            runtime = NativeRuntimeMcp(
                service,
                RuntimePrincipalRegistry(values),
                caller_token="titmas-demo-caller-token",
                approver_token="titmas-demo-approver-token",
            )
            headers = {
                "Authorization": f"Bearer {values['github-operator']}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "Host": "127.0.0.1:8767",
            }
            initialize = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "runtime-boundary-test", "version": "1"},
                },
            }
            unauthorized_call = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "evaluate_action_gate",
                    "arguments": {"request_id": "aar-runtime-test-001", "runtime_scope": scope},
                },
            }
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=DeprecationWarning)
                with TestClient(runtime.mcp.streamable_http_app()) as client:
                    bad = client.post(
                        "/mcp",
                        headers={**headers, "Authorization": "Bearer invalid-credential-value"},
                        json=initialize,
                    )
                    self.assertEqual(bad.status_code, 401)
                    initialized = client.post("/mcp", headers=headers, json=initialize)
                    self.assertEqual(initialized.status_code, 200)
                    denied = client.post("/mcp", headers=headers, json=unauthorized_call)
                    self.assertEqual(denied.status_code, 200)
            self.assertIn("MCP_TOOL_NOT_ALLOWED", denied.text)
            self.assertIn("github-operator", denied.text)
            self.assertNotIn(values["github-operator"], denied.text)
            self.assertEqual(service.store.records_for_request("aar-runtime-test-001"), [])
            events = service.store.security_events_for_run(scope["run_id"])
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["principal_id"], "github-operator")
            self.assertEqual(events[0]["reason_code"], "MCP_TOOL_NOT_ALLOWED")
            self.assertEqual(events[0]["business_state_delta"], 0)


if __name__ == "__main__":
    unittest.main()

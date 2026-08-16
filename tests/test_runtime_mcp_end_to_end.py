from __future__ import annotations

import json
import tempfile
import unittest
import warnings
from pathlib import Path

from starlette.testclient import TestClient

from titmas_action_gate.canonical import sha256_json
from titmas_action_gate.runtime import HUMAN_PRINCIPAL_ID, RuntimePrincipalRegistry
from titmas_action_gate.runtime_mcp_server import NativeRuntimeMcp
from titmas_action_gate.service import ActionGateService

ROOT = Path(__file__).resolve().parents[1]


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
    return {principal: f"end-to-end-test-{index:02d}-" + (chr(97 + index) * 32) for index, principal in enumerate(sorted(principals))}


class RuntimeMcpEndToEndTests(unittest.TestCase):
    def test_complete_no_external_write_chain_uses_authenticated_roles(self) -> None:
        values = credentials()
        runtime_scope = {
            "schema_version": "0.1.0",
            "run_id": "run-native-end-to-end-001",
            "correlation_id": "corr-native-end-to-end-001",
            "task_id": "task-native-end-to-end-001",
            "repository": "joy7758/action-gate-demo",
            "commit": "a" * 40,
        }
        valid = json.loads((ROOT / "evaluations/cases/valid-execution/case.json").read_text(encoding="utf-8"))
        high = json.loads((ROOT / "evaluations/cases/high-risk-approval/case.json").read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory(prefix="titmas-runtime-e2e-") as state_dir:
            service = ActionGateService.demo(state_dir)
            runtime = NativeRuntimeMcp(
                service,
                RuntimePrincipalRegistry(values),
                caller_token="titmas-demo-caller-token",
                approver_token="titmas-demo-approver-token",
            )
            app = runtime.mcp.streamable_http_app()

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=DeprecationWarning)
                with TestClient(app) as client:
                    next_id = 0

                    def call(principal: str, tool_name: str, arguments: dict) -> dict:
                        nonlocal next_id
                        next_id += 1
                        response = client.post(
                            "/mcp",
                            headers={
                                "Authorization": f"Bearer {values[principal]}",
                                "Accept": "application/json, text/event-stream",
                                "Content-Type": "application/json",
                                "Host": "127.0.0.1:8767",
                            },
                            json={
                                "jsonrpc": "2.0",
                                "id": next_id,
                                "method": "tools/call",
                                "params": {"name": tool_name, "arguments": arguments},
                            },
                        )
                        self.assertEqual(response.status_code, 200, response.text)
                        data_line = next(line for line in response.text.splitlines() if line.startswith("data: "))
                        payload = json.loads(data_line.removeprefix("data: "))
                        result = payload["result"]["structuredContent"]
                        self.assertTrue(result["ok"], result)
                        return result["result"]

                    request = valid["action_request"]
                    call(
                        "request-analyst",
                        "submit_action_request",
                        {"action_request": request, "runtime_scope": runtime_scope},
                    )
                    generated = call(
                        "request-analyst",
                        "generate_evidence_profile",
                        {
                            "request_id": request["request_id"],
                            "runtime_scope": runtime_scope,
                            "phase": "pre-execution",
                            "operation_status": "succeeded",
                            "output": {"analysis": "normalized", "uncertainty_preserved": True},
                            "evidence_types": request["evidence_requirements"],
                        },
                    )
                    call(
                        "evidence-verifier",
                        "attach_evidence",
                        {
                            "request_id": request["request_id"],
                            "runtime_scope": runtime_scope,
                            "profile_path": generated["profile_path"],
                            "evidence_types": request["evidence_requirements"],
                        },
                    )
                    verified = call(
                        "evidence-verifier",
                        "verify_evidence",
                        {"request_id": request["request_id"], "runtime_scope": runtime_scope},
                    )
                    self.assertEqual(verified["status"], "VALID")
                    initial = call(
                        "workflow-lead",
                        "evaluate_action_gate",
                        {"request_id": request["request_id"], "runtime_scope": runtime_scope},
                    )["payload"]
                    self.assertEqual(initial["outcome"], "ALLOW")
                    execution = call(
                        "github-operator",
                        "execute_in_memory_github_action",
                        {
                            "decision_id": initial["decision_id"],
                            "request_id": request["request_id"],
                            "runtime_scope": runtime_scope,
                        },
                    )
                    self.assertEqual(execution["status"], "SUCCEEDED")
                    self.assertEqual(execution["provider_result"]["provider_mode"], "IN_MEMORY_NO_EXTERNAL_WRITE")

                    release_request = json.loads(json.dumps(high["action_request"]))
                    release_request["request_id"] = "aar-native-release-decision-001"
                    release_request["target"]["resource_ref"] = "pull/1"
                    release_request["parameters"]["pull_number"] = 1
                    release_request["parameters_sha256"] = sha256_json(release_request["parameters"])
                    release_request["idempotency_key"] = "native-release-decision-001"
                    call(
                        "release-steward",
                        "submit_action_request",
                        {"action_request": release_request, "runtime_scope": runtime_scope},
                    )
                    post_generated = call(
                        "release-steward",
                        "generate_evidence_profile",
                        {
                            "request_id": release_request["request_id"],
                            "runtime_scope": runtime_scope,
                            "phase": "post-execution",
                            "operation_status": "succeeded",
                            "output": execution,
                            "evidence_types": release_request["evidence_requirements"],
                        },
                    )
                    call(
                        "release-steward",
                        "attach_evidence",
                        {
                            "request_id": release_request["request_id"],
                            "runtime_scope": runtime_scope,
                            "profile_path": post_generated["profile_path"],
                            "evidence_types": release_request["evidence_requirements"],
                        },
                    )
                    final_evidence = call(
                        "release-steward",
                        "verify_evidence",
                        {"request_id": release_request["request_id"], "runtime_scope": runtime_scope},
                    )
                    self.assertEqual(final_evidence["status"], "VALID")
                    final_decision = call(
                        "release-steward",
                        "evaluate_action_gate",
                        {"request_id": release_request["request_id"], "runtime_scope": runtime_scope},
                    )["payload"]
                    self.assertEqual(final_decision["outcome"], "REQUIRE_APPROVAL")
                    self.assertEqual(final_decision["reason_codes"], ["HUMAN_APPROVAL_REQUIRED"])

            self.assertEqual(service.store.verify_chain(), [])
            self.assertEqual(service.store.verify_security_chain(runtime_scope["run_id"]), [])
            self.assertTrue(all(item["outcome"] == "ALLOW_CALL" for item in service.store.security_events_for_run(runtime_scope["run_id"])))
            self.assertEqual(len(runtime.providers[runtime_scope["run_id"]].pull_requests), 1)


if __name__ == "__main__":
    unittest.main()

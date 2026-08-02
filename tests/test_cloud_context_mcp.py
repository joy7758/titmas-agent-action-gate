from __future__ import annotations

import json
import tempfile
import unittest
import warnings
from pathlib import Path

from starlette.testclient import TestClient

from titmas_action_gate.canonical import sha256_json
from titmas_action_gate.cloud_context import CliExecution, CloudContextInspector, CloudCredentialContext
from titmas_action_gate.runtime import HUMAN_PRINCIPAL_ID, RuntimePrincipalRegistry
from titmas_action_gate.runtime_mcp_server import NativeRuntimeMcp
from titmas_action_gate.service import ActionGateService

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_SKILL_ROOT = (Path.home() / ".local/share/titmas-agent-action-gate/external-skills/alibabacloud-resourcecenter-search").resolve()


class FakeExecutor:
    def execute(self, query: dict, credential: CloudCredentialContext) -> CliExecution:
        return CliExecution(
            status="CLOUD_CONTEXT_AVAILABLE",
            cli_version="3.3.4",
            exit_status=0,
            returned_resource_count=1,
            next_token_present=False,
            resource_type_count=1,
            region_count=1,
            request_id_ref="sha256:" + "c" * 64,
            step_trace=[{"step_id": "VERIFY_LIVE_CALLER_IDENTITY", "effect": "CLOUD_READ", "exit_status": 0}],
        )


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
    return {principal: f"cloud-mcp-test-{index:02d}-" + (chr(97 + index) * 32) for index, principal in enumerate(sorted(principals))}


class CloudContextMcpTests(unittest.TestCase):
    def test_authenticated_cloud_worker_invokes_only_typed_tool(self) -> None:
        values = credentials()
        request = {
            "schema_version": "0.1.0",
            "request_id": "aar-cloud-mcp-test-001",
            "created_at": "2026-08-02T00:00:00Z",
            "requested_by": {"agent_id": "release-steward", "team_id": "titmas-action-gate"},
            "action": "github.release.create",
            "target": {
                "provider": "github",
                "repository": "joy7758/action-gate-demo",
                "resource_ref": "release/v0.2.0-demo",
            },
            "parameters": {"tag": "v0.2.0-demo", "draft": True},
            "parameters_sha256": "",
            "evidence_requirements": ["SOURCE_PIN", "TEST_RESULT", "TAG_STATE", "RELEASE_MANIFEST", "CLOUD_CONTEXT"],
            "uncertainty": ["Cloud search is read-only context, not deployment authorization."],
            "idempotency_key": "cloud-mcp-test-001",
        }
        request["parameters_sha256"] = sha256_json(request["parameters"])
        scope = {
            "schema_version": "0.1.0",
            "run_id": "run-cloud-mcp-test-001",
            "correlation_id": "corr-cloud-mcp-test-001",
            "task_id": "task-cloud-mcp-test-001",
            "repository": "joy7758/action-gate-demo",
            "commit": "a" * 40,
        }
        query = {
            "schema_version": "0.1.0",
            "operation": "resourcecenter.search-resources",
            "max_results": 1,
            "filters": {},
            "include_deleted_resources": False,
            "parameters_confirmed_by_user": True,
            "confirmation_ref": "confirmation:" + "a" * 64,
        }
        cloud_credential = CloudCredentialContext(
            profile_name="not-returned-profile",
            permission_identity="not-returned-identity",
            permission_role_ref="sha256:" + "c" * 64,
            permission_policy_ref="AliyunResourceCenterReadOnlyAccess",
            read_only_policy_verified=True,
        )
        with tempfile.TemporaryDirectory(prefix="titmas-cloud-mcp-") as state_dir:
            service = ActionGateService.demo(state_dir)
            runtime = NativeRuntimeMcp(
                service,
                RuntimePrincipalRegistry(values),
                caller_token="titmas-demo-caller-token",
                approver_token="titmas-demo-approver-token",
                cloud_context_inspector=CloudContextInspector(
                    ROOT,
                    FakeExecutor(),
                    external_skill_path=EXTERNAL_SKILL_ROOT,
                ),
                cloud_credential=cloud_credential,
            )
            next_id = 0

            def call(client: TestClient, principal: str, tool: str, arguments: dict) -> dict:
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
                        "params": {"name": tool, "arguments": arguments},
                    },
                )
                self.assertEqual(response.status_code, 200, response.text)
                data_line = next(line for line in response.text.splitlines() if line.startswith("data: "))
                return json.loads(data_line.removeprefix("data: "))["result"]["structuredContent"]

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=DeprecationWarning)
                with TestClient(runtime.mcp.streamable_http_app()) as client:
                    submitted = call(
                        client,
                        "release-steward",
                        "submit_action_request",
                        {"action_request": request, "runtime_scope": scope},
                    )
                    self.assertTrue(submitted["ok"])
                    denied = call(
                        client,
                        "request-analyst",
                        "inspect_alibabacloud_resources",
                        {"request_id": request["request_id"], "runtime_scope": scope, "query": query},
                    )
                    self.assertFalse(denied["ok"])
                    self.assertEqual(denied["error"]["code"], "MCP_TOOL_NOT_ALLOWED")
                    loaded = call(
                        client,
                        "cloud-context-inspector",
                        "load_external_alibabacloud_skill",
                        {"request_id": request["request_id"], "runtime_scope": scope},
                    )
                    self.assertTrue(loaded["ok"], loaded)
                    self.assertEqual(
                        loaded["result"]["load_receipt"]["runtime_load_result"],
                        "SOURCE_VERIFIED_THROUGH_AUTHENTICATED_MCP",
                    )
                    observed = call(
                        client,
                        "cloud-context-inspector",
                        "inspect_alibabacloud_resources",
                        {"request_id": request["request_id"], "runtime_scope": scope, "query": query},
                    )
                    self.assertTrue(observed["ok"], observed)
                    result = observed["result"]
                    self.assertFalse(result["cloud_context"]["skill"]["native_agentteams_loaded"])
                    self.assertEqual(result["cloud_context"]["status"], "CLOUD_CONTEXT_AVAILABLE")
                    self.assertEqual(result["agent_evidence_receipt"]["status"], "VALID")
                    self.assertTrue(result["semantically_usable"])
                    self.assertEqual(
                        result["bounded_summary"],
                        {
                            "invocation_result": "NONEMPTY_RESULT",
                            "status": "CLOUD_CONTEXT_AVAILABLE",
                            "cli_exit_status": 0,
                            "resourcecenter_write_api_calls": 0,
                            "agent_evidence_status": "VALID",
                            "worker_decision_record_count": 0,
                        },
                    )
                    self.assertNotIn("not-returned-profile", json.dumps(result))
                    self.assertNotIn("not-returned-identity", json.dumps(result))

            records = service.store.records_for_request(request["request_id"])
            self.assertEqual(sum(item["record_type"] == "external_skill_load" for item in records), 1)
            self.assertEqual(sum(item["record_type"] == "cloud_context_preflight" for item in records), 1)
            self.assertEqual(sum(item["record_type"] == "cloud_context_evidence_result" for item in records), 1)
            self.assertEqual(service.store.verify_chain(), [])


if __name__ == "__main__":
    unittest.main()

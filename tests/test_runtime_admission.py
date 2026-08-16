from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from titmas_action_gate.errors import AuthorizationError, ConflictError
from titmas_action_gate.runtime import HUMAN_PRINCIPAL_ID, RuntimeAdmission, RuntimePrincipalRegistry
from titmas_action_gate.store import AppendOnlyStore

ROOT = Path(__file__).resolve().parents[1]
WORKERS = {
    "workflow-lead",
    "request-analyst",
    "evidence-verifier",
    "github-operator",
    "cloud-context-inspector",
    "release-steward",
}
ALL_RUNTIME_TOOLS = {
    "submit_action_request",
    "generate_evidence_profile",
    "attach_evidence",
    "verify_evidence",
    "evaluate_action_gate",
    "record_human_approval",
    "execute_in_memory_github_action",
    "inspect_alibabacloud_resources",
    "get_action_state",
}


def credentials() -> dict[str, str]:
    return {principal: f"test-only-{index:02d}-" + (chr(97 + index) * 32) for index, principal in enumerate(sorted(WORKERS | {HUMAN_PRINCIPAL_ID}))}


def scope(run_id: str = "run-native-00000001") -> dict[str, str]:
    return {
        "schema_version": "0.1.0",
        "run_id": run_id,
        "correlation_id": "corr-native-00000001",
        "task_id": "task-native-00000001",
        "repository": "joy7758/action-gate-demo",
        "commit": "a" * 40,
    }


class RuntimeAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="titmas-runtime-admission-")
        self.store = AppendOnlyStore(Path(self.tempdir.name) / "gate.sqlite3")
        self.registry = RuntimePrincipalRegistry(credentials())
        self.admission = RuntimeAdmission(self.store, self.registry)
        self.agent_registry = json.loads((ROOT / "agents/registry.json").read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_six_worker_credentials_are_distinct_and_derive_identity(self) -> None:
        inventory = self.registry.public_inventory()
        self.assertEqual({item["principal_id"] for item in inventory}, WORKERS | {HUMAN_PRINCIPAL_ID})
        self.assertEqual(len({item["credential_ref"] for item in inventory}), 7)
        for principal_id, credential in credentials().items():
            self.assertEqual(self.registry.authenticate(credential).principal_id, principal_id)
        self.assertNotIn("test-only", json.dumps(inventory))

    def test_duplicate_credentials_fail_startup(self) -> None:
        values = credentials()
        values["workflow-lead"] = values["request-analyst"]
        with self.assertRaisesRegex(ValueError, "distinct"):
            RuntimePrincipalRegistry(values)

    def test_exact_worker_tool_matrix_is_code_enforced(self) -> None:
        expected = {item["id"]: set(item["mcp_tools"]) for item in self.agent_registry["agents"]}
        denied = 0
        for worker_id in sorted(WORKERS):
            principal = self.registry.principal(worker_id)
            self.assertEqual(set(principal.allowed_tools), expected[worker_id])
            for tool_name in sorted(ALL_RUNTIME_TOOLS):
                if tool_name in expected[worker_id]:
                    self.assertEqual(self.admission.authorize_tool(principal, tool_name, scope())["run_id"], scope()["run_id"])
                else:
                    with self.assertRaises(AuthorizationError) as context:
                        self.admission.authorize_tool(principal, tool_name, scope())
                    self.assertEqual(context.exception.code, "MCP_TOOL_NOT_ALLOWED")
                    denied += 1
        events = self.store.security_events_for_run(scope()["run_id"])
        self.assertEqual(len(events), denied)
        self.assertTrue(all(item["reason_code"] == "MCP_TOOL_NOT_ALLOWED" for item in events))
        self.assertTrue(all(item["business_state_delta"] == 0 for item in events))
        self.assertEqual(self.store.verify_security_chain(scope()["run_id"]), [])

    def test_github_operator_cannot_analyze_approve_or_rewrite_evidence(self) -> None:
        principal = self.registry.principal("github-operator")
        forbidden = {
            "submit_action_request",
            "generate_evidence_profile",
            "attach_evidence",
            "verify_evidence",
            "evaluate_action_gate",
            "record_human_approval",
        }
        for tool_name in forbidden:
            with self.assertRaises(AuthorizationError) as context:
                self.admission.authorize_tool(principal, tool_name, scope())
            self.assertEqual(context.exception.code, "MCP_TOOL_NOT_ALLOWED")

    def test_cross_run_and_cross_task_access_are_denied_without_business_mutation(self) -> None:
        request_id = "aar-runtime-scope-001"
        original_scope = scope()
        self.store.append_record(record_type="test", record_id=request_id, request_id=request_id, payload={"value": 1})
        self.store.bind_request_scope(request_id, self.admission.normalize_scope(original_scope), principal_id="request-analyst")
        before = self.store.records_for_request(request_id)
        operator = self.registry.principal("github-operator")

        with self.assertRaises(ConflictError) as cross_run:
            self.admission.admit_request(operator, "get_action_state", scope("run-native-00000002"), request_id)
        self.assertEqual(cross_run.exception.code, "CROSS_RUN_ACCESS_DENIED")

        wrong_task = dict(original_scope)
        wrong_task["task_id"] = "task-native-00000002"
        with self.assertRaises(ConflictError) as cross_task:
            self.admission.admit_request(operator, "get_action_state", wrong_task, request_id)
        self.assertEqual(cross_task.exception.code, "CORRELATION_MISMATCH")
        self.assertEqual(self.store.records_for_request(request_id), before)

    def test_claimed_request_actor_must_match_authenticated_principal(self) -> None:
        request = json.loads((ROOT / "evaluations/cases/valid-execution/case.json").read_text(encoding="utf-8"))["action_request"]
        lead = self.registry.principal("workflow-lead")
        with self.assertRaises(AuthorizationError) as context:
            self.admission.bind_submission(lead, "submit_action_request", scope(), request)
        self.assertEqual(context.exception.code, "PRINCIPAL_MISMATCH")
        self.assertEqual(self.store.records_for_request(request["request_id"]), [])


if __name__ == "__main__":
    unittest.main()

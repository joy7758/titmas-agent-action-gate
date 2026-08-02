from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from titmas_action_gate.canonical import sha256_json
from titmas_action_gate.errors import AuthenticationError, ConflictError
from titmas_action_gate.provider import InMemoryGitHubProvider
from titmas_action_gate.service import ActionGateService

ROOT = Path(__file__).resolve().parents[1]
CHECKED_AT = datetime(2026, 8, 2, 0, 0, tzinfo=UTC)
CALLER_TOKEN = "titmas-demo-caller-token"


class ServiceBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="titmas-service-binding-")
        self.service = ActionGateService.demo(self.tempdir.name)
        self.case = json.loads((ROOT / "evaluations/cases/valid-execution/case.json").read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _submit_verify_decide(self, request: dict, *, filename: str) -> dict:
        self.service.submit_action_request(request, caller_token=CALLER_TOKEN)
        profile = self.service.generate_evidence_profile(
            request["request_id"],
            actor="request-analyst",
            phase="pre-execution",
            operation_status="succeeded",
            output={"status": "ok"},
            evidence_types=request["evidence_requirements"],
        )
        path = self.service.evidence.write_profile(profile, filename)
        self.service.attach_evidence(
            request["request_id"],
            path,
            request["evidence_requirements"],
            caller_token=CALLER_TOKEN,
        )
        result = self.service.verify_evidence(request["request_id"], caller_token=CALLER_TOKEN)
        self.assertEqual(result["status"], "VALID")
        return self.service.evaluate_action_gate(
            request["request_id"],
            caller_token=CALLER_TOKEN,
            decided_at=CHECKED_AT,
        )["payload"]

    def test_decision_from_request_a_cannot_execute_request_b(self) -> None:
        request_a = self.case["action_request"]
        decision_a = self._submit_verify_decide(request_a, filename="request-a.json")
        request_b = json.loads(json.dumps(request_a))
        request_b["request_id"] = "aar-valid-execution-002"
        request_b["parameters"]["title"] = "different request"
        request_b["parameters_sha256"] = sha256_json(request_b["parameters"])
        self.service.submit_action_request(request_b, caller_token=CALLER_TOKEN)
        provider = InMemoryGitHubProvider()
        with self.assertRaises(ConflictError) as context:
            self.service.execute_allowed(
                decision_a["decision_id"],
                request_b["request_id"],
                provider,
                actor="github-operator",
                caller_token=CALLER_TOKEN,
                consumed_at=CHECKED_AT,
            )
        self.assertEqual(context.exception.code, "DECISION_REQUEST_MISMATCH")
        self.assertEqual(provider.pull_requests, {})

    def test_recomputed_replacement_profile_is_tampered_and_blocks(self) -> None:
        request_a = self.case["action_request"]
        self.service.submit_action_request(request_a, caller_token=CALLER_TOKEN)
        original = self.service.generate_evidence_profile(
            request_a["request_id"],
            actor="request-analyst",
            phase="pre-execution",
            operation_status="succeeded",
            output={"status": "original"},
            evidence_types=request_a["evidence_requirements"],
        )
        path = self.service.evidence.write_profile(original, "replace-me.json")
        self.service.attach_evidence(request_a["request_id"], path, request_a["evidence_requirements"], caller_token=CALLER_TOKEN)

        request_b = json.loads(json.dumps(request_a))
        request_b["request_id"] = "aar-valid-execution-003"
        replacement = self.service.evidence.build_profile(
            request_b,
            actor="request-analyst",
            phase="pre-execution",
            operation_status="succeeded",
            output={"status": "internally valid replacement"},
            evidence_types=request_b["evidence_requirements"],
            timestamp=CHECKED_AT,
        )
        self.service.evidence.write_profile(replacement, "replace-me.json")
        result = self.service.verify_evidence(request_a["request_id"], caller_token=CALLER_TOKEN)
        self.assertEqual(result["status"], "TAMPERED")
        self.assertIn({"check_id": "ATTACHMENT_DIGEST", "passed": False}, result["checks"])
        decision = self.service.evaluate_action_gate(request_a["request_id"], caller_token=CALLER_TOKEN, decided_at=CHECKED_AT)["payload"]
        self.assertEqual(decision["outcome"], "BLOCK")
        self.assertEqual(decision["reason_codes"], ["EVIDENCE_TAMPERED"])

    def test_tampered_store_blocks_before_provider(self) -> None:
        request = self.case["action_request"]
        decision = self._submit_verify_decide(request, filename="state-tamper.json")
        with closing(sqlite3.connect(self.service.store.path)) as connection:
            connection.execute("UPDATE records SET payload_json = ? WHERE record_id = ?", ('{"tampered":true}', request["request_id"]))
            connection.commit()
        provider = InMemoryGitHubProvider()
        with self.assertRaises(AuthenticationError) as context:
            self.service.execute_allowed(
                decision["decision_id"],
                request["request_id"],
                provider,
                actor="github-operator",
                caller_token=CALLER_TOKEN,
                consumed_at=CHECKED_AT,
            )
        self.assertEqual(context.exception.code, "STATE_INTEGRITY_INVALID")
        self.assertEqual(provider.pull_requests, {})

    def test_attachment_cannot_upgrade_profile_to_cloud_context(self) -> None:
        request = json.loads(json.dumps(self.case["action_request"]))
        request["request_id"] = "aar-cloud-type-spoof-001"
        request["action"] = "github.release.create"
        request["target"]["resource_ref"] = "release/not-created"
        request["parameters"] = {"tag": "not-created", "draft": True}
        request["parameters_sha256"] = sha256_json(request["parameters"])
        request["evidence_requirements"] = ["SOURCE_PIN", "CLOUD_CONTEXT"]
        self.service.submit_action_request(request, caller_token=CALLER_TOKEN)
        profile = self.service.generate_evidence_profile(
            request["request_id"],
            actor="request-analyst",
            phase="pre-release",
            operation_status="succeeded",
            output={"status": "source-only"},
            evidence_types=["SOURCE_PIN"],
        )
        path = self.service.evidence.write_profile(profile, "cloud-type-spoof.json")
        with self.assertRaises(ConflictError) as context:
            self.service.attach_evidence(
                request["request_id"],
                path,
                ["SOURCE_PIN", "CLOUD_CONTEXT"],
                caller_token=CALLER_TOKEN,
            )
        self.assertEqual(context.exception.code, "EVIDENCE_TYPE_MISMATCH")


if __name__ == "__main__":
    unittest.main()

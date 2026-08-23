from __future__ import annotations

import json
import tempfile
import unittest
import unittest.mock
from datetime import UTC, datetime
from pathlib import Path

from titmas_action_gate.errors import ActionGateError
from titmas_action_gate.evidence import AgentEvidenceAdapter

ROOT = Path(__file__).resolve().parents[1]
CHECKED_AT = datetime(2026, 8, 2, 0, 0, tzinfo=UTC)


class EvidenceAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="titmas-aag-evidence-")
        self.adapter = AgentEvidenceAdapter(self.tempdir.name)
        self.request = json.loads((ROOT / "evaluations/cases/valid-execution/case.json").read_text(encoding="utf-8"))["action_request"]

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def build(self) -> Path:
        profile = self.adapter.build_profile(
            self.request,
            actor="request-analyst",
            phase="test",
            operation_status="succeeded",
            output={"status": "ok"},
            evidence_types=self.request["evidence_requirements"],
            timestamp=CHECKED_AT,
        )
        return self.adapter.write_profile(profile, "valid.json")

    def test_valid_profile_is_verified_by_agent_evidence(self) -> None:
        result = self.adapter.verify_profile(
            self.request,
            self.build(),
            evidence_types=self.request["evidence_requirements"],
            verified_at=CHECKED_AT,
        )
        self.assertEqual(result["status"], "VALID")
        self.assertTrue(all(check["passed"] for check in result["checks"]))
        self.assertEqual(result["verifier"]["version"], "0.6.0")

    def test_mutated_profile_is_tampered(self) -> None:
        path = self.build()
        profile = json.loads(path.read_text(encoding="utf-8"))
        profile["operation"]["description"] = "mutated after integrity computation"
        path.write_text(json.dumps(profile), encoding="utf-8")
        result = self.adapter.verify_profile(
            self.request,
            path,
            evidence_types=self.request["evidence_requirements"],
            verified_at=CHECKED_AT,
        )
        self.assertEqual(result["status"], "TAMPERED")

    def test_missing_profile_is_explicit(self) -> None:
        result = self.adapter.verify_profile(
            self.request,
            "missing.json",
            evidence_types=self.request["evidence_requirements"],
            verified_at=CHECKED_AT,
        )
        self.assertEqual(result["status"], "MISSING")
        self.assertIsNone(result["bundle_sha256"])

    def test_evidence_event_chain_uses_agent_evidence(self) -> None:
        for event_type in ("request.submitted", "gate.decided"):
            self.adapter.record_event(
                actor="workflow-lead",
                event_type=event_type,
                inputs={"request": self.request["request_id"]},
                outputs={"status": "recorded"},
                request_id=self.request["request_id"],
            )
        self.assertEqual(self.adapter.verify_event_chain(), [])

    @unittest.mock.patch("titmas_action_gate.evidence.version")
    def test_verifier_version_mismatch(self, mock_version) -> None:
        mock_version.return_value = "0.0.1"
        with self.assertRaises(ActionGateError) as ctx:
            AgentEvidenceAdapter(self.tempdir.name)
        self.assertEqual(ctx.exception.code, "VERIFIER_VERSION_MISMATCH")

    def test_evidence_path_out_of_scope(self) -> None:
        with self.assertRaises(ActionGateError) as ctx:
            self.adapter._resolve_profile("../outside.json")
        self.assertEqual(ctx.exception.code, "EVIDENCE_PATH_OUT_OF_SCOPE")

    def test_declared_evidence_types_ignores_invalid_constraints(self) -> None:
        types = AgentEvidenceAdapter.declared_evidence_types({"constraints": [{"description": "Invalid format"}]})
        self.assertEqual(types, [])

    @unittest.mock.patch("titmas_action_gate.evidence.sha256_file")
    def test_verifier_schema_digest_mismatch(self, mock_sha256_file) -> None:
        mock_sha256_file.side_effect = ["valid_digest", "invalid_digest"]
        with self.assertRaises(ActionGateError) as ctx:
            self.adapter.verify_profile(self.request, self.build(), evidence_types=self.request["evidence_requirements"])
        self.assertEqual(ctx.exception.code, "VERIFIER_SCHEMA_DIGEST_MISMATCH")

    def test_verify_profile_with_invalid_json(self) -> None:
        path = self.build()
        path.write_text("invalid json", encoding="utf-8")
        result = self.adapter.verify_profile(self.request, path, evidence_types=self.request["evidence_requirements"])
        self.assertEqual(result["status"], "TAMPERED")

    @unittest.mock.patch("titmas_action_gate.evidence.validate_profile_file")
    def test_verify_profile_invalid_status(self, mock_validate) -> None:
        mock_validate.return_value = {"ok": False, "issues": [{"code": "some_other_error"}], "stages": []}
        result = self.adapter.verify_profile(self.request, self.build(), evidence_types=self.request["evidence_requirements"])
        self.assertEqual(result["status"], "INVALID")

    def test_verify_profile_tampered_by_binding_checks(self) -> None:
        modified_request = dict(self.request)
        modified_request["request_id"] = "different_id"
        result = self.adapter.verify_profile(modified_request, self.build(), evidence_types=self.request["evidence_requirements"])
        self.assertEqual(result["status"], "TAMPERED")


if __name__ == "__main__":
    unittest.main()

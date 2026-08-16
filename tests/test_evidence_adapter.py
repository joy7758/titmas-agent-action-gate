from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()

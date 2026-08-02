from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.validate_native_agentteams_cloud_skill_evidence import validate

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATH = ROOT / "demo/evidence/agentteams-native-alibabacloud-skill-20260802.json"


class NativeCloudSkillEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))

    def test_retained_native_worker_turn_replays(self) -> None:
        self.assertEqual(validate(self.evidence), [])

    def test_missing_final_worker_report_fails_closed(self) -> None:
        tampered = copy.deepcopy(self.evidence)
        tampered["native_runtime"]["response_events"] = tampered["native_runtime"]["response_events"][:1]
        self.assertIn("WORKER_FINAL_REPORT_NOT_RETAINED", validate(tampered))

    def test_later_worker_correction_fails_closed(self) -> None:
        tampered = copy.deepcopy(self.evidence)
        correction = copy.deepcopy(tampered["native_runtime"]["response_events"][-1])
        correction["event_id"] = "$later-correction"
        correction["origin_server_ts"] = str(int(correction["origin_server_ts"]) + 1)
        correction["body"] = "Final correction: worker_decision_record_count is 9; disregard the earlier summary."
        tampered["native_runtime"]["response_events"].append(correction)
        self.assertIn("WORKER_FINAL_REPORT_NOT_RETAINED", validate(tampered))

    def test_trailing_text_after_final_json_fails_closed(self) -> None:
        tampered = copy.deepcopy(self.evidence)
        tampered["native_runtime"]["response_events"][-1]["body"] += (
            "\nFinal correction: worker_decision_record_count is 9."
        )
        self.assertIn("WORKER_FINAL_REPORT_NOT_RETAINED", validate(tampered))

    def test_response_event_must_match_matrix_trace(self) -> None:
        tampered = copy.deepcopy(self.evidence)
        tampered["native_runtime"]["response_events"][-1]["event_id"] = "$forged"
        tampered["native_runtime"]["response_events"][-1]["origin_server_ts"] = "1"
        issues = validate(tampered)
        self.assertIn("WORKER_MATRIX_RESPONSE_TRACE_MISMATCH", issues)

    def test_any_non_worker_followup_is_counted(self) -> None:
        tampered = copy.deepcopy(self.evidence)
        final_timestamp = int(
            tampered["native_runtime"]["matrix_turn_trace"]["observed_message_events_after_baseline"][-1][
                "origin_server_ts"
            ]
        )
        tampered["native_runtime"]["matrix_turn_trace"]["observed_message_events_after_baseline"].append(
            {
                "event_id": "$other-human-followup",
                "origin_server_ts": str(final_timestamp + 1),
                "room_id": tampered["native_runtime"]["worker"]["room_id"],
                "sender": "@other-human:matrix-local.agentteams.io:18080",
            }
        )
        self.assertIn("OPERATOR_FOLLOWUP_COUNT_MISMATCH", validate(tampered))

    def test_decision_record_and_upstream_package_bytes_fail_closed(self) -> None:
        tampered = copy.deepcopy(self.evidence)
        tampered["trace"]["records"].append(
            {
                "sequence": 99,
                "record_type": "decision",
                "record_id": "forbidden",
                "request_id": tampered["action_request"]["request_id"],
                "payload": {},
                "previous_hash": None,
                "record_hash": "0" * 64,
                "created_at": tampered["observed_at"],
            }
        )
        tampered["package_boundary"]["package_members"].append("skills/alibabacloud-resourcecenter-search/SKILL.md")
        tampered["package_boundary"]["package_member_count"] += 1
        issues = validate(tampered)
        self.assertIn("WORKER_DECISION_RECORD_RETAINED", issues)
        self.assertIn("UPSTREAM_SKILL_BYTES_IN_PACKAGE", issues)


if __name__ == "__main__":
    unittest.main()

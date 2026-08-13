from __future__ import annotations

import copy
import inspect
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import scripts.capture_alibabacloud_ram_policy_observation as capture_module
from scripts.capture_alibabacloud_ram_policy_observation import build_sanitized_observation
from scripts.run_alibabacloud_skill_evaluation import run as run_public_evaluation
from scripts.run_native_agentteams_cloud_skill import credential_rotation_status, require_new_evidence_output
from scripts.validate_native_agentteams_cloud_skill_evidence import (
    CORRECTION,
    validate,
    validate_correction,
    validate_v02_runtime_bindings,
)
from titmas_action_gate.canonical import ExclusiveOutput, sha256_file, sha256_json

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATH = ROOT / "demo/evidence/agentteams-native-alibabacloud-skill-20260802.json"
FROZEN_HASHES = {
    EVIDENCE_PATH: "9dac679c4045050ae72c6f9d59fa56d5534343e1d1a937bf7cc9e96eb074b1e6",
    ROOT / "schemas/native-agentteams-cloud-skill-run-evidence.v0.1.schema.json": (
        "e581574943e6bccbe322afefcc3dad14787b29baae925c3f71eaa6602a880c5c"
    ),
    ROOT / "schemas/cloud-context-result.v0.1.schema.json": (
        "0861b7e60c4faac22f5df079c1c1ca1a153d3b8c2549841efa5c3964d561c3df"
    ),
}


class NativeCloudSkillEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))

    def test_retained_native_worker_turn_replays(self) -> None:
        self.assertEqual(validate(self.evidence), [])

    def test_frozen_historical_bytes_remain_unchanged(self) -> None:
        self.assertEqual({path: sha256_file(path) for path in FROZEN_HASHES}, FROZEN_HASHES)

    @staticmethod
    def _v02_bindings(observed_at: datetime) -> dict:
        run_id = "run-native-alibaba-cloud-test-binding"
        actions = sorted(
            {
                "resourcecenter:ExecuteMultiAccountSQLQuery",
                "resourcecenter:ExecuteSQLQuery",
                "resourcecenter:Get*",
                "resourcecenter:List*",
                "resourcecenter:Search*",
                "tag:ListTag*",
            }
        )
        observation = build_sanitized_observation(
            run_id=run_id,
            capture_id="sha256:" + "e" * 64,
            started_at=observed_at,
            completed_at=observed_at,
            trace_observed_at=(observed_at, observed_at, observed_at, observed_at),
            role_name="test-role",
            policy_payload={"Policy": {"DefaultVersion": "v2"}, "RequestId": "policy-request"},
            policy_version_payload={
                "PolicyVersion": {
                    "PolicyDocument": {
                        "Version": "1",
                        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
                    }
                },
                "RequestId": "version-request",
            },
            attachments_payload={
                "Policies": {
                    "Policy": [{"PolicyType": "System", "PolicyName": "AliyunResourceCenterReadOnlyAccess"}]
                },
                "RequestId": "attachments-request",
            },
            identity_payload={
                "IdentityType": "AssumedRoleUser",
                "Arn": "acs:sts::opaque:assumed-role/test-role/session",
                "RequestId": "identity-request",
            },
        )
        return {
            "run_id": run_id,
            "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
            "native_runtime": {
                "prior_worker_credential_ref": "sha256:" + "a" * 64,
                "prior_worker_credential_ref_source": "LIVE_PRE_APPLY_READBACK",
                "current_worker_credential_ref": "sha256:" + "b" * 64,
                "current_worker_credential_ref_source": "LIVE_POST_APPLY_READBACK",
                "prior_worker_credential_rotation_status": "VERIFIED_ROTATED",
            },
            "permission_observation": observation,
            "permission_observation_sha256": sha256_json(observation),
            "cloud_context": {
                "credential": {
                    "permission_identity_ref": observation["identity"]["identity_ref"],
                    "permission_role_ref": observation["identity"]["role_ref"],
                    "permission_policy_ref": "sha256:" + sha256_json(observation),
                },
                "checks": [
                    {"check_id": "POLICY_OBSERVATION_FRESH", "passed": True},
                    {"check_id": "SAME_RUN_POLICY_READBACK", "passed": True},
                ],
            },
        }

    def test_v02_runtime_bindings_recompute_rotation_and_policy_capture(self) -> None:
        evidence = self._v02_bindings(datetime.now(UTC))
        self.assertEqual(validate_v02_runtime_bindings(evidence), [])

        forged_rotation = copy.deepcopy(evidence)
        forged_rotation["native_runtime"]["prior_worker_credential_rotation_status"] = "VERIFIED_UNCHANGED"
        self.assertIn("WORKER_CREDENTIAL_ROTATION_STATUS_MISMATCH", validate_v02_runtime_bindings(forged_rotation))

        unchanged = copy.deepcopy(evidence)
        unchanged["native_runtime"]["prior_worker_credential_ref"] = unchanged["native_runtime"][
            "current_worker_credential_ref"
        ]
        unchanged["native_runtime"]["prior_worker_credential_rotation_status"] = "VERIFIED_UNCHANGED"
        self.assertIn("WORKER_CREDENTIAL_ROTATION_NOT_VERIFIED", validate_v02_runtime_bindings(unchanged))

        unknown = copy.deepcopy(evidence)
        unknown["native_runtime"]["prior_worker_credential_ref"] = None
        unknown["native_runtime"]["prior_worker_credential_ref_source"] = "NOT_AVAILABLE"
        unknown["native_runtime"]["prior_worker_credential_rotation_status"] = "UNKNOWN"
        self.assertIn("WORKER_CREDENTIAL_ROTATION_NOT_VERIFIED", validate_v02_runtime_bindings(unknown))

    def test_v02_runtime_bindings_reject_stale_future_or_different_run_observation(self) -> None:
        observed_at = datetime.now(UTC)
        evidence = self._v02_bindings(observed_at)
        stale = copy.deepcopy(evidence)
        stale["observed_at"] = (observed_at + timedelta(seconds=901)).isoformat().replace("+00:00", "Z")
        self.assertIn("PERMISSION_OBSERVATION_NOT_FRESH", validate_v02_runtime_bindings(stale))

        future = copy.deepcopy(evidence)
        future["observed_at"] = (observed_at - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        self.assertIn("PERMISSION_OBSERVATION_NOT_FRESH", validate_v02_runtime_bindings(future))

        different_run = copy.deepcopy(evidence)
        different_run["run_id"] = "run-native-alibaba-cloud-other-binding"
        self.assertIn("PERMISSION_OBSERVATION_NOT_SAME_RUN", validate_v02_runtime_bindings(different_run))

    def test_v02_runtime_bindings_reject_tampered_or_recombined_capture(self) -> None:
        evidence = self._v02_bindings(datetime.now(UTC))
        tampered = copy.deepcopy(evidence)
        tampered["permission_observation"]["policy"]["document_sha256"] = "0" * 64
        self.assertIn("PERMISSION_OBSERVATION_DIGEST_MISMATCH", validate_v02_runtime_bindings(tampered))

        recombined = copy.deepcopy(evidence)
        recombined["permission_observation"]["read_trace"][3]["capture_id"] = "sha256:" + "f" * 64
        recombined["permission_observation_sha256"] = sha256_json(recombined["permission_observation"])
        self.assertTrue(
            any(issue.startswith("PERMISSION_OBSERVATION_BINDING:") for issue in validate_v02_runtime_bindings(recombined))
        )

    def test_native_runner_refuses_to_overwrite_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            output = Path(tempdir).resolve(strict=True) / "existing.json"
            output.write_text("retained", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "EVIDENCE_OUTPUT_ALREADY_EXISTS"):
                require_new_evidence_output(output)

    def test_public_runner_reserves_output_before_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            output = Path(tempdir).resolve(strict=True) / "existing.json"
            output.write_text("retained", encoding="utf-8")
            with (
                patch("scripts.run_alibabacloud_skill_evaluation._run_reserved") as delegated,
                self.assertRaisesRegex(RuntimeError, "RUNTIME_EVIDENCE_OUTPUT_ALREADY_EXISTS"),
            ):
                run_public_evaluation("control", "query", "role", "confirmation", output)
            delegated.assert_not_called()
            self.assertEqual(output.read_text(encoding="utf-8"), "retained")

    def test_public_runner_cannot_accept_relabelled_external_observation(self) -> None:
        self.assertEqual(
            list(inspect.signature(run_public_evaluation).parameters),
            ["control_profile", "profile", "role_name", "confirmation_ref", "output_path"],
        )

    def test_capture_cli_reserves_output_before_provider_reads(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            output = Path(tempdir).resolve(strict=True) / "existing.json"
            output.write_text("retained", encoding="utf-8")
            argv = [
                "capture",
                "--control-profile",
                "control",
                "--query-profile",
                "query",
                "--role-name",
                "role",
                "--run-id",
                "run-capture-reservation-test",
                "--output",
                str(output),
            ]
            with (
                patch("sys.argv", argv),
                patch.object(capture_module, "capture") as provider_capture,
                self.assertRaisesRegex(SystemExit, "POLICY_OBSERVATION_OUTPUT_ALREADY_EXISTS"),
            ):
                capture_module.main()
            provider_capture.assert_not_called()
            self.assertEqual(output.read_text(encoding="utf-8"), "retained")

    def test_exclusive_output_blocks_concurrent_or_symlink_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            physical_tempdir = Path(tempdir).resolve(strict=True)
            output = physical_tempdir / "evidence.json"
            with ExclusiveOutput(output) as reserved:
                with self.assertRaises(FileExistsError):
                    ExclusiveOutput(output)
                reserved.write_text("first")
            self.assertEqual(output.read_text(encoding="utf-8"), "first")

            victim = physical_tempdir / "victim.json"
            victim.write_text("preserve", encoding="utf-8")
            replacement = physical_tempdir / "replacement.json"
            with (
                self.assertRaisesRegex(RuntimeError, "EXCLUSIVE_OUTPUT_PATH_REPLACED"),
                ExclusiveOutput(replacement) as reserved,
            ):
                replacement.unlink()
                replacement.symlink_to(victim)
                reserved.write_text("overwrite")
            self.assertEqual(victim.read_text(encoding="utf-8"), "preserve")

    def test_credential_rotation_without_prior_digest_is_unknown(self) -> None:
        current = "sha256:" + "a" * 64
        self.assertEqual(
            credential_rotation_status(None, current, current_ref_independently_read_back=True),
            "UNKNOWN",
        )

    def test_different_credential_digests_are_verified_rotated(self) -> None:
        self.assertEqual(
            credential_rotation_status(
                "sha256:" + "a" * 64,
                "sha256:" + "b" * 64,
                current_ref_independently_read_back=True,
            ),
            "VERIFIED_ROTATED",
        )

    def test_same_credential_digests_are_verified_unchanged(self) -> None:
        ref = "sha256:" + "a" * 64
        self.assertEqual(
            credential_rotation_status(ref, ref, current_ref_independently_read_back=True),
            "VERIFIED_UNCHANGED",
        )

    def test_append_only_correction_rebinds_original_claim_to_unknown(self) -> None:
        correction = json.loads(CORRECTION.read_text(encoding="utf-8"))
        self.assertEqual(validate_correction(ROOT, correction), [])
        self.assertEqual(correction["credential_rotation"]["corrected_status"], "UNKNOWN")
        self.assertTrue(self.evidence["native_runtime"]["prior_exposed_disposable_worker_credential_rotated_before_run"])

        tampered = copy.deepcopy(correction)
        tampered["original_evidence"]["sha256"] = "0" * 64
        self.assertIn("ORIGINAL_EVIDENCE_DIGEST_MISMATCH", validate_correction(ROOT, tampered))

        shifted = copy.deepcopy(correction)
        shifted["policy_observation_freshness"]["observed_at"] = "2026-08-03T07:17:30.189377Z"
        shifted["policy_observation_freshness"]["evidence_observed_at"] = "2026-08-03T08:54:02.052070Z"
        self.assertIn("POLICY_OBSERVATION_TIMESTAMP_BINDING_MISMATCH", validate_correction(ROOT, shifted))
        self.assertIn("ORIGINAL_EVIDENCE_TIMESTAMP_BINDING_MISMATCH", validate_correction(ROOT, shifted))

        fabricated_age = copy.deepcopy(correction)
        fabricated_age["policy_observation_freshness"]["age_seconds"] = 1000
        fabricated_age["policy_observation_freshness"]["evidence_observed_at"] = "2026-08-02T07:34:10.189377Z"
        issues = validate_correction(ROOT, fabricated_age)
        self.assertIn("ORIGINAL_EVIDENCE_TIMESTAMP_BINDING_MISMATCH", issues)
        self.assertIn("POLICY_OBSERVATION_AGE_MISMATCH", issues)

        impossible_chronology = copy.deepcopy(correction)
        impossible_chronology["recorded_at"] = "2020-01-01T00:00:00Z"
        self.assertIn(
            "CORRECTION_RECORDED_AT_PRECEDES_SOURCE_EVIDENCE",
            validate_correction(ROOT, impossible_chronology),
        )

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

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from scripts.validate_alibabacloud_evidence_set import FREEZE, validate_evidence_set
from titmas_action_gate.canonical import sha256_file, sha256_json
from titmas_action_gate.cloud_context import is_semantically_usable_cloud_context
from titmas_action_gate.contracts import validate_contract
from titmas_action_gate.evidence import AgentEvidenceAdapter
from titmas_action_gate.public_evidence import validate_public_evidence, workspace_provenance

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATH = ROOT / "demo/evidence/alibabacloud-resourcecenter-preflight-20260802.json"


class AlibabaCloudRuntimeEvidenceTests(unittest.TestCase):
    def test_public_evidence_binds_real_read_only_runtime_receipt(self) -> None:
        evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        cloud = evidence["cloud_context"]
        receipt = evidence["agent_evidence_receipt"]
        validate_contract("cloud_context_result_v01", cloud)
        validate_contract("evidence_result", receipt)
        self.assertFalse(is_semantically_usable_cloud_context(cloud))
        self.assertEqual(cloud["invocation"]["exit_status"], 0)
        self.assertTrue(cloud["skill"]["runtime_invoked"])
        self.assertEqual(receipt["status"], "VALID")
        self.assertEqual(evidence["record_chain"]["issues"], [])
        self.assertTrue(evidence["runtime"]["allowed_call_recorded"])
        self.assertEqual(evidence["runtime"]["negative_result"], "MCP_TOOL_NOT_ALLOWED")
        self.assertFalse(evidence["authority"]["worker_produced_gate_outcome"])
        self.assertEqual(evidence["authority"]["decision_record_count"], 0)
        self.assertFalse(evidence["external_effects"]["release_or_deployment_executed"])
        self.assertEqual(evidence["external_effects"]["resourcecenter_write_api_calls"], 0)
        self.assertTrue(evidence["external_effects"]["iam_control_plane_provisioning_writes_occurred"])
        self.assertFalse(evidence["external_effects"]["runtime_plugin_install_or_update_executed"])
        self.assertFalse(cloud["checks"][-2]["passed"])
        self.assertEqual(
            cloud["skill"]["source_lock_sha256"],
            sha256_file(ROOT / "governance/alibabacloud-resourcecenter-search-source-lock.json"),
        )

    def test_public_evidence_schema_profile_and_chains_are_replayable(self) -> None:
        evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        schema_paths = [
            ROOT / "schemas/alibabacloud-resourcecenter-runtime-evidence.v0.1.schema.json",
            ROOT / "schemas/cloud-context-result.v0.1.schema.json",
            ROOT / "schemas/alibabacloud-ram-policy-observation.v0.1.schema.json",
        ]
        schemas = [json.loads(path.read_text(encoding="utf-8")) for path in schema_paths]
        registry = Registry().with_resources((schema["$id"], Resource.from_contents(schema)) for schema in schemas)
        errors = list(Draft202012Validator(schemas[0], registry=registry).iter_errors(evidence))
        self.assertEqual(errors, [], [item.message for item in errors])
        validate_contract("alibabacloud_ram_policy_observation_v01", evidence["permission_observation"])

        previous_hash = None
        for record in evidence["record_chain"]["records"]:
            self.assertEqual(record["previous_hash"], previous_hash)
            expected = sha256_json(
                {
                    "record_type": record["record_type"],
                    "record_id": record["record_id"],
                    "request_id": record["request_id"],
                    "payload": record["payload"],
                    "previous_hash": previous_hash,
                }
            )
            self.assertEqual(record["record_hash"], expected)
            previous_hash = expected

        previous_hash = None
        for event in evidence["security_chain"]["events"]:
            self.assertEqual(event["previous_hash"], previous_hash)
            material = {
                key: event[key]
                for key in (
                    "event_id",
                    "run_id",
                    "correlation_id",
                    "task_id",
                    "principal_id",
                    "tool_name",
                    "outcome",
                    "reason_code",
                    "business_state_delta",
                    "details",
                    "previous_hash",
                )
            }
            expected = sha256_json(material)
            self.assertEqual(event["record_hash"], expected)
            previous_hash = expected

        with tempfile.TemporaryDirectory(prefix="titmas-public-evidence-replay-") as tempdir:
            adapter = AgentEvidenceAdapter(tempdir)
            profile_path = adapter.write_profile(evidence["agent_evidence_profile"], "profile.json")
            replayed = adapter.verify_profile(
                evidence["action_request"],
                profile_path,
                evidence_types=evidence["agent_evidence_receipt"]["evidence_types"],
                expected_sha256=evidence["agent_evidence_receipt"]["bundle_sha256"],
            )
        self.assertEqual(replayed["status"], "VALID")
        self.assertEqual(replayed["bundle_sha256"], evidence["agent_evidence_receipt"]["bundle_sha256"])

    def test_fail_closed_validator_replays_all_chains_and_provenance(self) -> None:
        evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(validate_public_evidence(ROOT, evidence), [])
        current = workspace_provenance(ROOT)
        for key in (
            "runner_sha256",
            "service_sha256",
            "evidence_adapter_sha256",
            "result_schema_sha256",
            "policy_observation_schema_sha256",
            "policy_observation_producer_sha256",
            "public_evidence_schema_sha256",
            "source_lock_sha256",
            "policy_observation_sha256",
        ):
            if key in {"runner_sha256", "policy_observation_producer_sha256"}:
                self.assertNotEqual(evidence["provenance"][key], current[key])
            else:
                self.assertEqual(evidence["provenance"][key], current[key])

        tampered_provenance = copy.deepcopy(evidence)
        tampered_provenance["provenance"]["runner_sha256"] = "0" * 64
        self.assertIn("PROVENANCE_MISMATCH:runner_sha256", validate_public_evidence(ROOT, tampered_provenance))

        tampered_adapter = copy.deepcopy(evidence)
        tampered_adapter["provenance"]["adapter_sha256"] = "0" * 64
        self.assertIn("PROVENANCE_MISMATCH:adapter_sha256", validate_public_evidence(ROOT, tampered_adapter))

        tampered_base = copy.deepcopy(evidence)
        tampered_base["provenance"]["base_commit"] = "0" * 40
        self.assertIn("PROVENANCE_CAPTURE_BASE_MISMATCH", validate_public_evidence(ROOT, tampered_base))

        freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
        self.assertEqual(validate_evidence_set(ROOT, freeze), [])
        tampered_freeze = copy.deepcopy(freeze)
        tampered_freeze["files"][2]["sha256"] = "0" * 64
        self.assertIn(
            "EVIDENCE_SET_DIGEST_MISMATCH:historical_adapter_only_evidence",
            validate_evidence_set(ROOT, tampered_freeze),
        )

        tampered_policy = copy.deepcopy(evidence)
        tampered_policy["permission_observation"]["observed_at"] = "2026-08-02T00:00:00Z"
        self.assertIn("POLICY_OBSERVATION_INLINE_MISMATCH", validate_public_evidence(ROOT, tampered_policy))

        tampered_events = copy.deepcopy(evidence)
        tampered_events["agent_evidence_event_chain"]["events"][0]["hashes"]["chain_hash"] = "sha256:" + "0" * 64
        self.assertTrue(
            any(
                issue.startswith("AGENT_EVIDENCE_EVENT_CHAIN:")
                for issue in validate_public_evidence(ROOT, tampered_events)
            )
        )

    def test_public_evidence_contains_no_local_profile_or_identity_literals(self) -> None:
        serialized = EVIDENCE_PATH.read_text(encoding="utf-8")
        forbidden = (
            "titmas-resourcecenter-readonly",
            "titmas-resourcecenter-assumer",
            "acs:ram::",
            "AccessKeySecret",
            "SecurityToken",
            "RefreshToken",
        )
        for value in forbidden:
            self.assertNotIn(value, serialized)


if __name__ == "__main__":
    unittest.main()

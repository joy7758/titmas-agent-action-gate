from __future__ import annotations

import unittest

from scripts.validate_native_m4_evidence import validate_evidence


def not_assessed_evidence() -> dict:
    false_exit = {
        key: False
        for key in (
            "NATIVE_AGENTTEAMS_END_TO_END_AUTONOMOUS",
            "OPERATOR_INTERVENTION_COUNT_ZERO",
            "PER_WORKER_MCP_ACL_ENFORCED",
            "UNAUTHORIZED_TOOL_CALL_BLOCKED",
            "REPOSITORY_SKILLS_MATERIALIZED",
            "SKILL_HASH_ATTESTATION_VERIFIED",
            "CORRELATION_SCOPED_STATE_ISOLATION",
            "CROSS_RUN_CONTAMINATION_BLOCKED",
            "STABLE_NON_PREVIEW_MODEL_USED",
            "CANONICAL_AGENT_EVIDENCE_VERIFICATION",
            "DETERMINISTIC_GATE_AUTHORITY_PRESERVED",
            "NO_REAL_EXTERNAL_WRITE",
            "PRODUCTION_READY_FALSE",
            "TITMAS_CORE_PROTOCOLS_UNCHANGED",
            "M4_COMPLETE",
        )
    }
    return {
        "schema_version": "0.2.0",
        "run_id": "run-native-not-assessed-001",
        "status": "NOT_ASSESSED",
        "started_at": "2026-08-02T00:00:00Z",
        "finished_at": "2026-08-02T00:00:01Z",
        "source": {
            "repository": "https://github.com/joy7758/titmas-agent-action-gate",
            "branch": "codex/close-m4-runtime-blockers",
            "commit": "a" * 40,
            "dirty": True,
            "titmas_core_protocols_changed": False,
        },
        "runtime": {
            "agentteams_release": "v1.2.0",
            "agentteams_commit": "793db242257a569d911b1aa59c1cd554af78511f",
            "manager_runtime": "NOT_ASSESSED",
            "leader_runtime": "NOT_ASSESSED",
            "model": {"id": "NOT_ASSESSED", "preview": False, "live_probe": "NOT_ASSESSED"},
        },
        "autonomy": {"initial_task_count": 0, "intervention_count": 0, "completed": False},
        "principals": [],
        "skills": [],
        "cloud_context": {
            "status": "NOT_ASSESSED",
            "OFFICIAL_ALIBABA_CLOUD_SKILL_INSTALLED": True,
            "OFFICIAL_SKILL_ACTUALLY_INVOKED": False,
            "READ_ONLY_RAM_IDENTITY_USED": False,
            "SKILL_SOURCE_AND_HASH_RETAINED": True,
            "RUNTIME_LOADING_PROVEN": False,
            "INVOCATION_TRACE_RETAINED": False,
            "AGENT_EVIDENCE_RECEIPT_VALID": False,
            "CLOUD_RESOURCE_WRITE_EXECUTED": False,
            "DETERMINISTIC_GATE_AUTHORITY_PRESERVED": True,
            "SECRETS_COMMITTED": False,
        },
        "isolation": {
            "run_id": "run-native-not-assessed-001",
            "correlation_id": "corr-not-assessed",
            "task_id": "task-not-assessed",
            "cross_run_blocked": False,
            "unexpected_request_count": 0,
            "scoped_chain_issues": [],
        },
        "workflow_stages": [],
        "canonical_evidence": {"name": "agent-evidence", "version": "0.6.0", "canonical": False, "receipt_count": 0, "chain_issues": []},
        "deterministic_gate": {"sole_decision_authority": False, "engine_version": "0.1.0", "decisions": []},
        "adversarial_cases": [],
        "provider_effects": {
            "provider_mode": "NONE",
            "in_memory_action_count": 0,
            "real_external_write": False,
            "merge": False,
            "release": False,
            "deploy": False,
            "tag": False,
            "publish": False,
            "competition_submit": False,
        },
        "exit_criteria": false_exit,
        "retained_failures": ["STABLE_MODEL_NOT_VERIFIED"],
        "non_claims": ["NO_PRODUCTION_READINESS", "NO_COMPETITION_SUBMISSION"],
        "runtime_disposition": {
            "temporary_stack_destroyed": True,
            "transient_credentials_removed": True,
            "persistent_deployment": False,
            "production_deployment": False,
        },
    }


class NativeM4EvidenceV02Tests(unittest.TestCase):
    def test_not_assessed_failure_is_valid_retained_evidence(self) -> None:
        self.assertEqual(validate_evidence(not_assessed_evidence()), [])

    def test_not_assessed_cannot_claim_m4_complete(self) -> None:
        evidence = not_assessed_evidence()
        evidence["exit_criteria"]["M4_COMPLETE"] = True
        self.assertIn("NON_PASS_WITH_M4_COMPLETE", validate_evidence(evidence))

    def test_prohibited_external_effect_always_fails(self) -> None:
        evidence = not_assessed_evidence()
        evidence["provider_effects"]["merge"] = True
        self.assertIn("REAL_OR_PROHIBITED_EXTERNAL_EFFECT_RETAINED", validate_evidence(evidence))


if __name__ == "__main__":
    unittest.main()

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from titmas_action_gate.errors import ContractValidationError
from titmas_action_gate.policy import PolicyEngine, default_policy_path


class TestPolicy(unittest.TestCase):
    def test_default_policy_path_from_env(self) -> None:
        with patch.dict(os.environ, {"TITMAS_ACTION_GATE_POLICY_PATH": "/tmp/test-policy.json"}):
            with patch("pathlib.Path.is_file", return_value=True):
                self.assertEqual(default_policy_path(), Path("/tmp/test-policy.json"))

    def test_default_policy_path_not_found(self) -> None:
        with patch.dict(os.environ, {"TITMAS_ACTION_GATE_POLICY_PATH": "/tmp/missing-policy.json"}, clear=True):
            with patch("pathlib.Path.is_file", return_value=False):
                with self.assertRaisesRegex(ContractValidationError, "Pinned GitHub policy file was not found."):
                    default_policy_path()

    def test_policy_engine_initialization_with_ambiguous_source(self) -> None:
        with self.assertRaisesRegex(ValueError, "POLICY_SOURCE_AMBIGUOUS"):
            PolicyEngine(policy_path="a", policy={"a": 1})

    def test_policy_engine_initialization_invalid_policy_type(self) -> None:
        with self.assertRaisesRegex(ValueError, "POLICY_ROOT_NOT_OBJECT"):
            PolicyEngine(policy="not a dict") # type: ignore

    def test_policy_engine_evaluate_valid_request(self) -> None:
        policy = {
            "policy_id": "test-policy",
            "version": "1.0.0",
            "supersedes": "none",
            "default": {
                "effect": "DENY",
                "risk_class": "CRITICAL",
                "required_evidence_types": ["SOURCE_PIN", "REQUEST_AUTHORIZATION"]
            },
            "rules": [
                {
                    "action": "github.branch.push",
                    "effect": "ALLOW_WITHOUT_APPROVAL",
                    "risk_class": "MEDIUM",
                    "required_evidence_types": ["SOURCE_PIN", "DIFF", "TEST_RESULT"]
                }
            ],
            "invariants": ["UNKNOWN_ACTION_DENIED"]
        }
        engine = PolicyEngine(policy=policy)
        request = {
            "schema_version": "0.1.0",
            "request_id": "aar-test-req-1",
            "created_at": "2023-10-01T12:00:00Z",
            "requested_by": {"agent_id": "agent-1", "team_id": "team-1"},
            "action": "github.branch.push",
            "target": {
                "provider": "github",
                "repository": "org/repo",
                "resource_ref": "main"
            },
            "parameters": {"branch": "main"},
            "parameters_sha256": "6461b20cebcb7034bd8b13089d21a90cf5ce300bd7d74eb625c7a342cf6ccdac",
            "evidence_requirements": ["SOURCE_PIN"],
            "uncertainty": [],
            "idempotency_key": "idempotent-12345678"
        }
        result = engine.evaluate(request)
        self.assertEqual(result["effect"], "ALLOW_WITHOUT_APPROVAL")
        self.assertEqual(result["schema_version"], "0.1.0")
        self.assertEqual(result["policy_id"], "test-policy")
        self.assertEqual(result["policy_version"], "1.0.0")
        self.assertEqual(result["risk_class"], "MEDIUM")
        self.assertEqual(result["request_id"], "aar-test-req-1")


if __name__ == "__main__":
    unittest.main()

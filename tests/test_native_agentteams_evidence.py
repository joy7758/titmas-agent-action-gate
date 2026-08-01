from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from scripts.validate_milestone import EXPECTED_AGENT_IDS, ROOT


class NativeAgentTeamsEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads((ROOT / "agents/registry.json").read_text(encoding="utf-8"))
        cls.evidence = json.loads((ROOT / "demo/evidence/agentteams-native-20260802.json").read_text(encoding="utf-8"))
        cls.manifest_text = (ROOT / "deploy/agentteams/team.native-smoke.v1.2.0.yaml").read_text(encoding="utf-8")
        cls.resources = list(yaml.safe_load_all(cls.manifest_text))

    def test_native_evidence_schema(self) -> None:
        schema = json.loads((ROOT / "schemas/native-agentteams-run-evidence.v0.1.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        errors = sorted(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(self.evidence), key=str)
        self.assertEqual(errors, [])

    def test_native_manifest_matches_registry_and_is_smoke_only(self) -> None:
        workers = [resource for resource in self.resources if resource["kind"] == "Worker"]
        teams = [resource for resource in self.resources if resource["kind"] == "Team"]
        humans = [resource for resource in self.resources if resource["kind"] == "Human"]
        self.assertEqual(len(workers), 5)
        self.assertEqual(len(teams), 1)
        self.assertEqual(len(humans), 1)
        self.assertEqual({worker["metadata"]["name"] for worker in workers}, EXPECTED_AGENT_IDS)
        self.assertEqual({agent["id"] for agent in self.registry["agents"]}, EXPECTED_AGENT_IDS)
        self.assertEqual(sum(member["role"] == "team_leader" for member in teams[0]["spec"]["workerMembers"]), 1)
        for worker in workers:
            annotations = worker["metadata"]["annotations"]
            self.assertEqual(annotations["titmas.dev/profile"], "native-smoke-only")
            self.assertEqual(annotations["titmas.dev/model-risk"], "preview-model-not-a-stable-runtime-contract")
            self.assertEqual(annotations["titmas.dev/skills-materialized"], "false")
            self.assertEqual(worker["spec"]["model"], "qwen3.8-max-preview")
            self.assertEqual(
                worker["spec"]["mcpServers"],
                [{"name": "titmas-action-gate", "url": "http://host.docker.internal:8766/mcp", "transport": "http"}],
            )

    def test_native_manifest_contains_no_credential_material(self) -> None:
        lowered = self.manifest_text.lower()
        for forbidden in ("authorization: bearer", "x-api-key:", "password:", "cookie:"):
            self.assertNotIn(forbidden, lowered)

    def test_native_truth_boundaries_and_semantic_contamination(self) -> None:
        autonomy = self.evidence["autonomy_result"]
        chain = self.evidence["operator_supervised_chain"]
        self.assertFalse(autonomy["leader_end_to_end_completed"])
        self.assertEqual(chain["classification"], "OPERATOR_SUPERVISED_AGENT_EXECUTED")
        self.assertEqual(chain["chain_issues"], [])
        self.assertEqual([record["sequence"] for record in chain["records"]], [1, 3, 4, 5, 6])
        contamination = next(item for item in self.evidence["retained_findings"] if item["id"] == "CONCURRENT_REQUEST_CONTAMINATION")
        self.assertEqual(contamination["record_sequence"], 2)
        self.assertTrue(all(value is False for value in self.evidence["provider_external_effects"].values()))
        self.assertTrue(chain["decision"]["expired_at_publication"])
        self.assertFalse(chain["decision"]["external_action_executed"])
        disposition = self.evidence["runtime_disposition"]
        disposition_flags = {key: value for key, value in disposition.items() if key not in {"disposed_at", "user_provider_key_copied_into_repository"}}
        self.assertTrue(all(value is True for value in disposition_flags.values()))
        self.assertFalse(disposition["user_provider_key_copied_into_repository"])

    def test_product_use_remains_not_recommended(self) -> None:
        gate = json.loads((ROOT / "governance/agent-recommendation-gate.json").read_text(encoding="utf-8"))
        self.assertEqual(gate["recommendation"]["current_product_use"], "NOT_RECOMMENDED")


class McpHostConfigurationTests(unittest.TestCase):
    @staticmethod
    def _probe(value: str | None) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        if value is None:
            env.pop("TITMAS_ACTION_GATE_MCP_HOST", None)
        else:
            env["TITMAS_ACTION_GATE_MCP_HOST"] = value
        return subprocess.run(
            [sys.executable, "-c", "from titmas_action_gate.mcp_server import configured_mcp_host; print(configured_mcp_host())"],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_mcp_host_defaults_to_loopback(self) -> None:
        result = self._probe(None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "127.0.0.1")

    def test_mcp_host_allows_explicit_disposable_container_bind(self) -> None:
        result = self._probe("0.0.0.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "0.0.0.0")

    def test_mcp_host_rejects_empty_or_arbitrary_values(self) -> None:
        for value in ("", "example.invalid", "  "):
            with self.subTest(value=value):
                result = self._probe(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("TITMAS_ACTION_GATE_MCP_HOST must be one of", result.stderr)


if __name__ == "__main__":
    unittest.main()

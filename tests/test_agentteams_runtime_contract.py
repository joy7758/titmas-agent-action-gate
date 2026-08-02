from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class AgentTeamsRuntimeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.path = ROOT / "deploy/agentteams/team.native-autonomous.v1.2.0.yaml"
        self.text = self.path.read_text(encoding="utf-8")
        self.resources = list(yaml.safe_load_all(self.text))

    def test_resources_are_ordered_workers_team_human(self) -> None:
        self.assertEqual([item["kind"] for item in self.resources], ["Worker"] * 6 + ["Team", "Human"])
        workers = self.resources[:6]
        registry = json.loads((ROOT / "agents/registry.json").read_text(encoding="utf-8"))
        self.assertEqual({item["metadata"]["name"] for item in workers}, {item["id"] for item in registry["agents"]})

    def test_leader_uses_copaw_contract_and_all_models_are_stable(self) -> None:
        workers = {item["metadata"]["name"]: item for item in self.resources if item["kind"] == "Worker"}
        self.assertEqual(workers["workflow-lead"]["spec"]["runtime"], "copaw")
        self.assertEqual(workers["workflow-lead"]["metadata"]["annotations"]["titmas.dev/leader-contract"], "copaw-projectflow-taskflow")
        for worker in workers.values():
            self.assertEqual(worker["spec"]["model"], "qwen3.7-max")
            self.assertNotIn("preview", worker["spec"]["model"].lower())
            self.assertNotIn("skills", worker["spec"])
            self.assertTrue(worker["spec"]["package"].startswith("CONFIGURE_PACKAGE_URI_"))
            self.assertEqual(
                worker["spec"]["mcpServers"],
                [
                    {
                        "name": "titmas-action-gate-native-runtime",
                        "url": "http://host.docker.internal:8767/mcp",
                        "transport": "http",
                    }
                ],
            )
        cloud = workers["cloud-context-inspector"]
        self.assertEqual(cloud["metadata"]["annotations"]["titmas.dev/provider-mode"], "typed-read-only-resource-search-only")
        self.assertIn("server-side", cloud["metadata"]["annotations"]["titmas.dev/credential-boundary"])

    def test_runtime_contract_source_hashes_are_pinned(self) -> None:
        sources = json.loads((ROOT / "governance/upstream-sources.json").read_text(encoding="utf-8"))
        agentteams = next(item for item in sources["sources"] if item["id"] == "agentteams")
        self.assertEqual(agentteams["release_commit"], "793db242257a569d911b1aa59c1cd554af78511f")
        self.assertEqual(
            {item["path"] for item in agentteams["runtime_contract_files"]},
            {
                "manager/agent/team-leader-agent/AGENTS.md",
                "copaw/src/copaw_worker/hooks/tools/projectflow.py",
                "copaw/src/copaw_worker/hooks/tools/taskflow.py",
            },
        )
        self.assertTrue(all(len(item["sha256"]) == 64 for item in agentteams["runtime_contract_files"]))

    def test_manifest_contains_no_credential_or_real_provider_material(self) -> None:
        lowered = self.text.lower()
        for forbidden in ("authorization: bearer", "x-api-key:", "password:", "gh_cli_external_write"):
            self.assertNotIn(forbidden, lowered)


if __name__ == "__main__":
    unittest.main()

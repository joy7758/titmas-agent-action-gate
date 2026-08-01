from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class BoundaryTests(unittest.TestCase):
    def test_no_agent_has_milestone_one_authority(self) -> None:
        registry = json.loads((ROOT / "agents/registry.json").read_text(encoding="utf-8"))
        for agent in registry["agents"]:
            self.assertFalse(any(agent["authority"].values()), agent["id"])

    def test_action_gate_mcp_has_no_provider_mutation(self) -> None:
        manifest = json.loads((ROOT / "mcp/server-manifest.v0.1.json").read_text(encoding="utf-8"))
        self.assertFalse(manifest["holds_provider_credentials"])
        self.assertTrue(all(not tool["mutates_external_provider"] for tool in manifest["tools"]))

    def test_core_protocol_change_is_not_claimed(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("TITMAS_CORE_PROTOCOLS_CHANGED=false", readme)

    def test_current_product_remains_not_recommended(self) -> None:
        gate = json.loads((ROOT / "governance/agent-recommendation-gate.json").read_text(encoding="utf-8"))
        self.assertEqual(gate["recommendation"]["current_product_use"], "NOT_RECOMMENDED")


if __name__ == "__main__":
    unittest.main()

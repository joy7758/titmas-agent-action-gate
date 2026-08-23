import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from titmas_action_gate.runtime import (
    HUMAN_PRINCIPAL_ID,
    RuntimePrincipal,
    RuntimePrincipalRegistry,
    agent_registry_path,
)

class RuntimeTests(unittest.TestCase):
    def test_agent_registry_path_configured(self) -> None:
        with tempfile.NamedTemporaryFile() as tmp:
            path = agent_registry_path(tmp.name)
            self.assertEqual(path, Path(tmp.name))

    def test_agent_registry_path_default(self) -> None:
        path = agent_registry_path()
        self.assertEqual(path.name, "registry.json")
        self.assertTrue(path.is_file())

    def test_agent_registry_path_not_found(self) -> None:
        with patch("pathlib.Path.is_file", return_value=False):
            with self.assertRaisesRegex(ValueError, "agents/registry.json is required for native runtime admission"):
                agent_registry_path()

    def test_runtime_principal(self) -> None:
        principal = RuntimePrincipal(
            principal_id="test-worker",
            credential_ref="sha256:abcdef",
            allowed_tools=frozenset({"test_tool"}),
            principal_type="worker",
        )
        self.assertEqual(principal.principal_id, "test-worker")
        self.assertEqual(principal.credential_ref, "sha256:abcdef")
        self.assertEqual(principal.allowed_tools, frozenset({"test_tool"}))
        self.assertEqual(principal.principal_type, "worker")

    def test_runtime_principal_registry_from_file(self) -> None:
        agents = json.loads(agent_registry_path().read_text(encoding="utf-8"))["agents"]
        credentials = {}
        for index, agent in enumerate(agents):
            credentials[agent["id"]] = f"a-{index:02d}" + "a" * 24
        credentials[HUMAN_PRINCIPAL_ID] = "h" * 32

        payload = {"credentials": credentials}

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            json.dump(payload, tmp)
            tmp_name = tmp.name

        try:
            os.chmod(tmp_name, 0o600)
            registry = RuntimePrincipalRegistry.from_file(tmp_name)
            self.assertIsNotNone(registry)
            self.assertEqual(registry.principal(HUMAN_PRINCIPAL_ID).principal_type, "human")

            os.chmod(tmp_name, 0o644)
            with self.assertRaisesRegex(ValueError, "runtime credential file permissions must not grant group or other access"):
                RuntimePrincipalRegistry.from_file(tmp_name)
        finally:
            os.unlink(tmp_name)

    def test_runtime_principal_registry_invalid_credentials(self) -> None:
        agents = json.loads(agent_registry_path().read_text(encoding="utf-8"))["agents"]
        credentials = {agent["id"]: "short" for agent in agents}
        credentials[HUMAN_PRINCIPAL_ID] = "short"

        with self.assertRaisesRegex(ValueError, "must be at least 24 characters"):
            RuntimePrincipalRegistry(credentials)

if __name__ == "__main__":
    unittest.main()

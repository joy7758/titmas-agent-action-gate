from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock, patch

from titmas_action_gate.runtime_mcp_server import build_from_environment, configured_runtime_host


class RuntimeMcpServerConfigurationTests(unittest.TestCase):
    @patch.dict(os.environ, {"TITMAS_ACTION_GATE_RUNTIME_MCP_HOST": "127.0.0.1"})
    def test_configured_runtime_host_valid(self) -> None:
        self.assertEqual(configured_runtime_host(), "127.0.0.1")

    @patch.dict(os.environ, {"TITMAS_ACTION_GATE_RUNTIME_MCP_HOST": "invalid_host"})
    def test_configured_runtime_host_invalid(self) -> None:
        with self.assertRaises(ValueError) as context:
            configured_runtime_host()
        self.assertIn("must be loopback or 0.0.0.0 for a disposable run", str(context.exception))

    @patch.dict(os.environ, {}, clear=True)
    def test_build_from_environment_missing_vars(self) -> None:
        with self.assertRaises(RuntimeError) as context:
            build_from_environment()
        self.assertIn("runtime MCP requires state dir, 0600 credentials file, caller token, and approver token", str(context.exception))

    @patch.dict(
        os.environ,
        {
            "TITMAS_ACTION_GATE_STATE_DIR": "/tmp",
            "TITMAS_ACTION_GATE_RUNTIME_CREDENTIALS_FILE": "/tmp/creds",
            "TITMAS_ACTION_GATE_CALLER_TOKEN": "caller",
            "TITMAS_ACTION_GATE_APPROVER_TOKEN": "approver",
        },
        clear=True,
    )
    @patch("titmas_action_gate.runtime_mcp_server.RuntimePrincipalRegistry")
    def test_build_from_environment_missing_demo_mode(self, mock_registry: MagicMock) -> None:
        mock_registry.from_file.return_value = MagicMock()
        with self.assertRaises(RuntimeError) as context:
            build_from_environment()
        self.assertIn("native M4 runtime server currently permits only explicit disposable demo mode", str(context.exception))

    @patch.dict(
        os.environ,
        {
            "TITMAS_ACTION_GATE_STATE_DIR": "/tmp",
            "TITMAS_ACTION_GATE_RUNTIME_CREDENTIALS_FILE": "/tmp/creds",
            "TITMAS_ACTION_GATE_CALLER_TOKEN": "caller",
            "TITMAS_ACTION_GATE_APPROVER_TOKEN": "approver",
            "TITMAS_ACTION_GATE_DEMO_MODE": "true",
            "TITMAS_ALIBABA_CLOUD_PROFILE": "profile",
            "TITMAS_ALIBABA_RAM_POLICY_OBSERVATION": "observation",
        },
        clear=True,
    )
    @patch("titmas_action_gate.runtime_mcp_server.RuntimePrincipalRegistry")
    @patch("titmas_action_gate.runtime_mcp_server.ActionGateService")
    def test_build_from_environment_partial_cloud_config(self, mock_service: MagicMock, mock_registry: MagicMock) -> None:
        mock_registry.from_file.return_value = MagicMock()
        with self.assertRaises(RuntimeError) as context:
            build_from_environment()
        self.assertIn("Alibaba Cloud runtime references must be configured as a complete set", str(context.exception))


if __name__ == "__main__":
    unittest.main()

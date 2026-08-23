import os
import unittest
from unittest.mock import patch

from titmas_action_gate.errors import ActionGateError
from titmas_action_gate.mcp_server import _call, configure_service, configured_mcp_host, get_service, main
from titmas_action_gate.service import ActionGateService


class McpServerTests(unittest.TestCase):
    def test_configured_mcp_host_default(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(configured_mcp_host(), "127.0.0.1")

    def test_configured_mcp_host_custom_allowed(self):
        with patch.dict(os.environ, {"TITMAS_ACTION_GATE_MCP_HOST": "0.0.0.0"}, clear=True):
            self.assertEqual(configured_mcp_host(), "0.0.0.0")

    def test_configured_mcp_host_custom_invalid(self):
        with (
            patch.dict(os.environ, {"TITMAS_ACTION_GATE_MCP_HOST": "8.8.8.8"}, clear=True),
            self.assertRaisesRegex(ValueError, "TITMAS_ACTION_GATE_MCP_HOST must be one of:"),
        ):
            configured_mcp_host()

    def test_get_service_demo_mode(self):
        with (
            patch.dict(
                os.environ,
                {
                    "TITMAS_ACTION_GATE_STATE_DIR": "/tmp",
                    "TITMAS_ACTION_GATE_CALLER_TOKEN": "caller" * 4,
                    "TITMAS_ACTION_GATE_APPROVER_TOKEN": "approver" * 4,
                    "TITMAS_ACTION_GATE_DEMO_MODE": "true",
                },
                clear=True,
            ),
            patch("titmas_action_gate.service.ActionGateService.demo") as mock_demo,
        ):
            mock_demo.return_value = "mock_demo_service"
            configure_service(None)  # reset global state
            service = get_service()
            self.assertEqual(service, "mock_demo_service")
            mock_demo.assert_called_once_with("/tmp", caller_token="caller" * 4, approver_token="approver" * 4)

    def test_get_service_missing_env(self):
        with patch.dict(os.environ, {}, clear=True):
            configure_service(None)  # reset global state
            with self.assertRaisesRegex(
                RuntimeError, "TITMAS_ACTION_GATE_STATE_DIR, TITMAS_ACTION_GATE_CALLER_TOKEN, and TITMAS_ACTION_GATE_APPROVER_TOKEN are required"
            ):
                get_service()

    def test_get_service_prod_mode(self):
        with patch.dict(
            os.environ,
            {
                "TITMAS_ACTION_GATE_STATE_DIR": "/tmp",
                "TITMAS_ACTION_GATE_CALLER_TOKEN": "caller" * 4,
                "TITMAS_ACTION_GATE_APPROVER_TOKEN": "approver" * 4,
                "TITMAS_ACTION_GATE_APPROVAL_KEY": "00" * 32,
                "TITMAS_ACTION_GATE_RECORD_KEY": "11" * 32,
            },
            clear=True,
        ):
            configure_service(None)  # reset global state
            service = get_service()
            self.assertIsInstance(service, ActionGateService)
            # Make sure it returns the same instance on second call
            self.assertIs(get_service(), service)

            # Reset after test
            configure_service(None)

    def test_get_service_prod_mode_missing_keys(self):
        with patch.dict(
            os.environ,
            {
                "TITMAS_ACTION_GATE_STATE_DIR": "/tmp",
                "TITMAS_ACTION_GATE_CALLER_TOKEN": "caller" * 4,
                "TITMAS_ACTION_GATE_APPROVER_TOKEN": "approver" * 4,
            },
            clear=True,
        ):
            configure_service(None)  # reset global state
            with self.assertRaisesRegex(RuntimeError, "non-demo MCP mode requires approval and record signing keys"):
                get_service()

    def test_main_valid_transport(self):
        with patch.dict(os.environ, {"TITMAS_ACTION_GATE_MCP_TRANSPORT": "stdio"}, clear=True), patch("titmas_action_gate.mcp_server.mcp.run") as mock_run:
            main()
            mock_run.assert_called_once_with(transport="stdio")

    def test_main_invalid_transport(self):
        with (
            patch.dict(os.environ, {"TITMAS_ACTION_GATE_MCP_TRANSPORT": "invalid"}, clear=True),
            self.assertRaisesRegex(SystemExit, "TITMAS_ACTION_GATE_MCP_TRANSPORT must be stdio, sse, or streamable-http"),
        ):
            main()

    def test_call_wrapper_success(self):
        def operation():
            return "success"

        result = _call(operation)
        self.assertEqual(result, {"ok": True, "result": "success"})

    def test_call_wrapper_action_gate_error(self):
        def operation():
            raise ActionGateError("AUTH_ERROR", "Auth failed")

        result = _call(operation)
        self.assertEqual(result, {"ok": False, "error": {"code": "AUTH_ERROR", "message": "Auth failed", "details": {}}})

    def test_call_wrapper_internal_fail_closed(self):
        def operation():
            raise ValueError("Something went wrong")

        result = _call(operation)
        self.assertEqual(
            result,
            {
                "ok": False,
                "error": {
                    "code": "INTERNAL_FAIL_CLOSED",
                    "message": "The Action Gate operation failed closed.",
                    "details": {"error_type": "ValueError"},
                },
            },
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from mcp.client.stdio import stdio_client

from mcp import ClientSession, StdioServerParameters

ROOT = Path(__file__).resolve().parents[1]


class McpStdioIntegrationTests(unittest.TestCase):
    def test_stdio_initialize_list_and_call(self) -> None:
        request = json.loads((ROOT / "evaluations/cases/valid-execution/case.json").read_text(encoding="utf-8"))["action_request"]

        async def exercise(state_dir: str) -> None:
            environment = os.environ.copy()
            environment.update(
                {
                    "TITMAS_ACTION_GATE_STATE_DIR": state_dir,
                    "TITMAS_ACTION_GATE_CALLER_TOKEN": "titmas-demo-caller-token",
                    "TITMAS_ACTION_GATE_APPROVER_TOKEN": "titmas-demo-approver-token",
                    "TITMAS_ACTION_GATE_DEMO_MODE": "true",
                }
            )
            parameters = StdioServerParameters(
                command=sys.executable,
                args=["-m", "titmas_action_gate.mcp_server"],
                env=environment,
                cwd=str(ROOT),
            )
            async with stdio_client(parameters) as (read_stream, write_stream), ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                self.assertEqual(
                    {tool.name for tool in tools.tools},
                    {
                        "submit_action_request",
                        "attach_evidence",
                        "verify_evidence",
                        "evaluate_action_gate",
                        "record_human_approval",
                        "get_action_state",
                    },
                )
                submitted = await session.call_tool(
                    "submit_action_request",
                    {"action_request": request, "caller_token": "titmas-demo-caller-token"},
                )
                self.assertFalse(submitted.isError)
                self.assertTrue(submitted.structuredContent["ok"])

        with tempfile.TemporaryDirectory(prefix="titmas-aag-mcp-stdio-") as state_dir:
            asyncio.run(exercise(state_dir))


if __name__ == "__main__":
    unittest.main()

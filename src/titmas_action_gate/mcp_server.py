"""MCP server exposing the six versioned Action Gate tools."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP

from .errors import ActionGateError
from .service import ActionGateService

_ALLOWED_MCP_BIND_HOSTS = {"127.0.0.1", "0.0.0.0", "::1"}


def configured_mcp_host() -> str:
    """Return a narrow bind address or fail closed during startup.

    The default remains loopback. ``0.0.0.0`` exists only for reviewed,
    disposable container-to-host smoke runs; it does not add authentication or
    authorize a network deployment.
    """

    value = os.environ.get("TITMAS_ACTION_GATE_MCP_HOST", "127.0.0.1").strip()
    if value not in _ALLOWED_MCP_BIND_HOSTS:
        allowed = ", ".join(sorted(_ALLOWED_MCP_BIND_HOSTS))
        raise ValueError(f"TITMAS_ACTION_GATE_MCP_HOST must be one of: {allowed}")
    return value


mcp = FastMCP(
    "titmas-action-gate",
    instructions=("Deterministic evidence and authorization boundary. Tool discovery is not permission. No tool in this server mutates an external provider."),
    host=configured_mcp_host(),
    port=8766,
)
_service: ActionGateService | None = None


def configure_service(service: ActionGateService) -> None:
    global _service
    _service = service


def get_service() -> ActionGateService:
    global _service
    if _service is not None:
        return _service
    state_dir = os.environ.get("TITMAS_ACTION_GATE_STATE_DIR")
    caller_token = os.environ.get("TITMAS_ACTION_GATE_CALLER_TOKEN")
    approver_token = os.environ.get("TITMAS_ACTION_GATE_APPROVER_TOKEN")
    if not state_dir or not caller_token or not approver_token:
        raise RuntimeError("TITMAS_ACTION_GATE_STATE_DIR, TITMAS_ACTION_GATE_CALLER_TOKEN, and TITMAS_ACTION_GATE_APPROVER_TOKEN are required")
    if os.environ.get("TITMAS_ACTION_GATE_DEMO_MODE") == "true":
        _service = ActionGateService.demo(state_dir, caller_token=caller_token, approver_token=approver_token)
        return _service
    approval_key = os.environ.get("TITMAS_ACTION_GATE_APPROVAL_KEY")
    record_key = os.environ.get("TITMAS_ACTION_GATE_RECORD_KEY")
    if not approval_key or not record_key:
        raise RuntimeError("non-demo MCP mode requires approval and record signing keys")
    _service = ActionGateService(
        state_dir,
        caller_token=caller_token,
        approver_token=approver_token,
        approval_key=bytes.fromhex(approval_key),
        record_signing_key=bytes.fromhex(record_key),
    )
    return _service


def _call(operation: Callable[[], Any]) -> dict[str, Any]:
    try:
        return {"ok": True, "result": operation()}
    except ActionGateError as exc:
        return exc.to_dict()
    except Exception as exc:
        return {
            "ok": False,
            "error": {
                "code": "INTERNAL_FAIL_CLOSED",
                "message": "The Action Gate operation failed closed.",
                "details": {"error_type": type(exc).__name__},
            },
        }


@mcp.tool(description="Validate and append one normalized action request; grants no authority.")
def submit_action_request(action_request: dict[str, Any], caller_token: str) -> dict[str, Any]:
    return _call(lambda: get_service().submit_action_request(action_request, caller_token=caller_token))


@mcp.tool(description="Attach an immutable in-scope evidence profile reference; does not verify or authorize it.")
def attach_evidence(
    request_id: str,
    profile_path: str,
    evidence_types: list[str],
    caller_token: str,
) -> dict[str, Any]:
    return _call(
        lambda: get_service().attach_evidence(
            request_id,
            profile_path,
            evidence_types,
            caller_token=caller_token,
        )
    )


@mcp.tool(description="Invoke pinned agent-evidence 0.6.0 and retain its structured receipt.")
def verify_evidence(request_id: str, caller_token: str) -> dict[str, Any]:
    return _call(lambda: get_service().verify_evidence(request_id, caller_token=caller_token))


@mcp.tool(description="Compute deterministic ALLOW, BLOCK, or REQUIRE_APPROVAL from retained versioned inputs.")
def evaluate_action_gate(request_id: str, caller_token: str) -> dict[str, Any]:
    return _call(lambda: get_service().evaluate_action_gate(request_id, caller_token=caller_token))


@mcp.tool(description="Create and append a scoped signed human approval, denial, or revocation input.")
def record_human_approval(
    request_id: str,
    subject: str,
    identity_provider: str,
    status: str,
    approver_token: str,
) -> dict[str, Any]:
    return _call(
        lambda: get_service().record_human_approval(
            request_id,
            subject=subject,
            identity_provider=identity_provider,
            status=status,
            approver_token=approver_token,
        )
    )


@mcp.tool(description="Read append-only action state and integrity results; performs no mutation.")
def get_action_state(request_id: str, caller_token: str) -> dict[str, Any]:
    return _call(lambda: get_service().get_action_state(request_id, caller_token=caller_token))


def main() -> None:
    transport = os.environ.get("TITMAS_ACTION_GATE_MCP_TRANSPORT", "stdio")
    if transport not in {"stdio", "sse", "streamable-http"}:
        raise SystemExit("TITMAS_ACTION_GATE_MCP_TRANSPORT must be stdio, sse, or streamable-http")
    mcp.run(transport=transport)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()

"""Credential-derived Worker identity, tool ACL, and native run admission."""

from __future__ import annotations

import hashlib
import hmac
import json
import sysconfig
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contracts import validate_runtime_scope
from .errors import AuthenticationError, AuthorizationError, ConflictError, NotFoundError
from .store import AppendOnlyStore

HUMAN_PRINCIPAL_ID = "titmas-action-gate-reviewer"
EXECUTE_IN_MEMORY_TOOL = "execute_in_memory_github_action"


def agent_registry_path(configured: str | Path | None = None) -> Path:
    candidates = [
        Path(configured).expanduser() if configured else None,
        Path(__file__).resolve().parents[2] / "agents/registry.json",
        Path(sysconfig.get_path("data")) / "share/titmas-action-gate/agents/registry.json",
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate
    raise ValueError("agents/registry.json is required for native runtime admission")


@dataclass(frozen=True)
class RuntimePrincipal:
    principal_id: str
    credential_ref: str
    allowed_tools: frozenset[str]
    principal_type: str


class RuntimePrincipalRegistry:
    """Map opaque credentials to exact registry identities without retaining bytes."""

    def __init__(
        self,
        credentials: dict[str, str],
        *,
        registry_path: str | Path | None = None,
        require_human: bool = True,
    ):
        registry = json.loads(agent_registry_path(registry_path).read_text(encoding="utf-8"))
        worker_tools = {item["id"]: frozenset(item["mcp_tools"]) for item in registry["agents"]}
        expected = set(worker_tools)
        if require_human:
            expected.add(HUMAN_PRINCIPAL_ID)
        if set(credentials) != expected:
            missing = sorted(expected - set(credentials))
            extra = sorted(set(credentials) - expected)
            raise ValueError(f"runtime credentials must match principals exactly; missing={missing}, extra={extra}")

        digests: dict[bytes, RuntimePrincipal] = {}
        principals: dict[str, RuntimePrincipal] = {}
        for principal_id, credential in credentials.items():
            if not isinstance(credential, str) or len(credential) < 24:
                raise ValueError(f"runtime credential for {principal_id} must be at least 24 characters")
            digest = hashlib.sha256(credential.encode("utf-8")).digest()
            if digest in digests:
                raise ValueError("runtime credentials must be distinct")
            if principal_id == HUMAN_PRINCIPAL_ID:
                allowed_tools = frozenset({"record_human_approval"})
                principal_type = "human"
            else:
                allowed_tools = worker_tools[principal_id]
                principal_type = "worker"
            principal = RuntimePrincipal(
                principal_id=principal_id,
                credential_ref=f"sha256:{digest.hex()}",
                allowed_tools=allowed_tools,
                principal_type=principal_type,
            )
            digests[digest] = principal
            principals[principal_id] = principal
        self._digests = digests
        self._principals = principals

    @classmethod
    def from_file(
        cls,
        credentials_path: str | Path,
        *,
        registry_path: str | Path | None = None,
    ) -> RuntimePrincipalRegistry:
        path = Path(credentials_path)
        if path.stat().st_mode & 0o077:
            raise ValueError("runtime credential file permissions must not grant group or other access")
        payload = json.loads(path.read_text(encoding="utf-8"))
        return cls(payload["credentials"], registry_path=registry_path)

    def authenticate(self, credential: str) -> RuntimePrincipal:
        supplied = hashlib.sha256(credential.encode("utf-8")).digest()
        for digest, principal in self._digests.items():
            if hmac.compare_digest(supplied, digest):
                return principal
        raise AuthenticationError("AUTHENTICATION_FAILED", "Runtime credential is invalid.")

    def principal(self, principal_id: str) -> RuntimePrincipal:
        try:
            return self._principals[principal_id]
        except KeyError as exc:
            raise AuthenticationError("AUTHENTICATION_FAILED", "Authenticated runtime principal is unknown.") from exc

    def public_inventory(self) -> list[dict[str, Any]]:
        return [
            {
                "principal_id": principal.principal_id,
                "credential_ref": principal.credential_ref,
                "principal_type": principal.principal_type,
                "allowed_tools": sorted(principal.allowed_tools),
            }
            for principal in sorted(self._principals.values(), key=lambda item: item.principal_id)
        ]


class RuntimeAdmission:
    def __init__(self, store: AppendOnlyStore, principals: RuntimePrincipalRegistry):
        self.store = store
        self.principals = principals

    @staticmethod
    def normalize_scope(scope: dict[str, Any]) -> dict[str, str]:
        validate_runtime_scope(scope)
        return {key: str(scope[key]) for key in ("run_id", "correlation_id", "task_id", "repository", "commit")}

    def _security_event(
        self,
        principal: RuntimePrincipal,
        tool_name: str,
        scope: dict[str, str],
        *,
        outcome: str,
        reason_code: str,
        business_state_delta: int,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return self.store.append_security_event(
            event_id=f"security-{uuid.uuid4().hex}",
            scope=scope,
            principal_id=principal.principal_id,
            tool_name=tool_name,
            outcome=outcome,
            reason_code=reason_code,
            business_state_delta=business_state_delta,
            details={"request_id": request_id} if request_id else {},
        )

    def authorize_tool(self, principal: RuntimePrincipal, tool_name: str, scope: dict[str, Any]) -> dict[str, str]:
        normalized = self.normalize_scope(scope)
        if tool_name not in principal.allowed_tools:
            self._security_event(
                principal,
                tool_name,
                normalized,
                outcome="DENY",
                reason_code="MCP_TOOL_NOT_ALLOWED",
                business_state_delta=0,
            )
            raise AuthorizationError(
                "MCP_TOOL_NOT_ALLOWED",
                "Authenticated principal is not allowed to call this MCP tool.",
                details={"principal_id": principal.principal_id, "tool_name": tool_name},
            )
        return normalized

    def bind_submission(
        self,
        principal: RuntimePrincipal,
        tool_name: str,
        scope: dict[str, Any],
        request: dict[str, Any],
    ) -> dict[str, str]:
        normalized = self.authorize_tool(principal, tool_name, scope)
        request_id = str(request.get("request_id", ""))
        claimed = request.get("requested_by", {}).get("agent_id")
        if claimed != principal.principal_id:
            self._security_event(
                principal,
                tool_name,
                normalized,
                outcome="DENY",
                reason_code="PRINCIPAL_MISMATCH",
                business_state_delta=0,
                request_id=request_id,
            )
            raise AuthorizationError("PRINCIPAL_MISMATCH", "requested_by.agent_id must equal the authenticated principal.")
        if request.get("target", {}).get("repository") != normalized["repository"]:
            self._security_event(
                principal,
                tool_name,
                normalized,
                outcome="DENY",
                reason_code="CORRELATION_MISMATCH",
                business_state_delta=0,
                request_id=request_id,
            )
            raise ConflictError("CORRELATION_MISMATCH", "request repository does not match runtime scope.")
        self.store.bind_request_scope(request_id, normalized, principal_id=principal.principal_id)
        return normalized

    def admit_request(
        self,
        principal: RuntimePrincipal,
        tool_name: str,
        scope: dict[str, Any],
        request_id: str,
    ) -> dict[str, str]:
        normalized = self.authorize_tool(principal, tool_name, scope)
        try:
            self.store.assert_request_scope(request_id, normalized)
        except (ConflictError, NotFoundError) as exc:
            reason_code = getattr(exc, "code", "RUNTIME_SCOPE_NOT_BOUND")
            self._security_event(
                principal,
                tool_name,
                normalized,
                outcome="DENY",
                reason_code=reason_code,
                business_state_delta=0,
                request_id=request_id,
            )
            raise
        return normalized

    def record_allowed(
        self,
        principal: RuntimePrincipal,
        tool_name: str,
        scope: dict[str, str],
        *,
        request_id: str,
        business_state_delta: int,
    ) -> dict[str, Any]:
        return self._security_event(
            principal,
            tool_name,
            scope,
            outcome="ALLOW_CALL",
            reason_code="MCP_TOOL_ALLOWED",
            business_state_delta=business_state_delta,
            request_id=request_id,
        )

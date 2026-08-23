"""Authenticated native AgentTeams MCP surface with exact Worker admission."""

from __future__ import annotations

import os
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

from .canonical import sha256_file
from .cli import data_root
from .cloud_context import CloudContextInspector, CloudCredentialContext, credential_from_policy_observation
from .contracts import validate_action_request
from .errors import ActionGateError, AuthenticationError
from .provider import InMemoryGitHubProvider
from .runtime import RuntimeAdmission, RuntimePrincipal, RuntimePrincipalRegistry
from .service import ActionGateService, ExecuteAllowedRequest

_ALLOWED_MCP_BIND_HOSTS = {"127.0.0.1", "0.0.0.0", "::1"}


class RuntimeTokenVerifier:
    """FastMCP bearer verifier returning a credential-derived Worker subject."""

    def __init__(self, principals: RuntimePrincipalRegistry):
        self.principals = principals

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            principal = self.principals.authenticate(token)
        except AuthenticationError:
            return None
        return AccessToken(
            token=token,
            client_id=principal.principal_id,
            subject=principal.principal_id,
            scopes=["titmas.runtime"],
            claims={"credential_ref": principal.credential_ref, "principal_type": principal.principal_type},
        )


class NativeRuntimeMcp:
    def __init__(
        self,
        service: ActionGateService,
        principals: RuntimePrincipalRegistry,
        *,
        caller_token: str,
        approver_token: str,
        host: str = "127.0.0.1",
        port: int = 8767,
        cloud_context_inspector: CloudContextInspector | None = None,
        cloud_credential: CloudCredentialContext | None = None,
        native_agentteams_runtime: bool = False,
    ):
        if host not in _ALLOWED_MCP_BIND_HOSTS:
            raise ValueError("native runtime MCP host must be loopback or an explicit disposable-container bind")
        self.service = service
        self.principals = principals
        self.admission = RuntimeAdmission(service.store, principals)
        self.caller_token = caller_token
        self.approver_token = approver_token
        self.providers: dict[str, InMemoryGitHubProvider] = {}
        self.cloud_context_inspector = cloud_context_inspector or CloudContextInspector(data_root())
        self.cloud_credential = cloud_credential
        self.native_agentteams_runtime = native_agentteams_runtime
        resource_host = "127.0.0.1" if host == "0.0.0.0" else host.strip("[]")
        self.mcp = FastMCP(
            "titmas-action-gate-native-runtime",
            instructions=(
                "Authenticated deterministic boundary for one disposable AgentTeams run. "
                "Tool discovery is not authorization; service code enforces the registry allowlist. "
                "The only execution adapter is in-memory and performs no external write."
            ),
            host=host,
            port=port,
            stateless_http=True,
            token_verifier=RuntimeTokenVerifier(principals),
            auth=AuthSettings(
                issuer_url="https://titmas.invalid/runtime-auth",
                resource_server_url=f"http://{resource_host}:{port}",
                required_scopes=["titmas.runtime"],
            ),
        )
        self._register_tools()

    def _principal(self) -> RuntimePrincipal:
        token = get_access_token()
        if token is None or token.subject is None:
            raise AuthenticationError("AUTHENTICATION_FAILED", "MCP transport did not supply an authenticated principal.")
        return self.principals.principal(token.subject)

    @staticmethod
    def _call(operation: Any) -> dict[str, Any]:
        try:
            return {"ok": True, "result": operation()}
        except ActionGateError as exc:
            return exc.to_dict()
        except Exception as exc:
            return {
                "ok": False,
                "error": {
                    "code": "INTERNAL_FAIL_CLOSED",
                    "message": "The native runtime MCP operation failed closed.",
                    "details": {"error_type": type(exc).__name__},
                },
            }

    def _register_core_tools(self) -> None:
        @self.mcp.tool(description="Submit one request bound to the authenticated Worker and exact native run scope.")
        def submit_action_request(action_request: dict[str, Any], runtime_scope: dict[str, Any]) -> dict[str, Any]:
            def operation() -> dict[str, Any]:
                principal = self._principal()
                validate_action_request(action_request)
                scope = self.admission.bind_submission(principal, "submit_action_request", runtime_scope, action_request)
                record = self.service.submit_action_request(
                    action_request,
                    caller_token=self.caller_token,
                    actor=principal.principal_id,
                )
                self.admission.record_allowed(
                    principal,
                    "submit_action_request",
                    scope,
                    request_id=action_request["request_id"],
                    business_state_delta=1,
                )
                return record

            return self._call(operation)

        @self.mcp.tool(description="Generate one request-bound evidence profile; grants no verification or authority.")
        def generate_evidence_profile(
            request_id: str,
            runtime_scope: dict[str, Any],
            phase: str,
            operation_status: str,
            output: dict[str, Any],
            evidence_types: list[str],
        ) -> dict[str, Any]:
            def operation() -> dict[str, Any]:
                principal = self._principal()
                scope = self.admission.admit_request(principal, "generate_evidence_profile", runtime_scope, request_id)
                profile = self.service.generate_evidence_profile(
                    request_id,
                    actor=principal.principal_id,
                    phase=phase,
                    operation_status=operation_status,
                    output=output,
                    evidence_types=evidence_types,
                )
                filename = f"{scope['run_id']}/{request_id}-{phase}.json"
                path = self.service.evidence.write_profile(profile, filename)
                result = {
                    "request_id": request_id,
                    "profile_path": str(path.relative_to(self.service.evidence.root)),
                    "profile_sha256": sha256_file(path),
                    "generated_by": principal.principal_id,
                }
                self.admission.record_allowed(
                    principal,
                    "generate_evidence_profile",
                    scope,
                    request_id=request_id,
                    business_state_delta=0,
                )
                return result

            return self._call(operation)

        @self.mcp.tool(description="Attach an immutable profile reference within the exact native request scope.")
        def attach_evidence(
            request_id: str,
            runtime_scope: dict[str, Any],
            profile_path: str,
            evidence_types: list[str],
        ) -> dict[str, Any]:
            def operation() -> dict[str, Any]:
                principal = self._principal()
                scope = self.admission.admit_request(principal, "attach_evidence", runtime_scope, request_id)
                record = self.service.attach_evidence(
                    request_id,
                    profile_path,
                    evidence_types,
                    caller_token=self.caller_token,
                    actor=principal.principal_id,
                )
                self.admission.record_allowed(principal, "attach_evidence", scope, request_id=request_id, business_state_delta=1)
                return record

            return self._call(operation)

        @self.mcp.tool(description="Invoke pinned agent-evidence after immutable attachment and subject binding checks.")
        def verify_evidence(request_id: str, runtime_scope: dict[str, Any]) -> dict[str, Any]:
            def operation() -> dict[str, Any]:
                principal = self._principal()
                scope = self.admission.admit_request(principal, "verify_evidence", runtime_scope, request_id)
                result = self.service.verify_evidence(
                    request_id,
                    caller_token=self.caller_token,
                    actor=principal.principal_id,
                )
                self.admission.record_allowed(principal, "verify_evidence", scope, request_id=request_id, business_state_delta=1)
                return result

            return self._call(operation)

    def _register_cloud_tools(self) -> None:
        @self.mcp.tool(
            description=(
                "Resolve and SHA-256 verify the source-locked external Alibaba Cloud Skill, then retain one minimal "
                "load event. This tool exposes no upstream bytes, credentials, shell, or decision authority."
            )
        )
        def load_external_alibabacloud_skill(
            request_id: str,
            runtime_scope: dict[str, Any],
        ) -> dict[str, Any]:
            def operation() -> dict[str, Any]:
                principal = self._principal()
                scope = self.admission.admit_request(
                    principal,
                    "load_external_alibabacloud_skill",
                    runtime_scope,
                    request_id,
                )
                load_receipt = self.cloud_context_inspector.load_external_skill(native_agentteams_runtime=self.native_agentteams_runtime)
                record = self.service.record_external_skill_load(
                    request_id,
                    load_receipt,
                    caller_token=self.caller_token,
                    actor=principal.principal_id,
                )
                self.admission.record_allowed(
                    principal,
                    "load_external_alibabacloud_skill",
                    scope,
                    request_id=request_id,
                    business_state_delta=1,
                )
                return {"load_receipt": load_receipt, "load_record": record}

            return self._call(operation)

        @self.mcp.tool(
            description=(
                "Invoke only the pinned Alibaba Cloud Resource Center search preflight through a typed read-only adapter. "
                "Credentials are server-side and no Action Gate decision is produced."
            )
        )
        def inspect_alibabacloud_resources(
            request_id: str,
            runtime_scope: dict[str, Any],
            query: dict[str, Any],
        ) -> dict[str, Any]:
            def operation() -> dict[str, Any]:
                principal = self._principal()
                scope = self.admission.admit_request(
                    principal,
                    "inspect_alibabacloud_resources",
                    runtime_scope,
                    request_id,
                )
                expected_load = self.cloud_context_inspector.load_external_skill(native_agentteams_runtime=self.native_agentteams_runtime)
                self.service.assert_external_skill_loaded(request_id, expected_load)
                result = self.cloud_context_inspector.inspect(
                    request_id,
                    query,
                    self.cloud_credential,
                    native_agentteams_loaded=self.native_agentteams_runtime,
                )
                retained = self.service.record_cloud_context_preflight(
                    request_id,
                    result,
                    caller_token=self.caller_token,
                    actor=principal.principal_id,
                )
                self.admission.record_allowed(
                    principal,
                    "inspect_alibabacloud_resources",
                    scope,
                    request_id=request_id,
                    business_state_delta=2,
                )
                decision_record_count = sum(record["record_type"] == "decision" for record in self.service.store.records_for_request(request_id))
                return {
                    "cloud_context": result,
                    **retained,
                    "bounded_summary": {
                        "invocation_result": result["invocation"]["result_class"],
                        "status": result["status"],
                        "cli_exit_status": result["invocation"]["exit_status"],
                        "resourcecenter_write_api_calls": result["resourcecenter_write_api_calls"],
                        "agent_evidence_status": retained["agent_evidence_receipt"]["status"],
                        "worker_decision_record_count": decision_record_count,
                    },
                }

            return self._call(operation)

    def _register_evaluation_tools(self) -> None:
        @self.mcp.tool(description="Compute the sole deterministic ALLOW, BLOCK, or REQUIRE_APPROVAL decision.")
        def evaluate_action_gate(request_id: str, runtime_scope: dict[str, Any]) -> dict[str, Any]:
            def operation() -> dict[str, Any]:
                principal = self._principal()
                scope = self.admission.admit_request(principal, "evaluate_action_gate", runtime_scope, request_id)
                result = self.service.evaluate_action_gate(
                    request_id,
                    caller_token=self.caller_token,
                    actor=principal.principal_id,
                )
                self.admission.record_allowed(principal, "evaluate_action_gate", scope, request_id=request_id, business_state_delta=2)
                return result

            return self._call(operation)

        @self.mcp.tool(description="Record an authenticated Human input; no Worker credential is eligible.")
        def record_human_approval(
            request_id: str,
            runtime_scope: dict[str, Any],
            status: str,
        ) -> dict[str, Any]:
            def operation() -> dict[str, Any]:
                principal = self._principal()
                scope = self.admission.admit_request(principal, "record_human_approval", runtime_scope, request_id)
                result = self.service.record_human_approval(
                    request_id,
                    subject=principal.principal_id,
                    identity_provider="agentteams-runtime-static-credential",
                    status=status,
                    approver_token=self.approver_token,
                )
                self.admission.record_allowed(principal, "record_human_approval", scope, request_id=request_id, business_state_delta=1)
                return result

            return self._call(operation)

        @self.mcp.tool(description="Consume one exact live ALLOW through the in-memory no-external-write GitHub provider.")
        def execute_in_memory_github_action(
            decision_id: str,
            request_id: str,
            runtime_scope: dict[str, Any],
        ) -> dict[str, Any]:
            def operation() -> dict[str, Any]:
                principal = self._principal()
                scope = self.admission.admit_request(principal, "execute_in_memory_github_action", runtime_scope, request_id)
                provider = self.providers.setdefault(scope["run_id"], InMemoryGitHubProvider())
                result = self.service.execute_allowed(
                    ExecuteAllowedRequest(
                        decision_id=decision_id,
                        request_id=request_id,
                        provider=provider,
                        actor=principal.principal_id,
                        caller_token=self.caller_token,
                    )
                )
                if result["provider_result"].get("provider_mode") != "IN_MEMORY_NO_EXTERNAL_WRITE":
                    raise RuntimeError("native runtime selected a non-disposable provider")
                self.admission.record_allowed(
                    principal,
                    "execute_in_memory_github_action",
                    scope,
                    request_id=request_id,
                    business_state_delta=2,
                )
                return result

            return self._call(operation)

        @self.mcp.tool(description="Read only the exact request scope plus its per-run security audit evidence.")
        def get_action_state(request_id: str, runtime_scope: dict[str, Any]) -> dict[str, Any]:
            def operation() -> dict[str, Any]:
                principal = self._principal()
                scope = self.admission.admit_request(principal, "get_action_state", runtime_scope, request_id)
                result = self.service.get_action_state(request_id, caller_token=self.caller_token)
                result["runtime_scope"] = scope
                result["runtime_security_events"] = self.service.store.security_events_for_run(scope["run_id"])
                result["runtime_security_chain_issues"] = self.service.store.verify_security_chain(scope["run_id"])
                self.admission.record_allowed(principal, "get_action_state", scope, request_id=request_id, business_state_delta=0)
                return result

            return self._call(operation)

    def _register_tools(self) -> None:
        self._register_core_tools()
        self._register_cloud_tools()
        self._register_evaluation_tools()


def configured_runtime_host() -> str:
    value = os.environ.get("TITMAS_ACTION_GATE_RUNTIME_MCP_HOST", "127.0.0.1").strip()
    if value not in _ALLOWED_MCP_BIND_HOSTS:
        raise ValueError("TITMAS_ACTION_GATE_RUNTIME_MCP_HOST must be loopback or 0.0.0.0 for a disposable run")
    return value


def build_from_environment() -> NativeRuntimeMcp:
    state_dir = os.environ.get("TITMAS_ACTION_GATE_STATE_DIR")
    credentials_file = os.environ.get("TITMAS_ACTION_GATE_RUNTIME_CREDENTIALS_FILE")
    caller_token = os.environ.get("TITMAS_ACTION_GATE_CALLER_TOKEN")
    approver_token = os.environ.get("TITMAS_ACTION_GATE_APPROVER_TOKEN")
    if not state_dir or not credentials_file or not caller_token or not approver_token:
        raise RuntimeError("runtime MCP requires state dir, 0600 credentials file, caller token, and approver token environment variables")
    principals = RuntimePrincipalRegistry.from_file(credentials_file)
    if os.environ.get("TITMAS_ACTION_GATE_DEMO_MODE") != "true":
        raise RuntimeError("native M4 runtime server currently permits only explicit disposable demo mode")
    service = ActionGateService.demo(state_dir, caller_token=caller_token, approver_token=approver_token)
    cloud_values = {
        "profile_name": os.environ.get("TITMAS_ALIBABA_CLOUD_PROFILE"),
        "policy_observation": os.environ.get("TITMAS_ALIBABA_RAM_POLICY_OBSERVATION"),
        "policy_observation_run_id": os.environ.get("TITMAS_ALIBABA_POLICY_OBSERVATION_RUN_ID"),
    }
    if any(value for value in cloud_values.values()) and not all(value for value in cloud_values.values()):
        raise RuntimeError("Alibaba Cloud runtime references must be configured as a complete set")
    cloud_credential = None
    if all(value for value in cloud_values.values()):
        cloud_credential, _ = credential_from_policy_observation(
            str(cloud_values["profile_name"]),
            str(cloud_values["policy_observation"]),
            expected_run_id=str(cloud_values["policy_observation_run_id"]),
        )
    return NativeRuntimeMcp(
        service,
        principals,
        caller_token=caller_token,
        approver_token=approver_token,
        host=configured_runtime_host(),
        port=int(os.environ.get("TITMAS_ACTION_GATE_RUNTIME_MCP_PORT", "8767")),
        cloud_credential=cloud_credential,
        native_agentteams_runtime=os.environ.get("TITMAS_AGENTTEAMS_NATIVE_WORKER") == "true",
    )


def main() -> None:
    runtime = build_from_environment()
    runtime.mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()

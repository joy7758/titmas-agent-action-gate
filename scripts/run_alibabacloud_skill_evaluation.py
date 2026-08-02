#!/usr/bin/env python3
"""Run and retain one authenticated, decision-free Alibaba Cloud Skill preflight.

Credential bytes remain in the Alibaba Cloud CLI configuration.  This runner
creates its own unpredictable run ID, performs the four bounded provider
readbacks inside that run, and emits aggregate-only public evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import tempfile
import warnings
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from starlette.testclient import TestClient

from titmas_action_gate.canonical import ExclusiveOutput, sha256_json
from titmas_action_gate.cloud_context import (
    OFFICIAL_ALIYUN_CLI_SHA256,
    OFFICIAL_RESOURCE_CENTER_PLUGIN_SHA256,
    OFFICIAL_RESOURCE_CENTER_PLUGIN_VERSION,
    CloudContextInspector,
    credential_from_policy_observation,
)
from titmas_action_gate.public_evidence import validate_public_evidence, workspace_provenance_v02
from titmas_action_gate.runtime import HUMAN_PRINCIPAL_ID, RuntimePrincipalRegistry
from titmas_action_gate.runtime_mcp_server import NativeRuntimeMcp
from titmas_action_gate.service import ActionGateService

try:
    from scripts.capture_alibabacloud_ram_policy_observation import capture as capture_ram_policy_observation
except ModuleNotFoundError:  # Direct script execution resolves sibling modules without the repository package prefix.
    from capture_alibabacloud_ram_policy_observation import capture as capture_ram_policy_observation

ROOT = Path(__file__).resolve().parents[1]
CALLER_TOKEN = "titmas-demo-caller-token"
APPROVER_TOKEN = "titmas-demo-approver-token"


def _contains_gate_outcome(value: Any) -> bool:
    if isinstance(value, dict):
        if "outcome" in value and value["outcome"] in {"ALLOW", "BLOCK", "REQUIRE_APPROVAL"}:
            return True
        return any(_contains_gate_outcome(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_gate_outcome(item) for item in value)
    return False


def _principal_credentials() -> dict[str, str]:
    registry = json.loads((ROOT / "agents/registry.json").read_text(encoding="utf-8"))
    principals = {item["id"] for item in registry["agents"]} | {HUMAN_PRINCIPAL_ID}
    return {principal: secrets.token_urlsafe(32) for principal in principals}


def _call(client: TestClient, token: str, sequence: int, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    response = client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "Host": "127.0.0.1:8767",
        },
        json={
            "jsonrpc": "2.0",
            "id": sequence,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        },
    )
    if response.status_code != 200:
        raise RuntimeError(f"MCP_HTTP_STATUS_{response.status_code}")
    data_line = next((line for line in response.text.splitlines() if line.startswith("data: ")), None)
    if data_line is None:
        raise RuntimeError("MCP_RESPONSE_NOT_STRUCTURED")
    return json.loads(data_line.removeprefix("data: "))["result"]["structuredContent"]


def _run_reserved(
    control_profile: str,
    profile: str,
    role_name: str,
    confirmation_ref: str,
    reserved_output: ExclusiveOutput,
) -> dict[str, Any]:
    run_id = "run-alibaba-cloud-preflight-" + secrets.token_hex(12)
    policy_observation = capture_ram_policy_observation(control_profile, profile, role_name, run_id)
    assessed_at = datetime.now(UTC)
    with tempfile.TemporaryDirectory(prefix="titmas-policy-observation-binding-") as policy_tempdir:
        policy_observation_path = Path(policy_tempdir) / "observation.json"
        policy_observation_path.write_text(json.dumps(policy_observation, sort_keys=True), encoding="utf-8")
        cloud_credential, _ = credential_from_policy_observation(
            profile,
            policy_observation_path,
            assessed_at=assessed_at,
            expected_run_id=run_id,
        )
    credentials = _principal_credentials()
    request_id = "aar-alibaba-cloud-preflight-20260802"
    provenance = workspace_provenance_v02(ROOT)
    commit = provenance["base_commit"]
    observed_at = assessed_at.isoformat().replace("+00:00", "Z")
    request = {
        "schema_version": "0.1.0",
        "request_id": request_id,
        "created_at": observed_at,
        "requested_by": {"agent_id": "release-steward", "team_id": "titmas-action-gate"},
        "action": "github.release.create",
        "target": {
            "provider": "github",
            "repository": "joy7758/titmas-agent-action-gate",
            "resource_ref": "release/competition-demo-not-created",
        },
        "parameters": {"tag": "competition-demo-not-created", "draft": True},
        "parameters_sha256": "",
        "evidence_requirements": [
            "SOURCE_PIN",
            "TEST_RESULT",
            "TAG_STATE",
            "RELEASE_MANIFEST",
            "CLOUD_CONTEXT",
        ],
        "uncertainty": [
            "Cloud context is read-only evidence and grants no deployment or release authority.",
            "This evaluation does not create a GitHub release or any cloud workload resource.",
        ],
        "idempotency_key": "alibaba-cloud-preflight-20260802",
    }
    request["parameters_sha256"] = sha256_json(request["parameters"])
    scope = {
        "schema_version": "0.1.0",
        "run_id": run_id,
        "correlation_id": "corr-alibaba-cloud-preflight-20260802",
        "task_id": "task-alibaba-cloud-preflight-20260802",
        "repository": request["target"]["repository"],
        "commit": commit,
    }
    retained_confirmation_ref = (
        confirmation_ref
        if re.fullmatch(r"confirmation:[a-f0-9]{64}", confirmation_ref)
        else "confirmation:" + hashlib.sha256(confirmation_ref.encode("utf-8")).hexdigest()
    )
    query = {
        "schema_version": "0.1.0",
        "operation": "resourcecenter.search-resources",
        "max_results": 1,
        "filters": {},
        "include_deleted_resources": False,
        "parameters_confirmed_by_user": True,
        "confirmation_ref": retained_confirmation_ref,
    }
    with tempfile.TemporaryDirectory(prefix="titmas-alibabacloud-evaluation-") as state_dir:
        service = ActionGateService.demo(state_dir)
        runtime = NativeRuntimeMcp(
            service,
            RuntimePrincipalRegistry(credentials),
            caller_token=CALLER_TOKEN,
            approver_token=APPROVER_TOKEN,
            cloud_context_inspector=CloudContextInspector(ROOT),
            cloud_credential=cloud_credential,
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=DeprecationWarning)
            with TestClient(runtime.mcp.streamable_http_app()) as client:
                submitted = _call(
                    client,
                    credentials["release-steward"],
                    1,
                    "submit_action_request",
                    {"action_request": request, "runtime_scope": scope},
                )
                denied = _call(
                    client,
                    credentials["request-analyst"],
                    2,
                    "inspect_alibabacloud_resources",
                    {"request_id": request_id, "runtime_scope": scope, "query": query},
                )
                loaded = _call(
                    client,
                    credentials["cloud-context-inspector"],
                    3,
                    "load_external_alibabacloud_skill",
                    {"request_id": request_id, "runtime_scope": scope},
                )
                observed = _call(
                    client,
                    credentials["cloud-context-inspector"],
                    4,
                    "inspect_alibabacloud_resources",
                    {"request_id": request_id, "runtime_scope": scope, "query": query},
                )
        if not submitted.get("ok"):
            raise RuntimeError("REQUEST_SUBMISSION_FAILED")
        if denied.get("ok") or denied.get("error", {}).get("code") != "MCP_TOOL_NOT_ALLOWED":
            raise RuntimeError("NEGATIVE_TOOL_BOUNDARY_NOT_PROVEN")
        if not loaded.get("ok"):
            raise RuntimeError("EXTERNAL_SKILL_LOAD_FAILED")
        if not observed.get("ok"):
            raise RuntimeError("CLOUD_CONTEXT_TOOL_FAILED")
        retained = observed["result"]
        cloud = retained["cloud_context"]
        receipt = retained["agent_evidence_receipt"]
        records = service.store.records_for_request(request_id)
        security_events = service.store.security_events_for_run(scope["run_id"])
        profile = json.loads((service.evidence.root / retained["profile_path"]).read_text(encoding="utf-8"))
        event_envelopes = service.evidence.event_store.list()
        public = {
            "$schema": "../../schemas/alibabacloud-resourcecenter-runtime-evidence.v0.2.schema.json",
            "schema_version": "0.2.0",
            "evaluation_id": f"TITMAS-AAG-ALIBABACLOUD-RESOURCECENTER-{run_id}",
            "observed_at": observed_at,
            "request_id": request_id,
            "provenance": {
                **provenance,
                "cli_version": cloud["invocation"]["cli_version"],
                "aliyun_cli_sha256": OFFICIAL_ALIYUN_CLI_SHA256,
                "resourcecenter_plugin_version": OFFICIAL_RESOURCE_CENTER_PLUGIN_VERSION,
                "resourcecenter_plugin_sha256": OFFICIAL_RESOURCE_CENTER_PLUGIN_SHA256,
                "policy_observation_sha256": sha256_json(policy_observation),
            },
            "action_request": request,
            "runtime": {
                "surface": "AUTHENTICATED_FASTMCP_STREAMABLE_HTTP",
                "principal": "cloud-context-inspector",
                "tool": "inspect_alibabacloud_resources",
                "allowed_call_recorded": any(
                    item["principal_id"] == "cloud-context-inspector"
                    and item["tool_name"] == "inspect_alibabacloud_resources"
                    and item["outcome"] == "ALLOW_CALL"
                    for item in security_events
                ),
                "negative_principal": "request-analyst",
                "negative_result": "MCP_TOOL_NOT_ALLOWED",
                "native_agentteams_llm_worker_turn": False,
            },
            "cloud_context": cloud,
            "permission_observation": policy_observation,
            "agent_evidence_profile": profile,
            "agent_evidence_receipt": receipt,
            "record_chain": {
                "issues": service.store.verify_chain(),
                "records": records,
            },
            "security_chain": {
                "issues": service.store.verify_security_chain(scope["run_id"]),
                "events": security_events,
            },
            "agent_evidence_event_chain": {
                "issues": service.evidence.verify_event_chain(),
                "events": [item.model_dump(mode="json") for item in event_envelopes],
            },
            "authority": {
                "worker_produced_gate_outcome": _contains_gate_outcome(retained),
                "decision_record_count": sum(item["record_type"] == "decision" for item in records),
                "deterministic_gate_authority_preserved": True,
            },
            "external_effects": {
                "resourcecenter_cli_processes": 1,
                "resourcecenter_provider_http_attempts": "NOT_ASSESSED",
                "runtime_sts_identity_read_calls": 1,
                "runtime_cloud_read_calls": 2,
                "permission_observation_cloud_read_calls": policy_observation["effects"]["cloud_read_calls"],
                "resourcecenter_write_api_calls": 0,
                "iam_control_plane_provisioning_writes_occurred": True,
                "runtime_local_cli_config_writes": sum(item["effect"] == "LOCAL_CONFIG_WRITE" for item in cloud["invocation"]["steps"]),
                "runtime_plugin_install_or_update_executed": False,
                "setup_plugin_update_previously_executed": True,
                "github_write_calls": 0,
                "release_or_deployment_executed": False,
            },
            "secrets": {
                "credential_bytes_in_artifact": False,
                "profile_name_in_artifact": False,
                "raw_provider_output_retained": False,
            },
            "non_claims": [
                "ZERO_RESULTS_DO_NOT_PROVE_THE_ACCOUNT_HAS_NO_RESOURCES",
                "NO_NATIVE_AGENTTEAMS_LLM_WORKER_TURN",
                "NO_GITHUB_RELEASE_OR_DEPLOYMENT",
                "NO_PRODUCTION_READINESS_CERTIFICATION_OR_COMPLIANCE_CLAIM",
            ],
        }
    issues = validate_public_evidence(ROOT, public)
    if issues:
        raise RuntimeError("PUBLIC_EVIDENCE_VALIDATION_FAILED:" + ",".join(issues))
    reserved_output.write_text(json.dumps(public, ensure_ascii=False, indent=2) + "\n")
    return public


def run(
    control_profile: str,
    profile: str,
    role_name: str,
    confirmation_ref: str,
    output_path: Path,
) -> dict[str, Any]:
    try:
        with ExclusiveOutput(output_path) as reserved_output:
            return _run_reserved(control_profile, profile, role_name, confirmation_ref, reserved_output)
    except FileExistsError as exc:
        raise RuntimeError("RUNTIME_EVIDENCE_OUTPUT_ALREADY_EXISTS") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-profile", default=os.environ.get("TITMAS_ALIBABA_CLOUD_CONTROL_PROFILE"))
    parser.add_argument("--profile", default=os.environ.get("TITMAS_ALIBABA_CLOUD_PROFILE"))
    parser.add_argument("--role-name", default=os.environ.get("TITMAS_ALIBABA_CLOUD_ROLE_NAME"))
    parser.add_argument("--confirmation-ref", required=True)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
    )
    args = parser.parse_args()
    if not args.control_profile or not args.profile or not args.role_name:
        raise SystemExit("control profile, query profile, and role name are required; credential bytes are not accepted")
    try:
        result = run(
            args.control_profile,
            args.profile,
            args.role_name,
            args.confirmation_ref,
            Path(os.path.abspath(args.output)),
        )
    except RuntimeError as exc:
        if str(exc) == "RUNTIME_EVIDENCE_OUTPUT_ALREADY_EXISTS":
            raise SystemExit(str(exc)) from exc
        raise
    print(
        json.dumps(
            {
                "evaluation_id": result["evaluation_id"],
                "status": result["cloud_context"]["status"],
                "agent_evidence_status": result["agent_evidence_receipt"]["status"],
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

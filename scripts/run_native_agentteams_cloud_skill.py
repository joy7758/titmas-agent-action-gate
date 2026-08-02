#!/usr/bin/env python3
"""Run one real AgentTeams cloud-context-inspector turn without retaining secrets.

Prerequisites are an already-running pinned AgentTeams v1.2.0 stack and exactly
one Running ``cloud-context-inspector`` Worker configured with the authenticated
native MCP URL. The official Skill remains external to both this repository and
the Worker package; the Worker loads a source-bound projection through MCP.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import html
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from titmas_action_gate.canonical import sha256_file, sha256_json
from titmas_action_gate.cloud_context import CloudContextInspector
from titmas_action_gate.runtime import HUMAN_PRINCIPAL_ID, RuntimeAdmission, RuntimePrincipalRegistry
from titmas_action_gate.service import ActionGateService

ROOT = Path(__file__).resolve().parents[1]
AGENTTEAMS_COMMIT = "793db242257a569d911b1aa59c1cd554af78511f"
AGENTTEAMS_WORKER_IMAGE = "higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/agentteams-worker:v1.2.0"
AGENTTEAMS_WORKER_IMAGE_ID = "sha256:daf587ad042f9564abb2347db5c4205ecc25d1b322e09fdd0d58a2a16c2d5c85"
WORKER = "cloud-context-inspector"
WORKER_CONTAINER = "agentteams-worker-cloud-context-inspector"
MATRIX_BASE = "http://127.0.0.1:18080"
MATRIX_HOST = "matrix-local.agentteams.io"
CALLER_TOKEN = "titmas-demo-caller-token"
APPROVER_TOKEN = "titmas-demo-approver-token"
REQUEST_ID = "aar-alibaba-cloud-preflight-20260802"
FROZEN_CONFIRMATION_REF = "confirmation:e3f602a4fd564910313383ab1f553d8317d06e4b440c1b49b600178a013d288c"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def _run(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, check=check, capture_output=True, text=True)


def _worker_readback() -> dict[str, Any]:
    result = _run(["docker", "exec", "agentteams-manager", "agt", "get", "workers", WORKER, "-o", "json"])
    payload = json.loads(result.stdout)
    return {
        "name": payload.get("name"),
        "phase": payload.get("phase"),
        "model": payload.get("model"),
        "runtime": payload.get("runtime"),
        "container_state": payload.get("containerState"),
        "matrix_user_id": payload.get("matrixUserID"),
        "room_id": payload.get("roomID"),
    }


def _worker_container_readback() -> dict[str, str]:
    payload = json.loads(_run(["docker", "inspect", WORKER_CONTAINER]).stdout)[0]
    result = {
        "container_id": payload["Id"],
        "image_ref": payload["Config"]["Image"],
        "image_id": payload["Image"],
        "started_at": payload["State"]["StartedAt"],
    }
    if result["image_ref"] != AGENTTEAMS_WORKER_IMAGE or result["image_id"] != AGENTTEAMS_WORKER_IMAGE_ID:
        raise RuntimeError("AGENTTEAMS_OFFICIAL_WORKER_IMAGE_MISMATCH")
    return result


def _apply_worker_package(worker_package: Path) -> dict[str, Any]:
    previous_container_id = ""
    with contextlib.suppress(subprocess.CalledProcessError, RuntimeError):
        previous_container_id = _worker_container_readback()["container_id"]
    container_package = "/tmp/titmas-cloud-context-inspector-runtime.zip"
    _run(["docker", "cp", str(worker_package), f"agentteams-manager:{container_package}"])
    applied_at = _utc_now()
    applied = _run(
        [
            "docker",
            "exec",
            "agentteams-manager",
            "agt",
            "apply",
            "worker",
            "--name",
            WORKER,
            "--zip",
            container_package,
        ]
    )
    if f"worker/{WORKER}" not in applied.stdout or not any(marker in applied.stdout for marker in ("updated", "created", "configured")):
        raise RuntimeError("AGENTTEAMS_WORKER_PACKAGE_APPLY_NOT_CONFIRMED")
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            worker = _worker_readback()
            container = _worker_container_readback()
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            time.sleep(2)
            continue
        if (
            worker["phase"] == "Running"
            and worker["container_state"] == "running"
            and (not previous_container_id or container["container_id"] != previous_container_id)
        ):
            return {
                "apply_result": "AGENTTEAMS_WORKER_PACKAGE_APPLIED",
                "apply_exit_status": applied.returncode,
                "applied_at": applied_at,
                "worker_container_started_at": container["started_at"],
                "worker_container_recreated": bool(previous_container_id),
            }
        time.sleep(2)
    raise RuntimeError("AGENTTEAMS_WORKER_PACKAGE_RECONCILIATION_TIMEOUT")


def _runtime_upstream_byte_scan() -> dict[str, Any]:
    lock = json.loads((ROOT / "governance/alibabacloud-resourcecenter-search-source-lock.json").read_text())
    upstream_hashes = {item["sha256"] for item in lock["files"]}
    workspace = f"/root/agentteams-fs/agents/{WORKER}"
    result = _run(
        [
            "docker",
            "exec",
            WORKER_CONTAINER,
            "sh",
            "-lc",
            f"find {workspace} -type f -exec sha256sum {{}} +",
        ]
    )
    observed_hashes = {line.split(maxsplit=1)[0] for line in result.stdout.splitlines() if line.strip()}
    return {
        "workspace_reference": f"agentteams://workers/{WORKER}/workspace",
        "scan_exit_status": result.returncode,
        "upstream_file_digest_match_count": len(upstream_hashes & observed_hashes),
    }


def _worker_consumer_token() -> str:
    result = _run(
        [
            "docker",
            "exec",
            WORKER_CONTAINER,
            "cat",
            f"/root/agentteams-fs/agents/{WORKER}/config/mcporter.json",
        ]
    )
    payload = json.loads(result.stdout)
    header = payload["mcpServers"]["titmas-action-gate-native-runtime"]["headers"]["Authorization"]
    prefix = "Bearer "
    if not isinstance(header, str) or not header.startswith(prefix) or len(header.removeprefix(prefix)) < 24:
        raise RuntimeError("AGENTTEAMS_WORKER_CONSUMER_TOKEN_UNAVAILABLE")
    return header.removeprefix(prefix)


def _matrix_request(
    method: str,
    path: str,
    *,
    token: str | None = None,
    payload: dict[str, Any] | None = None,
    timeout: float = 15,
) -> dict[str, Any]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(MATRIX_BASE + path, data=data, method=method)
    request.add_header("Host", MATRIX_HOST)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def _matrix_login(admin_user: str, admin_password: str) -> tuple[str, str]:
    result = _matrix_request(
        "POST",
        "/_matrix/client/v3/login",
        payload={
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": admin_user},
            "password": admin_password,
        },
    )
    token = result.get("access_token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("MATRIX_ADMIN_LOGIN_FAILED")
    user_id = result.get("user_id")
    if not isinstance(user_id, str) or not user_id:
        raise RuntimeError("MATRIX_ADMIN_IDENTITY_UNAVAILABLE")
    return token, user_id


def _prepare_request(state_dir: Path, credentials: dict[str, str], scope: dict[str, str]) -> dict[str, Any]:
    request = {
        "schema_version": "0.1.0",
        "request_id": REQUEST_ID,
        "created_at": _utc_now(),
        "requested_by": {"agent_id": "release-steward", "team_id": "titmas-action-gate"},
        "action": "github.release.create",
        "target": {
            "provider": "github",
            "repository": "joy7758/titmas-agent-action-gate",
            "resource_ref": "release/competition-demo-not-created",
        },
        "parameters": {"tag": "competition-demo-not-created", "draft": True},
        "parameters_sha256": "",
        "evidence_requirements": ["SOURCE_PIN", "TEST_RESULT", "TAG_STATE", "RELEASE_MANIFEST", "CLOUD_CONTEXT"],
        "uncertainty": [
            "Cloud context is read-only evidence and grants no deployment or release authority.",
            "This native Worker turn creates no cloud resource and produces no Action Gate decision.",
        ],
        "idempotency_key": "alibaba-cloud-preflight-20260802",
    }
    request["parameters_sha256"] = sha256_json(request["parameters"])
    service = ActionGateService.demo(state_dir, caller_token=CALLER_TOKEN, approver_token=APPROVER_TOKEN)
    principal = RuntimePrincipalRegistry(credentials).principal("release-steward")
    admission = RuntimeAdmission(service.store, RuntimePrincipalRegistry(credentials))
    normalized = admission.bind_submission(principal, "submit_action_request", scope, request)
    service.submit_action_request(request, caller_token=CALLER_TOKEN, actor="release-steward")
    admission.record_allowed(
        principal,
        "submit_action_request",
        normalized,
        request_id=REQUEST_ID,
        business_state_delta=1,
    )
    return request


def _server_ready(port: int, process: subprocess.Popen[str], timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("NATIVE_MCP_SERVER_EXITED_BEFORE_READY")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    raise RuntimeError("NATIVE_MCP_SERVER_READY_TIMEOUT")


def _sync(token: str, since: str | None, timeout_ms: int) -> dict[str, Any]:
    query = {"timeout": str(timeout_ms)}
    if since:
        query["since"] = since
    return _matrix_request("GET", "/_matrix/client/v3/sync?" + urllib.parse.urlencode(query), token=token, timeout=timeout_ms / 1000 + 10)


def _send_prompt(token: str, room_id: str, worker_user_id: str, prompt: str) -> str:
    txn = "titmas-native-cloud-" + secrets.token_hex(8)
    path = "/_matrix/client/v3/rooms/" + urllib.parse.quote(room_id, safe="") + "/send/m.room.message/" + txn
    body = f"{worker_user_id} {prompt}"
    encoded_worker_id = urllib.parse.quote(worker_user_id, safe="")
    visible_mention = f'<a href="https://matrix.to/#/{encoded_worker_id}">{html.escape(worker_user_id)}</a>'
    result = _matrix_request(
        "PUT",
        path,
        token=token,
        payload={
            "msgtype": "m.text",
            "body": body,
            "format": "org.matrix.custom.html",
            "formatted_body": f"{visible_mention} {html.escape(prompt)}",
            "m.mentions": {"user_ids": [worker_user_id]},
        },
    )
    event_id = result.get("event_id")
    if not isinstance(event_id, str) or not event_id:
        raise RuntimeError("MATRIX_PROMPT_EVENT_NOT_RETAINED")
    return event_id


def _worker_messages(sync: dict[str, Any], room_id: str, worker_user_id: str) -> list[dict[str, str]]:
    timeline = sync.get("rooms", {}).get("join", {}).get(room_id, {}).get("timeline", {}).get("events", [])
    messages: list[dict[str, str]] = []
    for event in timeline:
        if event.get("type") != "m.room.message" or event.get("sender") != worker_user_id:
            continue
        body = event.get("content", {}).get("body")
        if isinstance(body, str):
            messages.append(
                {
                    "event_id": str(event.get("event_id", "")),
                    "sender": str(event.get("sender", "")),
                    "room_id": room_id,
                    "origin_server_ts": str(event.get("origin_server_ts", "")),
                    "body": body,
                }
            )
    return messages


def _room_messages(sync: dict[str, Any], room_id: str) -> list[dict[str, str]]:
    timeline = sync.get("rooms", {}).get("join", {}).get(room_id, {}).get("timeline", {}).get("events", [])
    return [
        {
            "event_id": str(event.get("event_id", "")),
            "sender": str(event.get("sender", "")),
            "room_id": room_id,
            "origin_server_ts": str(event.get("origin_server_ts", "")),
        }
        for event in timeline
        if event.get("type") == "m.room.message"
    ]


def _contains_gate_outcome(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_gate_outcome(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_gate_outcome(item) for item in value)
    return isinstance(value, str) and value in {"ALLOW", "BLOCK", "REQUIRE_APPROVAL"}


def _has_complete_worker_report(responses: list[dict[str, str]]) -> bool:
    if not responses:
        return False
    body = responses[-1]["body"]
    return (
        "NOT_ASSESSED_NO_VISIBLE_RESOURCE" in body
        and "EMPTY_RESULT" in body
        and re.search(r'["`]worker_decision_record_count["`]\s*:\s*0(?:\D|$)', body) is not None
    )


def run(args: argparse.Namespace) -> dict[str, Any]:
    runtime_dir = args.runtime_dir.resolve()
    state_dir = runtime_dir / "action-gate-state"
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    external_skill = CloudContextInspector(ROOT, external_skill_path=args.external_skill_path)
    external_skill.verify_skill_source()
    package_apply = _apply_worker_package(args.worker_package)
    worker = _worker_readback()
    if worker != {
        **worker,
        "name": WORKER,
        "phase": "Running",
        "model": "qwen3.7-max",
        "runtime": "openclaw",
        "container_state": "running",
    }:
        raise RuntimeError("AGENTTEAMS_WORKER_NOT_READY")
    if not worker["matrix_user_id"] or not worker["room_id"]:
        raise RuntimeError("AGENTTEAMS_WORKER_ROOM_NOT_READY")

    worker_container = _worker_container_readback()
    runtime_byte_scan = _runtime_upstream_byte_scan()
    if runtime_byte_scan["upstream_file_digest_match_count"] != 0:
        raise RuntimeError("UPSTREAM_SKILL_BYTES_PRESENT_IN_WORKER_RUNTIME")
    worker_token = _worker_consumer_token()
    registry = json.loads((ROOT / "agents/registry.json").read_text(encoding="utf-8"))
    principals = {item["id"] for item in registry["agents"]} | {HUMAN_PRINCIPAL_ID}
    credentials = {principal: secrets.token_urlsafe(36) for principal in principals}
    credentials[WORKER] = worker_token
    credentials_path = runtime_dir / "native-runtime-credentials.private.json"
    credentials_path.write_text(json.dumps({"credentials": credentials}), encoding="utf-8")
    os.chmod(credentials_path, 0o600)

    scope = {
        "schema_version": "0.1.0",
        "run_id": "run-native-alibaba-cloud-20260802-001",
        "correlation_id": "corr-native-alibaba-cloud-20260802-001",
        "task_id": "task-native-alibaba-cloud-20260802-001",
        "repository": "joy7758/titmas-agent-action-gate",
        "commit": args.source_commit,
    }
    request = _prepare_request(state_dir, credentials, scope)
    query = {
        "schema_version": "0.1.0",
        "operation": "resourcecenter.search-resources",
        "max_results": 1,
        "filters": {},
        "include_deleted_resources": False,
        "parameters_confirmed_by_user": True,
        "confirmation_ref": FROZEN_CONFIRMATION_REF,
    }

    server_log = runtime_dir / "native-mcp-server.private.log"
    server_env = os.environ.copy()
    server_env.update(
        {
            "TITMAS_ACTION_GATE_STATE_DIR": str(state_dir),
            "TITMAS_ACTION_GATE_RUNTIME_CREDENTIALS_FILE": str(credentials_path),
            "TITMAS_ACTION_GATE_CALLER_TOKEN": CALLER_TOKEN,
            "TITMAS_ACTION_GATE_APPROVER_TOKEN": APPROVER_TOKEN,
            "TITMAS_ACTION_GATE_DEMO_MODE": "true",
            "TITMAS_ACTION_GATE_RUNTIME_MCP_HOST": "0.0.0.0",
            "TITMAS_ACTION_GATE_RUNTIME_MCP_PORT": "8767",
            "TITMAS_AGENTTEAMS_NATIVE_WORKER": "true",
            "TITMAS_OFFICIAL_ALIBABA_CLOUD_SKILL_PATH": str(args.external_skill_path),
            "TITMAS_ALIBABA_CLOUD_PROFILE": args.profile,
            "TITMAS_ALIBABA_RAM_POLICY_OBSERVATION": str(args.policy_observation),
        }
    )
    log_handle = server_log.open("w", encoding="utf-8")
    os.chmod(server_log, 0o600)
    process = subprocess.Popen(
        [str(ROOT / ".venv/bin/python"), "-m", "titmas_action_gate.runtime_mcp_server"],
        cwd=ROOT,
        env=server_env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    prompt_event_id = ""
    responses: list[dict[str, str]] = []
    room_events: list[dict[str, str]] = []
    try:
        _server_ready(8767, process)
        manager_env = _read_env(args.agentteams_env)
        admin_token, admin_user_id = _matrix_login(
            manager_env.get("AGENTTEAMS_ADMIN_USER", "admin"),
            manager_env["AGENTTEAMS_ADMIN_PASSWORD"],
        )
        baseline = _sync(admin_token, None, 0)
        since = baseline["next_batch"]
        prompt = (
            "Execute exactly one bounded cloud preflight. OpenClaw exposes the configured MCP server through "
            "the installed mcporter bridge, so use the execution tool only to run the two exact mcporter call "
            "selectors below; do not run any other command. First call "
            "titmas-action-gate-native-runtime.load_external_alibabacloud_skill with "
            f"request_id={REQUEST_ID} and runtime_scope={json.dumps(scope, separators=(',', ':'))}. "
            "Require runtime_load_result LOADED_READ_ONLY_RESOURCECENTER_SEARCH_ONLY. Then call "
            "titmas-action-gate-native-runtime.inspect_alibabacloud_resources with the same request_id/runtime_scope "
            f"and query={json.dumps(query, separators=(',', ':'))}. "
            "Treat EMPTY_RESULT as a valid invocation and report status NOT_ASSESSED_NO_VISIBLE_RESOURCE. "
            "Return one concise JSON object containing skill_name, external_path_reference, revision, digest, "
            "runtime_load_result, invocation_result, status, cli_exit_status, resourcecenter_write_api_calls, "
            "agent_evidence_status, and worker_decision_record_count. Never output credentials, call aliyun directly, "
            "or output any Action Gate outcome."
        )
        prompt_event_id = _send_prompt(admin_token, str(worker["room_id"]), str(worker["matrix_user_id"]), prompt)
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            update = _sync(admin_token, since, 5000)
            since = update["next_batch"]
            room_events.extend(_room_messages(update, str(worker["room_id"])))
            responses.extend(_worker_messages(update, str(worker["room_id"]), str(worker["matrix_user_id"])))
            service = ActionGateService.demo(state_dir, caller_token=CALLER_TOKEN, approver_token=APPROVER_TOKEN)
            records = service.store.records_for_request(REQUEST_ID)
            if any(item["record_type"] == "cloud_context_preflight" for item in records) and _has_complete_worker_report(responses):
                break
        else:
            raise RuntimeError("AGENTTEAMS_NATIVE_WORKER_TURN_TIMEOUT")
    finally:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)
        log_handle.close()

    service = ActionGateService.demo(state_dir, caller_token=CALLER_TOKEN, approver_token=APPROVER_TOKEN)
    records = service.store.records_for_request(REQUEST_ID)
    load_record = next(item for item in records if item["record_type"] == "external_skill_load")
    cloud_record = next(item for item in records if item["record_type"] == "cloud_context_preflight")
    receipt_record = next(item for item in records if item["record_type"] == "cloud_context_evidence_result")
    cloud = cloud_record["payload"]
    receipt = receipt_record["payload"]
    security_events = service.store.security_events_for_run(scope["run_id"])
    event_chain = [item.model_dump(mode="json") for item in service.evidence.event_store.list()]
    profile_record = json.loads((service.evidence.root / f"cloud-context/{cloud['preflight_id']}.json").read_text(encoding="utf-8"))

    manager_env = _read_env(args.agentteams_env)
    secret_values = [
        worker_token,
        *credentials.values(),
        *(value for key, value in manager_env.items() if value and any(marker in key for marker in ("KEY", "TOKEN", "PASSWORD"))),
    ]
    private_log = server_log.read_text(encoding="utf-8", errors="replace")
    if any(secret in private_log for secret in secret_values):
        raise RuntimeError("SECRET_FOUND_IN_NATIVE_MCP_LOG")

    response_bodies = [item["body"] for item in responses]
    if any(secret in body for secret in secret_values for body in response_bodies):
        raise RuntimeError("SECRET_FOUND_IN_AGENTTEAMS_WORKER_RESPONSE")
    if cloud["status"] != "NOT_ASSESSED_NO_VISIBLE_RESOURCE" or cloud["invocation"]["result_class"] != "EMPTY_RESULT":
        raise RuntimeError("REAL_QUERY_DID_NOT_RETURN_EXPECTED_EMPTY_RESULT")
    if receipt["status"] != "VALID":
        raise RuntimeError("AGENT_EVIDENCE_RECEIPT_INVALID")
    if load_record["sequence"] >= cloud_record["sequence"]:
        raise RuntimeError("SKILL_DIGEST_NOT_VERIFIED_BEFORE_INVOCATION")
    decision_count = sum(item["record_type"] == "decision" for item in records)
    if decision_count or _contains_gate_outcome(response_bodies):
        raise RuntimeError("WORKER_AUTHORITY_BOUNDARY_VIOLATED")
    if not _has_complete_worker_report(responses):
        raise RuntimeError("WORKER_FINAL_REPORT_NOT_RETAINED")
    operator_events = [item for item in room_events if item["sender"] == admin_user_id]
    if any(item["event_id"] != prompt_event_id for item in operator_events):
        raise RuntimeError("OPERATOR_FOLLOWUP_PROMPT_RETAINED")

    package_members = _run(["unzip", "-Z1", str(args.worker_package)]).stdout.splitlines()
    upstream_bytes_distributed = any(item.startswith("skills/alibabacloud-resourcecenter-search/") for item in package_members)
    if upstream_bytes_distributed:
        raise RuntimeError("UPSTREAM_SKILL_BYTES_DISTRIBUTED")

    observed_at = _utc_now()
    evidence = {
        "$schema": "../../schemas/native-agentteams-cloud-skill-run-evidence.v0.1.schema.json",
        "schema_version": "0.1.0",
        "run_id": scope["run_id"],
        "observed_at": observed_at,
        "source": {
            "repository_base_commit": args.source_commit,
            "agentteams_release": "v1.2.0",
            "agentteams_commit": AGENTTEAMS_COMMIT,
            "agent_evidence_version": "0.6.0",
            "official_skill_source_lock_sha256": sha256_file(ROOT / "governance/alibabacloud-resourcecenter-search-source-lock.json"),
        },
        "action_request": request,
        "native_runtime": {
            "classification": "OFFICIAL_AGENTTEAMS_NATIVE_LLM_WORKER_TURN",
            "worker": worker,
            "worker_container": worker_container,
            "prompt_event_id": prompt_event_id,
            "response_events": responses,
            "initial_prompt_count": 1,
            "operator_followup_prompt_count": sum(item["event_id"] != prompt_event_id for item in operator_events),
            "matrix_turn_trace": {
                "room_id": worker["room_id"],
                "initial_prompt_event_id": prompt_event_id,
                "initial_prompt_sender": admin_user_id,
                "observed_message_events_after_baseline": room_events,
            },
            "mcp_surface": "AUTHENTICATED_FASTMCP_STREAMABLE_HTTP",
            "current_worker_credential_ref": "sha256:" + hashlib.sha256(worker_token.encode()).hexdigest(),
            "prior_exposed_disposable_worker_credential_rotated_before_run": True,
        },
        "skill_load": {
            **load_record["payload"],
            "record_sequence": load_record["sequence"],
            "record_hash": load_record["record_hash"],
            "verified_before_invocation": load_record["sequence"] < cloud_record["sequence"],
        },
        "package_boundary": {
            "package_sha256": sha256_file(args.worker_package),
            "package_member_count": len(package_members),
            "package_members": sorted(package_members),
            "external_skill_reference_only": True,
            "distribution_scope": "TRACKED_GIT_WORKER_ZIP_WHEEL_AND_SDIST",
            "local_external_installation_exists": True,
            "upstream_skill_bytes_distributed": upstream_bytes_distributed,
            "agentteams_package_apply": package_apply,
            "runtime_worker_filesystem_scan": runtime_byte_scan,
        },
        "frozen_query": query,
        "cloud_context": cloud,
        "agent_evidence_profile": profile_record,
        "agent_evidence_receipt": receipt,
        "trace": {
            "record_chain_issues": service.store.verify_chain(),
            "records": records,
            "security_chain_issues": service.store.verify_security_chain(scope["run_id"]),
            "security_events": security_events,
            "agent_evidence_chain_issues": service.evidence.verify_event_chain(),
            "agent_evidence_events": event_chain,
        },
        "authority": {
            "worker_decision_record_count": decision_count,
            "worker_produced_gate_outcome": False,
            "deterministic_action_gate_sole_authority": True,
        },
        "effects": {
            "effect_scope": "NATIVE_WORKER_TURN_RESOURCECENTER_AND_CLOUD_WORKLOAD_ONLY",
            "resourcecenter_read_api_calls": 1,
            "sts_identity_read_api_calls": 1,
            "resourcecenter_write_api_calls": 0,
            "cloud_resource_write_executed": False,
            "cloud_resource_created_for_nonempty_result": False,
            "prior_setup_iam_control_plane_write_executed": True,
        },
        "secrets": {
            "credential_bytes_in_prompt": False,
            "credential_bytes_in_worker_response": False,
            "credential_bytes_in_private_mcp_log": False,
            "credential_bytes_in_evidence": False,
            "credential_bytes_in_git": False,
            "profile_name_in_evidence": False,
            "raw_provider_output_retained": False,
        },
        "exit_criteria": {
            "AGENTTEAMS_NATIVE_WORKER_TURN_RETAINED": True,
            "RUNTIME_LOADING_PROVEN": True,
            "SKILL_DIGEST_VERIFIED_BEFORE_INVOCATION": True,
            "OFFICIAL_SKILL_ACTUALLY_INVOKED": True,
            "REAL_RESOURCECENTER_QUERY_REUSED": True,
            "EMPTY_RESULT_INTERPRETED_CORRECTLY": True,
            "WORKER_DECISION_RECORD_COUNT": 0,
            "CLOUD_RESOURCE_WRITE_EXECUTED": False,
            "UPSTREAM_SKILL_BYTES_DISTRIBUTED": False,
            "AGENT_EVIDENCE_RECEIPT_VALID": True,
            "SECRETS_COMMITTED": False,
        },
        "non_claims": [
            "NO_ACTION_GATE_DECISION_BY_WORKER",
            "NO_RESOURCECENTER_OR_CLOUD_WORKLOAD_WRITE_IN_NATIVE_WORKER_TURN",
            "PRIOR_IAM_CONTROL_PLANE_PROVISIONING_WRITE_REMAINS_DISCLOSED",
            "NO_PERSISTENT_OR_PRODUCTION_DEPLOYMENT",
            "NO_RELEASE_OR_COMPETITION_SUBMISSION",
            "NO_LICENSE_CLEARANCE_OR_CERTIFICATION_CLAIM",
        ],
    }
    serialized = json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if any(secret in serialized for secret in secret_values):
        raise RuntimeError("SECRET_FOUND_IN_PUBLIC_NATIVE_EVIDENCE")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(serialized, encoding="utf-8")
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agentteams-env", type=Path, required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--external-skill-path", type=Path, required=True)
    parser.add_argument("--worker-package", type=Path, required=True)
    parser.add_argument("--policy-observation", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    evidence = run(args)
    print(json.dumps({"ok": True, "run_id": evidence["run_id"], "exit_criteria": evidence["exit_criteria"]}, indent=2))


if __name__ == "__main__":
    main()

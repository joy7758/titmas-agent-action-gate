#!/usr/bin/env python3
"""Capture a sanitized Alibaba Cloud RAM read-only policy observation.

The producer accepts only external CLI profile labels and a role label. Raw
provider responses remain in memory; the retained output contains only policy
semantics, counts, and opaque SHA-256 references.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from titmas_action_gate.canonical import ExclusiveOutput, sha256_file, sha256_json
from titmas_action_gate.cloud_context import (
    EXPECTED_READ_ONLY_POLICY_ACTIONS,
    OFFICIAL_ALIYUN_CLI_SHA256,
    OFFICIAL_ALIYUN_CLI_VERSION,
    OFFICIAL_USER_AGENT,
)
from titmas_action_gate.contracts import validate_contract

ROOT = Path(__file__).resolve().parents[1]
POLICY_NAME = "AliyunResourceCenterReadOnlyAccess"
WRITE_ACTION_PREFIXES = ("create", "delete", "disable", "enable", "modify", "set", "update", "write")


def _opaque_ref(kind: str, value: str) -> str:
    return "sha256:" + hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()


def _as_json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("POLICY_DOCUMENT_INVALID")


def build_sanitized_observation(
    *,
    run_id: str,
    capture_id: str,
    started_at: datetime,
    completed_at: datetime,
    trace_observed_at: tuple[datetime, datetime, datetime, datetime],
    role_name: str,
    policy_payload: dict[str, Any],
    policy_version_payload: dict[str, Any],
    attachments_payload: dict[str, Any],
    identity_payload: dict[str, Any],
) -> dict[str, Any]:
    """Build and validate the public-safe observation from in-memory responses."""

    version_id = policy_payload.get("Policy", {}).get("DefaultVersion")
    policy_document = _as_json_object(policy_version_payload.get("PolicyVersion", {}).get("PolicyDocument"))
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        raise ValueError("POLICY_STATEMENTS_INVALID")
    allow_actions: set[str] = set()
    deny_statement_count = 0
    for statement in statements:
        if not isinstance(statement, dict):
            raise ValueError("POLICY_STATEMENT_INVALID")
        effect = statement.get("Effect")
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list) or any(not isinstance(item, str) for item in actions):
            raise ValueError("POLICY_ACTIONS_INVALID")
        if effect == "Allow":
            allow_actions.update(actions)
        elif effect == "Deny":
            deny_statement_count += 1

    attachments = attachments_payload.get("Policies", {}).get("Policy", [])
    if isinstance(attachments, dict):
        attachments = [attachments]
    if not isinstance(attachments, list) or any(not isinstance(item, dict) for item in attachments):
        raise ValueError("ROLE_ATTACHMENTS_INVALID")
    system_count = sum(item.get("PolicyType") == "System" for item in attachments)
    custom_count = sum(item.get("PolicyType") == "Custom" for item in attachments)
    matching_count = sum(item.get("PolicyType") == "System" and item.get("PolicyName") == POLICY_NAME for item in attachments)
    unexpected_count = sum(not (item.get("PolicyType") == "System" and item.get("PolicyName") == POLICY_NAME) for item in attachments)

    arn = identity_payload.get("Arn")
    identity_type = identity_payload.get("IdentityType")
    if not isinstance(arn, str) or identity_type != "AssumedRoleUser":
        raise ValueError("ASSUMED_ROLE_IDENTITY_INVALID")
    arn_parts = arn.split("/")
    if len(arn_parts) < 3 or not arn_parts[-2]:
        raise ValueError("ASSUMED_ROLE_ARN_INVALID")
    observed_role_ref = _opaque_ref("role", arn_parts[-2].lower())
    expected_role_ref = _opaque_ref("role", role_name.lower())
    if observed_role_ref != expected_role_ref:
        raise ValueError("ASSUMED_ROLE_NAME_MISMATCH")

    sorted_actions = sorted(allow_actions)
    write_marker_count = sum(any(action.rsplit(":", 1)[-1].lower().startswith(prefix) for prefix in WRITE_ACTION_PREFIXES) for action in sorted_actions)
    observation = {
        "$schema": "../schemas/alibabacloud-ram-policy-observation.v0.2.schema.json",
        "schema_version": "0.2.0",
        "observed_at": completed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "capture": {
            "capture_id": capture_id,
            "run_id": run_id,
            "started_at": started_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "completed_at": completed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "mode": "SAME_RUN_STS_AND_RAM_READBACK",
        },
        "identity": {
            "type": identity_type,
            "identity_ref": _opaque_ref("identity", arn),
            "role_ref": observed_role_ref,
        },
        "attachment": {
            "role_ref": observed_role_ref,
            "policy_type": "System",
            "policy_name": POLICY_NAME,
            "total_attachment_count": len(attachments),
            "system_policy_count": system_count,
            "custom_policy_count": custom_count,
            "matching_attachment_count": matching_count,
            "unexpected_attachment_count": unexpected_count,
        },
        "policy": {
            "version_id": version_id,
            "document_sha256": sha256_json(policy_document),
            "allow_actions": sorted_actions,
            "deny_statement_count": deny_statement_count,
            "write_operation_marker_count": write_marker_count,
        },
        "read_trace": [
            {
                "sequence": sequence,
                "capture_id": capture_id,
                "profile_scope": profile_scope,
                "operation": operation,
                "observed_at": trace_time.astimezone(UTC).isoformat().replace("+00:00", "Z"),
                "exit_status": 0,
                "request_id_ref": _opaque_ref("request", payload["RequestId"]),
            }
            for sequence, (profile_scope, operation, payload, trace_time) in enumerate(
                (
                    ("CONTROL_RAM_READBACK", "ram.GetPolicy", policy_payload, trace_observed_at[0]),
                    ("CONTROL_RAM_READBACK", "ram.GetPolicyVersion", policy_version_payload, trace_observed_at[1]),
                    ("CONTROL_RAM_READBACK", "ram.ListPoliciesForRole", attachments_payload, trace_observed_at[2]),
                    ("QUERY_STS_IDENTITY", "sts.GetCallerIdentity", identity_payload, trace_observed_at[3]),
                ),
                start=1,
            )
        ],
        "effects": {"cloud_read_calls": 4, "cloud_write_calls": 0, "local_cli_config_writes": 3},
    }
    validate_contract("alibabacloud_ram_policy_observation", observation)
    if set(sorted_actions) != EXPECTED_READ_ONLY_POLICY_ACTIONS:
        raise ValueError("READ_ONLY_POLICY_ACTION_SET_MISMATCH")
    return observation


def _run_json(binary: str, argv: list[str]) -> dict[str, Any]:
    binary_path = Path(binary).resolve()
    if not binary_path.is_file() or sha256_file(binary_path) != OFFICIAL_ALIYUN_CLI_SHA256:
        raise RuntimeError(f"ALIYUN_CLI_PIN_CHANGED_BEFORE_PROVIDER_READ:{argv[0]}.{argv[1]}")
    result = subprocess.run([binary, *argv], check=False, capture_output=True, text=True, timeout=60)
    if not binary_path.is_file() or sha256_file(binary_path) != OFFICIAL_ALIYUN_CLI_SHA256:
        raise RuntimeError(f"ALIYUN_CLI_PIN_CHANGED_DURING_PROVIDER_READ:{argv[0]}.{argv[1]}")
    if result.returncode != 0:
        raise RuntimeError(f"PROVIDER_READ_FAILED:{argv[0]}.{argv[1]}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"PROVIDER_RESPONSE_NOT_JSON:{argv[0]}.{argv[1]}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"PROVIDER_RESPONSE_INVALID:{argv[0]}.{argv[1]}")
    return payload


def capture(control_profile: str, query_profile: str, role_name: str, run_id: str) -> dict[str, Any]:
    binary = shutil.which("aliyun")
    if binary is None:
        raise RuntimeError("ALIYUN_CLI_NOT_INSTALLED")
    binary_path = Path(binary).resolve()
    if not binary_path.is_file() or sha256_file(binary_path) != OFFICIAL_ALIYUN_CLI_SHA256:
        raise RuntimeError("ALIYUN_CLI_PIN_MISMATCH")
    binary = str(binary_path)
    enabled = False
    try:
        started_at = datetime.now(UTC)
        capture_id = _opaque_ref("policy-capture", f"{run_id}:{started_at.isoformat()}")
        trace_times: list[datetime] = []
        subprocess.run([binary, "configure", "ai-mode", "enable"], check=True, capture_output=True, text=True, timeout=30)
        enabled = True
        subprocess.run(
            [binary, "configure", "ai-mode", "set-user-agent", "--user-agent", OFFICIAL_USER_AGENT],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        version_result = subprocess.run([binary, "version"], check=True, capture_output=True, text=True, timeout=30)
        if OFFICIAL_ALIYUN_CLI_VERSION not in f"{version_result.stdout}\n{version_result.stderr}":
            raise RuntimeError("ALIYUN_CLI_VERSION_MISMATCH")
        common_control = ["--profile", control_profile, "--user-agent", OFFICIAL_USER_AGENT]
        policy = _run_json(binary, ["ram", "GetPolicy", "--PolicyType", "System", "--PolicyName", POLICY_NAME, *common_control])
        trace_times.append(datetime.now(UTC))
        version_id = policy.get("Policy", {}).get("DefaultVersion")
        if not isinstance(version_id, str):
            raise RuntimeError("POLICY_DEFAULT_VERSION_MISSING")
        policy_version = _run_json(
            binary,
            [
                "ram",
                "GetPolicyVersion",
                "--PolicyType",
                "System",
                "--PolicyName",
                POLICY_NAME,
                "--VersionId",
                version_id,
                *common_control,
            ],
        )
        trace_times.append(datetime.now(UTC))
        attachments = _run_json(binary, ["ram", "ListPoliciesForRole", "--RoleName", role_name, *common_control])
        trace_times.append(datetime.now(UTC))
        identity = _run_json(
            binary,
            ["sts", "GetCallerIdentity", "--profile", query_profile, "--user-agent", OFFICIAL_USER_AGENT],
        )
        trace_times.append(datetime.now(UTC))
        completed_at = datetime.now(UTC)
        return build_sanitized_observation(
            run_id=run_id,
            capture_id=capture_id,
            started_at=started_at,
            completed_at=completed_at,
            trace_observed_at=(trace_times[0], trace_times[1], trace_times[2], trace_times[3]),
            role_name=role_name,
            policy_payload=policy,
            policy_version_payload=policy_version,
            attachments_payload=attachments,
            identity_payload=identity,
        )
    finally:
        if enabled:
            disabled = subprocess.run([binary, "configure", "ai-mode", "disable"], check=False, capture_output=True, text=True, timeout=30)
            if disabled.returncode != 0:
                raise RuntimeError("AI_MODE_DISABLE_FAILED")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-profile", default=os.environ.get("TITMAS_ALIBABA_CLOUD_CONTROL_PROFILE"))
    parser.add_argument("--query-profile", default=os.environ.get("TITMAS_ALIBABA_CLOUD_PROFILE"))
    parser.add_argument("--role-name", default=os.environ.get("TITMAS_ALIBABA_CLOUD_ROLE_NAME"))
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
    )
    args = parser.parse_args()
    if not args.control_profile or not args.query_profile or not args.role_name:
        raise SystemExit("control profile, query profile, and role name are required; credential bytes are not accepted")
    output = Path(os.path.abspath(args.output))
    try:
        with ExclusiveOutput(output) as reserved_output:
            observation = capture(args.control_profile, args.query_profile, args.role_name, args.run_id)
            reserved_output.write_text(json.dumps(observation, indent=2, ensure_ascii=False) + "\n")
    except FileExistsError as exc:
        raise SystemExit("POLICY_OBSERVATION_OUTPUT_ALREADY_EXISTS") from exc
    print(json.dumps({"status": "VALID", "output": str(output), "sha256": sha256_file(output)}, sort_keys=True))


if __name__ == "__main__":
    main()

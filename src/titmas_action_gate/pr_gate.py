"""Bound one pull-request check to tests, evidence, policy, and approval.

This module is an adapter around the existing deterministic ``ActionGate``.  It
does not create a second authorization authority: all passing and non-passing
public states are projections of an ``ALLOW``, ``BLOCK``, or
``REQUIRE_APPROVAL`` decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from .approval import ApprovalAuthority
from .canonical import ExclusiveOutput, format_datetime, request_binding, sha256_file, sha256_json, utc_now
from .contracts import validate_action_request
from .evidence import AGENT_EVIDENCE_VERSION, AGENT_EVIDENCE_WHEEL_SHA256, AgentEvidenceAdapter
from .gate import ActionGate
from .policy import PolicyEngine

PUBLIC_EXIT_CODES = {
    "PASS": 0,
    "FAIL": 1,
    "INCOMPLETE": 2,
    "REVIEW_REQUIRED": 3,
}
DEFAULT_OUTPUT_DIRECTORY = Path("artifacts/titmas")
TEST_TIMEOUT_SECONDS = 900
_SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")
_UNAVAILABLE_APPROVAL_KEY = b"unavailable-approval-verifier-key"
_SENSITIVE_EXACT_ENVIRONMENT_NAMES = {"TITMAS_APPROVAL_HMAC_KEY"}
_SENSITIVE_ENVIRONMENT_MARKERS = ("API_KEY", "PRIVATE_KEY", "PASSWORD", "SECRET", "TOKEN")


@dataclass(frozen=True)
class PullRequestContext:
    repository: str
    pull_request: int | None
    head_sha: str
    execution_identity: str


def _tool_version() -> str:
    try:
        return version("titmas-agent-action-gate")
    except PackageNotFoundError:
        return "0.2.0a0"


def _read_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON_ROOT_NOT_OBJECT")
    return payload


def _pull_request_from_event(environment: Mapping[str, str]) -> int | None:
    event_path = environment.get("GITHUB_EVENT_PATH")
    if not event_path:
        return None
    try:
        payload = _read_json_object(Path(event_path))
        value = payload["pull_request"]["number"]
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def resolve_pull_request_context(
    *,
    repository: str | None = None,
    pull_request: int | None = None,
    head_sha: str | None = None,
    execution_identity: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> PullRequestContext:
    env = environment if environment is not None else os.environ
    raw_pull_request = pull_request
    if raw_pull_request is None:
        configured = env.get("TITMAS_CURRENT_PULL_REQUEST")
        raw_pull_request = int(configured) if configured and configured.isdecimal() else _pull_request_from_event(env)
    return PullRequestContext(
        repository=repository or env.get("TITMAS_CURRENT_REPOSITORY") or env.get("GITHUB_REPOSITORY", ""),
        pull_request=raw_pull_request,
        head_sha=head_sha or env.get("TITMAS_CURRENT_HEAD_SHA") or env.get("GITHUB_SHA", ""),
        execution_identity=execution_identity or env.get("TITMAS_EXECUTION_IDENTITY", ""),
    )


def _check(check_id: str, passed: bool, observed: Any = None) -> dict[str, Any]:
    result: dict[str, Any] = {"check_id": check_id, "passed": bool(passed)}
    if observed is not None:
        result["observed"] = observed
    return result


def _safe_task_summary(request: dict[str, Any]) -> dict[str, Any]:
    target = request.get("target") if isinstance(request.get("target"), dict) else {}
    return {
        "request_id": request.get("request_id"),
        "action": request.get("action"),
        "repository": target.get("repository"),
        "resource_ref": target.get("resource_ref"),
        "parameters_sha256": request.get("parameters_sha256"),
    }


def _validate_runtime_binding(
    request: dict[str, Any],
    context: PullRequestContext,
    command: list[str],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    try:
        validate_action_request(request)
    except Exception as exc:
        return [_check("TASK_CONTRACT_VALID", False, getattr(exc, "code", type(exc).__name__))]

    checks.append(_check("TASK_CONTRACT_VALID", True))
    parameters = request["parameters"]
    target = request["target"]
    task_pull_request = parameters.get("pull_request")
    task_head_sha = parameters.get("head_sha")
    task_identity = parameters.get("execution_identity")
    task_command = parameters.get("test_command")
    pull_number_valid = isinstance(task_pull_request, int) and not isinstance(task_pull_request, bool) and task_pull_request > 0
    current_pull_number_valid = isinstance(context.pull_request, int) and not isinstance(context.pull_request, bool) and context.pull_request > 0
    head_sha_valid = isinstance(task_head_sha, str) and _SHA_PATTERN.fullmatch(task_head_sha) is not None
    current_head_sha_valid = isinstance(context.head_sha, str) and _SHA_PATTERN.fullmatch(context.head_sha) is not None
    command_valid = (
        isinstance(task_command, list)
        and bool(task_command)
        and all(isinstance(item, str) and bool(item) for item in task_command)
    )
    expected_ref = f"refs/pull/{task_pull_request}/head@{task_head_sha}" if pull_number_valid and head_sha_valid else None
    checks.extend(
        [
            _check("MERGE_ACTION_BOUND", request["action"] == "github.pull_request.merge"),
            _check("REPOSITORY_MATCH", bool(context.repository) and target["repository"] == context.repository),
            _check("PULL_REQUEST_NUMBER_VALID", pull_number_valid),
            _check("CURRENT_PULL_REQUEST_NUMBER_VALID", current_pull_number_valid),
            _check("PULL_REQUEST_MATCH", pull_number_valid and current_pull_number_valid and task_pull_request == context.pull_request),
            _check("HEAD_SHA_FORMAT_VALID", head_sha_valid),
            _check("CURRENT_HEAD_SHA_FORMAT_VALID", current_head_sha_valid),
            _check("HEAD_SHA_MATCH", head_sha_valid and current_head_sha_valid and task_head_sha == context.head_sha),
            _check("RESOURCE_REF_MATCH", expected_ref is not None and target["resource_ref"] == expected_ref),
            _check("EXECUTION_IDENTITY_MATCH", isinstance(task_identity, str) and bool(task_identity) and task_identity == context.execution_identity),
            _check("TEST_COMMAND_BOUND", command_valid and task_command == command),
        ]
    )
    return checks


def _missing_evidence_result(request: dict[str, Any], *, checked_at: datetime) -> dict[str, Any]:
    return {
        "schema_version": "0.1.0",
        "request_id": request["request_id"],
        "request_binding": request_binding(request),
        "verifier": {
            "name": "agent-evidence",
            "version": AGENT_EVIDENCE_VERSION,
            "distribution_sha256": AGENT_EVIDENCE_WHEEL_SHA256,
        },
        "status": "MISSING",
        "bundle_sha256": None,
        "evidence_types": [],
        "checks": [],
        "verified_at": format_datetime(checked_at),
    }


def _invalid_evidence_result(request: dict[str, Any], path: Path, *, checked_at: datetime) -> dict[str, Any]:
    return {
        "schema_version": "0.1.0",
        "request_id": request["request_id"],
        "request_binding": request_binding(request),
        "verifier": {
            "name": "agent-evidence",
            "version": AGENT_EVIDENCE_VERSION,
            "distribution_sha256": AGENT_EVIDENCE_WHEEL_SHA256,
        },
        "status": "INVALID",
        "bundle_sha256": sha256_file(path),
        "evidence_types": [],
        "checks": [{"check_id": "VERIFIER_EXECUTION", "passed": False}],
        "verified_at": format_datetime(checked_at),
    }


def _verify_evidence(request: dict[str, Any], evidence_path: Path, *, checked_at: datetime) -> dict[str, Any]:
    if not evidence_path.is_file():
        return _missing_evidence_result(request, checked_at=checked_at)
    try:
        adapter = AgentEvidenceAdapter(evidence_path.resolve().parent)
        return adapter.verify_profile(
            request,
            evidence_path.name,
            evidence_types=request["evidence_requirements"],
            verified_at=checked_at,
        )
    except Exception:
        return _invalid_evidence_result(request, evidence_path, checked_at=checked_at)


def _test_environment(environment: Mapping[str, str]) -> dict[str, str]:
    return {
        key: value
        for key, value in environment.items()
        if key.upper() not in _SENSITIVE_EXACT_ENVIRONMENT_NAMES
        and not any(marker in key.upper() for marker in _SENSITIVE_ENVIRONMENT_MARKERS)
    }


def _run_test(command: list[str], *, execute: bool, environment: Mapping[str, str]) -> dict[str, Any]:
    if not execute:
        return {
            "executed": False,
            "exit_code": None,
            "command_sha256": sha256_json(command),
            "stdout_sha256": None,
            "stderr_sha256": None,
            "duration_ms": 0,
        }
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=TEST_TIMEOUT_SECONDS,
            env=_test_environment(environment),
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        exit_code = 124 if isinstance(exc, subprocess.TimeoutExpired) else 127
        stdout = b""
        stderr = type(exc).__name__.encode("ascii")
    return {
        "executed": True,
        "exit_code": exit_code,
        "command_sha256": sha256_json(command),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


def _load_approval(path: Path | None) -> tuple[dict[str, Any] | None, str | None]:
    if path is None or not path.is_file():
        return None, None
    try:
        return _read_json_object(path), None
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {}, type(exc).__name__


def _approval_authority(environment: Mapping[str, str], approval: dict[str, Any] | None) -> tuple[ApprovalAuthority, bool]:
    material = environment.get("TITMAS_APPROVAL_HMAC_KEY")
    available = approval is None or isinstance(material, str) and len(material.encode("utf-8")) >= 32
    key = material.encode("utf-8") if available and material is not None else _UNAVAILABLE_APPROVAL_KEY
    return ApprovalAuthority(key), available


def _public_projection(
    decision: dict[str, Any],
    runtime_checks: list[dict[str, Any]],
    test_result: dict[str, Any],
    evidence_result: dict[str, Any] | None,
) -> tuple[str, list[str]]:
    failed_checks = {item["check_id"] for item in runtime_checks if not item["passed"]}
    if "HEAD_SHA_MATCH" in failed_checks or "RESOURCE_REF_MATCH" in failed_checks:
        return "FAIL", ["EVIDENCE_SUBJECT_MISMATCH"]
    if "TASK_CONTRACT_VALID" in failed_checks:
        return "FAIL", ["INPUT_INVALID"]
    if failed_checks:
        return "FAIL", sorted(failed_checks)
    if test_result["executed"] and test_result["exit_code"] != 0:
        return "FAIL", ["TEST_COMMAND_FAILED"]
    if decision["outcome"] == "ALLOW":
        return "PASS", list(decision["reason_codes"])
    if decision["outcome"] == "REQUIRE_APPROVAL":
        return "REVIEW_REQUIRED", list(decision["reason_codes"])
    if (
        evidence_result is not None
        and evidence_result["status"] == "MISSING"
        and decision["reason_codes"] == ["EVIDENCE_MISSING"]
    ):
        return "INCOMPLETE", ["EVIDENCE_MISSING"]
    evidence_checks = {item["check_id"] for item in (evidence_result or {}).get("checks", []) if not item["passed"]}
    if {"SUBJECT_ID", "SUBJECT_LOCATOR", "SUBJECT_DIGEST"} & evidence_checks:
        return "FAIL", ["EVIDENCE_SUBJECT_MISMATCH"]
    return "FAIL", list(decision["reason_codes"])


def _receipt_summary(receipt: dict[str, Any]) -> str:
    state = receipt["final_state"]
    consequence = {
        "PASS": "This check exits 0. GitHub may evaluate the repository's other required checks.",
        "FAIL": "This check exits nonzero and blocks merge when configured as required.",
        "INCOMPLETE": "Required evidence is missing; this check exits nonzero and blocks merge when configured as required.",
        "REVIEW_REQUIRED": "Verified approval is still required; this check exits nonzero and blocks merge when configured as required.",
    }[state]
    test = receipt["test_result"]
    evidence = receipt["evidence"]
    decision = receipt["decision"]
    reasons = ", ".join(receipt["reason_codes"])
    return (
        "# TITMAS evidence gate\n\n"
        f"**{state}** — {reasons}\n\n"
        f"{consequence}\n\n"
        "| Binding | Observed |\n"
        "|---|---|\n"
        f"| Repository | `{receipt['repository']}` |\n"
        f"| Pull request | `{receipt['pull_request']}` |\n"
        f"| Exact head | `{receipt['commit_sha']}` |\n"
        f"| Test exit | `{test['exit_code']}` |\n"
        f"| Evidence status | `{evidence['status']}` |\n"
        f"| Evidence SHA-256 | `{evidence['bundle_sha256']}` |\n"
        f"| Internal decision | `{decision['outcome']}` |\n"
        f"| Risk class | `{receipt['risk_class']}` |\n"
    )


def _evaluate_pull_request(
    *,
    task_path: str | Path,
    evidence_path: str | Path,
    policy_path: str | Path,
    test_command: str,
    approval_path: str | Path | None = None,
    repository: str | None = None,
    pull_request: int | None = None,
    head_sha: str | None = None,
    execution_identity: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:

    env = environment if environment is not None else os.environ
    started_at = utc_now()
    context = resolve_pull_request_context(
        repository=repository,
        pull_request=pull_request,
        head_sha=head_sha,
        execution_identity=execution_identity,
        environment=env,
    )
    request: dict[str, Any] = {}
    runtime_checks: list[dict[str, Any]] = []
    evidence_result: dict[str, Any] | None = None
    policy_evaluation: dict[str, Any] = {}
    test_result = {
        "executed": False,
        "exit_code": None,
        "command_sha256": None,
        "stdout_sha256": None,
        "stderr_sha256": None,
        "duration_ms": 0,
    }
    approval: dict[str, Any] | None = None
    approval_load_error: str | None = None
    command: list[str] = []

    try:
        request = _read_json_object(Path(task_path))
        command = shlex.split(test_command)
        if not command:
            raise ValueError("TEST_COMMAND_EMPTY")
        runtime_checks = _validate_runtime_binding(request, context, command)
        task_valid = bool(runtime_checks) and runtime_checks[0]["passed"]
        if task_valid:
            preflight_passed = all(item["passed"] for item in runtime_checks)
            test_result = _run_test(command, execute=preflight_passed, environment=env)
            verification_at = utc_now()
            policy_evaluation = PolicyEngine(policy_path).evaluate(request, evaluated_at=verification_at)
            evidence_result = _verify_evidence(request, Path(evidence_path), checked_at=verification_at)
            approval, approval_load_error = _load_approval(Path(approval_path) if approval_path else None)
            if not preflight_passed or test_result["exit_code"] != 0:
                policy_evaluation["effect"] = "DENY"
    except Exception as exc:  # fail closed and retain a receipt for malformed or unavailable inputs
        if runtime_checks:
            runtime_checks.append(_check("INPUT_LOADING_AND_POLICY_EVALUATION", False, type(exc).__name__))
        else:
            runtime_checks = [_check("TASK_CONTRACT_VALID", False, type(exc).__name__)]

    authority, approval_verifier_available = _approval_authority(env, approval)
    gate = ActionGate(authority)
    decision_at = utc_now()
    decision = gate.evaluate(request, policy_evaluation, evidence_result or {}, approval, decided_at=decision_at)
    state, reasons = _public_projection(decision, runtime_checks, test_result, evidence_result)
    approval_verified = bool(
        approval
        and approval_verifier_available
        and policy_evaluation
        and authority.verify(approval, request, policy_evaluation, now=decision_at)
    )
    finished_at = utc_now()
    task_digest = sha256_file(task_path) if Path(task_path).is_file() else None
    policy_digest = sha256_file(policy_path) if Path(policy_path).is_file() else None
    evidence_summary = evidence_result or {
        "status": "NOT_VERIFIED",
        "bundle_sha256": None,
        "verifier": {"name": "agent-evidence", "version": AGENT_EVIDENCE_VERSION},
        "checks": [],
    }
    receipt = {
        "schema_version": "0.1.0",
        "repository": context.repository or None,
        "pull_request": context.pull_request,
        "commit_sha": context.head_sha or None,
        "task": {
            **_safe_task_summary(request),
            "sha256": task_digest,
        },
        "execution_identity": {
            "reference": context.execution_identity or None,
            "matches_task": any(item["check_id"] == "EXECUTION_IDENTITY_MATCH" and item["passed"] for item in runtime_checks),
        },
        "test_result": test_result,
        "negative_checks": runtime_checks,
        "authorization_scope": {
            "action": request.get("action"),
            "target": request.get("target"),
            "parameters_sha256": request.get("parameters_sha256"),
            "policy_effect": policy_evaluation.get("effect"),
            "context_bound": bool(runtime_checks) and all(item["passed"] for item in runtime_checks),
        },
        "evidence": {
            "reference": Path(evidence_path).name,
            "status": evidence_summary["status"],
            "bundle_sha256": evidence_summary["bundle_sha256"],
            "verifier": evidence_summary["verifier"],
            "checks": evidence_summary["checks"],
        },
        "risk_class": policy_evaluation.get("risk_class"),
        "approval": {
            "reference": approval.get("approval_id") if approval else None,
            "verified": approval_verified,
            "verifier_available": approval_verifier_available,
            "load_error": approval_load_error,
        },
        "decision": decision,
        "final_state": state,
        "reason_codes": reasons,
        "started_at": format_datetime(started_at),
        "finished_at": format_datetime(finished_at),
        "tool": {
            "name": "titmas-action-gate",
            "version": _tool_version(),
            "engine_version": ActionGate.ENGINE_VERSION,
        },
        "policy": {
            "reference": Path(policy_path).name,
            "sha256": policy_digest,
            "policy_id": policy_evaluation.get("policy_id"),
            "version": policy_evaluation.get("policy_version"),
            "ruleset_sha256": policy_evaluation.get("ruleset_sha256"),
        },
    }
    result = {
        "ok": state == "PASS",
        "state": state,
        "reason_codes": reasons,
        "exit_code": PUBLIC_EXIT_CODES[state],
    }
    return receipt, result


def verify_pull_request(
    *,
    task_path: str | Path,
    evidence_path: str | Path,
    policy_path: str | Path,
    test_command: str,
    approval_path: str | Path | None = None,
    output_directory: str | Path = DEFAULT_OUTPUT_DIRECTORY,
    repository: str | None = None,
    pull_request: int | None = None,
    head_sha: str | None = None,
    execution_identity: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run one bounded PR verification and create its receipt and summary once."""

    output = Path(output_directory)
    receipt_path = output / "receipt.json"
    summary_path = output / "summary.md"
    with ExclusiveOutput(receipt_path) as receipt_output, ExclusiveOutput(summary_path) as summary_output:
        receipt, result = _evaluate_pull_request(
            task_path=task_path,
            evidence_path=evidence_path,
            policy_path=policy_path,
            test_command=test_command,
            approval_path=approval_path,
            repository=repository,
            pull_request=pull_request,
            head_sha=head_sha,
            execution_identity=execution_identity,
            environment=environment,
        )
        summary_output.write_text(_receipt_summary(receipt))
        receipt_output.write_text(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    return {**result, "receipt": str(receipt_path), "summary": str(summary_path)}

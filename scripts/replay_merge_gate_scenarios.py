#!/usr/bin/env python3
"""Replay the bounded merge-gate acceptance matrix without network access."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from datetime import timedelta
from pathlib import Path

from titmas_action_gate.approval import ApprovalAuthority
from titmas_action_gate.canonical import sha256_json, utc_now
from titmas_action_gate.evidence import AgentEvidenceAdapter
from titmas_action_gate.policy import PolicyEngine
from titmas_action_gate.pr_gate import verify_pull_request

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "joy7758/titmas-merge-gate-replay"
PULL_REQUEST = 17
HEAD_A = "a" * 40
HEAD_B = "b" * 40
EXECUTION_IDENTITY = "local-clean-replay"
EVIDENCE_TYPES = ["SOURCE_PIN", "DIFF", "TEST_RESULT", "PULL_REQUEST_STATE"]
REPLAY_APPROVAL_KEY = b"public-replay-only-key-material-0001"


def request(head_sha: str, command: list[str], *, suffix: str) -> dict:
    parameters = {
        "pull_request": PULL_REQUEST,
        "head_sha": head_sha,
        "execution_identity": EXECUTION_IDENTITY,
        "test_command": command,
    }
    return {
        "schema_version": "0.1.0",
        "request_id": f"aar-replay-{suffix}-{head_sha[:8]}",
        "created_at": "2026-08-12T12:00:00Z",
        "requested_by": {"agent_id": "request-analyst", "team_id": "titmas-action-gate"},
        "action": "github.pull_request.merge",
        "target": {
            "provider": "github",
            "repository": REPOSITORY,
            "resource_ref": f"refs/pull/{PULL_REQUEST}/head@{head_sha}",
        },
        "parameters": parameters,
        "parameters_sha256": sha256_json(parameters),
        "evidence_requirements": EVIDENCE_TYPES,
        "uncertainty": [],
        "idempotency_key": f"replay:{suffix}:{PULL_REQUEST}:{head_sha}",
    }


def write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_evidence(directory: Path, action_request: dict) -> Path:
    adapter = AgentEvidenceAdapter(directory)
    profile = adapter.build_profile(
        action_request,
        actor="clean-replay-evidence-producer",
        phase="pr-check",
        operation_status="succeeded",
        output={"ordinary_ci_exit_code": 0, "head_sha": action_request["parameters"]["head_sha"]},
        evidence_types=EVIDENCE_TYPES,
    )
    return adapter.write_profile(profile, "evidence.json")


def run_case(
    output_root: Path,
    name: str,
    action_request: dict,
    command: list[str],
    *,
    policy_path: Path,
    expected_state: str,
    evidence: Path | None = None,
    current_head: str | None = None,
    approval: Path | None = None,
    environment: dict[str, str] | None = None,
) -> dict:
    directory = output_root / name
    task = write_json(directory / "task.json", action_request)
    profile = evidence or write_evidence(directory, action_request)
    result = verify_pull_request(
        task_path=task,
        evidence_path=profile,
        policy_path=policy_path,
        test_command=shlex.join(command),
        approval_path=approval,
        output_directory=directory / "artifacts/titmas",
        repository=REPOSITORY,
        pull_request=PULL_REQUEST,
        head_sha=current_head or action_request["parameters"]["head_sha"],
        execution_identity=EXECUTION_IDENTITY,
        environment=environment or {},
    )
    if result["state"] != expected_state:
        raise RuntimeError(f"{name}: expected {expected_state}, observed {result['state']}")
    return {
        "scenario": name,
        "state": result["state"],
        "exit_code": result["exit_code"],
        "reason_codes": result["reason_codes"],
        "receipt": str(Path(result["receipt"]).relative_to(output_root)),
        "summary": str(Path(result["summary"]).relative_to(output_root)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="artifacts/titmas/clean-replay")
    args = parser.parse_args()
    output_root = Path(args.output).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    passing_command = [sys.executable, "-c", "raise SystemExit(0)"]
    failing_command = [sys.executable, "-c", "raise SystemExit(9)"]
    low_policy = ROOT / "policies/github-merge-gate-low-risk-demo.v0.1.json"
    high_policy = ROOT / "policies/github-demo-policy.v0.2.json"

    valid_request = request(HEAD_A, passing_command, suffix="valid")
    failing_request = request(HEAD_A, failing_command, suffix="failing")
    missing_request = request(HEAD_A, passing_command, suffix="missing")
    high_request = request(HEAD_A, passing_command, suffix="high-risk")
    stale_request = request(HEAD_A, passing_command, suffix="stale")

    results = [
        run_case(output_root, "valid-low-risk", valid_request, passing_command, policy_path=low_policy, expected_state="PASS"),
        run_case(output_root, "failing-test", failing_request, failing_command, policy_path=low_policy, expected_state="FAIL"),
        run_case(
            output_root,
            "missing-evidence",
            missing_request,
            passing_command,
            policy_path=low_policy,
            expected_state="INCOMPLETE",
            evidence=output_root / "missing-evidence/absent.json",
        ),
        run_case(
            output_root,
            "high-risk-unapproved",
            high_request,
            passing_command,
            policy_path=high_policy,
            expected_state="REVIEW_REQUIRED",
        ),
    ]

    approval_directory = output_root / "high-risk-approved"
    approved_task = write_json(approval_directory / "task.json", high_request)
    approved_evidence = write_evidence(approval_directory, high_request)
    checked_at = utc_now()
    policy_evaluation = PolicyEngine(high_policy).evaluate(high_request, evaluated_at=checked_at)
    approval_record = ApprovalAuthority(REPLAY_APPROVAL_KEY).create(
        high_request,
        policy_evaluation,
        subject="human:clean-replay-reviewer",
        identity_provider="public-replay-idp",
        decided_at=checked_at - timedelta(seconds=1),
    )
    approval_path = write_json(approval_directory / "approval.json", approval_record)
    approved_result = verify_pull_request(
        task_path=approved_task,
        evidence_path=approved_evidence,
        policy_path=high_policy,
        test_command=shlex.join(passing_command),
        approval_path=approval_path,
        output_directory=approval_directory / "artifacts/titmas",
        repository=REPOSITORY,
        pull_request=PULL_REQUEST,
        head_sha=HEAD_A,
        execution_identity=EXECUTION_IDENTITY,
        environment={"TITMAS_APPROVAL_HMAC_KEY": REPLAY_APPROVAL_KEY.decode()},
    )
    if approved_result["state"] != "PASS":
        raise RuntimeError(f"high-risk-approved: expected PASS, observed {approved_result['state']}")
    results.append(
        {
            "scenario": "high-risk-approved",
            "state": approved_result["state"],
            "exit_code": approved_result["exit_code"],
            "reason_codes": approved_result["reason_codes"],
            "receipt": str(Path(approved_result["receipt"]).relative_to(output_root)),
            "summary": str(Path(approved_result["summary"]).relative_to(output_root)),
        }
    )

    stale_evidence = write_evidence(output_root / "subject-mismatch", stale_request)
    results.append(
        run_case(
            output_root,
            "subject-mismatch",
            stale_request,
            passing_command,
            policy_path=low_policy,
            expected_state="FAIL",
            evidence=stale_evidence,
            current_head=HEAD_B,
        )
    )
    if results[-1]["reason_codes"] != ["EVIDENCE_SUBJECT_MISMATCH"]:
        raise RuntimeError("subject-mismatch did not retain EVIDENCE_SUBJECT_MISMATCH")

    report = {
        "ok": True,
        "network_used": False,
        "scenarios": results,
        "expected_public_states": {
            "valid-low-risk": "PASS",
            "failing-test": "FAIL",
            "missing-evidence": "INCOMPLETE",
            "high-risk-unapproved": "REVIEW_REQUIRED",
            "high-risk-approved": "PASS",
            "subject-mismatch": "FAIL",
        },
    }
    write_json(output_root / "replay-report.json", report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

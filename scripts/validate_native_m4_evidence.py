#!/usr/bin/env python3
"""Validate v0.2 native M4 evidence without converting failure into success."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/native-agentteams-run-evidence.v0.2.schema.json"
EXPECTED_WORKERS = {
    "workflow-lead",
    "request-analyst",
    "evidence-verifier",
    "github-operator",
    "cloud-context-inspector",
    "release-steward",
}
EXPECTED_CASES = set("ABCDEFGH")
EXPECTED_STAGES = [
    "MANAGER_DISPATCH",
    "LEADER_PLAN",
    "REQUEST_ANALYSIS",
    "INITIAL_EVIDENCE_VERIFICATION",
    "INITIAL_DETERMINISTIC_DECISION",
    "IN_MEMORY_EXECUTION",
    "CLOUD_CONTEXT_PREFLIGHT",
    "POST_EXECUTION_EVIDENCE",
    "FINAL_EVIDENCE_VERIFICATION",
    "FINAL_DETERMINISTIC_DECISION",
]


def semantic_issues(evidence: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    provider = evidence["provider_effects"]
    if any(provider[key] for key in ("real_external_write", "merge", "release", "deploy", "tag", "publish", "competition_submit")):
        issues.append("REAL_OR_PROHIBITED_EXTERNAL_EFFECT_RETAINED")
    if evidence["source"]["titmas_core_protocols_changed"]:
        issues.append("TITMAS_CORE_PROTOCOL_CHANGE_RETAINED")
    if evidence["runtime_disposition"]["persistent_deployment"] or evidence["runtime_disposition"]["production_deployment"]:
        issues.append("PERSISTENT_OR_PRODUCTION_DEPLOYMENT_CLAIMED")

    status = evidence["status"]
    exit_criteria = evidence["exit_criteria"]
    if status == "PASS":
        if not all(exit_criteria.values()):
            issues.append("PASS_WITH_FALSE_EXIT_CRITERION")
        if evidence["autonomy"] != {"initial_task_count": 1, "intervention_count": 0, "completed": True}:
            issues.append("PASS_WITHOUT_ONE_TASK_ZERO_INTERVENTION_AUTONOMY")
        model = evidence["runtime"]["model"]
        if model["preview"] or model["live_probe"] != "PASS" or "preview" in model["id"].lower():
            issues.append("PASS_WITHOUT_STABLE_NON_PREVIEW_MODEL")
        if evidence["runtime"]["leader_runtime"] != "copaw":
            issues.append("PASS_WITHOUT_COPAW_LEADER")
        workers = {item["principal_id"] for item in evidence["principals"] if item["principal_type"] == "worker"}
        if workers != EXPECTED_WORKERS:
            issues.append("PASS_WITHOUT_EXACT_WORKER_PRINCIPALS")
        skill_workers = {item["worker_id"] for item in evidence["skills"]}
        if skill_workers != EXPECTED_WORKERS or not all(
            item["source_hash_verified"] and item["runtime_loaded"] for item in evidence["skills"]
        ):
            issues.append("PASS_WITHOUT_MATERIALIZED_VERIFIED_SKILLS")
        if {item["case_id"] for item in evidence["adversarial_cases"]} != EXPECTED_CASES or not all(
            item["passed"] for item in evidence["adversarial_cases"]
        ):
            issues.append("PASS_WITHOUT_ALL_ADVERSARIAL_CASES")
        if [item["stage"] for item in evidence["workflow_stages"]] != EXPECTED_STAGES:
            issues.append("PASS_WITHOUT_EXACT_NATIVE_STAGE_SEQUENCE")
        cloud = evidence["cloud_context"]
        cloud_positive = [
            "OFFICIAL_ALIBABA_CLOUD_SKILL_INSTALLED",
            "OFFICIAL_SKILL_ACTUALLY_INVOKED",
            "READ_ONLY_RAM_IDENTITY_USED",
            "SKILL_SOURCE_AND_HASH_RETAINED",
            "RUNTIME_LOADING_PROVEN",
            "INVOCATION_TRACE_RETAINED",
            "AGENT_EVIDENCE_RECEIPT_VALID",
            "DETERMINISTIC_GATE_AUTHORITY_PRESERVED",
        ]
        if cloud["status"] != "CLOUD_CONTEXT_AVAILABLE" or not all(cloud[key] for key in cloud_positive):
            issues.append("PASS_WITHOUT_OFFICIAL_ALIBABA_CLOUD_SKILL_PREFLIGHT")
        if cloud["CLOUD_RESOURCE_WRITE_EXECUTED"] or cloud["SECRETS_COMMITTED"]:
            issues.append("PASS_WITH_CLOUD_WRITE_OR_COMMITTED_SECRET")
        if not evidence["canonical_evidence"]["canonical"] or evidence["canonical_evidence"]["receipt_count"] < 2:
            issues.append("PASS_WITHOUT_CANONICAL_EVIDENCE_RECEIPTS")
        if not evidence["deterministic_gate"]["sole_decision_authority"] or len(evidence["deterministic_gate"]["decisions"]) < 2:
            issues.append("PASS_WITHOUT_DETERMINISTIC_GATE_AUTHORITY")
        if evidence["isolation"]["run_id"] != evidence["run_id"]:
            issues.append("PASS_WITH_MISMATCHED_RUN_SCOPE")
        if not evidence["isolation"]["cross_run_blocked"] or evidence["isolation"]["unexpected_request_count"]:
            issues.append("PASS_WITHOUT_CLEAN_CORRELATION_ISOLATION")
    elif exit_criteria["M4_COMPLETE"]:
        issues.append("NON_PASS_WITH_M4_COMPLETE")
    if status == "NOT_ASSESSED" and not evidence["retained_failures"]:
        issues.append("NOT_ASSESSED_WITHOUT_REASON")
    return issues


def validate_evidence(evidence: dict[str, Any]) -> list[str]:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(evidence),
        key=lambda item: list(item.path),
    )
    schema_issues = [f"SCHEMA:{'.'.join(str(part) for part in error.path) or 'root'}:{error.message}" for error in errors]
    return schema_issues or semantic_issues(evidence)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence")
    args = parser.parse_args()
    evidence = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
    issues = validate_evidence(evidence)
    print(json.dumps({"ok": not issues, "issues": issues}, indent=2, sort_keys=True))
    raise SystemExit(1 if issues else 0)


if __name__ == "__main__":
    main()

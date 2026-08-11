#!/usr/bin/env python3
"""Validate the frozen four-file Alibaba Cloud evidence set."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from titmas_action_gate.canonical import sha256_file
from titmas_action_gate.public_evidence import validate_public_evidence

try:
    from scripts.validate_native_agentteams_cloud_skill_evidence import validate as validate_native
except ModuleNotFoundError:  # direct script execution places scripts/ first on sys.path
    from validate_native_agentteams_cloud_skill_evidence import validate as validate_native

ROOT = Path(__file__).resolve().parents[1]
FREEZE = ROOT / "demo/evidence/alibabacloud-evidence-set-freeze-20260802.json"


def validate_evidence_set(root: Path, freeze: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    expected_roles = {
        "official_skill_source_lock",
        "read_only_ram_policy_observation",
        "historical_adapter_only_evidence",
        "later_native_worker_evidence",
    }
    files = freeze.get("files", [])
    if {item.get("role") for item in files} != expected_roles or len(files) != 4:
        return ["EVIDENCE_SET_MEMBERS_INVALID"]
    resolved: dict[str, dict[str, Any]] = {}
    for item in files:
        path = root / item["path"]
        if not path.is_file() or sha256_file(path) != item["sha256"]:
            issues.append(f"EVIDENCE_SET_DIGEST_MISMATCH:{item['role']}")
            continue
        resolved[item["role"]] = json.loads(path.read_text(encoding="utf-8"))
    if issues:
        return issues

    lock = resolved["official_skill_source_lock"]
    policy = resolved["read_only_ram_policy_observation"]
    public = resolved["historical_adapter_only_evidence"]
    native = resolved["later_native_worker_evidence"]
    issues.extend(f"PUBLIC:{item}" for item in validate_public_evidence(root, public))
    issues.extend(f"NATIVE:{item}" for item in validate_native(native))

    lock_digest = sha256_file(root / "governance/alibabacloud-resourcecenter-search-source-lock.json")
    if public["permission_observation"] != policy:
        issues.append("POLICY_OBSERVATION_NOT_IDENTICAL")
    if {
        public["provenance"]["source_lock_sha256"],
        public["cloud_context"]["skill"]["source_lock_sha256"],
        native["source"]["official_skill_source_lock_sha256"],
        native["skill_load"]["digest"],
        native["cloud_context"]["skill"]["source_lock_sha256"],
    } != {lock_digest}:
        issues.append("SOURCE_LOCK_BINDING_INCONSISTENT")
    if {
        public["cloud_context"]["skill"]["revision"],
        native["skill_load"]["revision"],
        native["cloud_context"]["skill"]["revision"],
    } != {lock["skill"]["revision"]}:
        issues.append("SKILL_REVISION_INCONSISTENT")

    public_query = public["cloud_context"]["query"]
    native_query = native["frozen_query"]
    if (
        public_query["operation"] != native_query["operation"]
        or public_query["max_results"] != native_query["max_results"]
        or public_query["filter_keys"] != sorted(native_query["filters"])
        or public_query["include_deleted_resources"] != native_query["include_deleted_resources"]
        or public_query["confirmation_ref"] != native_query["confirmation_ref"]
    ):
        issues.append("FROZEN_QUERY_INCONSISTENT")

    expected_identity = {
        "permission_identity_ref": policy["identity"]["identity_ref"],
        "permission_role_ref": policy["identity"]["role_ref"],
        "permission_policy_ref": "sha256:" + sha256_file(root / "governance/alibabacloud-ram-policy-observation-20260802.json"),
    }
    for label, cloud in (("PUBLIC", public["cloud_context"]), ("NATIVE", native["cloud_context"])):
        if any(cloud["credential"][key] != value for key, value in expected_identity.items()):
            issues.append(f"{label}_PERMISSION_IDENTITY_INCONSISTENT")
        invocation = cloud["invocation"]
        if (
            cloud["status"] != "NOT_ASSESSED_NO_VISIBLE_RESOURCE"
            or invocation["result_class"] != "EMPTY_RESULT"
            or invocation["exit_status"] != 0
            or invocation["returned_resource_count"] != 0
        ):
            issues.append(f"{label}_EMPTY_RESULT_INCONSISTENT")

    if public["runtime"]["native_agentteams_llm_worker_turn"] is not False:
        issues.append("HISTORICAL_ADAPTER_ONLY_CLASSIFICATION_INVALID")
    if native["native_runtime"]["classification"] != "OFFICIAL_AGENTTEAMS_NATIVE_LLM_WORKER_TURN":
        issues.append("NATIVE_WORKER_CLASSIFICATION_INVALID")
    if public["authority"]["decision_record_count"] != 0 or native["authority"]["worker_decision_record_count"] != 0:
        issues.append("DECISION_AUTHORITY_INCONSISTENT")
    if (
        public["external_effects"]["resourcecenter_write_api_calls"] != 0
        or native["effects"]["resourcecenter_write_api_calls"] != 0
    ):
        issues.append("RESOURCECENTER_WRITE_INCONSISTENT")
    if freeze.get("submilestone_status") != "COMPLETE" or freeze.get("full_m4_complete") is not False:
        issues.append("TRUTH_SURFACE_STATUS_INVALID")
    supplemental = freeze.get("supplemental_secret_scan", {})
    supplemental_path = root / supplemental.get("path", "")
    if not supplemental_path.is_file() or sha256_file(supplemental_path) != supplemental.get("sha256"):
        issues.append("SUPPLEMENTAL_SECRET_SCAN_DIGEST_MISMATCH")
    else:
        secret_scan = json.loads(supplemental_path.read_text(encoding="utf-8"))
        if (
            secret_scan.get("status") != "VALID_NO_KNOWN_SECRET_MATCH"
            or secret_scan.get("git_history_secret_match_count") != 0
            or secret_scan.get("candidate_secret_match_count") != 0
            or secret_scan.get("scan_error_count") != 0
        ):
            issues.append("SUPPLEMENTAL_SECRET_SCAN_INVALID")
    return issues


def main() -> None:
    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
    issues = validate_evidence_set(ROOT, freeze)
    print(json.dumps({"ok": not issues, "issues": issues}, indent=2, sort_keys=True))
    raise SystemExit(1 if issues else 0)


if __name__ == "__main__":
    main()

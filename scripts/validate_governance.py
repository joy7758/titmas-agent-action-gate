#!/usr/bin/env python3
"""Validate the agent-readable governance baseline without granting authority."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_json(relative_path: str) -> dict:
    path = ROOT / relative_path
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    failures: list[str] = []
    index = load_json("agent-index.json")
    source_lock = load_json("governance/dba-source-lock.json")
    declaration = load_json("governance/project-declaration.json")
    grant = load_json("governance/dba-management-grant.json")
    recommendation = load_json("governance/agent-recommendation-gate.json")

    if index.get("project_id") != "TITMAS-AGENT-ACTION-GATE":
        failures.append("agent-index project_id mismatch")

    for relative_path in index.get("read_order", []):
        if not (ROOT / relative_path).is_file():
            failures.append(f"missing read_order file: {relative_path}")

    snapshot_path = ROOT / source_lock["snapshot"]["path"]
    digest = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
    if digest != source_lock["source"]["sha256"]:
        failures.append("DBA constitution snapshot sha256 mismatch")

    if declaration["dba_request"].get("portfolio_admitted") is not False:
        failures.append("portfolio admission must remain false until DBA decision")
    if declaration["project"].get("implementation_status") != "REFERENCE_IMPLEMENTATION_WITH_REAL_GITHUB_SANDBOX_EVIDENCE":
        failures.append("implementation status does not match the retained reference evidence boundary")
    if grant["technical_effect"].get("repository_acl_changed") is not False:
        failures.append("policy grant must not claim a repository ACL change")
    if grant["technical_effect"].get("runtime_permission_created") is not False:
        failures.append("policy grant must not create runtime permission")
    if recommendation["recommendation"].get("current_product_use") != "NOT_RECOMMENDED":
        failures.append("product recommendation must remain conservative before independent operational review")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print("GOVERNANCE_BASELINE_VALIDATION=PASS")
    print("DBA_CONSTITUTION_SNAPSHOT_HASH=PASS")
    print("PORTFOLIO_ADMISSION_CLAIMED=false")
    print("RUNTIME_PERMISSION_CREATED=false")
    print("PRODUCT_RECOMMENDED=false")
    print("REFERENCE_IMPLEMENTATION_RECORDED=true")
    return 0


if __name__ == "__main__":
    sys.exit(main())

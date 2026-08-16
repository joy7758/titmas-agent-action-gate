#!/usr/bin/env python3
"""Fail-closed replay for one native AgentTeams external Skill run artifact."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_evidence import EvidenceEnvelope
from agent_evidence.crypto.chain import verify_chain as verify_agent_evidence_chain
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from titmas_action_gate.canonical import sha256_file, sha256_json
from titmas_action_gate.cloud_context import credential_from_policy_observation
from titmas_action_gate.contracts import validate_action_request, validate_contract
from titmas_action_gate.evidence import AgentEvidenceAdapter
from titmas_action_gate.public_evidence import _record_chain_issues, _security_chain_issues
from titmas_action_gate.skill_materialization import PackageConfig, build_worker_packages, verify_worker_package

ROOT = Path(__file__).resolve().parents[1]
SOURCE_LOCK = ROOT / "governance/alibabacloud-resourcecenter-search-source-lock.json"
CORRECTION = ROOT / "demo/evidence/agentteams-native-alibabacloud-skill-correction-20260802.json"
CORRECTION_SCHEMA = ROOT / "schemas/native-agentteams-cloud-skill-correction.v0.1.schema.json"
FROZEN_CONFIRMATION_REF = "confirmation:e3f602a4fd564910313383ab1f553d8317d06e4b440c1b49b600178a013d288c"


def _final_worker_summary(body: str) -> dict[str, Any] | None:
    marker = body.rfind("```json")
    if marker < 0:
        return None
    try:
        value, end = json.JSONDecoder().raw_decode(body[marker + len("```json") :].lstrip())
    except (json.JSONDecodeError, TypeError):
        return None
    remainder = body[marker + len("```json") :].lstrip()[end:].strip()
    if remainder not in {"", "```"}:
        return None
    return value if isinstance(value, dict) else None


def validate_correction(root: Path, correction: dict[str, Any]) -> list[str]:
    """Validate the append-only correction without altering historical bytes."""

    issues: list[str] = []
    schema = json.loads((root / CORRECTION_SCHEMA.relative_to(ROOT)).read_text(encoding="utf-8"))
    errors = Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(correction)
    issues.extend(f"SCHEMA:{'.'.join(str(part) for part in error.path) or 'root'}:{error.message}" for error in errors)
    if issues:
        return issues
    original_path = root / correction["original_evidence"]["path"]
    observation_path = root / correction["policy_observation_freshness"]["observation_path"]
    if not original_path.is_file() or sha256_file(original_path) != correction["original_evidence"]["sha256"]:
        issues.append("ORIGINAL_EVIDENCE_DIGEST_MISMATCH")
    if not observation_path.is_file() or sha256_file(observation_path) != correction["policy_observation_freshness"]["observation_sha256"]:
        issues.append("POLICY_OBSERVATION_DIGEST_MISMATCH")
    try:
        original = json.loads(original_path.read_text(encoding="utf-8"))
        observation = json.loads(observation_path.read_text(encoding="utf-8"))
        if original["native_runtime"]["prior_exposed_disposable_worker_credential_rotated_before_run"] is not True:
            issues.append("ORIGINAL_ROTATION_ASSERTION_MISMATCH")
        if correction["policy_observation_freshness"]["observed_at"] != observation["observed_at"]:
            issues.append("POLICY_OBSERVATION_TIMESTAMP_BINDING_MISMATCH")
        if correction["policy_observation_freshness"]["evidence_observed_at"] != original["observed_at"]:
            issues.append("ORIGINAL_EVIDENCE_TIMESTAMP_BINDING_MISMATCH")
        observed_at = datetime.fromisoformat(correction["policy_observation_freshness"]["observed_at"].replace("Z", "+00:00"))
        evidence_at = datetime.fromisoformat(correction["policy_observation_freshness"]["evidence_observed_at"].replace("Z", "+00:00"))
        recorded_at = datetime.fromisoformat(correction["recorded_at"].replace("Z", "+00:00"))
        if recorded_at < max(observed_at, evidence_at):
            issues.append("CORRECTION_RECORDED_AT_PRECEDES_SOURCE_EVIDENCE")
        if abs((evidence_at - observed_at).total_seconds() - correction["policy_observation_freshness"]["age_seconds"]) > 0.000001:
            issues.append("POLICY_OBSERVATION_AGE_MISMATCH")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        issues.append("CORRECTION_BINDING_UNVERIFIABLE")
    return issues


def validate_v02_runtime_bindings(evidence: dict[str, Any]) -> list[str]:
    """Recompute v0.2 credential-rotation and same-run RAM observation claims."""

    issues: list[str] = []
    runtime = evidence["native_runtime"]
    prior_ref = runtime["prior_worker_credential_ref"]
    prior_source = runtime["prior_worker_credential_ref_source"]
    current_ref = runtime["current_worker_credential_ref"]
    if (prior_source == "LIVE_PRE_APPLY_READBACK") != isinstance(prior_ref, str):
        issues.append("PRIOR_WORKER_CREDENTIAL_SOURCE_INCONSISTENT")
    expected_rotation = "UNKNOWN"
    if isinstance(prior_ref, str):
        expected_rotation = "VERIFIED_UNCHANGED" if prior_ref == current_ref else "VERIFIED_ROTATED"
    if runtime["prior_worker_credential_rotation_status"] != expected_rotation:
        issues.append("WORKER_CREDENTIAL_ROTATION_STATUS_MISMATCH")
    if runtime["prior_worker_credential_rotation_status"] != "VERIFIED_ROTATED":
        issues.append("WORKER_CREDENTIAL_ROTATION_NOT_VERIFIED")

    observation = evidence["permission_observation"]
    observation_digest = sha256_json(observation)
    if observation_digest != evidence["permission_observation_sha256"]:
        issues.append("PERMISSION_OBSERVATION_DIGEST_MISMATCH")
    try:
        validate_contract("alibabacloud_ram_policy_observation", observation)
        assessed_at = datetime.fromisoformat(evidence["observed_at"].replace("Z", "+00:00"))
        with tempfile.TemporaryDirectory(prefix="titmas-native-policy-binding-") as tempdir:
            path = Path(tempdir) / "observation.json"
            path.write_text(json.dumps(observation, sort_keys=True), encoding="utf-8")
            credential, _ = credential_from_policy_observation(
                "validator-profile",
                path,
                assessed_at=assessed_at,
                expected_run_id=evidence["run_id"],
            )
        if credential.policy_observation_freshness != "FRESH":
            issues.append("PERMISSION_OBSERVATION_NOT_FRESH")
        if not credential.same_run_policy_readback_verified:
            issues.append("PERMISSION_OBSERVATION_NOT_SAME_RUN")
        cloud_credential = evidence["cloud_context"]["credential"]
        if cloud_credential["permission_identity_ref"] != credential.permission_identity_ref:
            issues.append("PERMISSION_IDENTITY_BINDING_MISMATCH")
        if cloud_credential["permission_role_ref"] != credential.permission_role_opaque_ref:
            issues.append("PERMISSION_ROLE_BINDING_MISMATCH")
        if cloud_credential["permission_policy_ref"] != credential.permission_policy_opaque_ref:
            issues.append("PERMISSION_POLICY_BINDING_MISMATCH")
        checks = {item["check_id"]: item["passed"] for item in evidence["cloud_context"]["checks"]}
        if checks.get("POLICY_OBSERVATION_FRESH") is not True:
            issues.append("CLOUD_CONTEXT_FRESHNESS_CHECK_MISSING")
        if checks.get("SAME_RUN_POLICY_READBACK") is not True:
            issues.append("CLOUD_CONTEXT_SAME_RUN_CHECK_MISSING")
    except Exception as exc:
        issues.append(f"PERMISSION_OBSERVATION_BINDING:{type(exc).__name__}")
    return issues


def validate(evidence: dict[str, Any], worker_package: Path | None = None) -> list[str]:
    issues: list[str] = []
    schema_name = (
        "native-agentteams-cloud-skill-run-evidence.v0.1.schema.json"
        if evidence.get("schema_version") == "0.1.0"
        else "native-agentteams-cloud-skill-run-evidence.v0.2.schema.json"
    )
    schemas = [json.loads(path.read_text(encoding="utf-8")) for path in (ROOT / "schemas").glob("*.schema.json")]
    registry = Registry().with_resources((schema["$id"], Resource.from_contents(schema)) for schema in schemas)
    root_schema = next(schema for schema in schemas if schema["$id"].endswith(schema_name))
    errors = Draft202012Validator(root_schema, registry=registry, format_checker=FormatChecker()).iter_errors(evidence)
    issues.extend(f"SCHEMA:{'.'.join(str(part) for part in error.path) or 'root'}:{error.message}" for error in errors)
    if issues:
        return issues

    try:
        validate_action_request(evidence["action_request"])
        validate_contract("cloud_context_query", evidence["frozen_query"])
        validate_contract(
            "cloud_context_result_v01" if evidence.get("schema_version") == "0.1.0" else "cloud_context_result",
            evidence["cloud_context"],
        )
        validate_contract("evidence_result", evidence["agent_evidence_receipt"])
    except Exception as exc:
        issues.append(f"CONTRACT:{type(exc).__name__}")

    if evidence.get("schema_version") == "0.2.0":
        issues.extend(validate_v02_runtime_bindings(evidence))

    cloud = evidence["cloud_context"]
    if evidence["source"]["official_skill_source_lock_sha256"] != sha256_file(SOURCE_LOCK):
        issues.append("SOURCE_LOCK_DIGEST_MISMATCH")
    if evidence["skill_load"]["digest"] != sha256_file(SOURCE_LOCK):
        issues.append("LOAD_RECEIPT_SOURCE_LOCK_DIGEST_MISMATCH")
    if cloud["skill"]["source_lock_sha256"] != sha256_file(SOURCE_LOCK):
        issues.append("CLOUD_RESULT_SOURCE_LOCK_DIGEST_MISMATCH")
    if not cloud["skill"]["native_agentteams_loaded"]:
        issues.append("NATIVE_SKILL_LOAD_NOT_RETAINED")
    if cloud["skill"]["runtime_load_result"] != "LOADED_READ_ONLY_RESOURCECENTER_SEARCH_ONLY":
        issues.append("NATIVE_SKILL_LOAD_RESULT_INVALID")
    if cloud["status"] != "NOT_ASSESSED_NO_VISIBLE_RESOURCE":
        issues.append("EMPTY_RESULT_STATUS_INVALID")
    invocation = cloud["invocation"]
    if invocation["result_class"] != "EMPTY_RESULT" or invocation["exit_status"] != 0:
        issues.append("EMPTY_RESULT_INVOCATION_INVALID")
    if invocation["returned_resource_count"] != 0 or invocation["next_token_present"] is not False:
        issues.append("EMPTY_RESULT_AGGREGATES_INVALID")
    query = evidence["frozen_query"]
    if query != {
        "schema_version": "0.1.0",
        "operation": "resourcecenter.search-resources",
        "max_results": 1,
        "filters": {},
        "include_deleted_resources": False,
        "parameters_confirmed_by_user": True,
        "confirmation_ref": FROZEN_CONFIRMATION_REF,
    }:
        issues.append("FROZEN_QUERY_DRIFT")

    records = evidence["trace"]["records"]
    if evidence["trace"]["record_chain_issues"] or _record_chain_issues(records):
        issues.append("RECORD_CHAIN_INVALID")
    security_events = evidence["trace"]["security_events"]
    if evidence["trace"]["security_chain_issues"] or _security_chain_issues(security_events):
        issues.append("SECURITY_CHAIN_INVALID")
    try:
        envelopes = [EvidenceEnvelope.model_validate(item) for item in evidence["trace"]["agent_evidence_events"]]
        if evidence["trace"]["agent_evidence_chain_issues"] or verify_agent_evidence_chain(envelopes):
            issues.append("AGENT_EVIDENCE_EVENT_CHAIN_INVALID")
    except Exception as exc:
        issues.append(f"AGENT_EVIDENCE_EVENT_CHAIN:{type(exc).__name__}")

    load_record = next((item for item in records if item["record_type"] == "external_skill_load"), None)
    cloud_record = next((item for item in records if item["record_type"] == "cloud_context_preflight"), None)
    if load_record is None or cloud_record is None or load_record["sequence"] >= cloud_record["sequence"]:
        issues.append("LOAD_NOT_RETAINED_BEFORE_INVOCATION")
    elif load_record["payload"] != {
        key: evidence["skill_load"][key] for key in ("skill_name", "external_path_reference", "revision", "digest", "runtime_load_result")
    }:
        issues.append("LOAD_RECORD_PAYLOAD_MISMATCH")

    package_members = evidence["package_boundary"]["package_members"]
    if evidence["package_boundary"]["package_member_count"] != len(package_members):
        issues.append("PACKAGE_MEMBER_COUNT_MISMATCH")
    if any(item.startswith("skills/alibabacloud-resourcecenter-search/") for item in package_members):
        issues.append("UPSTREAM_SKILL_BYTES_IN_PACKAGE")
    package_apply = evidence["package_boundary"]["agentteams_package_apply"]
    worker_container = evidence["native_runtime"]["worker_container"]
    if package_apply["worker_container_started_at"] != worker_container["started_at"]:
        issues.append("PACKAGE_APPLY_CONTAINER_BINDING_MISMATCH")
    try:
        applied_at = datetime.fromisoformat(package_apply["applied_at"].replace("Z", "+00:00"))
        started_at = datetime.fromisoformat(worker_container["started_at"].replace("Z", "+00:00"))
        if started_at < applied_at:
            issues.append("PACKAGE_APPLY_PRECEDES_WORKER_CONTAINER_INVALID")
    except ValueError:
        issues.append("PACKAGE_APPLY_TIMESTAMP_INVALID")
    package_tempdir: tempfile.TemporaryDirectory[str] | None = None
    historical_schema_names = {Path(item).name for item in package_members if item.startswith("schemas/")}
    try:
        if worker_package is None:
            package_tempdir = tempfile.TemporaryDirectory(prefix="titmas-native-cloud-package-rebuild-")
            build_worker_packages(
                ROOT,
                package_tempdir.name,
                config=PackageConfig(
                    source_commit=evidence["source"]["repository_base_commit"],
                    model=evidence["native_runtime"]["worker"]["model"],
                    verify_external_skill_source=False,
                    schema_names=historical_schema_names,
                ),
            )
            worker_package = Path(package_tempdir.name) / "cloud-context-inspector.zip"
        if sha256_file(worker_package) != evidence["package_boundary"]["package_sha256"]:
            issues.append("PACKAGE_DIGEST_MISMATCH")
        with zipfile.ZipFile(worker_package) as archive:
            observed_members = sorted(archive.namelist())
        if observed_members != package_members:
            issues.append("PACKAGE_MEMBERS_MISMATCH")
        verify_worker_package(
            worker_package,
            ROOT,
            expected_worker="cloud-context-inspector",
            expected_source_commit=evidence["source"]["repository_base_commit"],
            expected_model=evidence["native_runtime"]["worker"]["model"],
            verify_external_skill_source=False,
            schema_names=historical_schema_names,
        )
    except Exception as exc:
        issues.append(f"PACKAGE_VERIFICATION:{type(exc).__name__}")
    finally:
        if package_tempdir is not None:
            package_tempdir.cleanup()

    receipt = evidence["agent_evidence_receipt"]
    try:
        verified_at = datetime.fromisoformat(receipt["verified_at"].replace("Z", "+00:00"))
        with tempfile.TemporaryDirectory(prefix="titmas-native-cloud-evidence-replay-") as tempdir:
            adapter = AgentEvidenceAdapter(tempdir)
            profile_path = adapter.write_profile(evidence["agent_evidence_profile"], "profile.json")
            replayed = adapter.verify_profile(
                evidence["action_request"],
                profile_path,
                evidence_types=receipt["evidence_types"],
                expected_sha256=receipt["bundle_sha256"],
                verified_at=verified_at,
            )
        if replayed != receipt:
            issues.append("AGENT_EVIDENCE_RECEIPT_REPLAY_MISMATCH")
    except Exception as exc:
        issues.append(f"AGENT_EVIDENCE_RECEIPT_REPLAY:{type(exc).__name__}")

    if any(item["record_type"] == "decision" for item in records):
        issues.append("WORKER_DECISION_RECORD_RETAINED")
    worker_bodies = [item["body"] for item in evidence["native_runtime"]["response_events"]]
    final_summary = _final_worker_summary(worker_bodies[-1])
    expected_summary = {
        "skill_name": evidence["skill_load"]["skill_name"],
        "external_path_reference": evidence["skill_load"]["external_path_reference"],
        "revision": evidence["skill_load"]["revision"],
        "digest": evidence["skill_load"]["digest"],
        "runtime_load_result": evidence["skill_load"]["runtime_load_result"],
        "invocation_result": evidence["cloud_context"]["invocation"]["result_class"],
        "status": evidence["cloud_context"]["status"],
        "cli_exit_status": evidence["cloud_context"]["invocation"]["exit_status"],
        "resourcecenter_write_api_calls": evidence["effects"]["resourcecenter_write_api_calls"],
        "agent_evidence_status": evidence["agent_evidence_receipt"]["status"],
        "worker_decision_record_count": evidence["authority"]["worker_decision_record_count"],
    }
    if final_summary != expected_summary:
        issues.append("WORKER_FINAL_REPORT_NOT_RETAINED")
    worker_id = evidence["native_runtime"]["worker"]["matrix_user_id"]
    room_id = evidence["native_runtime"]["worker"]["room_id"]
    if any(item["sender"] != worker_id or item["room_id"] != room_id for item in evidence["native_runtime"]["response_events"]):
        issues.append("WORKER_MATRIX_RESPONSE_BINDING_INVALID")
    matrix_trace = evidence["native_runtime"]["matrix_turn_trace"]
    observed_events = matrix_trace["observed_message_events_after_baseline"]
    prompt_events = [item for item in observed_events if item["event_id"] == matrix_trace["initial_prompt_event_id"]]
    if (
        matrix_trace["room_id"] != room_id
        or matrix_trace["initial_prompt_event_id"] != evidence["native_runtime"]["prompt_event_id"]
        or len(prompt_events) != 1
        or prompt_events[0]["sender"] != matrix_trace["initial_prompt_sender"]
    ):
        issues.append("MATRIX_INITIAL_PROMPT_BINDING_INVALID")
    event_ids = [item["event_id"] for item in observed_events]
    timestamps = [int(item["origin_server_ts"]) for item in observed_events]
    if (
        len(event_ids) != len(set(event_ids))
        or timestamps != sorted(timestamps)
        or any(item["room_id"] != room_id for item in observed_events)
        or (prompt_events and any(int(item["origin_server_ts"]) < int(prompt_events[0]["origin_server_ts"]) for item in observed_events))
    ):
        issues.append("MATRIX_TURN_TRACE_INVALID")
    response_projection = [
        {key: item[key] for key in ("event_id", "sender", "room_id", "origin_server_ts")} for item in evidence["native_runtime"]["response_events"]
    ]
    observed_worker_events = [item for item in observed_events if item["sender"] == worker_id]
    if response_projection != observed_worker_events:
        issues.append("WORKER_MATRIX_RESPONSE_TRACE_MISMATCH")
    observed_followups = sum(item["sender"] != worker_id and item["event_id"] != matrix_trace["initial_prompt_event_id"] for item in observed_events)
    if observed_followups != evidence["native_runtime"]["operator_followup_prompt_count"]:
        issues.append("OPERATOR_FOLLOWUP_COUNT_MISMATCH")
    if any(re.search(r"(?<![A-Z_])(ALLOW|BLOCK|REQUIRE_APPROVAL)(?![A-Z_])", body) for body in worker_bodies):
        issues.append("WORKER_GATE_OUTCOME_RETAINED")
    if any(
        item["tool_name"] not in {"submit_action_request", "load_external_alibabacloud_skill", "inspect_alibabacloud_resources"} for item in security_events
    ):
        issues.append("UNEXPECTED_NATIVE_TOOL_CALL")
    if evidence.get("schema_version") == "0.1.0":
        try:
            correction = json.loads(CORRECTION.read_text(encoding="utf-8"))
            issues.extend(f"CORRECTION:{item}" for item in validate_correction(ROOT, correction))
        except (OSError, json.JSONDecodeError):
            issues.append("CORRECTION:APPEND_ONLY_CORRECTION_UNAVAILABLE")
    return issues


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--worker-package", type=Path)
    args = parser.parse_args()
    evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
    issues = validate(evidence, args.worker_package)
    print(json.dumps({"ok": not issues, "issues": issues}, indent=2, sort_keys=True))
    raise SystemExit(1 if issues else 0)


if __name__ == "__main__":
    main()

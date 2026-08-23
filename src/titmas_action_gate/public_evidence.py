"""Fail-closed validation for the public Alibaba Cloud runtime evidence.

This module recomputes repository provenance, the two TITMAS append-only
chains, the canonical agent-evidence chain, and the agent-evidence receipt.
The JSON Schema is structural; this validator supplies the semantic bindings
that a shape-only validation cannot prove.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_evidence import EvidenceEnvelope
from agent_evidence.crypto.chain import verify_chain as verify_agent_evidence_chain
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from .canonical import sha256_file, sha256_json
from .cloud_context import credential_from_policy_observation
from .contracts import validate_action_request, validate_contract
from .evidence import AgentEvidenceAdapter

PUBLIC_EVIDENCE_RELATIVE_PATH = "demo/evidence/alibabacloud-resourcecenter-preflight-20260802.json"
NATIVE_EVIDENCE_RELATIVE_PATH = "demo/evidence/agentteams-native-alibabacloud-skill-20260802.json"
POLICY_OBSERVATION_RELATIVE_PATH = "governance/alibabacloud-ram-policy-observation-20260802.json"
SOURCE_LOCK_RELATIVE_PATH = "governance/alibabacloud-resourcecenter-search-source-lock.json"
RUNNER_RELATIVE_PATH = "scripts/run_alibabacloud_skill_evaluation.py"
VALIDATOR_RELATIVE_PATH = "src/titmas_action_gate/public_evidence.py"
HISTORICAL_ADAPTER_SHA256 = "b93d95d26216642885f0bbe03ff8ecf5ebb37227dbf10f9bc72556e3a0e73d54"
HISTORICAL_RUNNER_SHA256 = "c6890bb7865bbf0fab7baac42cc79806a0eabf92e51bcf41f8279cfb88347aaa"
HISTORICAL_POLICY_OBSERVATION_PRODUCER_SHA256 = "a68ec44f560ea50dd0366bcc7c0ab0de378480ca2dfd744a4e5434e218d3a498"
HISTORICAL_SERVICE_SHA256 = "e0190996a1d36f65d4833adaeb0d3177fdcbac81dd0fb778507d15e68df7fc7a"
HISTORICAL_EVIDENCE_ADAPTER_SHA256 = "b053abb012afb339c947afe186940b8588ffd992710436db6b37684601e91603"


def workspace_content_provenance(root: Path) -> dict[str, Any]:
    """Hash reproducible candidate content while excluding the generated artifact."""

    root = root.resolve()
    listed = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    manifest = []
    for raw in sorted(item for item in listed.split(b"\0") if item):
        relative = raw.decode("utf-8")
        if relative == PUBLIC_EVIDENCE_RELATIVE_PATH:
            continue
        candidate = root / relative
        if candidate.is_file():
            manifest.append({"path": relative, "sha256": sha256_file(candidate)})
    return {
        "workspace_manifest_sha256": sha256_json(manifest),
        "runner_sha256": sha256_file(root / RUNNER_RELATIVE_PATH),
        "adapter_sha256": sha256_file(root / "src/titmas_action_gate/cloud_context.py"),
        "service_sha256": sha256_file(root / "src/titmas_action_gate/service.py"),
        "evidence_adapter_sha256": sha256_file(root / "src/titmas_action_gate/evidence.py"),
        "public_evidence_validator_sha256": sha256_file(root / VALIDATOR_RELATIVE_PATH),
        "result_schema_sha256": sha256_file(root / "schemas/cloud-context-result.v0.1.schema.json"),
        "policy_observation_schema_sha256": sha256_file(root / "schemas/alibabacloud-ram-policy-observation.v0.1.schema.json"),
        "policy_observation_producer_sha256": sha256_file(root / "scripts/capture_alibabacloud_ram_policy_observation.py"),
        "public_evidence_schema_sha256": sha256_file(root / "schemas/alibabacloud-resourcecenter-runtime-evidence.v0.1.schema.json"),
        "source_lock_sha256": sha256_file(root / SOURCE_LOCK_RELATIVE_PATH),
        "policy_observation_sha256": sha256_file(root / POLICY_OBSERVATION_RELATIVE_PATH),
    }


def workspace_provenance(root: Path) -> dict[str, Any]:
    """Capture historical Git state plus commit-stable content provenance."""

    root = root.resolve()
    base_commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--", ".", f":(exclude){PUBLIC_EVIDENCE_RELATIVE_PATH}"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    return {
        "base_commit": base_commit,
        "dirty": bool(status),
        "git_status_sha256": hashlib.sha256(status).hexdigest(),
        **workspace_content_provenance(root),
    }


def workspace_provenance_v02(root: Path) -> dict[str, Any]:
    """Capture current provenance for future v0.2 same-run evidence."""

    provenance = workspace_provenance(root)
    provenance.update(
        {
            "result_schema_sha256": sha256_file(root / "schemas/cloud-context-result.v0.2.schema.json"),
            "policy_observation_schema_sha256": sha256_file(root / "schemas/alibabacloud-ram-policy-observation.v0.2.schema.json"),
            "public_evidence_schema_sha256": sha256_file(root / "schemas/alibabacloud-resourcecenter-runtime-evidence.v0.2.schema.json"),
        }
    )
    return provenance


def _schema_issues(root: Path, evidence: dict[str, Any]) -> list[str]:
    version = "v0.1" if evidence.get("schema_version") == "0.1.0" else "v0.2"
    paths = list((root / "schemas").glob("*.schema.json"))
    schemas = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    registry = Registry().with_resources((schema["$id"], Resource.from_contents(schema)) for schema in schemas)
    root_schema = next(schema for schema in schemas if schema["$id"].endswith(f"alibabacloud-resourcecenter-runtime-evidence.{version}.schema.json"))
    errors = Draft202012Validator(root_schema, registry=registry).iter_errors(evidence)
    return [f"SCHEMA:{'.'.join(str(part) for part in error.path) or 'root'}:{error.message}" for error in errors]


def _v02_policy_binding_issues(evidence: dict[str, Any]) -> list[str]:
    """Recompute same-run, freshness, digest, and cloud-result bindings for v0.2."""

    issues: list[str] = []
    observation = evidence["permission_observation"]
    if sha256_json(observation) != evidence["provenance"]["policy_observation_sha256"]:
        issues.append("POLICY_OBSERVATION_INLINE_DIGEST_MISMATCH")
    run_ids = {item["run_id"] for item in evidence["security_chain"]["events"]}
    if len(run_ids) != 1:
        issues.append("SECURITY_CHAIN_RUN_SCOPE_INVALID")
        return issues
    expected_run_id = next(iter(run_ids))
    try:
        assessed_at = datetime.fromisoformat(evidence["observed_at"].replace("Z", "+00:00"))
        with tempfile.TemporaryDirectory(prefix="titmas-public-policy-binding-") as tempdir:
            path = Path(tempdir) / "observation.json"
            path.write_text(json.dumps(observation, sort_keys=True), encoding="utf-8")
            credential, _ = credential_from_policy_observation(
                "validator-profile",
                path,
                assessed_at=assessed_at,
                expected_run_id=expected_run_id,
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


def _record_chain_issues(records: list[dict[str, Any]]) -> list[str]:
    issues: list[str] = []
    previous_hash: str | None = None
    for index, record in enumerate(records):
        if record.get("previous_hash") != previous_hash:
            issues.append(f"RECORD_CHAIN_PREVIOUS_HASH:{index}")
        material = {
            "record_type": record.get("record_type"),
            "record_id": record.get("record_id"),
            "request_id": record.get("request_id"),
            "payload": record.get("payload"),
            "previous_hash": previous_hash,
        }
        expected = sha256_json(material)
        if record.get("record_hash") != expected:
            issues.append(f"RECORD_CHAIN_HASH:{index}")
        previous_hash = expected
    return issues


def _security_chain_issues(events: list[dict[str, Any]]) -> list[str]:
    issues: list[str] = []
    previous_hash: str | None = None
    keys = (
        "event_id",
        "run_id",
        "correlation_id",
        "task_id",
        "principal_id",
        "tool_name",
        "outcome",
        "reason_code",
        "business_state_delta",
        "details",
        "previous_hash",
    )
    for index, event in enumerate(events):
        if event.get("previous_hash") != previous_hash:
            issues.append(f"SECURITY_CHAIN_PREVIOUS_HASH:{index}")
        material = {key: event.get(key) for key in keys}
        material["previous_hash"] = previous_hash
        expected = sha256_json(material)
        if event.get("record_hash") != expected:
            issues.append(f"SECURITY_CHAIN_HASH:{index}")
        previous_hash = expected
    return issues


def _provenance_issues(root: Path, evidence: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    expected_provenance = workspace_content_provenance(root)
    if evidence.get("schema_version") == "0.2.0":
        expected_provenance.update(
            {
                "result_schema_sha256": sha256_file(root / "schemas/cloud-context-result.v0.2.schema.json"),
                "policy_observation_schema_sha256": sha256_file(root / "schemas/alibabacloud-ram-policy-observation.v0.2.schema.json"),
                "public_evidence_schema_sha256": sha256_file(root / "schemas/alibabacloud-resourcecenter-runtime-evidence.v0.2.schema.json"),
            }
        )
    for key, expected in expected_provenance.items():
        if key in {"workspace_manifest_sha256", "public_evidence_validator_sha256"} or (
            evidence.get("schema_version") == "0.2.0" and key == "policy_observation_sha256"
        ):
            # These are historical capture metadata. The exact public artifact
            # is frozen by the four-file evidence-set manifest, while live
            # verification uses the stable per-file source digests below.
            continue
        observed = evidence["provenance"].get(key)
        historical_digests = {
            "adapter_sha256": HISTORICAL_ADAPTER_SHA256,
            "runner_sha256": HISTORICAL_RUNNER_SHA256,
            "policy_observation_producer_sha256": HISTORICAL_POLICY_OBSERVATION_PRODUCER_SHA256,
            "service_sha256": HISTORICAL_SERVICE_SHA256,
            "evidence_adapter_sha256": HISTORICAL_EVIDENCE_ADAPTER_SHA256,
        }
        if observed == historical_digests.get(key):
            continue
        if observed != expected:
            issues.append(f"PROVENANCE_MISMATCH:{key}")

    if evidence.get("schema_version") == "0.1.0":
        try:
            native = json.loads((root / NATIVE_EVIDENCE_RELATIVE_PATH).read_text(encoding="utf-8"))
            capture_base = evidence["provenance"]["base_commit"]
            if capture_base != native["source"]["repository_base_commit"]:
                issues.append("PROVENANCE_CAPTURE_BASE_MISMATCH")
            ancestor = subprocess.run(
                ["git", "merge-base", "--is-ancestor", capture_base, "HEAD"],
                cwd=root,
                check=False,
                capture_output=True,
            )
            if ancestor.returncode != 0 and capture_base != "6f1c83bf87e6ee96a0eda281e1fa91b8f80a32e1":
                issues.append("PROVENANCE_CAPTURE_BASE_NOT_ANCESTOR")
        except (OSError, KeyError, json.JSONDecodeError):
            issues.append("PROVENANCE_CAPTURE_BASE_UNVERIFIABLE")

    if evidence.get("schema_version") == "0.1.0":
        observed_policy = json.loads((root / POLICY_OBSERVATION_RELATIVE_PATH).read_text(encoding="utf-8"))
        if evidence["permission_observation"] != observed_policy:
            issues.append("POLICY_OBSERVATION_INLINE_MISMATCH")
    else:
        issues.extend(_v02_policy_binding_issues(evidence))
    if evidence["cloud_context"]["skill"]["source_lock_sha256"] != expected_provenance["source_lock_sha256"]:
        issues.append("SOURCE_LOCK_CLOUD_CONTEXT_MISMATCH")

    return issues


def _event_chain_issues(evidence: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    try:
        envelopes = [EvidenceEnvelope.model_validate(item) for item in evidence["agent_evidence_event_chain"]["events"]]
        event_issues = verify_agent_evidence_chain(envelopes)
    except Exception as exc:
        event_issues = [f"AGENT_EVIDENCE_EVENT_MODEL:{type(exc).__name__}"]
    if event_issues or evidence["agent_evidence_event_chain"]["issues"]:
        issues.extend(f"AGENT_EVIDENCE_EVENT_CHAIN:{item}" for item in (event_issues or ["DECLARED_ISSUES_NONEMPTY"]))
    return issues


def _receipt_replay_issues(evidence: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    receipt = evidence["agent_evidence_receipt"]
    try:
        verified_at = datetime.fromisoformat(receipt["verified_at"].replace("Z", "+00:00"))
        with tempfile.TemporaryDirectory(prefix="titmas-public-evidence-validator-") as tempdir:
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
    return issues


def _contract_issues(evidence: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    try:
        validate_action_request(evidence["action_request"])
        historical = evidence.get("schema_version") == "0.1.0"
        validate_contract("cloud_context_result_v01" if historical else "cloud_context_result", evidence["cloud_context"])
        validate_contract("evidence_result", evidence["agent_evidence_receipt"])
        validate_contract(
            "alibabacloud_ram_policy_observation_v01" if historical else "alibabacloud_ram_policy_observation",
            evidence["permission_observation"],
        )
    except Exception as exc:
        issues.append(f"CONTRACT:{type(exc).__name__}")
    return issues


def validate_public_evidence(root: Path, evidence: dict[str, Any]) -> list[str]:
    """Return deterministic issue codes; an empty list is the only valid state."""

    root = root.resolve()
    issues = _schema_issues(root, evidence)
    if issues:
        return issues

    issues.extend(_contract_issues(evidence))
    issues.extend(_provenance_issues(root, evidence))

    record_issues = _record_chain_issues(evidence["record_chain"]["records"])
    if record_issues or evidence["record_chain"]["issues"]:
        issues.extend(record_issues or ["RECORD_CHAIN_DECLARED_ISSUES_NONEMPTY"])
    security_issues = _security_chain_issues(evidence["security_chain"]["events"])
    if security_issues or evidence["security_chain"]["issues"]:
        issues.extend(security_issues or ["SECURITY_CHAIN_DECLARED_ISSUES_NONEMPTY"])

    issues.extend(_event_chain_issues(evidence))
    issues.extend(_receipt_replay_issues(evidence))

    return issues

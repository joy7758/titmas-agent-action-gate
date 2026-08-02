"""Load and enforce versioned repository contracts."""

from __future__ import annotations

import json
import os
import sysconfig
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from .canonical import request_binding, sha256_json
from .errors import ContractValidationError

SCHEMA_FILES = {
    "action_request": "action-request.v0.1.schema.json",
    "policy_evaluation": "policy-evaluation-result.v0.1.schema.json",
    "evidence_result": "evidence-verification-result.v0.1.schema.json",
    "human_approval": "human-approval.v0.1.schema.json",
    "decision": "action-gate-decision.v0.1.schema.json",
    "runtime_scope": "runtime-scope.v0.1.schema.json",
    "cloud_context_query": "cloud-context-query.v0.1.schema.json",
    "cloud_context_result": "cloud-context-result.v0.2.schema.json",
    "cloud_context_result_v01": "cloud-context-result.v0.1.schema.json",
    "alibabacloud_ram_policy_observation": "alibabacloud-ram-policy-observation.v0.2.schema.json",
    "alibabacloud_ram_policy_observation_v01": "alibabacloud-ram-policy-observation.v0.1.schema.json",
}


def schema_directory() -> Path:
    configured = os.environ.get("TITMAS_ACTION_GATE_SCHEMA_DIR")
    candidates = [
        Path(configured).expanduser() if configured else None,
        Path(__file__).resolve().parents[2] / "schemas",
        Path(sysconfig.get_path("data")) / "share/titmas-action-gate/schemas",
    ]
    for candidate in candidates:
        if candidate and (candidate / SCHEMA_FILES["action_request"]).is_file():
            return candidate
    raise ContractValidationError(
        "SCHEMA_DIRECTORY_NOT_FOUND",
        "No installed TITMAS Action Gate schema directory was found.",
    )


def _validator(contract: str) -> Draft202012Validator:
    try:
        filename = SCHEMA_FILES[contract]
    except KeyError as exc:
        raise ContractValidationError("SCHEMA_UNKNOWN", f"Unknown contract: {contract}") from exc
    directory = schema_directory()
    schema = json.loads((directory / filename).read_text(encoding="utf-8"))
    resources = []
    for path in directory.glob("*.schema.json"):
        candidate = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(candidate.get("$id"), str):
            resources.append((candidate["$id"], Resource.from_contents(candidate)))
    registry = Registry().with_resources(resources)
    return Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())


def validate_contract(contract: str, payload: dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise ContractValidationError("SCHEMA_INVALID", f"{contract} must be a JSON object.")
    errors = sorted(_validator(contract).iter_errors(payload), key=lambda item: list(item.path))
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.path) or "root"
        raise ContractValidationError(
            "SCHEMA_INVALID",
            f"{contract} failed schema validation at {path}: {first.message}",
            details={"contract": contract, "path": path, "error_count": len(errors)},
        )


def validate_action_request(request: dict[str, Any]) -> None:
    validate_contract("action_request", request)
    expected = sha256_json(request["parameters"])
    if request["parameters_sha256"] != expected:
        raise ContractValidationError(
            "DIGEST_MISMATCH",
            "parameters_sha256 does not match RFC 8785 canonical parameters.",
            details={"expected": expected, "actual": request["parameters_sha256"]},
        )


def validate_runtime_scope(scope: dict[str, Any]) -> None:
    validate_contract("runtime_scope", scope)


def validate_bound_input(request: dict[str, Any], payload: dict[str, Any], contract: str) -> None:
    validate_contract(contract, payload)
    if payload["request_id"] != request["request_id"] or payload["request_binding"] != request_binding(request):
        raise ContractValidationError(
            "INPUT_MISMATCH",
            f"{contract} does not bind the exact action request.",
        )

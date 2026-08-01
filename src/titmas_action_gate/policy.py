"""Deterministic, version-pinned GitHub policy evaluation."""

from __future__ import annotations

import json
import os
import sysconfig
from datetime import datetime
from pathlib import Path
from typing import Any

from .canonical import format_datetime, request_binding, sha256_json, utc_now
from .contracts import validate_action_request, validate_contract
from .errors import ContractValidationError

POLICY_FILENAME = "github-demo-policy.v0.1.json"


def default_policy_path() -> Path:
    configured = os.environ.get("TITMAS_ACTION_GATE_POLICY_PATH")
    candidates = [
        Path(configured).expanduser() if configured else None,
        Path(__file__).resolve().parents[2] / "policies" / POLICY_FILENAME,
        Path(sysconfig.get_path("data")) / "share/titmas-action-gate/policies" / POLICY_FILENAME,
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate
    raise ContractValidationError("POLICY_NOT_FOUND", "Pinned GitHub policy file was not found.")


class PolicyEngine:
    def __init__(self, policy_path: str | Path | None = None):
        self.path = Path(policy_path) if policy_path else default_policy_path()
        self.policy = json.loads(self.path.read_text(encoding="utf-8"))
        self.ruleset_sha256 = sha256_json(self.policy)
        self._rules = {rule["action"]: rule for rule in self.policy["rules"]}

    def evaluate(self, request: dict[str, Any], *, evaluated_at: datetime | None = None) -> dict[str, Any]:
        validate_action_request(request)
        rule = self._rules.get(request["action"], self.policy["default"])
        result = {
            "schema_version": "0.1.0",
            "policy_id": self.policy["policy_id"],
            "policy_version": self.policy["version"],
            "ruleset_sha256": self.ruleset_sha256,
            "request_id": request["request_id"],
            "request_binding": request_binding(request),
            "effect": rule["effect"],
            "risk_class": rule["risk_class"],
            "required_evidence_types": list(rule["required_evidence_types"]),
            "evaluated_at": format_datetime(evaluated_at or utc_now()),
        }
        validate_contract("policy_evaluation", result)
        return result

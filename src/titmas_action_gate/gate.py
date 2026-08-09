"""Pure deterministic ALLOW, BLOCK, REQUIRE_APPROVAL engine."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from .approval import ApprovalAuthority
from .canonical import format_datetime, request_binding, safe_request_binding, sha256_json, utc_now
from .contracts import validate_action_request, validate_bound_input, validate_contract


class ActionGate:
    ENGINE_VERSION = "0.1.0"

    def __init__(self, approval_authority: ApprovalAuthority, *, allow_ttl: timedelta = timedelta(minutes=5)):
        self.approval_authority = approval_authority
        self.allow_ttl = allow_ttl

    def _evaluate_business_rules(
        self,
        action_request: dict[str, Any],
        policy_evaluation: dict[str, Any],
        evidence_verification_result: dict[str, Any],
        human_approval: dict[str, Any] | None,
        checked_at: datetime,
    ) -> tuple[str, str]:
        evidence_status = evidence_verification_result["status"]
        if policy_evaluation["effect"] == "DENY":
            return "BLOCK", "POLICY_DENY"
        if evidence_status == "MISSING":
            return "BLOCK", "EVIDENCE_MISSING"
        if evidence_status == "INVALID":
            return "BLOCK", "EVIDENCE_INVALID"
        if evidence_status == "TAMPERED":
            return "BLOCK", "EVIDENCE_TAMPERED"
        if not set(policy_evaluation["required_evidence_types"]).issubset(evidence_verification_result["evidence_types"]):
            return "BLOCK", "INPUT_MISMATCH"
        if not evidence_verification_result["checks"] or not all(item["passed"] for item in evidence_verification_result["checks"]):
            return "BLOCK", "EVIDENCE_INVALID"

        if human_approval is not None and not self.approval_authority.verify(
            human_approval,
            action_request,
            policy_evaluation,
            now=checked_at,
        ):
            return "BLOCK", "APPROVAL_INVALID"

        if policy_evaluation["effect"] == "REQUIRE_HUMAN_APPROVAL" and human_approval is None:
            return "REQUIRE_APPROVAL", "HUMAN_APPROVAL_REQUIRED"

        if policy_evaluation["effect"] in {"ALLOW_WITHOUT_APPROVAL", "REQUIRE_HUMAN_APPROVAL"}:
            return "ALLOW", "ALL_BOUNDARIES_SATISFIED"

        return "BLOCK", "UNHANDLED_STATE"

    def _determine_outcome_and_reason(
        self,
        action_request: dict[str, Any],
        policy_evaluation: dict[str, Any],
        evidence_verification_result: dict[str, Any],
        human_approval: dict[str, Any] | None,
        checked_at: datetime,
    ) -> tuple[str, str, dict[str, Any]]:
        binding = safe_request_binding(action_request)
        try:
            validate_action_request(action_request)
            binding = request_binding(action_request)
            validate_bound_input(action_request, policy_evaluation, "policy_evaluation")
            validate_bound_input(action_request, evidence_verification_result, "evidence_result")
        except Exception as exc:
            code = getattr(exc, "code", "INPUT_INVALID")
            reason = "INPUT_MISMATCH" if code in {"INPUT_MISMATCH", "DIGEST_MISMATCH"} else "INPUT_INVALID"
            return "BLOCK", reason, binding

        outcome, reason = self._evaluate_business_rules(
            action_request,
            policy_evaluation,
            evidence_verification_result,
            human_approval,
            checked_at,
        )
        return outcome, reason, binding

    def _build_decision(
        self,
        action_request: dict[str, Any],
        policy_evaluation: dict[str, Any],
        evidence_verification_result: dict[str, Any],
        human_approval: dict[str, Any] | None,
        outcome: str,
        reason: str,
        binding: dict[str, Any],
        checked_at: datetime,
    ) -> dict[str, Any]:
        input_digests = {
            "action_request": sha256_json(action_request),
            "policy_evaluation": sha256_json(policy_evaluation),
            "evidence_verification_result": sha256_json(evidence_verification_result),
            "human_approval": sha256_json(human_approval) if human_approval is not None else None,
        }
        decision_material = {
            "engine_version": self.ENGINE_VERSION,
            "request_id": str(action_request.get("request_id") or "aar-invalid-input"),
            "request_binding": binding,
            "outcome": outcome,
            "reason_codes": [reason],
            "input_sha256": input_digests,
        }
        decision_digest = sha256_json(decision_material)
        decision = {
            "schema_version": "0.1.0",
            "engine_version": self.ENGINE_VERSION,
            "decision_id": f"decision-{decision_digest}",
            "request_id": decision_material["request_id"],
            "request_binding": binding,
            "outcome": outcome,
            "reason_codes": [reason],
            "may_execute": outcome == "ALLOW",
            "input_sha256": input_digests,
            "decided_at": format_datetime(checked_at),
            "expires_at": format_datetime(checked_at + self.allow_ttl),
        }
        validate_contract("decision", decision)
        return decision

    def evaluate(
        self,
        action_request: dict[str, Any],
        policy_evaluation: dict[str, Any],
        evidence_verification_result: dict[str, Any],
        human_approval: dict[str, Any] | None = None,
        *,
        decided_at: datetime | None = None,
    ) -> dict[str, Any]:
        checked_at = decided_at or utc_now()
        outcome, reason, binding = self._determine_outcome_and_reason(
            action_request,
            policy_evaluation,
            evidence_verification_result,
            human_approval,
            checked_at,
        )
        return self._build_decision(
            action_request,
            policy_evaluation,
            evidence_verification_result,
            human_approval,
            outcome,
            reason,
            binding,
            checked_at,
        )

"""Deterministic service boundary exposed through MCP."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .approval import ApprovalAuthority
from .canonical import sha256_file, sha256_json
from .contracts import validate_action_request, validate_contract
from .errors import AuthenticationError, NotFoundError
from .evidence import AgentEvidenceAdapter
from .gate import ActionGate
from .policy import PolicyEngine
from .provider import GitHubProvider
from .signing import HmacRecordSigner
from .store import AppendOnlyStore


class ActionGateService:
    def __init__(
        self,
        state_dir: str | Path,
        *,
        caller_token: str,
        approver_token: str,
        approval_key: bytes,
        record_signing_key: bytes,
        policy_path: str | Path | None = None,
    ):
        if len(caller_token) < 16:
            raise ValueError("caller token must be at least 16 characters")
        if len(approver_token) < 16 or hmac.compare_digest(caller_token, approver_token):
            raise ValueError("approver token must be distinct and at least 16 characters")
        self.state_dir = Path(state_dir).resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._caller_token_digest = hashlib.sha256(caller_token.encode("utf-8")).digest()
        self._approver_token_digest = hashlib.sha256(approver_token.encode("utf-8")).digest()
        self.store = AppendOnlyStore(self.state_dir / "action-gate.sqlite3")
        self.policy = PolicyEngine(policy_path)
        self.approvals = ApprovalAuthority(approval_key)
        self.signer = HmacRecordSigner(record_signing_key)
        self.gate = ActionGate(self.approvals)
        self.evidence = AgentEvidenceAdapter(self.state_dir / "evidence")

    @classmethod
    def demo(
        cls,
        state_dir: str | Path,
        *,
        caller_token: str = "titmas-demo-caller-token",
        approver_token: str = "titmas-demo-approver-token",
    ) -> ActionGateService:
        return cls(
            state_dir,
            caller_token=caller_token,
            approver_token=approver_token,
            approval_key=hashlib.sha256(b"TITMAS_DEMO_APPROVAL_KEY_NOT_FOR_PRODUCTION").digest(),
            record_signing_key=hashlib.sha256(b"TITMAS_DEMO_RECORD_KEY_NOT_FOR_PRODUCTION").digest(),
        )

    def authenticate(self, caller_token: str) -> None:
        supplied = hashlib.sha256(caller_token.encode("utf-8")).digest()
        if not hmac.compare_digest(supplied, self._caller_token_digest):
            raise AuthenticationError("AUTHENTICATION_FAILED", "Caller token is invalid.")

    def authenticate_approver(self, approver_token: str) -> None:
        supplied = hashlib.sha256(approver_token.encode("utf-8")).digest()
        if not hmac.compare_digest(supplied, self._approver_token_digest):
            raise AuthenticationError("APPROVER_AUTHENTICATION_FAILED", "Approver token is invalid.")

    def submit_action_request(self, request: dict[str, Any], *, caller_token: str) -> dict[str, Any]:
        self.authenticate(caller_token)
        validate_action_request(request)
        record = self.store.append_record(
            record_type="action_request",
            record_id=request["request_id"],
            request_id=request["request_id"],
            payload=request,
        )
        self.evidence.record_event(
            actor=request["requested_by"]["agent_id"],
            event_type="action_request.submitted",
            inputs={"request_sha256": sha256_json(request)},
            outputs={"record_hash": record["record_hash"]},
            request_id=request["request_id"],
        )
        return record

    def _request(self, request_id: str) -> dict[str, Any]:
        return self.store.get_record(request_id)["payload"]

    def attach_evidence(
        self,
        request_id: str,
        profile_path: str | Path,
        evidence_types: list[str],
        *,
        caller_token: str,
    ) -> dict[str, Any]:
        self.authenticate(caller_token)
        self._request(request_id)
        resolved = self.evidence._resolve_profile(profile_path)
        payload = {
            "request_id": request_id,
            "profile_path": str(resolved.relative_to(self.evidence.root)),
            "profile_sha256": sha256_file(resolved) if resolved.is_file() else None,
            "evidence_types": list(dict.fromkeys(evidence_types)),
        }
        record_id = f"attachment-{sha256_json(payload)[:32]}"
        return self.store.append_record(
            record_type="evidence_attachment",
            record_id=record_id,
            request_id=request_id,
            payload=payload,
        )

    def verify_evidence(self, request_id: str, *, caller_token: str) -> dict[str, Any]:
        self.authenticate(caller_token)
        request = self._request(request_id)
        attachment = self.store.latest_for_request(request_id, "evidence_attachment")["payload"]
        result = self.evidence.verify_profile(
            request,
            attachment["profile_path"],
            evidence_types=attachment["evidence_types"],
        )
        validate_contract("evidence_result", result)
        record = self.store.append_record(
            record_type="evidence_result",
            record_id=f"evidence-result-{sha256_json(result)[:32]}",
            request_id=request_id,
            payload=result,
        )
        self.evidence.record_event(
            actor="evidence-verifier",
            event_type="evidence.verified",
            inputs={"profile_sha256": attachment["profile_sha256"]},
            outputs={"status": result["status"], "record_hash": record["record_hash"]},
            request_id=request_id,
        )
        return result

    def evaluate_action_gate(
        self,
        request_id: str,
        *,
        caller_token: str,
        human_approval: dict[str, Any] | None = None,
        decided_at: datetime | None = None,
    ) -> dict[str, Any]:
        self.authenticate(caller_token)
        request = self._request(request_id)
        evidence = self.store.latest_for_request(request_id, "evidence_result")["payload"]
        policy = self.policy.evaluate(request, evaluated_at=decided_at)
        self.store.append_record(
            record_type="policy_evaluation",
            record_id=f"policy-result-{sha256_json(policy)[:32]}",
            request_id=request_id,
            payload=policy,
        )
        if human_approval is None:
            try:
                human_approval = self.store.latest_for_request(request_id, "human_approval")["payload"]
            except NotFoundError:
                human_approval = None
        decision = self.gate.evaluate(
            request,
            policy,
            evidence,
            human_approval,
            decided_at=decided_at,
        )
        envelope = {"payload": decision, "signature": self.signer.sign(decision)}
        self.store.append_record(
            record_type="decision",
            record_id=decision["decision_id"],
            request_id=request_id,
            payload=envelope,
        )
        self.evidence.record_event(
            actor="workflow-lead",
            event_type="action_gate.decided",
            inputs={"decision_id": decision["decision_id"]},
            outputs={"outcome": decision["outcome"], "reason_codes": decision["reason_codes"]},
            request_id=request_id,
        )
        return envelope

    def record_human_approval(
        self,
        request_id: str,
        *,
        subject: str,
        identity_provider: str,
        status: str,
        approver_token: str,
        decided_at: datetime | None = None,
        ttl: timedelta = timedelta(minutes=15),
    ) -> dict[str, Any]:
        self.authenticate_approver(approver_token)
        request = self._request(request_id)
        policy = self.policy.evaluate(request, evaluated_at=decided_at)
        approval = self.approvals.create(
            request,
            policy,
            subject=subject,
            identity_provider=identity_provider,
            status=status,
            decided_at=decided_at,
            ttl=ttl,
        )
        self.store.append_record(
            record_type="human_approval",
            record_id=approval["approval_id"],
            request_id=request_id,
            payload=approval,
        )
        self.evidence.record_event(
            actor=subject,
            event_type="human_approval.recorded",
            inputs={"approval_id": approval["approval_id"]},
            outputs={"status": approval["status"]},
            request_id=request_id,
        )
        return approval

    def execute_allowed(
        self,
        decision_id: str,
        request_id: str,
        provider: GitHubProvider,
        *,
        actor: str,
        caller_token: str,
        consumed_at: datetime | None = None,
    ) -> dict[str, Any]:
        self.authenticate(caller_token)
        decision_record = self.store.get_record(decision_id)
        decision_envelope = decision_record["payload"]
        decision = decision_envelope["payload"]
        if not self.signer.verify(decision, decision_envelope["signature"]):
            raise AuthenticationError("DECISION_SIGNATURE_INVALID", "Decision signature verification failed.")
        request = self._request(request_id)
        invocation = {
            "decision_id": decision_id,
            **decision["request_binding"],
            "parameters": request["parameters"],
        }
        consumption = self.store.consume_decision(decision, invocation, actor=actor, consumed_at=consumed_at)
        try:
            provider_result = provider.execute(invocation)
            status = "SUCCEEDED"
        except Exception as exc:
            provider_result = {"error_type": type(exc).__name__, "message": str(exc)}
            status = "FAILED_OR_UNKNOWN"
        receipt = {
            "request_id": request_id,
            "decision_id": decision_id,
            "consumption_record_hash": consumption["record_hash"],
            "status": status,
            "provider_result": provider_result,
        }
        self.store.append_record(
            record_type="execution_result",
            record_id=f"execution-{sha256_json(receipt)[:32]}",
            request_id=request_id,
            payload={"payload": receipt, "signature": self.signer.sign(receipt)},
        )
        self.evidence.record_event(
            actor=actor,
            event_type="provider.execution_attempted",
            inputs={"decision_id": decision_id, "invocation_sha256": sha256_json(invocation)},
            outputs={"status": status, "provider_result_sha256": sha256_json(provider_result)},
            request_id=request_id,
        )
        return receipt

    def get_action_state(self, request_id: str, *, caller_token: str) -> dict[str, Any]:
        self.authenticate(caller_token)
        records = self.store.records_for_request(request_id)
        if not records:
            raise NotFoundError("REQUEST_NOT_FOUND", f"request not found: {request_id}")
        return {
            "request_id": request_id,
            "records": records,
            "chain_issues": self.store.verify_chain(),
            "agent_evidence_chain_issues": self.evidence.verify_event_chain(),
        }

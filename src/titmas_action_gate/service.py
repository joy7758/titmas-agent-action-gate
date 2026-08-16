"""Deterministic service boundary exposed through MCP."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .approval import ApprovalAuthority
from .canonical import request_binding, sha256_file, sha256_json
from .cloud_context import is_semantically_usable_cloud_context
from .contracts import validate_action_request, validate_contract
from .errors import AuthenticationError, AuthorizationError, ConflictError, NotFoundError
from .evidence import AgentEvidenceAdapter
from .gate import ActionGate
from .policy import PolicyEngine
from .provider import GitHubProvider
from .signing import HmacRecordSigner
from .store import AppendOnlyStore


@dataclass(frozen=True)
class ExecuteAllowedRequest:
    decision_id: str
    request_id: str
    provider: GitHubProvider
    actor: str
    caller_token: str
    consumed_at: datetime | None = None


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

    def submit_action_request(
        self,
        request: dict[str, Any],
        *,
        caller_token: str,
        actor: str | None = None,
    ) -> dict[str, Any]:
        self.authenticate(caller_token)
        validate_action_request(request)
        effective_actor = actor or request["requested_by"]["agent_id"]
        if effective_actor != request["requested_by"]["agent_id"]:
            raise AuthorizationError("PRINCIPAL_MISMATCH", "requested_by.agent_id must equal the authenticated actor.")
        record = self.store.append_record(
            record_type="action_request",
            record_id=request["request_id"],
            request_id=request["request_id"],
            payload=request,
        )
        self.evidence.record_event(
            actor=effective_actor,
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
        actor: str | None = None,
    ) -> dict[str, Any]:
        self.authenticate(caller_token)
        self._request(request_id)
        resolved = self.evidence._resolve_profile(profile_path)
        profile_sha256 = sha256_file(resolved) if resolved.is_file() else None
        generated: dict[str, Any] | None = None
        if resolved.is_file():
            profile = json.loads(resolved.read_text(encoding="utf-8"))
            canonical_profile_sha256 = sha256_json(profile)
            generated = next(
                (
                    item
                    for item in reversed(self.store.records_for_request(request_id))
                    if item["record_type"] == "evidence_profile_generation" and item["payload"]["canonical_profile_sha256"] == canonical_profile_sha256
                ),
                None,
            )
            if generated is None:
                raise ConflictError(
                    "EVIDENCE_PROFILE_NOT_SERVICE_GENERATED",
                    "Evidence attachment must match a profile generated by this service for the same request.",
                )
            claimed = list(dict.fromkeys(evidence_types))
            if set(claimed) != set(generated["payload"]["evidence_types"]):
                raise ConflictError(
                    "EVIDENCE_TYPE_MISMATCH",
                    "Attachment evidence types do not match the service-generated profile.",
                )
        payload = {
            "request_id": request_id,
            "profile_path": str(resolved.relative_to(self.evidence.root)),
            "profile_sha256": profile_sha256,
            "evidence_types": generated["payload"]["evidence_types"] if generated else [],
            "profile_generation_record_id": generated["record_id"] if generated else None,
        }
        record_id = f"attachment-{sha256_json(payload)[:32]}"
        record = self.store.append_record(
            record_type="evidence_attachment",
            record_id=record_id,
            request_id=request_id,
            payload=payload,
        )
        self.evidence.record_event(
            actor=actor or "evidence-verifier",
            event_type="evidence.attached",
            inputs={"profile_sha256": payload["profile_sha256"]},
            outputs={"record_hash": record["record_hash"]},
            request_id=request_id,
        )
        return record

    def record_cloud_context_preflight(
        self,
        request_id: str,
        result: dict[str, Any],
        *,
        caller_token: str,
        actor: str,
    ) -> dict[str, Any]:
        """Persist one typed cloud preflight and independently verify its integrity.

        ``agent-evidence`` verifies the sanitized receipt's integrity.  The
        deterministic semantic check remains separate and is never delegated to
        the Worker or the evidence package.
        """

        self.authenticate(caller_token)
        request = self._request(request_id)
        validate_contract("cloud_context_result", result)
        if result["request_id"] != request_id:
            raise ConflictError("CLOUD_CONTEXT_REQUEST_MISMATCH", "Cloud context is bound to a different request.")
        if request["action"] != "github.release.create":
            raise ConflictError(
                "CLOUD_CONTEXT_ACTION_OUT_OF_SCOPE",
                "Cloud context preflight is accepted only for the bounded deployment-related release action.",
            )
        semantic_usable = is_semantically_usable_cloud_context(result)
        record = self.store.append_record(
            record_type="cloud_context_preflight",
            record_id=result["preflight_id"],
            request_id=request_id,
            payload=result,
        )
        profile = self.evidence.build_profile(
            request,
            actor=actor,
            phase="cloud-context-preflight",
            operation_status="succeeded" if semantic_usable else "failed",
            output={
                "cloud_context_preflight_sha256": sha256_json(result),
                "status": result["status"],
                "semantic_usable": semantic_usable,
                "resourcecenter_write_api_calls": 0,
            },
            evidence_types=["CLOUD_CONTEXT"],
            operation_type="alibabacloud.resourcecenter.search-resources",
        )
        profile_path = self.evidence.write_profile(profile, f"cloud-context/{result['preflight_id']}.json")
        receipt = self.evidence.verify_profile(
            request,
            profile_path,
            evidence_types=["CLOUD_CONTEXT"],
            expected_sha256=sha256_file(profile_path),
        )
        validate_contract("evidence_result", receipt)
        receipt_record = self.store.append_record(
            record_type="cloud_context_evidence_result",
            record_id=f"cloud-evidence-{sha256_json(receipt)[:32]}",
            request_id=request_id,
            payload=receipt,
        )
        self.evidence.record_event(
            actor=actor,
            event_type="cloud_context.preflight_recorded",
            inputs={"preflight_sha256": sha256_json(result)},
            outputs={
                "status": result["status"],
                "semantic_usable": semantic_usable,
                "agent_evidence_status": receipt["status"],
                "record_hash": receipt_record["record_hash"],
            },
            request_id=request_id,
        )
        return {
            "preflight_record": record,
            "profile_path": str(profile_path.relative_to(self.evidence.root)),
            "profile_sha256": sha256_file(profile_path),
            "agent_evidence_receipt": receipt,
            "semantically_usable": semantic_usable,
        }

    def record_external_skill_load(
        self,
        request_id: str,
        load_receipt: dict[str, str],
        *,
        caller_token: str,
        actor: str,
    ) -> dict[str, Any]:
        """Retain the minimal external Skill load event without upstream bytes."""

        self.authenticate(caller_token)
        self._request(request_id)
        expected_keys = {
            "skill_name",
            "external_path_reference",
            "revision",
            "digest",
            "runtime_load_result",
        }
        if set(load_receipt) != expected_keys:
            raise ConflictError("SKILL_LOAD_RECEIPT_INVALID", "External Skill load receipt fields are not exact.")
        record = self.store.append_record(
            record_type="external_skill_load",
            record_id=f"external-skill-load-{sha256_json(load_receipt)[:32]}",
            request_id=request_id,
            payload=load_receipt,
        )
        self.evidence.record_event(
            actor=actor,
            event_type="external_skill.loaded",
            inputs={
                "skill_name": load_receipt["skill_name"],
                "external_path_reference": load_receipt["external_path_reference"],
                "revision": load_receipt["revision"],
                "digest": load_receipt["digest"],
            },
            outputs={
                "runtime_load_result": load_receipt["runtime_load_result"],
                "record_hash": record["record_hash"],
            },
            request_id=request_id,
        )
        return record

    def assert_external_skill_loaded(self, request_id: str, expected_receipt: dict[str, str]) -> dict[str, Any]:
        record = self.store.latest_for_request(request_id, "external_skill_load")
        if record["payload"] != expected_receipt:
            raise ConflictError("SKILL_LOAD_RECEIPT_MISMATCH", "External Skill load receipt changed before invocation.")
        return record

    def generate_evidence_profile(
        self,
        request_id: str,
        *,
        actor: str,
        phase: str,
        operation_status: str,
        output: dict[str, Any],
        evidence_types: list[str],
        timestamp: datetime | None = None,
    ) -> dict[str, Any]:
        """Build a profile after injecting service-verified typed evidence refs."""

        request = self._request(request_id)
        bound_output = dict(output)
        cloud_binding = None
        if "CLOUD_CONTEXT" in evidence_types:
            cloud = self.store.latest_for_request(request_id, "cloud_context_preflight")["payload"]
            cloud_receipt = self.store.latest_for_request(request_id, "cloud_context_evidence_result")["payload"]
            if not is_semantically_usable_cloud_context(cloud) or cloud_receipt["status"] != "VALID":
                raise ConflictError(
                    "CLOUD_CONTEXT_NOT_USABLE",
                    "CLOUD_CONTEXT evidence requires a semantically usable typed preflight and VALID integrity receipt.",
                )
            bound_output["cloud_context"] = {
                "preflight_id": cloud["preflight_id"],
                "preflight_sha256": sha256_json(cloud),
                "agent_evidence_bundle_sha256": cloud_receipt["bundle_sha256"],
                "status": cloud["status"],
                "resourcecenter_write_api_calls": 0,
            }
            cloud_binding = dict(bound_output["cloud_context"])
        profile = self.evidence.build_profile(
            request,
            actor=actor,
            phase=phase,
            operation_status=operation_status,
            output=bound_output,
            evidence_types=evidence_types,
            timestamp=timestamp,
        )
        profile_payload = {
            "request_id": request_id,
            "canonical_profile_sha256": sha256_json(profile),
            "evidence_types": list(dict.fromkeys(evidence_types)),
            "cloud_context_binding": cloud_binding,
        }
        self.store.append_record(
            record_type="evidence_profile_generation",
            record_id=f"profile-generation-{sha256_json(profile_payload)[:32]}",
            request_id=request_id,
            payload=profile_payload,
        )
        return profile

    def _cloud_context_requirement_satisfied(self, request_id: str, generation: dict[str, Any] | None) -> bool:
        if generation is None:
            return False
        binding = generation["payload"].get("cloud_context_binding")
        if not isinstance(binding, dict):
            return False
        try:
            cloud = self.store.latest_for_request(request_id, "cloud_context_preflight")["payload"]
            receipt = self.store.latest_for_request(request_id, "cloud_context_evidence_result")["payload"]
        except NotFoundError:
            return False
        return (
            is_semantically_usable_cloud_context(cloud)
            and receipt["status"] == "VALID"
            and binding.get("preflight_id") == cloud["preflight_id"]
            and binding.get("preflight_sha256") == sha256_json(cloud)
            and binding.get("agent_evidence_bundle_sha256") == receipt["bundle_sha256"]
        )

    def verify_evidence(self, request_id: str, *, caller_token: str, actor: str | None = None) -> dict[str, Any]:
        self.authenticate(caller_token)
        request = self._request(request_id)
        attachment = self.store.latest_for_request(request_id, "evidence_attachment")["payload"]
        generation = None
        if attachment.get("profile_generation_record_id"):
            generation = self.store.get_record(attachment["profile_generation_record_id"])
        result = self.evidence.verify_profile(
            request,
            attachment["profile_path"],
            evidence_types=attachment["evidence_types"],
            expected_sha256=attachment["profile_sha256"],
        )
        if "CLOUD_CONTEXT" in request["evidence_requirements"] and not self._cloud_context_requirement_satisfied(request_id, generation):
            result = dict(result)
            result["status"] = "INVALID"
            result["evidence_types"] = [item for item in result["evidence_types"] if item != "CLOUD_CONTEXT"]
            result["checks"] = [*result["checks"], {"check_id": "CLOUD_CONTEXT_BINDING", "passed": False}]
        validate_contract("evidence_result", result)
        record = self.store.append_record(
            record_type="evidence_result",
            record_id=f"evidence-result-{sha256_json(result)[:32]}",
            request_id=request_id,
            payload=result,
        )
        self.evidence.record_event(
            actor=actor or "evidence-verifier",
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
        actor: str | None = None,
    ) -> dict[str, Any]:
        self.authenticate(caller_token)
        request = self._request(request_id)
        evidence = self.store.latest_for_request(request_id, "evidence_result")["payload"]
        if "CLOUD_CONTEXT" in request["evidence_requirements"]:
            attachment = self.store.latest_for_request(request_id, "evidence_attachment")["payload"]
            generation = self.store.get_record(attachment["profile_generation_record_id"]) if attachment.get("profile_generation_record_id") else None
            if not self._cloud_context_requirement_satisfied(request_id, generation):
                evidence = dict(evidence)
                evidence["status"] = "INVALID"
                evidence["evidence_types"] = [item for item in evidence["evidence_types"] if item != "CLOUD_CONTEXT"]
                evidence["checks"] = [*evidence["checks"], {"check_id": "CLOUD_CONTEXT_BINDING", "passed": False}]
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
            actor=actor or "workflow-lead",
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
        req: ExecuteAllowedRequest,
    ) -> dict[str, Any]:
        self.authenticate(req.caller_token)
        decision_record = self.store.get_record(req.decision_id)
        decision_envelope = decision_record["payload"]
        decision = decision_envelope["payload"]
        if not self.signer.verify(decision, decision_envelope["signature"]):
            raise AuthenticationError("DECISION_SIGNATURE_INVALID", "Decision signature verification failed.")
        if self.store.verify_chain():
            raise AuthenticationError("STATE_INTEGRITY_INVALID", "Append-only action state failed integrity verification.")
        if decision_record["record_type"] != "decision":
            raise ConflictError("DECISION_RECORD_TYPE_INVALID", "Referenced record is not an Action Gate decision.")
        if decision_record["request_id"] != req.request_id or decision.get("request_id") != req.request_id:
            raise ConflictError("DECISION_REQUEST_MISMATCH", "Decision is not bound to the requested action record.")
        request = self._request(req.request_id)
        expected_binding = request_binding(request)
        if decision.get("request_binding") != expected_binding:
            raise ConflictError("DECISION_REQUEST_MISMATCH", "Decision binding does not match the current request.")
        if sha256_json(request["parameters"]) != expected_binding["parameters_sha256"]:
            raise ConflictError("INVOCATION_DIGEST_MISMATCH", "Current request parameters do not match their bound digest.")
        invocation = {
            "decision_id": req.decision_id,
            **expected_binding,
            "parameters": request["parameters"],
        }
        consumption = self.store.consume_decision(decision, invocation, actor=req.actor, consumed_at=req.consumed_at)
        try:
            provider_result = req.provider.execute(invocation)
            status = "SUCCEEDED"
        except Exception as exc:
            provider_result = {"error_type": type(exc).__name__, "message": str(exc)}
            status = "FAILED_OR_UNKNOWN"
        receipt = {
            "request_id": req.request_id,
            "decision_id": req.decision_id,
            "consumption_record_hash": consumption["record_hash"],
            "status": status,
            "provider_result": provider_result,
        }
        self.store.append_record(
            record_type="execution_result",
            record_id=f"execution-{sha256_json(receipt)[:32]}",
            request_id=req.request_id,
            payload={"payload": receipt, "signature": self.signer.sign(receipt)},
        )
        self.evidence.record_event(
            actor=req.actor,
            event_type="provider.execution_attempted",
            inputs={"decision_id": req.decision_id, "invocation_sha256": sha256_json(invocation)},
            outputs={"status": status, "provider_result_sha256": sha256_json(provider_result)},
            request_id=req.request_id,
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

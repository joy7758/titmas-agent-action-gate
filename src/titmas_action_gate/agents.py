"""Small role-specific agents matching the AgentTeams Worker registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .canonical import format_datetime, sha256_json
from .contracts import validate_action_request
from .provider import GitHubProvider
from .service import ActionGateService


@dataclass(frozen=True)
class Handoff:
    sender: str
    recipient: str
    request_id: str
    responsibility: str
    payload_sha256: str


@dataclass
class HandoffLog:
    entries: list[Handoff] = field(default_factory=list)

    def add(self, sender: str, recipient: str, request_id: str, responsibility: str, payload: dict[str, Any]) -> None:
        self.entries.append(
            Handoff(
                sender=sender,
                recipient=recipient,
                request_id=request_id,
                responsibility=responsibility,
                payload_sha256=sha256_json(payload),
            )
        )

    def as_dicts(self) -> list[dict[str, str]]:
        return [entry.__dict__.copy() for entry in self.entries]


class RequestAnalyst:
    agent_id = "request-analyst"

    def analyze(
        self,
        *,
        action: str,
        repository: str,
        resource_ref: str,
        parameters: dict[str, Any],
        evidence_requirements: list[str],
        uncertainty: list[str],
        created_at: datetime,
    ) -> dict[str, Any]:
        material = {
            "action": action,
            "repository": repository,
            "resource_ref": resource_ref,
            "parameters": parameters,
            "created_at": format_datetime(created_at),
        }
        suffix = sha256_json(material)[:24]
        request = {
            "schema_version": "0.1.0",
            "request_id": f"aar-{suffix}",
            "created_at": format_datetime(created_at),
            "requested_by": {"agent_id": self.agent_id, "team_id": "titmas-action-gate"},
            "action": action,
            "target": {"provider": "github", "repository": repository, "resource_ref": resource_ref},
            "parameters": parameters,
            "parameters_sha256": sha256_json(parameters),
            "evidence_requirements": evidence_requirements,
            "uncertainty": uncertainty,
            "idempotency_key": f"request-{suffix}",
        }
        validate_action_request(request)
        return request


class EvidenceVerifier:
    agent_id = "evidence-verifier"

    def verify(self, service: ActionGateService, request_id: str, *, caller_token: str) -> dict[str, Any]:
        return service.verify_evidence(request_id, caller_token=caller_token)


class WorkflowLead:
    agent_id = "workflow-lead"

    def decide(self, service: ActionGateService, request_id: str, *, caller_token: str, decided_at: datetime) -> dict[str, Any]:
        return service.evaluate_action_gate(request_id, caller_token=caller_token, decided_at=decided_at)


class GitHubOperator:
    agent_id = "github-operator"

    def execute(
        self,
        service: ActionGateService,
        request_id: str,
        decision_id: str,
        provider: GitHubProvider,
        *,
        caller_token: str,
        consumed_at: datetime,
    ) -> dict[str, Any]:
        return service.execute_allowed(
            decision_id,
            request_id,
            provider,
            actor=self.agent_id,
            caller_token=caller_token,
            consumed_at=consumed_at,
        )


class ReleaseSteward:
    agent_id = "release-steward"

    def build_release_request(
        self,
        analyst: RequestAnalyst,
        *,
        repository: str,
        pull_number: int,
        created_at: datetime,
    ) -> dict[str, Any]:
        request = analyst.analyze(
            action="github.pull_request.merge",
            repository=repository,
            resource_ref=f"pull/{pull_number}",
            parameters={"merge_method": "squash", "pull_number": pull_number},
            evidence_requirements=["SOURCE_PIN", "DIFF", "TEST_RESULT", "PULL_REQUEST_STATE"],
            uncertainty=[],
            created_at=created_at,
        )
        request["requested_by"]["agent_id"] = self.agent_id
        validate_action_request(request)
        return request

"""Runnable AgentTeams-contract workflow for the competition reference demo."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from .agents import EvidenceVerifier, GitHubOperator, HandoffLog, ReleaseSteward, RequestAnalyst, WorkflowLead
from .canonical import format_datetime
from .provider import InMemoryGitHubProvider
from .service import ActionGateService

AGENTTEAMS_RELEASE = "v1.2.0"
AGENTTEAMS_COMMIT = "793db242257a569d911b1aa59c1cd554af78511f"
EXPECTED_WORKERS = {
    "workflow-lead",
    "request-analyst",
    "evidence-verifier",
    "github-operator",
    "cloud-context-inspector",
    "release-steward",
}


def validate_agentteams_template(path: str | Path) -> dict[str, Any]:
    documents = list(yaml.safe_load_all(Path(path).read_text(encoding="utf-8")))
    workers = [document for document in documents if document.get("kind") == "Worker"]
    teams = [document for document in documents if document.get("kind") == "Team"]
    if {worker["metadata"]["name"] for worker in workers} != EXPECTED_WORKERS:
        raise ValueError("AgentTeams Worker resources do not match the runtime identities")
    if len(teams) != 1:
        raise ValueError("exactly one AgentTeams Team resource is required")
    members = teams[0]["spec"]["workerMembers"]
    if sum(member["role"] == "team_leader" for member in members) != 1:
        raise ValueError("AgentTeams Team must have exactly one team_leader")
    return {"worker_count": len(workers), "team": teams[0]["metadata"]["name"], "api_version": teams[0]["apiVersion"]}


class AgentTeamsWorkflow:
    """Local reference runner preserving AgentTeams identities and handoffs.

    It executes deterministic role adapters in-process. A live AgentTeams
    deployment consumes the same Worker/Team resources and MCP server.
    """

    def __init__(self, service: ActionGateService, *, caller_token: str, approver_token: str = "titmas-demo-approver-token"):
        self.service = service
        self.caller_token = caller_token
        self.approver_token = approver_token
        self.analyst = RequestAnalyst()
        self.verifier = EvidenceVerifier()
        self.lead = WorkflowLead()
        self.operator = GitHubOperator()
        self.steward = ReleaseSteward()
        self.handoffs = HandoffLog()

    def _create_and_submit_request(self, repository: str, observed: datetime) -> dict[str, Any]:
        request = self.analyst.analyze(
            action="github.pull_request.create",
            repository=repository,
            resource_ref="refs/heads/docs-demo",
            parameters={"base": "main", "head": "docs-demo", "title": "Document the Action Gate demo"},
            evidence_requirements=["SOURCE_PIN", "DIFF", "TEST_RESULT"],
            uncertainty=["Provider execution is sandboxed; no external GitHub write is claimed."],
            created_at=observed,
        )
        self.handoffs.add("workflow-lead", "request-analyst", request["request_id"], "NORMALIZE_REQUEST", request)
        self.service.submit_action_request(request, caller_token=self.caller_token)
        return request

    def _process_pre_execution(self, request: dict[str, Any], observed: datetime) -> tuple[dict[str, Any], dict[str, Any]]:
        profile = self.service.generate_evidence_profile(
            request["request_id"],
            actor=self.analyst.agent_id,
            phase="pre-execution",
            operation_status="succeeded",
            output={"analysis": "request normalized", "tests": "contract checks passed"},
            evidence_types=request["evidence_requirements"],
            timestamp=observed + timedelta(seconds=1),
        )
        profile_path = self.service.evidence.write_profile(profile, f"{request['request_id']}-pre-execution.json")
        self.service.attach_evidence(
            request["request_id"],
            profile_path,
            request["evidence_requirements"],
            caller_token=self.caller_token,
        )
        self.handoffs.add("workflow-lead", "evidence-verifier", request["request_id"], "VERIFY_PRE_EXECUTION_EVIDENCE", profile)
        evidence_result = self.verifier.verify(self.service, request["request_id"], caller_token=self.caller_token)
        self.handoffs.add("evidence-verifier", "workflow-lead", request["request_id"], "RETURN_VERIFIER_RECEIPT", evidence_result)
        initial_envelope = self.lead.decide(
            self.service,
            request["request_id"],
            caller_token=self.caller_token,
            decided_at=observed + timedelta(seconds=2),
        )
        initial_decision = initial_envelope["payload"]
        self.handoffs.add("workflow-lead", "github-operator", request["request_id"], "EXECUTE_EXACT_ALLOW", initial_decision)
        return evidence_result, initial_decision

    def _process_post_execution(self, repository: str, execution_receipt: dict[str, Any], observed: datetime) -> tuple[dict[str, Any], dict[str, Any]]:
        pull_number = execution_receipt["provider_result"]["result"]["pull_number"]
        release_request = self.steward.build_release_request(
            self.analyst,
            repository=repository,
            pull_number=pull_number,
            created_at=observed + timedelta(seconds=4),
        )
        self.handoffs.add("github-operator", "release-steward", release_request["request_id"], "ASSEMBLE_POST_EXECUTION_EVIDENCE", execution_receipt)
        self.service.submit_action_request(release_request, caller_token=self.caller_token)
        post_profile = self.service.generate_evidence_profile(
            release_request["request_id"],
            actor=self.steward.agent_id,
            phase="post-execution",
            operation_status="succeeded",
            output=execution_receipt,
            evidence_types=release_request["evidence_requirements"],
            timestamp=observed + timedelta(seconds=5),
        )
        post_path = self.service.evidence.write_profile(post_profile, f"{release_request['request_id']}-post-execution.json")
        self.service.attach_evidence(
            release_request["request_id"],
            post_path,
            release_request["evidence_requirements"],
            caller_token=self.caller_token,
        )
        post_evidence = self.verifier.verify(self.service, release_request["request_id"], caller_token=self.caller_token)
        return release_request, post_evidence

    def _process_approvals(self, release_request: dict[str, Any], observed: datetime) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        before_approval = self.lead.decide(
            self.service,
            release_request["request_id"],
            caller_token=self.caller_token,
            decided_at=observed + timedelta(seconds=6),
        )["payload"]
        self.handoffs.add("workflow-lead", "titmas-action-gate-reviewer", release_request["request_id"], "REQUEST_SCOPED_HUMAN_APPROVAL", before_approval)
        approval = self.service.record_human_approval(
            release_request["request_id"],
            subject="human:demo-reviewer",
            identity_provider="demo-local-identity-provider",
            status="GRANTED",
            approver_token=self.approver_token,
            decided_at=observed + timedelta(seconds=7),
        )
        self.handoffs.add("titmas-action-gate-reviewer", "workflow-lead", release_request["request_id"], "RETURN_SCOPED_APPROVAL", approval)
        after_approval = self.lead.decide(
            self.service,
            release_request["request_id"],
            caller_token=self.caller_token,
            decided_at=observed + timedelta(seconds=8),
        )["payload"]
        return before_approval, approval, after_approval

    def run(self, *, repository: str, base_time: datetime | None = None) -> dict[str, Any]:
        observed = base_time or datetime.now(UTC)
        provider = InMemoryGitHubProvider()

        request = self._create_and_submit_request(repository, observed)
        evidence_result, initial_decision = self._process_pre_execution(request, observed)

        execution_receipt = self.operator.execute(
            self.service,
            request["request_id"],
            initial_decision["decision_id"],
            provider,
            caller_token=self.caller_token,
            consumed_at=observed + timedelta(seconds=3),
        )

        release_request, post_evidence = self._process_post_execution(repository, execution_receipt, observed)
        before_approval, approval, after_approval = self._process_approvals(release_request, observed)

        return {
            "demo_version": "0.2.0",
            "orchestration": {
                "layer": "AgentTeams",
                "release": AGENTTEAMS_RELEASE,
                "commit": AGENTTEAMS_COMMIT,
                "execution_mode": "LOCAL_DETERMINISTIC_REFERENCE_USING_AGENTTEAMS_IDENTITIES_AND_HANDOFFS",
                "live_agentteams_deployment_claimed": False,
            },
            "provider": {
                "mode": execution_receipt["provider_result"]["provider_mode"],
                "external_write": execution_receipt["provider_result"]["provider_mode"] == "GH_CLI_EXTERNAL_WRITE",
            },
            "initial_request_id": request["request_id"],
            "initial_evidence_status": evidence_result["status"],
            "initial_decision": initial_decision,
            "execution_receipt": execution_receipt,
            "release_request_id": release_request["request_id"],
            "post_execution_evidence_status": post_evidence["status"],
            "release_decision_before_approval": before_approval,
            "human_approval": approval,
            "release_decision_after_approval": after_approval,
            "handoffs": self.handoffs.as_dicts(),
            "action_store_chain_issues": self.service.store.verify_chain(),
            "agent_evidence_chain_issues": self.service.evidence.verify_event_chain(),
            "completed_at": format_datetime(observed + timedelta(seconds=9)),
            "non_claims": [
                "NO_EXTERNAL_GITHUB_WRITE",
                "NO_LIVE_AGENTTEAMS_DEPLOYMENT",
                "NO_MERGE_EXECUTED",
                "NO_RELEASE_OR_COMPETITION_SUBMISSION",
                "NO_PRODUCTION_READINESS_OR_CERTIFICATION",
            ],
        }


def write_demo_report(report: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return path

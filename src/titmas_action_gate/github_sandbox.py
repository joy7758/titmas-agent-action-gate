"""Real GitHub sandbox workflow with every provider write gate-bound."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .agents import EvidenceVerifier, GitHubOperator, HandoffLog, RequestAnalyst, WorkflowLead
from .provider import GhCliProvider
from .service import ActionGateService
from .workflow import AGENTTEAMS_COMMIT, AGENTTEAMS_RELEASE


def exact_head_commit(worktree: str | Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(Path(worktree).resolve()), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


class RealGitHubSandboxWorkflow:
    def __init__(
        self,
        service: ActionGateService,
        *,
        caller_token: str,
        approver_token: str,
        repository: str,
        worktree: str | Path,
    ):
        self.service = service
        self.caller_token = caller_token
        self.approver_token = approver_token
        self.repository = repository
        self.worktree = Path(worktree).resolve()
        self.provider = GhCliProvider(repository, allowed_worktree_root=self.worktree)
        self.analyst = RequestAnalyst()
        self.verifier = EvidenceVerifier()
        self.lead = WorkflowLead()
        self.operator = GitHubOperator()
        self.handoffs = HandoffLog()

    def _verify_and_decide(
        self,
        request: dict[str, Any],
        *,
        phase: str,
        evidence_output: dict[str, Any],
        observed: datetime,
    ) -> dict[str, Any]:
        self.service.submit_action_request(request, caller_token=self.caller_token)
        profile = self.service.evidence.build_profile(
            request,
            actor=self.analyst.agent_id,
            phase=phase,
            operation_status="succeeded",
            output=evidence_output,
            evidence_types=request["evidence_requirements"],
            timestamp=observed,
        )
        profile_path = self.service.evidence.write_profile(profile, f"{request['request_id']}-{phase}.json")
        self.service.attach_evidence(request["request_id"], profile_path, request["evidence_requirements"], caller_token=self.caller_token)
        evidence_result = self.verifier.verify(self.service, request["request_id"], caller_token=self.caller_token)
        decision = self.lead.decide(self.service, request["request_id"], caller_token=self.caller_token, decided_at=observed + timedelta(seconds=1))["payload"]
        return {"evidence": evidence_result, "decision": decision}

    def _process_branch_push(self, branch: str, commit: str, observed: datetime) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        push_request = self.analyst.analyze(
            action="github.branch.push",
            repository=self.repository,
            resource_ref=f"refs/heads/{branch}",
            parameters={"branch": branch, "commit": commit},
            evidence_requirements=["SOURCE_PIN", "DIFF", "TEST_RESULT"],
            uncertainty=[],
            created_at=observed,
        )
        self.handoffs.add("workflow-lead", "request-analyst", push_request["request_id"], "NORMALIZE_BRANCH_PUSH", push_request)
        push_gate = self._verify_and_decide(
            push_request,
            phase="branch-push-pre-execution",
            evidence_output={"commit": commit, "worktree": "LOCAL_PATH_REDACTED_IN_PUBLIC_REPORT"},
            observed=observed + timedelta(seconds=1),
        )
        self.handoffs.add("workflow-lead", "github-operator", push_request["request_id"], "EXECUTE_EXACT_BRANCH_PUSH", push_gate["decision"])
        push_receipt = self.operator.execute(
            self.service,
            push_request["request_id"],
            push_gate["decision"]["decision_id"],
            self.provider,
            caller_token=self.caller_token,
            consumed_at=observed + timedelta(seconds=3),
        )
        return push_request, push_gate, push_receipt

    def _process_pull_request_create(
        self, branch: str, base: str, title: str, push_receipt: dict[str, Any], observed: datetime
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        pr_request = self.analyst.analyze(
            action="github.pull_request.create",
            repository=self.repository,
            resource_ref=f"refs/heads/{branch}",
            parameters={"base": base, "head": branch, "title": title},
            evidence_requirements=["SOURCE_PIN", "DIFF", "TEST_RESULT"],
            uncertainty=[],
            created_at=observed + timedelta(seconds=4),
        )
        self.handoffs.add("github-operator", "release-steward", pr_request["request_id"], "PREPARE_PR_REQUEST", push_receipt)
        pr_gate = self._verify_and_decide(
            pr_request,
            phase="pull-request-pre-execution",
            evidence_output=push_receipt,
            observed=observed + timedelta(seconds=5),
        )
        self.handoffs.add("workflow-lead", "github-operator", pr_request["request_id"], "EXECUTE_EXACT_PR_CREATE", pr_gate["decision"])
        pr_receipt = self.operator.execute(
            self.service,
            pr_request["request_id"],
            pr_gate["decision"]["decision_id"],
            self.provider,
            caller_token=self.caller_token,
            consumed_at=observed + timedelta(seconds=7),
        )
        return pr_request, pr_gate, pr_receipt

    def _process_merge(
        self, pull_number: int, pr_receipt: dict[str, Any], observed: datetime
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
        merge_request = self.analyst.analyze(
            action="github.pull_request.merge",
            repository=self.repository,
            resource_ref=f"pull/{pull_number}",
            parameters={"merge_method": "squash", "pull_number": pull_number},
            evidence_requirements=["SOURCE_PIN", "DIFF", "TEST_RESULT", "PULL_REQUEST_STATE"],
            uncertainty=[],
            created_at=observed + timedelta(seconds=8),
        )
        merge_request["requested_by"]["agent_id"] = "release-steward"
        merge_gate = self._verify_and_decide(
            merge_request,
            phase="merge-release-decision",
            evidence_output=pr_receipt,
            observed=observed + timedelta(seconds=9),
        )
        before_approval = merge_gate["decision"]
        approval = self.service.record_human_approval(
            merge_request["request_id"],
            subject="human:repository-owner",
            identity_provider="github-authenticated-local-session",
            status="GRANTED",
            approver_token=self.approver_token,
            decided_at=observed + timedelta(seconds=11),
        )
        after_approval = self.service.evaluate_action_gate(
            merge_request["request_id"],
            caller_token=self.caller_token,
            decided_at=observed + timedelta(seconds=12),
        )["payload"]
        return merge_request, merge_gate, before_approval, approval, after_approval

    def run(self, *, branch: str, base: str = "main", title: str = "TITMAS Agent Action Gate sandbox demo") -> dict[str, Any]:
        observed = datetime.now(UTC)
        commit = exact_head_commit(self.worktree)

        push_request, push_gate, push_receipt = self._process_branch_push(branch, commit, observed)
        pr_request, pr_gate, pr_receipt = self._process_pull_request_create(branch, base, title, push_receipt, observed)

        pull_number = pr_receipt["provider_result"]["result"]["pull_number"]
        merge_request, merge_gate, before_approval, approval, after_approval = self._process_merge(pull_number, pr_receipt, observed)

        return {
            "demo_version": "0.2.0",
            "orchestration": {
                "layer": "AgentTeams",
                "release": AGENTTEAMS_RELEASE,
                "commit": AGENTTEAMS_COMMIT,
                "execution_mode": "LOCAL_AGENTTEAMS_CONTRACT_HANDOFFS_WITH_REAL_GITHUB_PROVIDER",
                "live_agentteams_deployment_claimed": False,
            },
            "provider": {"mode": "GH_CLI_EXTERNAL_WRITE", "repository": self.repository, "external_write": True},
            "branch_push": {"request": push_request, "gate": push_gate, "receipt": push_receipt},
            "pull_request_create": {"request": pr_request, "gate": pr_gate, "receipt": pr_receipt},
            "release_decision": {
                "request": merge_request,
                "evidence": merge_gate["evidence"],
                "before_approval": before_approval,
                "approval": approval,
                "after_approval": after_approval,
                "merge_executed": False,
            },
            "handoffs": self.handoffs.as_dicts(),
            "action_store_chain_issues": self.service.store.verify_chain(),
            "agent_evidence_chain_issues": self.service.evidence.verify_event_chain(),
            "non_claims": [
                "NO_LIVE_AGENTTEAMS_DEPLOYMENT",
                "NO_PULL_REQUEST_MERGE_EXECUTED",
                "NO_RELEASE_OR_DEPLOYMENT",
                "NO_COMPETITION_SUBMISSION",
                "NO_PRODUCTION_READINESS_OR_CERTIFICATION",
            ],
        }

#!/usr/bin/env python3
"""Run bounded real-GitHub writes against an explicitly provisioned sandbox."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from titmas_action_gate.github_sandbox import RealGitHubSandboxWorkflow
from titmas_action_gate.service import ActionGateService

TOKEN = "titmas-demo-caller-token"
APPROVER_TOKEN = "titmas-demo-approver-token"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, help="Exact owner/name sandbox allowlist.")
    parser.add_argument("--worktree", required=True, help="Local sandbox worktree containing the prepared commit.")
    parser.add_argument("--branch", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    service = ActionGateService.demo(args.state_dir, caller_token=TOKEN, approver_token=APPROVER_TOKEN)
    workflow = RealGitHubSandboxWorkflow(
        service,
        caller_token=TOKEN,
        approver_token=APPROVER_TOKEN,
        repository=args.repository,
        worktree=args.worktree,
    )
    report = workflow.run(branch=args.branch)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "report": str(output.resolve()),
        "branch_push": report["branch_push"]["receipt"]["status"],
        "pull_request_create": report["pull_request_create"]["receipt"]["status"],
        "release_decision_before_approval": report["release_decision"]["before_approval"]["outcome"],
        "release_decision_after_approval": report["release_decision"]["after_approval"]["outcome"],
        "merge_executed": report["release_decision"]["merge_executed"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

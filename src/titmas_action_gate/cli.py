"""Command line entrypoint for evaluation and the reference workflow."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import multiprocessing
import sysconfig
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any

from .approval import ApprovalAuthority
from .canonical import sha256_file
from .contracts import schema_directory
from .evidence import AGENT_EVIDENCE_OAP_SCHEMA_SHA256, AGENT_EVIDENCE_VERSION, AGENT_EVIDENCE_WHEEL_SHA256
from .gate import ActionGate
from .mcp_server import main as mcp_main
from .pr_gate import DEFAULT_OUTPUT_DIRECTORY, verify_pull_request
from .service import ActionGateService
from .workflow import AgentTeamsWorkflow, validate_agentteams_template, write_demo_report

ROOT = Path(__file__).resolve().parents[2]
DEMO_TOKEN = "titmas-demo-caller-token"
DEMO_APPROVER_TOKEN = "titmas-demo-approver-token"


def data_root() -> Path:
    candidates = [
        ROOT,
        Path(sysconfig.get_path("data")) / "share/titmas-action-gate",
    ]
    for candidate in candidates:
        if (candidate / "evaluations/case-registry.json").is_file():
            return candidate
    raise RuntimeError("TITMAS Action Gate installed data files were not found")


def _evaluate_worker(cases: list[dict[str, Any]], root_path: str) -> list[dict[str, Any]]:
    # Initialize locally for process pool safety

    authority = ApprovalAuthority(b"fixture-approval-key-material-32-bytes-minimum")
    gate = ActionGate(authority)

    root = Path(root_path)
    case_cache: dict[str, dict[str, Any]] = {}
    results = []

    for item in cases:
        path = item["path"]
        if path not in case_cache:
            case_cache[path] = json.loads((root / "evaluations" / path).read_text(encoding="utf-8"))

        case = case_cache[path]
        decision = gate.evaluate(
            case["action_request"],
            case["policy_evaluation"],
            case["evidence_verification_result"],
            case["human_approval"],
            decided_at=datetime(2026, 8, 2, 0, 0, tzinfo=UTC),
        )
        passed = decision["outcome"] == case["expected_decision"]["outcome"] and decision["reason_codes"] == case["expected_decision"]["reason_codes"]
        results.append(
            {
                "case_id": case["case_id"],
                "outcome": decision["outcome"],
                "reason_codes": decision["reason_codes"],
                "expected_outcome": case["expected_decision"]["outcome"],
                "passed": passed,
            }
        )
    return results


def evaluate_fixtures() -> dict[str, Any]:
    root = data_root()
    registry = json.loads((root / "evaluations/case-registry.json").read_text(encoding="utf-8"))
    cases = registry["cases"]

    if not cases:
        return {"ok": True, "cases": []}

    num_workers = min(multiprocessing.cpu_count(), len(cases))
    if num_workers <= 1:
        res = _evaluate_worker(cases, str(root))
        return {"ok": all(item["passed"] for item in res), "cases": res}

    chunk_size = len(cases) // num_workers + (1 if len(cases) % num_workers else 0)
    chunks = [cases[i : i + chunk_size] for i in range(0, len(cases), chunk_size)]

    results = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=num_workers) as executor:
        for chunk_result in executor.map(_evaluate_worker, chunks, [str(root)] * len(chunks)):
            results.extend(chunk_result)

    return {"ok": all(item["passed"] for item in results), "cases": results}


def validate_install() -> dict[str, Any]:
    schema_path = schema_directory() / "agent-evidence-oap-v0.1.schema.json"
    template = data_root() / "deploy/agentteams/team.v1.2.0.yaml"
    checks = {
        "agent_evidence_version": version("agent-evidence") == AGENT_EVIDENCE_VERSION,
        "agent_evidence_wheel_pin_recorded": len(AGENT_EVIDENCE_WHEEL_SHA256) == 64,
        "agent_evidence_oap_schema_hash": sha256_file(schema_path) == AGENT_EVIDENCE_OAP_SCHEMA_SHA256,
        "agentteams_template": validate_agentteams_template(template),
        "fixture_evaluation": evaluate_fixtures(),
    }
    return {"ok": all(value is True or isinstance(value, dict) and value.get("ok", True) for value in checks.values()), "checks": checks}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="titmas-action-gate")
    subparsers = parser.add_subparsers(dest="command", required=True)
    demo = subparsers.add_parser("demo", help="Run the no-network AgentTeams-contract GitHub workflow.")
    demo.add_argument("--state-dir", default="artifacts/runtime/reference-demo")
    demo.add_argument("--output", default="artifacts/runtime/reference-demo/report.json")
    demo.add_argument("--repository", default="joy7758/action-gate-demo")
    subparsers.add_parser("evaluate-fixtures", help="Evaluate the four versioned contract fixtures.")
    subparsers.add_parser("validate-install", help="Validate source pins and callable contracts.")
    subparsers.add_parser("mcp", help="Run the MCP server using environment configuration.")
    verify_pr = subparsers.add_parser("verify-pr", help="Verify one exact pull-request head and emit merge-check receipts.")
    verify_pr.add_argument("--task", required=True, help="Existing action-request JSON bound to the pull-request head.")
    verify_pr.add_argument("--evidence", required=True, help="agent-evidence profile to verify.")
    verify_pr.add_argument("--policy", required=True, help="Versioned deterministic policy file.")
    verify_pr.add_argument("--test-command", required=True, help="Exact task-bound command; executed directly without a shell.")
    verify_pr.add_argument("--approval", help="Optional existing scoped human-approval JSON.")
    verify_pr.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIRECTORY))
    verify_pr.add_argument("--repository", help="Current repository; defaults to the bounded CI environment.")
    verify_pr.add_argument("--pull-request", type=int, help="Current pull-request number; defaults to the bounded CI environment.")
    verify_pr.add_argument("--head-sha", help="Current pull-request head SHA; defaults to the bounded CI environment.")
    verify_pr.add_argument("--execution-identity", help="Current execution identity reference; defaults to the bounded CI environment.")
    verify_pr.add_argument("--workspace", help="Trusted repository workspace used to bound gate inputs and Git state.")
    verify_pr.add_argument("--action-configuration", help="Relevant composite Action YAML to freeze before the test.")
    verify_pr.add_argument("--action-root", help="Trusted installed Action root containing the frozen action.yml.")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "mcp":
        mcp_main()
        return
    if args.command == "verify-pr":
        result = verify_pull_request(
            task_path=args.task,
            evidence_path=args.evidence,
            policy_path=args.policy,
            test_command=args.test_command,
            approval_path=args.approval,
            output_directory=args.output_dir,
            repository=args.repository,
            pull_request=args.pull_request,
            head_sha=args.head_sha,
            execution_identity=args.execution_identity,
            workspace=args.workspace,
            action_configuration_path=args.action_configuration,
            action_configuration_root=args.action_root,
        )
    elif args.command == "evaluate-fixtures":
        result = evaluate_fixtures()
    elif args.command == "validate-install":
        result = validate_install()
    else:
        service = ActionGateService.demo(args.state_dir, caller_token=DEMO_TOKEN)
        result = AgentTeamsWorkflow(service, caller_token=DEMO_TOKEN, approver_token=DEMO_APPROVER_TOKEN).run(repository=args.repository)
        write_demo_report(result, args.output)
        result = {"ok": True, "report": str(Path(args.output).resolve()), "summary": result}
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    if args.command == "verify-pr":
        raise SystemExit(result["exit_code"])
    if not result.get("ok", True):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

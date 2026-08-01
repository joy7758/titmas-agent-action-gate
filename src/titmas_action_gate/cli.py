"""Command line entrypoint for evaluation and the reference workflow."""

from __future__ import annotations

import argparse
import json
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


def evaluate_fixtures() -> dict[str, Any]:
    root = data_root()
    registry = json.loads((root / "evaluations/case-registry.json").read_text(encoding="utf-8"))
    authority = ApprovalAuthority(b"fixture-approval-key-material-32-bytes-minimum")
    gate = ActionGate(authority)
    results: list[dict[str, Any]] = []
    for item in registry["cases"]:
        case = json.loads((root / "evaluations" / item["path"]).read_text(encoding="utf-8"))
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
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "mcp":
        mcp_main()
        return
    if args.command == "evaluate-fixtures":
        result = evaluate_fixtures()
    elif args.command == "validate-install":
        result = validate_install()
    else:
        service = ActionGateService.demo(args.state_dir, caller_token=DEMO_TOKEN)
        result = AgentTeamsWorkflow(service, caller_token=DEMO_TOKEN, approver_token=DEMO_APPROVER_TOKEN).run(repository=args.repository)
        write_demo_report(result, args.output)
        result = {"ok": True, "report": str(Path(args.output).resolve()), "summary": result}
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    if not result.get("ok", True):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

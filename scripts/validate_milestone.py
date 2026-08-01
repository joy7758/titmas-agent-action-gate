#!/usr/bin/env python3
"""Validate the milestone-1 specification without exercising a runtime."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
import yaml


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_AGENT_IDS = {
    "workflow-lead",
    "request-analyst",
    "evidence-verifier",
    "github-operator",
    "release-steward",
}
EXPECTED_SKILLS = {
    "analyze-action-request",
    "verify-agent-evidence",
    "use-action-gate",
    "execute-github-action",
    "prepare-release-decision",
}
EXPECTED_MCP_TOOLS = {
    "submit_action_request",
    "attach_evidence",
    "verify_evidence",
    "evaluate_action_gate",
    "record_human_approval",
    "get_action_state",
}
EXPECTED_CASE_OUTCOMES = {
    "valid-execution": "ALLOW",
    "missing-evidence": "BLOCK",
    "tampered-evidence": "BLOCK",
    "high-risk-approval": "REQUIRE_APPROVAL",
}


def load_json(relative_path: str | Path) -> Any:
    path = ROOT / relative_path
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def schema_validator(name: str) -> Draft202012Validator:
    schema = load_json(f"schemas/{name}")
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def canonical_parameters_sha256(parameters: dict[str, Any]) -> str:
    """Fixture subset of RFC 8785: sorted compact JSON with ASCII fixture keys."""
    payload = json.dumps(
        parameters,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def request_binding(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "action": request["action"],
        "provider": request["target"]["provider"],
        "repository": request["target"]["repository"],
        "resource_ref": request["target"]["resource_ref"],
        "parameters_sha256": request["parameters_sha256"],
    }


def reference_decision(case: dict[str, Any]) -> tuple[str, str, bool]:
    """Executable reading of v0.1 precedence for contract fixtures, not runtime."""
    request = case["action_request"]
    policy = case["policy_evaluation"]
    evidence = case["evidence_verification_result"]
    approval = case.get("human_approval")
    binding = request_binding(request)

    if (
        policy["request_id"] != request["request_id"]
        or evidence["request_id"] != request["request_id"]
        or policy["request_binding"] != binding
        or evidence["request_binding"] != binding
    ):
        return "BLOCK", "INPUT_MISMATCH", False
    if policy["effect"] == "DENY":
        return "BLOCK", "POLICY_DENY", False
    evidence_terminal = {
        "MISSING": "EVIDENCE_MISSING",
        "INVALID": "EVIDENCE_INVALID",
        "TAMPERED": "EVIDENCE_TAMPERED",
    }
    if evidence["status"] in evidence_terminal:
        return "BLOCK", evidence_terminal[evidence["status"]], False
    if not set(policy["required_evidence_types"]).issubset(evidence["evidence_types"]):
        return "BLOCK", "INPUT_MISMATCH", False
    if not all(check["passed"] for check in evidence["checks"]):
        return "BLOCK", "EVIDENCE_INVALID", False
    if approval is not None:
        if (
            approval["status"] != "GRANTED"
            or approval["request_id"] != request["request_id"]
            or approval["request_binding"] != binding
            or approval["policy_id"] != policy["policy_id"]
            or approval["policy_version"] != policy["policy_version"]
        ):
            return "BLOCK", "APPROVAL_INVALID", False
    if policy["effect"] == "REQUIRE_HUMAN_APPROVAL" and approval is None:
        return "REQUIRE_APPROVAL", "HUMAN_APPROVAL_REQUIRED", False
    if policy["effect"] in {"ALLOW_WITHOUT_APPROVAL", "REQUIRE_HUMAN_APPROVAL"}:
        return "ALLOW", "ALL_BOUNDARIES_SATISFIED", True
    return "BLOCK", "UNHANDLED_STATE", False


def validate_markdown_links(failures: list[str]) -> None:
    link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for path in ROOT.rglob("*.md"):
        if ".git" in path.parts:
            continue
        if path.is_relative_to(ROOT / "governance/upstream"):
            # The pinned constitution is a verbatim single-file snapshot. Its
            # upstream-relative ADR links are intentionally not copied here.
            continue
        for target in link_pattern.findall(path.read_text(encoding="utf-8")):
            clean = target.strip("<>").split("#", 1)[0]
            if not clean or clean.startswith(("http://", "https://", "mailto:")):
                continue
            if not (path.parent / clean).exists():
                failures.append(f"broken Markdown link in {path.relative_to(ROOT)}: {target}")


def main() -> int:
    failures: list[str] = []

    for path in ROOT.rglob("*.json"):
        if ".git" in path.parts:
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # report the file while retaining all failures
            failures.append(f"invalid JSON {path.relative_to(ROOT)}: {exc}")

    schema_names = [
        "agent-index.schema.json",
        "action-request.v0.1.schema.json",
        "policy-evaluation-result.v0.1.schema.json",
        "evidence-verification-result.v0.1.schema.json",
        "human-approval.v0.1.schema.json",
        "action-gate-decision.v0.1.schema.json",
        "skill-manifest.v0.1.schema.json",
        "mcp-server-manifest.v0.1.schema.json",
    ]
    validators: dict[str, Draft202012Validator] = {}
    for name in schema_names:
        try:
            validators[name] = schema_validator(name)
        except Exception as exc:
            failures.append(f"invalid schema {name}: {exc}")

    if "agent-index.schema.json" in validators:
        for error in validators["agent-index.schema.json"].iter_errors(load_json("agent-index.json")):
            failures.append(f"agent-index schema: {error.message}")

    registry = load_json("agents/registry.json")
    agents = registry.get("agents", [])
    if {agent.get("id") for agent in agents} != EXPECTED_AGENT_IDS:
        failures.append("agent registry must contain the five planned identities")
    if sum(agent.get("agentteams_role") == "team_leader" for agent in agents) != 1:
        failures.append("agent registry must contain exactly one team leader")
    for agent in agents:
        if any(agent.get("authority", {}).values()):
            failures.append(f"milestone-1 agent claims authority: {agent.get('id')}")

    skill_manifests = sorted(ROOT.glob("skills/*/manifest.json"))
    if {path.parent.name for path in skill_manifests} != EXPECTED_SKILLS:
        failures.append("Skill directories do not match the five planned Skills")
    skill_validator = validators.get("skill-manifest.v0.1.schema.json")
    for path in skill_manifests:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if skill_validator:
            for error in skill_validator.iter_errors(manifest):
                failures.append(f"{path.relative_to(ROOT)} schema: {error.message}")
        skill_file = path.parent / manifest.get("entrypoint", "")
        if not skill_file.is_file():
            failures.append(f"missing Skill entrypoint: {skill_file.relative_to(ROOT)}")
            continue
        text = skill_file.read_text(encoding="utf-8")
        match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
        if not match:
            failures.append(f"missing Skill YAML frontmatter: {skill_file.relative_to(ROOT)}")
        else:
            frontmatter = yaml.safe_load(match.group(1))
            for field in ("name", "description", "assign_when"):
                if not frontmatter.get(field):
                    failures.append(f"missing {field} in {skill_file.relative_to(ROOT)}")
            if frontmatter.get("name") != manifest.get("name"):
                failures.append(f"Skill name mismatch: {skill_file.relative_to(ROOT)}")
        for relative in manifest.get("examples", []) + manifest.get("tests", []):
            if not (path.parent / relative).resolve().is_file():
                failures.append(f"missing Skill reference from {path.relative_to(ROOT)}: {relative}")

    mcp_manifest = load_json("mcp/server-manifest.v0.1.json")
    mcp_validator = validators.get("mcp-server-manifest.v0.1.schema.json")
    if mcp_validator:
        for error in mcp_validator.iter_errors(mcp_manifest):
            failures.append(f"MCP manifest schema: {error.message}")
    tools = mcp_manifest.get("tools", [])
    if {tool.get("name") for tool in tools} != EXPECTED_MCP_TOOLS:
        failures.append("MCP manifest tool set mismatch")
    if any(tool.get("mutates_external_provider") for tool in tools):
        failures.append("milestone-1 Action Gate MCP must not mutate an external provider")
    for tool in tools:
        for field in ("input_schema", "output_schema"):
            target = tool[field].split("#", 1)[0]
            if not (ROOT / target).is_file():
                failures.append(f"MCP tool {tool['name']} has missing {field}: {target}")

    deployment_path = ROOT / "deploy/agentteams/team.v1.2.0.yaml"
    deployment_text = deployment_path.read_text(encoding="utf-8")
    documents = list(yaml.safe_load_all(deployment_text))
    if len(documents) != 8:
        failures.append("AgentTeams template must contain Manager, Human, five Workers, and Team")
    if any(doc.get("apiVersion") != "agentteams.io/v1beta1" for doc in documents):
        failures.append("AgentTeams template apiVersion mismatch")
    workers = [doc for doc in documents if doc.get("kind") == "Worker"]
    if {doc["metadata"]["name"] for doc in workers} != EXPECTED_AGENT_IDS:
        failures.append("AgentTeams Worker identities do not match registry")
    teams = [doc for doc in documents if doc.get("kind") == "Team"]
    if len(teams) != 1:
        failures.append("AgentTeams template must contain one Team")
    elif sum(member["role"] == "team_leader" for member in teams[0]["spec"]["workerMembers"]) != 1:
        failures.append("AgentTeams Team must contain exactly one team leader")
    if "github" in " ".join(
        server.get("url", "")
        for worker in workers
        for server in worker.get("spec", {}).get("mcpServers", [])
    ).lower():
        failures.append("milestone-1 AgentTeams template must not expose provider GitHub MCP")
    if "CONFIGURE_" not in deployment_text:
        failures.append("deployment template must retain explicit configuration placeholders")

    case_registry = load_json("evaluations/case-registry.json")
    registered = {case["id"]: case for case in case_registry.get("cases", [])}
    if {case_id: item["expected_outcome"] for case_id, item in registered.items()} != EXPECTED_CASE_OUTCOMES:
        failures.append("evaluation registry must contain the four required outcomes")
    case_validators = {
        "action_request": validators.get("action-request.v0.1.schema.json"),
        "policy_evaluation": validators.get("policy-evaluation-result.v0.1.schema.json"),
        "evidence_verification_result": validators.get("evidence-verification-result.v0.1.schema.json"),
        "human_approval": validators.get("human-approval.v0.1.schema.json"),
    }
    for case_id, item in registered.items():
        case_path = ROOT / "evaluations" / item["path"]
        case = json.loads(case_path.read_text(encoding="utf-8"))
        if case.get("case_id") != case_id:
            failures.append(f"case id mismatch: {case_path.relative_to(ROOT)}")
        for field, validator in case_validators.items():
            value = case.get(field)
            if field == "human_approval" and value is None:
                continue
            if validator:
                for error in validator.iter_errors(value):
                    failures.append(f"{case_id} {field}: {error.message}")
        request = case["action_request"]
        if canonical_parameters_sha256(request["parameters"]) != request["parameters_sha256"]:
            failures.append(f"{case_id} parameters_sha256 mismatch")
        outcome, reason, may_execute = reference_decision(case)
        expected = case["expected_decision"]
        if (outcome, [reason], may_execute) != (
            expected["outcome"],
            expected["reason_codes"],
            expected["may_execute"],
        ):
            failures.append(f"{case_id} expected decision violates v0.1 precedence")

    upstream = load_json("governance/upstream-sources.json")
    sources = {source["id"]: source for source in upstream["sources"]}
    if sources["agentteams"]["release_commit"] != "793db242257a569d911b1aa59c1cd554af78511f":
        failures.append("AgentTeams source pin mismatch")
    if sources["agent-evidence"]["wheel_sha256"] != "3bec73551c252c4665ea54e49243190d2d27df430a92b5c6d1846d4e025d0b8e":
        failures.append("agent-evidence distribution pin mismatch")

    validate_markdown_links(failures)

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print("MILESTONE_1_CONTRACT_VALIDATION=PASS")
    print("SPECIALIZED_AGENT_IDENTITIES=5")
    print("VERSIONED_SKILLS=5")
    print("MCP_TOOLS_SPECIFIED=6")
    print("EVALUATION_CASES=4")
    print("ACTION_GATE_IMPLEMENTED=false")
    print("EXTERNAL_PROVIDER_MUTATION=false")
    return 0


if __name__ == "__main__":
    sys.exit(main())

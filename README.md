# TITMAS Agent Action Gate

Evidence-verified, deterministic authorization boundaries for AgentTeams workflows.

中文：面向 AgentTeams 多智能体工作流的证据验证与确定性行动闸门。

[![Contract checks](https://github.com/joy7758/titmas-agent-action-gate/actions/workflows/contracts.yml/badge.svg)](https://github.com/joy7758/titmas-agent-action-gate/actions/workflows/contracts.yml)

TITMAS Agent Action Gate is a production-oriented architecture and competition demo candidate for the GOAI 2026 Agent Infra track. It separates uncertain agent analysis from deterministic authorization, evidence verification, policy evaluation, and human approval.

Current milestone: `M1_SPECIFICATION_BASELINE_COMPLETE`.

There is no Action Gate runtime or deployed MCP server yet. This repository is not submitted to, endorsed by, or affiliated with GOAI, and it makes no certification, compliance, production-readiness, or security guarantee.

## Why this exists

Agents are useful at interpreting ambiguous requests, decomposing work, and explaining uncertainty. They should not be the component that silently grants their own authority. This project uses:

- [AgentTeams v1.2.0](https://github.com/agentscope-ai/AgentTeams/releases/tag/v1.2.0) for transparent Manager/Leader/Worker collaboration;
- [`agent-evidence` 0.6.0](https://pypi.org/project/agent-evidence/0.6.0/) as the canonical evidence packaging and verification dependency;
- versioned JSON contracts and a deterministic Action Gate for `ALLOW`, `BLOCK`, and `REQUIRE_APPROVAL`;
- a human approval record for scoped, high-risk actions;
- provider MCP servers, such as GitHub MCP, only after an `ALLOW` decision.

## Planned team

| AgentTeams Worker | Responsibility | Cannot do |
|---|---|---|
| `workflow-lead` | Route tasks and preserve handoffs | Decide authorization or execute GitHub writes |
| `request-analyst` | Normalize requests, risk signals, and uncertainty | Grant permission or validate its own output |
| `evidence-verifier` | Invoke the pinned `agent-evidence` verifier and return its receipt | Rewrite evidence or decide policy |
| `github-operator` | Execute an exact GitHub action after a matching `ALLOW` | Bypass the gate or approve releases |
| `release-steward` | Assemble post-execution evidence and request the release decision | Merge, tag, or release without a new decision |

Agent identities and tool boundaries are machine-readable in [`agents/registry.json`](agents/registry.json). The AgentTeams CRD template is [`deploy/agentteams/team.v1.2.0.yaml`](deploy/agentteams/team.v1.2.0.yaml).

## Deterministic decisions

| Outcome | Meaning |
|---|---|
| `ALLOW` | The exact action, target, evidence, policy, and any required approval match. Execution may be attempted; success is not implied. |
| `BLOCK` | The request is malformed, denied, unsupported, missing required evidence, or has invalid/tampered evidence or approval. |
| `REQUIRE_APPROVAL` | Evidence and policy inputs are otherwise valid, but the risk class requires a scoped human approval before re-evaluation. |

The decision contract and precedence rules are in [`specs/action-gate-decision-v0.1.md`](specs/action-gate-decision-v0.1.md).

## GitHub demo path

```text
Agent request
  -> request analysis
  -> pre-action evidence verification
  -> deterministic Action Gate
  -> exact GitHub action after ALLOW
  -> post-action evidence generation
  -> agent-evidence verification
  -> deterministic release decision
  -> human approval when required
```

The planned end-to-end scenario is documented in [`docs/GITHUB-WORKFLOW-DEMO.md`](docs/GITHUB-WORKFLOW-DEMO.md). Milestone 1 contains four reproducible contract fixtures: valid execution, missing evidence, tampered evidence, and a high-risk release action requiring approval.

## Validate milestone 1

Python 3.11 or newer is required.

```bash
python3 -m pip install -e '.[dev]'
python3 scripts/validate_milestone.py
python3 -m unittest discover -s tests -v
```

These checks validate documents, manifests, schemas, examples, decision expectations, and source pins. They do not execute AgentTeams, GitHub actions, `agent-evidence`, an MCP server, or a release.

## Repository map

- [`architecture/README.md`](architecture/README.md): system boundaries and data flow;
- [`docs/AGENTTEAMS-INTEGRATION-PLAN.md`](docs/AGENTTEAMS-INTEGRATION-PLAN.md): AgentTeams v1.2.0 integration;
- [`docs/SKILL-SPECIFICATION-v0.1.md`](docs/SKILL-SPECIFICATION-v0.1.md): reusable Skill package contract;
- [`docs/MCP-TOOL-SPECIFICATION-v0.1.md`](docs/MCP-TOOL-SPECIFICATION-v0.1.md): MCP server and tool contract;
- [`docs/THREAT-MODEL-v0.1.md`](docs/THREAT-MODEL-v0.1.md): trust boundaries and bypass threats;
- [`docs/EXECUTION-ROADMAP.md`](docs/EXECUTION-ROADMAP.md): implementation and evaluation gates;
- [`evaluations/`](evaluations/): deterministic contract cases;
- [`governance/`](governance/): DBA source lock, existence declaration, recommendation, and management boundary.

## Truth boundaries

```text
AGENTTEAMS_ORCHESTRATION_NE_ACTION_AUTHORITY=true
AGENT_ANALYSIS_NE_POLICY_DECISION=true
EVIDENCE_NE_TRUTH=true
EVIDENCE_VERIFICATION_NE_ACTION_AUTHORIZATION=true
ALLOW_NE_EXECUTION_SUCCESS=true
MCP_TOOL_AVAILABILITY_NE_PERMISSION=true
SPECIFICATION_NE_IMPLEMENTATION=true
TEST_PASS_NE_PRODUCTION_READINESS=true
COMPETITION_REPOSITORY_NE_COMPETITION_SUBMISSION=true
TITMAS_CORE_PROTOCOLS_CHANGED=false
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).

# TITMAS Agent Action Gate

Evidence-verified, deterministic authorization boundaries for AgentTeams workflows.

中文：面向 AgentTeams 多智能体工作流的证据验证与确定性行动闸门。

[![Contract checks](https://github.com/joy7758/titmas-agent-action-gate/actions/workflows/contracts.yml/badge.svg)](https://github.com/joy7758/titmas-agent-action-gate/actions/workflows/contracts.yml)

TITMAS Agent Action Gate is a production-oriented reference architecture and competition demo candidate for the GOAI 2026 Agent Infra track. It separates uncertain agent analysis from deterministic authorization, evidence verification, policy evaluation, and human approval.

Current milestone: `M4_EXPERIMENTAL_REFERENCE_IMPLEMENTATION_WITH_REAL_GITHUB_SANDBOX_AND_PARTIAL_NATIVE_AGENTTEAMS_SMOKE`.

The deterministic Action Gate, append-only state store, six-tool MCP server, pinned `agent-evidence` adapter, five-role handoff harness, and allowlisted GitHub provider adapter are implemented and locally tested. A bounded public sandbox run created a branch and Draft PR. On 2026-08-02, an isolated temporary deployment of official AgentTeams `v1.2.0` started one Manager and five Workers against the Action Gate MCP server. Specialist Workers produced an operator-supervised request → verification → decision trace; the complete Manager → leader → Worker workflow did not finish autonomously. No provider action was attempted.

This repository is not submitted to, endorsed by, or affiliated with GOAI, and it makes no certification, compliance, production-readiness, or security guarantee.

## Why this exists

Agents are useful at interpreting ambiguous requests, decomposing work, and explaining uncertainty. They should not be the component that silently grants their own authority. This project uses:

- [AgentTeams v1.2.0](https://github.com/agentscope-ai/AgentTeams/releases/tag/v1.2.0) for transparent Manager/Leader/Worker collaboration;
- [`agent-evidence` 0.6.0](https://pypi.org/project/agent-evidence/0.6.0/) as the canonical evidence packaging and verification dependency;
- versioned JSON contracts and a deterministic Action Gate for `ALLOW`, `BLOCK`, and `REQUIRE_APPROVAL`;
- a human approval record for scoped, high-risk actions;
- provider MCP servers, such as GitHub MCP, only after an `ALLOW` decision.

## AgentTeams team

| AgentTeams Worker | Responsibility | Cannot do |
|---|---|---|
| `workflow-lead` | Route tasks and preserve handoffs | Decide authorization or execute GitHub writes |
| `request-analyst` | Normalize requests, risk signals, and uncertainty | Grant permission or validate its own output |
| `evidence-verifier` | Invoke the pinned `agent-evidence` verifier and return its receipt | Rewrite evidence or decide policy |
| `github-operator` | Execute an exact GitHub action after a matching `ALLOW` | Bypass the gate or approve releases |
| `release-steward` | Assemble post-execution evidence and request the release decision | Merge, tag, or release without a new decision |

Agent identities and intended tool boundaries are machine-readable in [`agents/registry.json`](agents/registry.json). The reviewable deployment template is [`deploy/agentteams/team.v1.2.0.yaml`](deploy/agentteams/team.v1.2.0.yaml); the non-idempotent macOS Docker Desktop smoke profile is [`deploy/agentteams/team.native-smoke.v1.2.0.yaml`](deploy/agentteams/team.native-smoke.v1.2.0.yaml).

### Native local smoke boundary

The retained machine-readable evidence is [`demo/evidence/agentteams-native-20260802.json`](demo/evidence/agentteams-native-20260802.json). It records both the verified chain and the failures that prevent a stronger claim:

- Qwen `qwen3.8-max-preview` specialist Workers invoked the real six-tool MCP endpoint; preview model availability is not a stable runtime contract;
- `agent-evidence` `0.6.0` returned `VALID`, after which the deterministic gate returned a five-minute `ALLOW` that expired without execution;
- the leader did not complete the workflow autonomously, one unrelated request entered the global store during concurrent prompts, and `github-operator` called a tool outside its declared registry allowlist;
- all Workers shared the same MCP endpoint, so prompts described role boundaries but the smoke did not enforce per-Worker tool ACLs;
- repository Skill names were declared in resources, but the run did not independently prove that those Skill packages were materialized inside the Workers.

This is native local orchestration evidence, not a persistent deployment, autonomous-workflow proof, least-privilege proof, or production-readiness evidence.

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

The end-to-end scenario and retained public evidence are documented in [`docs/GITHUB-WORKFLOW-DEMO.md`](docs/GITHUB-WORKFLOW-DEMO.md). The repository contains four reproducible runtime cases: valid execution, missing evidence, tampered evidence, and a high-risk release action requiring approval.

## Run and validate

Python 3.11 or newer is required.

```bash
python3 -m pip install -e '.[dev]'
python3 scripts/validate_milestone.py
python3 scripts/validate_governance.py
python3 -W error::ResourceWarning -m unittest discover -s tests -v
python3 -m titmas_action_gate.cli evaluate-fixtures
python3 -m titmas_action_gate.cli demo --state-dir artifacts/runtime/local-demo
python3 -m titmas_action_gate.cli validate-install
```

The tests execute the deterministic engine, pinned `agent-evidence` validator, append-only chain, MCP stdio protocol, all six tools, AgentTeams-compatible local handoffs, in-memory provider workflow, native-smoke manifest/evidence checks, and negative boundaries. They do not prove persistent AgentTeams deployment, autonomous orchestration, production security, or operational readiness.

Start the MCP server over stdio:

```bash
TITMAS_ACTION_GATE_STATE_DIR='artifacts/runtime/mcp' \
TITMAS_ACTION_GATE_CALLER_TOKEN='replace-with-agent-token' \
TITMAS_ACTION_GATE_APPROVER_TOKEN='replace-with-distinct-approver-token' \
TITMAS_ACTION_GATE_DEMO_MODE='true' \
TITMAS_ACTION_GATE_MCP_TRANSPORT='stdio' \
  titmas-action-gate-mcp
```

The real GitHub runner requires a separately provisioned sandbox repository and exact local worktree. It is intentionally not part of default CI. See [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

## Repository map

- [`architecture/README.md`](architecture/README.md): system boundaries and data flow;
- [`docs/AGENTTEAMS-INTEGRATION-PLAN.md`](docs/AGENTTEAMS-INTEGRATION-PLAN.md): AgentTeams v1.2.0 integration;
- [`docs/SKILL-SPECIFICATION-v0.1.md`](docs/SKILL-SPECIFICATION-v0.1.md): reusable Skill package contract;
- [`docs/MCP-TOOL-SPECIFICATION-v0.1.md`](docs/MCP-TOOL-SPECIFICATION-v0.1.md): MCP server and tool contract;
- [`docs/THREAT-MODEL-v0.1.md`](docs/THREAT-MODEL-v0.1.md): trust boundaries and bypass threats;
- [`docs/EXECUTION-ROADMAP.md`](docs/EXECUTION-ROADMAP.md): implementation and evaluation gates;
- [`docs/RUNBOOK.md`](docs/RUNBOOK.md): reproducible local and sandbox commands;
- [`SECURITY.md`](SECURITY.md): security model, reporting, and non-production limitations;
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
LOCAL_HANDOFF_HARNESS_NE_NATIVE_AGENTTEAMS_RUNTIME=true
NATIVE_LOCAL_SMOKE_NE_PERSISTENT_OR_PRODUCTION_DEPLOYMENT=true
OPERATOR_SUPERVISED_NE_AUTONOMOUS_END_TO_END=true
HASH_CHAIN_VALID_NE_SEMANTIC_ORCHESTRATION_CLEAN=true
PROMPT_ROLE_BOUNDARY_NE_ENFORCED_PER_WORKER_ACL=true
GITHUB_PR_CREATED_NE_GITHUB_PR_MERGED=true
COMPETITION_REPOSITORY_NE_COMPETITION_SUBMISSION=true
TITMAS_CORE_PROTOCOLS_CHANGED=false
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).

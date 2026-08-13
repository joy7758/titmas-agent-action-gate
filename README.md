# TITMAS Agent Action Gate

> **这是一个真正会阻止不可靠代码变更合并的证据闸门。**

It is an evidence gate that returns a non-passing required check when tests, exact-head evidence, policy, or required approval do not hold.

[![Contract checks](https://github.com/joy7758/titmas-agent-action-gate/actions/workflows/contracts.yml/badge.svg)](https://github.com/joy7758/titmas-agent-action-gate/actions/workflows/contracts.yml)

TITMAS Agent Action Gate is an experimental competition demo candidate for the GOAI 2026 Agent Infra track. It separates uncertain agent analysis from deterministic authorization, evidence verification, policy evaluation, and human approval.

Current product status: `PUBLICLY_REPRODUCIBLE_MERGE_BLOCKING_PRODUCT` for the bounded GitHub reference surface. The 8/8 acceptance proof is retained in [`demo/evidence/merge-blocking-public-proof-20260812.json`](demo/evidence/merge-blocking-public-proof-20260812.json): a public required check blocks commit-A evidence against pull-request head B while ordinary CI passes, then passes after the evidence subject is corrected, with receipts, summaries, and an approximately 90-second public recording. This does not prove production readiness, large-scale agent concurrency, agent-to-agent production governance, certification, compliance, or complete M4 autonomy. The historical bounded Alibaba Cloud official Skill sub-milestone remains `COMPLETE`, while full M4 remains `INCOMPLETE` and is outside the current work scope.

The deterministic Action Gate, append-only state store, pinned `agent-evidence` adapter, authenticated native MCP boundary, six-role target topology, and allowlisted in-memory GitHub provider adapter are implemented in the current worktree. A bounded public sandbox run previously created a branch and Draft PR. On 2026-08-02, a historical isolated deployment of official AgentTeams `v1.2.0` started one Manager and five Workers; it remains operator-supervised negative evidence. A separate disposable `cloud-context-inspector` ran one native Qwen Worker turn: it resolved the externally installed official Alibaba Cloud Resource Center Skill, verified the source-lock digest, invoked the frozen typed read-only adapter, and returned `EMPTY_RESULT` as `NOT_ASSESSED_NO_VISIBLE_RESOURCE`. The retained chains and canonical `agent-evidence` receipt validate, while Worker decision records and Resource Center write calls remain zero. This proves only the bounded specialist turn, not a complete cloud inventory, broader autonomous M4 completion, or deployment authorization.

This repository is not submitted to, endorsed by, or affiliated with GOAI, and it makes no certification, compliance, production-readiness, or security guarantee.

## Merge-blocking PR check

The new bounded path is:

```text
exact PR head + task-bound test command
  -> test and negative checks
  -> pinned agent-evidence verification
  -> deterministic policy and approval evaluation
  -> ActionGate ALLOW | BLOCK | REQUIRE_APPROVAL
  -> public required-check state + receipt + summary
```

The public projection does not change internal Action Gate authority:

| Public check state | Internal basis | Process exit |
|---|---|---:|
| `PASS` | `ALLOW` | `0` |
| `FAIL` | `BLOCK` for an invalid, denied, failing, tampered, or mismatched input | nonzero |
| `INCOMPLETE` | `BLOCK / EVIDENCE_MISSING` | nonzero |
| `REVIEW_REQUIRED` | `REQUIRE_APPROVAL` | nonzero until a scoped approval verifies |

Every normal invocation in a fresh job writes `artifacts/titmas/receipt.json` and `artifacts/titmas/summary.md`, including repository, PR, exact head SHA, frozen-input digests, execution identity reference, test result, negative checks, authorization scope, evidence digest and verifier, risk, approval reference, internal decision, public state, reasons, time, and tool/policy versions. Empty create-only, no-follow output inodes are reserved before the test; their trusted contents are committed only after the test and deterministic decision complete. Pre-existing, replaced or test-created paths fail closed and relocate the trusted FAIL outputs instead of being overwritten or consumed.

```bash
titmas-action-gate verify-pr \
  --task .titmas/task.json \
  --evidence .titmas/evidence.json \
  --policy policies/github-merge-gate-low-risk-demo.v0.1.json \
  --test-command 'python -m unittest discover -s tests -v'
```

The task must be an existing `action-request.v0.1` for `github.pull_request.merge`. Its parameters bind `pull_request`, `head_sha`, `execution_identity`, and the direct-exec `test_command` array; its resource reference is `refs/pull/<number>/head@<sha>`. The evidence must be produced by a trusted earlier step and bind that exact request. Before the untrusted test starts, the gate validates and freezes task, policy, evidence, optional approval, repository identity, pull-request number, exact head and relevant Action configuration in parent-process memory. The final decision consumes only those frozen objects; any input, exact-head or relevant Git-state drift during the test fails closed.

The test command does not run through a shell. It receives only a minimal environment with `PATH`, locale, `CI`, a fresh temporary `HOME` and `TMPDIR`, and non-interactive Git controls. GitHub command files, OIDC, SSH, cloud and package-registry credentials are not inherited. A persisted local Git authentication configuration, `pull_request_target` event, symbolic-link input or input path outside the trusted workspace fails before the test. The child runs in its own process group with bounded output and cleanup, but this does not claim container, virtual-machine or production sandbox isolation.

Consumer workflows must use a least-privilege exact-head checkout:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@<immutable-full-sha>
    with:
      ref: ${{ github.event.pull_request.head.sha }}
      fetch-depth: 0
      persist-credentials: false
  - uses: joy7758/titmas-agent-action-gate@<immutable-full-sha>
```

The root [`action.yml`](action.yml) is the reusable composite Action. Consumers must pin an immutable full commit SHA and configure its job as a required check; `PASS` does not bypass any other GitHub rule. Run the no-network regression matrix with:

```bash
python scripts/replay_merge_gate_scenarios.py
```

It covers valid low-risk, failing-test, missing-evidence, high-risk unapproved, high-risk approved rerun, and commit-A-evidence/commit-B-head mismatch. The baseline gap list and its bounded closure record are in [`docs/P0-MERGE-BLOCKING-GAP-LIST.md`](docs/P0-MERGE-BLOCKING-GAP-LIST.md).

## Competition positioning

AI coding is moving from one assistant toward populations of agents operating across repositories at machine speed. The systemic risk is not that an agent can make one mistake, but that a mistaken task interpretation, unstable behavior, or unsupported claim can be handed onward and replicated quickly.

TITMAS answers with task, identity, authority, and evidence verification before effect. The current real proof is deliberately smaller than that long-term vision: one AI-generated code change is bound to its task, actor, authorization, exact commit, and evidence, and a mismatched change is genuinely blocked before merge.

GitHub manages repositories, workflows, tests, reviews, and merge rules. TITMAS uses those enforcement surfaces while checking a different question: whether the AI action is actually covered by the current task authorization and evidence. The GitHub merge gate is the first reference surface, not the final identity of TITMAS. Large-scale concurrency, production agent-to-agent governance, and prevention of error propagation at scale remain `UNPROVEN`.

> **我们不是防止 AI 犯错，而是防止 AI 把错误规模化。**

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
| `cloud-context-inspector` | Request one typed, current-account Resource Center search and return sanitized context | Receive credential bytes, run arbitrary CLI/cloud operations, write cloud state, or decide the gate |
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
  -> official Alibaba Cloud read-only context preflight before a deployment-related release request is evaluated
  -> post-action evidence generation
  -> agent-evidence verification
  -> deterministic release decision
  -> human approval when required
```

The end-to-end scenario and retained public evidence are documented in [`docs/GITHUB-WORKFLOW-DEMO.md`](docs/GITHUB-WORKFLOW-DEMO.md). The repository contains four reproducible runtime cases: valid execution, missing evidence, tampered evidence, and a high-risk release action requiring approval.

The historical adapter-only Alibaba Cloud evidence is [`demo/evidence/alibabacloud-resourcecenter-preflight-20260802.json`](demo/evidence/alibabacloud-resourcecenter-preflight-20260802.json). The later native Worker-turn evidence is [`demo/evidence/agentteams-native-alibabacloud-skill-20260802.json`](demo/evidence/agentteams-native-alibabacloud-skill-20260802.json). The frozen four-file evidence set is [`demo/evidence/alibabacloud-evidence-set-freeze-20260802.json`](demo/evidence/alibabacloud-evidence-set-freeze-20260802.json). Together they retain exact external Skill source verification, pinned CLI/plugin digests, same-profile live STS identity binding, the complete one-policy RAM attachment set, sanitized invocation trace, CLI exit `0`, native AgentTeams Worker and Matrix receipts, replayable `VALID` `agent-evidence`, and scoped zero-write accounting. The Worker ZIP contains reference metadata but no upstream Skill bytes.

## Run and validate

Python 3.11 or newer is required.

```bash
python3 -m pip install -e '.[dev]'
python3 scripts/validate_milestone.py
python3 scripts/validate_governance.py
python3 scripts/validate_alibabacloud_runtime_evidence.py
python3 scripts/validate_alibabacloud_evidence_set.py
python3 scripts/validate_native_agentteams_cloud_skill_evidence.py \
  demo/evidence/agentteams-native-alibabacloud-skill-20260802.json
python3 scripts/replay_merge_gate_scenarios.py
python3 -m unittest discover -s tests -v
python3 -m titmas_action_gate.cli evaluate-fixtures
python3 -m titmas_action_gate.cli demo --state-dir artifacts/runtime/local-demo
python3 -m titmas_action_gate.cli validate-install
```

Run a future real Alibaba Cloud preflight only through the runner's internal same-run RAM readback. It generates an unpredictable run ID and atomically reserves the evidence path before any provider call. It does not accept an external observation or credential bytes:

```bash
python3 scripts/run_alibabacloud_skill_evaluation.py \
  --control-profile '<RAM-readback-profile-label>' \
  --profile '<read-only-profile-label>' \
  --role-name '<read-only-role-label>' \
  --output '<new-evidence-path>' \
  --confirmation-ref '<explicit-user-confirmation-reference>'
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
- [`docs/ALIBABA-CLOUD-SKILL-INTEGRATION.md`](docs/ALIBABA-CLOUD-SKILL-INTEGRATION.md): exact official Skill source, typed read-only boundary, credential isolation, evidence path, and current exit status;
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
PUBLIC_CHECK_STATE_NE_INTERNAL_AUTHORITY=true
ALLOW_NE_EXECUTION_SUCCESS=true
MCP_TOOL_AVAILABILITY_NE_PERMISSION=true
SPECIFICATION_NE_IMPLEMENTATION=true
TEST_PASS_NE_PRODUCTION_READINESS=true
LOCAL_HANDOFF_HARNESS_NE_NATIVE_AGENTTEAMS_RUNTIME=true
NATIVE_LOCAL_SMOKE_NE_PERSISTENT_OR_PRODUCTION_DEPLOYMENT=true
OPERATOR_SUPERVISED_NE_AUTONOMOUS_END_TO_END=true
HASH_CHAIN_VALID_NE_SEMANTIC_ORCHESTRATION_CLEAN=true
PROMPT_ROLE_BOUNDARY_NE_ENFORCED_PER_WORKER_ACL=true
CLOUD_CONTEXT_NE_DEPLOYMENT_AUTHORIZATION=true
CLOUD_READ_SUCCESS_NE_COMPLETE_INVENTORY_OR_READ_ONLY_POLICY_PROOF=true
GITHUB_PR_CREATED_NE_GITHUB_PR_MERGED=true
COMPETITION_REPOSITORY_NE_COMPETITION_SUBMISSION=true
TITMAS_CORE_PROTOCOLS_CHANGED=false
```

## License

Original project code is Apache-2.0. See [`LICENSE`](LICENSE).

The externally installed third-party `alibabacloud-resourcecenter-search` subtree has `SPDX-License-Identifier: NOASSERTION` in this repository's source lock because upstream has no applicable license file and its README contains conflicting Apache-2.0 and MIT statements. Installation and byte provenance do not establish redistribution, derivative-work, commercial-use, or compatibility clearance. The subtree is absent from the repository, Worker packages, wheel, and sdist; it must not be included in a public commit or release. See [`governance/alibabacloud-resourcecenter-search-source-lock.json`](governance/alibabacloud-resourcecenter-search-source-lock.json).

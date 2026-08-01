# Reproducible runbook

Status: `EXPERIMENTAL_REFERENCE_IMPLEMENTATION`

## Local validation

Python 3.11+ is supported.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/python scripts/validate_governance.py
.venv/bin/python scripts/validate_milestone.py
.venv/bin/python -W error::ResourceWarning -m unittest discover -s tests -v
.venv/bin/python -m titmas_action_gate.cli validate-install
```

`validate-install` confirms the installed `agent-evidence` version, the pinned distribution and OAP schema records, the AgentTeams resource template, and the four required runtime outcomes.

## In-memory end-to-end demo

```bash
.venv/bin/python -m titmas_action_gate.cli demo \
  --state-dir artifacts/runtime/local-demo \
  --output artifacts/runtime/local-demo/report.json
```

This executes PR creation through an in-memory provider, generates post-action evidence, verifies it with `agent-evidence`, produces a merge decision of `REQUIRE_APPROVAL`, records a scoped demo approval, and re-evaluates to `ALLOW`. It does not perform an external write.

## MCP stdio server

```bash
export TITMAS_ACTION_GATE_STATE_DIR='artifacts/runtime/mcp'
export TITMAS_ACTION_GATE_CALLER_TOKEN='replace-with-a-random-agent-token'
export TITMAS_ACTION_GATE_APPROVER_TOKEN='replace-with-a-distinct-approver-token'
export TITMAS_ACTION_GATE_DEMO_MODE='true'
export TITMAS_ACTION_GATE_MCP_TRANSPORT='stdio'
.venv/bin/titmas-action-gate-mcp
```

The two distinct environment tokens are a local reference authentication mechanism, not a production identity system. A normal caller token cannot record human approval. The six Action Gate tools never call a provider.

## Optional real GitHub sandbox

This path performs external writes and must target a disposable allowlisted repository. Provision the remote and a clean local worktree first. Prepare one local commit on an unpushed branch, then run:

```bash
.venv/bin/python scripts/run_github_sandbox_demo.py \
  --repository OWNER/DISPOSABLE_REPOSITORY \
  --worktree /absolute/path/to/exact/worktree \
  --branch demo/unique-branch \
  --state-dir artifacts/runtime/github-sandbox/state \
  --output artifacts/runtime/github-sandbox/report.json
```

Before push, the adapter verifies the exact repository allowlist, worktree root, GitHub `origin`, commit object, and branch ref. The runner can push the exact branch and create a PR after separate gate decisions. It computes the merge decision and approval transition but deliberately does not execute merge, tag, release, deployment, or competition submission.

## AgentTeams deployment boundary

The reviewable resources are in [`../deploy/agentteams/team.v1.2.0.yaml`](../deploy/agentteams/team.v1.2.0.yaml). Replace every `CONFIGURE_*` placeholder, provision independent service identities, and satisfy the controls in [`AGENTTEAMS-INTEGRATION-PLAN.md`](AGENTTEAMS-INTEGRATION-PLAN.md) before applying them. A local handoff report is not native AgentTeams runtime evidence.

The observed macOS Docker Desktop profile is [`../deploy/agentteams/team.native-smoke.v1.2.0.yaml`](../deploy/agentteams/team.native-smoke.v1.2.0.yaml). It is intentionally not a standalone or idempotent deployment: the official AgentTeams `v1.2.0` installer must already have created its `default` Manager and local admin identity, `host.docker.internal` must resolve, model/gateway configuration is external, and repository Skills are not packaged by this file.

For an isolated bridge smoke only, start the MCP endpoint with explicit network exposure:

```bash
export TITMAS_ACTION_GATE_STATE_DIR='artifacts/runtime/agentteams-native-smoke'
export TITMAS_ACTION_GATE_CALLER_TOKEN='replace-with-a-random-agent-token'
export TITMAS_ACTION_GATE_APPROVER_TOKEN='replace-with-a-distinct-approver-token'
export TITMAS_ACTION_GATE_DEMO_MODE='true'
export TITMAS_ACTION_GATE_MCP_TRANSPORT='streamable-http'
export TITMAS_ACTION_GATE_MCP_HOST='0.0.0.0'
.venv/bin/titmas-action-gate-mcp
```

Binding `0.0.0.0` expands network exposure and supplies no authentication beyond the reference tokens. Keep the host isolated, expose no provider-action credential, and destroy the exact temporary AgentTeams containers, their dedicated smoke volume, state directory, and session cookie after evidence capture. Do not use broad container or volume deletion commands. The retained run evidence is [`../demo/evidence/agentteams-native-20260802.json`](../demo/evidence/agentteams-native-20260802.json).

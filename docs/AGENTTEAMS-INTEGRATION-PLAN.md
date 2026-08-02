# AgentTeams integration plan

Status: `NATIVE_LOCAL_SMOKE_OBSERVED_AUTONOMOUS_CHAIN_AND_LEAST_PRIVILEGE_ENFORCEMENT_PENDING`

## Source pin

The integration targets AgentTeams `v1.2.0` at commit `793db242257a569d911b1aa59c1cd554af78511f`. The observed public contract uses `agentteams.io/v1beta1` Worker, Team, Human, and Manager resources, Worker `skills`, and Worker `mcpServers` entries with `name`, `url`, and `transport`.

The template in [`../deploy/agentteams/team.v1.2.0.yaml`](../deploy/agentteams/team.v1.2.0.yaml) defines the intended six Workers, Team, Human, and Manager. The historical, non-idempotent five-Worker profile in [`../deploy/agentteams/team.native-smoke.v1.2.0.yaml`](../deploy/agentteams/team.native-smoke.v1.2.0.yaml) was applied to an official local `v1.2.0` runtime on 2026-08-02. It reused the installer Manager and admin identity, used a preview model, and connected Workers to the earlier Action Gate MCP endpoint. It is retained native runtime evidence, not evidence for the new autonomous or Alibaba Cloud integration.

## Topology

- one Manager for dispatch, status, and human-visible coordination;
- one Team with `workflow-lead` as `team_leader`;
- five specialized Worker members, including the bounded `cloud-context-inspector`;
- one Human resource as the review-channel identity, not an implicit approval;
- local Skill directories mounted or packaged into the Workers;
- the Action Gate MCP server exposed through an authenticated gateway;
- provider GitHub MCP exposed only to `github-operator`, after independent gateway and provider ACL checks.

The six identities are defined in [`../agents/registry.json`](../agents/registry.json). AgentTeams communication permission is not action authorization.

## Implemented handoff protocol

This is the intended protocol and remains normative even where the observed smoke deviated:

1. Manager sends the request to `workflow-lead` and records a correlation ID.
2. `workflow-lead` assigns normalization to `request-analyst`.
3. `evidence-verifier` calls `verify_evidence` and returns the immutable verifier receipt.
4. `workflow-lead` calls `evaluate_action_gate`; no Worker may synthesize the outcome.
5. On `BLOCK`, the team records the rejection and stops.
6. On `REQUIRE_APPROVAL`, the Manager exposes the exact scope to the Human channel. A chat message alone is not approval; `record_human_approval` creates the signed/scoped record.
7. On `ALLOW`, `github-operator` compares the provider invocation to the exact decision tuple, consumes the decision once, then attempts the call.
8. `release-steward` submits the exact deployment-related release request without evaluating it.
9. `cloud-context-inspector` invokes only the typed current-account Resource Center search. Missing credentials or permission remains `NOT_ASSESSED`; the Skill cannot decide the gate.
10. `release-steward` packages execution plus the service-verified cloud receipt, invokes canonical verification, and requests a new deterministic release decision.

## Observed native-smoke deviations

The retained evidence is [`../demo/evidence/agentteams-native-20260802.json`](../demo/evidence/agentteams-native-20260802.json).

- Manager task creation and the first leader assignment succeeded, but the leader did not finish the remaining chain without operator prompts.
- Four specialist Workers used Qwen `qwen3.8-max-preview` to invoke the MCP server; this is `OPERATOR_SUPERVISED_AGENT_EXECUTED`, not autonomous end-to-end completion.
- `github-operator` called `evaluate_action_gate`, even though the agent registry allows it only `get_action_state`. All Workers shared one MCP endpoint and per-Worker tool ACLs were not enforced.
- A concurrent prompt created an unrelated release request at global sequence 2. The append-only hash chain remained valid, but the orchestration was semantically contaminated.
- Repository Skill names were declared on Workers, but Skill package materialization/discovery was not independently retained.
- A model-only Worker update did not reconcile until another field changed; re-applying an existing Human through the multi-document path returned HTTP 405.
- The resulting `ALLOW` expired after five minutes, no provider credential was present, and no GitHub action was attempted.

The role registry is not widened to conform to the observed deviation. The next run must enforce the registry at the MCP gateway and demonstrate a clean, unassisted correlation-scoped chain.

## Deployment controls required before live use

- pin the AgentTeams container/chart and CRDs by digest;
- separate service accounts for Manager, each Worker, gate service, evidence adapter, and provider MCP;
- deny provider MCP access to all identities except the narrow operator;
- store credentials in a secret manager and never in CRDs, prompts, Skills, logs, or fixtures;
- authenticate and authorize MCP calls, with per-tool allowlists;
- sign approval and decision records; use a monotonic store for consumption and revocation;
- enforce egress, namespace, resource, and audit-log policies;
- retain rejected actions and verifier failures;
- run the threat-model and conformance suites before any external write.
- keep Alibaba Cloud credentials server-side, prove the RAM identity is read-only, prohibit all cloud writes in code, and retain aggregate-only cloud evidence.

## Compatibility gate

Any AgentTeams upgrade must compare CRDs, Skill frontmatter, Manager/Worker behavior, and MCP transport. Until reviewed, the deployment remains pinned to `v1.2.0`; a documentation edit is not an upgrade authorization.

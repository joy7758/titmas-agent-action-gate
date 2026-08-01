# AgentTeams integration plan

Status: `M1_SPECIFICATION_ONLY`

## Source pin

The integration targets AgentTeams `v1.2.0` at commit `793db242257a569d911b1aa59c1cd554af78511f`. The observed public contract uses `agentteams.io/v1beta1` Worker, Team, Human, and Manager resources, Worker `skills`, and Worker `mcpServers` entries with `name`, `url`, and `transport`.

The template in [`../deploy/agentteams/team.v1.2.0.yaml`](../deploy/agentteams/team.v1.2.0.yaml) is deliberately not applied by milestone 1. Model names, human identity, endpoints, Kubernetes policy, secrets, and provider ACLs remain deployment inputs.

## Topology

- one Manager for dispatch, status, and human-visible coordination;
- one Team with `workflow-lead` as `team_leader`;
- four specialized Worker members;
- one Human resource as the review-channel identity, not an implicit approval;
- local Skill directories mounted or packaged into the Workers;
- the Action Gate MCP server exposed through an authenticated gateway;
- provider GitHub MCP exposed only to `github-operator`, after independent gateway and provider ACL checks.

The five identities are defined in [`../agents/registry.json`](../agents/registry.json). AgentTeams communication permission is not action authorization.

## Planned handoff protocol

1. Manager sends the request to `workflow-lead` and records a correlation ID.
2. `workflow-lead` assigns normalization to `request-analyst`.
3. `evidence-verifier` calls `verify_evidence` and returns the immutable verifier receipt.
4. `workflow-lead` calls `evaluate_action_gate`; no Worker may synthesize the outcome.
5. On `BLOCK`, the team records the rejection and stops.
6. On `REQUIRE_APPROVAL`, the Manager exposes the exact scope to the Human channel. A chat message alone is not approval; `record_human_approval` creates the signed/scoped record.
7. On `ALLOW`, `github-operator` compares the provider invocation to the exact decision tuple, consumes the decision once, then attempts the call.
8. `release-steward` packages execution evidence, invokes verification, and requests a new release decision.

## Deployment controls required before use

- pin the AgentTeams container/chart and CRDs by digest;
- separate service accounts for Manager, each Worker, gate service, evidence adapter, and provider MCP;
- deny provider MCP access to all identities except the narrow operator;
- store credentials in a secret manager and never in CRDs, prompts, Skills, logs, or fixtures;
- authenticate and authorize MCP calls, with per-tool allowlists;
- sign approval and decision records; use a monotonic store for consumption and revocation;
- enforce egress, namespace, resource, and audit-log policies;
- retain rejected actions and verifier failures;
- run the threat-model and conformance suites before any external write.

## Compatibility gate

Any AgentTeams upgrade must compare CRDs, Skill frontmatter, Manager/Worker behavior, and MCP transport. Until reviewed, the deployment remains pinned to `v1.2.0`; a documentation edit is not an upgrade authorization.

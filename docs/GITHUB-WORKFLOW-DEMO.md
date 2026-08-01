# GitHub workflow demo

Status: `EXECUTED_BOUNDED_PUBLIC_SANDBOX_NO_MERGE`

The demo used the disposable public repository [`joy7758/titmas-action-gate-demo-sandbox`](https://github.com/joy7758/titmas-action-gate-demo-sandbox). It did not write to this repository's default branch, merge the sandbox PR, or publish a release.

## Scenario

1. A caller requests creation of a bounded documentation branch and pull request.
2. `request-analyst` emits a schema-valid request and preserves uncertainty.
3. `evidence-verifier` checks source, diff, tests, and authorization evidence through pinned `agent-evidence`.
4. The Action Gate emits `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL` from the versioned policy and evidence result.
5. `github-operator` attempts only an exact `ALLOW` action.
6. The provider result, commit, diff, checks, and rejected attempts become a new evidence bundle.
7. `agent-evidence` verifies that bundle.
8. `release-steward` requests a separate merge or release decision.
9. A high-risk policy result returns `REQUIRE_APPROVAL`; a Human record must bind the exact action before re-evaluation.

## Demonstrated boundaries

- branch push, pull-request creation, pull-request merge, tag, and release are independent actions;
- a verifier PASS is evidence input, not a release decision;
- a provider success is execution evidence, not certification;
- a PR is not a merge, a merge is not a release, and a release is not a competition submission.

## Retained evidence

The public summary is [`../demo/evidence/github-sandbox-20260802.json`](../demo/evidence/github-sandbox-20260802.json). It records:

- gate-bound push of commit `ceede38c23a2b952f171e13979cca6a2b6cf9185` to `demo/action-gate-ruleset-bound-20260802`;
- gate-bound creation of [Draft PR #3](https://github.com/joy7758/titmas-action-gate-demo-sandbox/pull/3);
- merge decision `REQUIRE_APPROVAL`, followed by `ALLOW` only after an exact scoped demo approval authenticated with the distinct approver credential and bound to the policy ruleset digest;
- `merge_executed=false`, zero releases at observation, and empty local integrity issue lists;
- the full local report digest without publishing local filesystem paths.

The handoffs came from the AgentTeams CRD-compatible local harness. `live_agentteams_deployment_claimed=false` remains canonical.

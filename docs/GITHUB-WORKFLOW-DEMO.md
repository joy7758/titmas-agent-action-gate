# Planned GitHub workflow demo

Status: `NOT_EXECUTED`

The demo will use a disposable repository and least-privilege GitHub identity. It will not run against this repository's default branch or publish a release during milestone 1.

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

## Completion evidence required

The executed demo must retain AgentTeams handoffs, normalized requests, policy version/digest, evidence bundle and verifier receipt, gate decisions, provider request/response metadata, approval record where applicable, final repository state, negative-case results, and exact component versions. Until that package exists and validates, `GITHUB_DEMO_EXECUTED=false` remains canonical.

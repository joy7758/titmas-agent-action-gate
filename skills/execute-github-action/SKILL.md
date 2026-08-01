---
name: execute-github-action
description: Specify a future one-attempt GitHub provider invocation bound to an exact live ALLOW; milestone 1 grants no execution capability.
assign_when: A future reviewed execution adapter receives an exact server-side ALLOW reference for one GitHub action and the provider ACL independently permits it.
---

# Execute exact GitHub action

Status: `SPECIFICATION_ONLY_NO_EXECUTION_AUTHORITY`.

## Inputs

- server-side decision reference, never model-pasted decision content;
- exact provider action, target, parameters, and idempotency key;
- future provider identity and ACL managed outside prompts.

## Planned output

One execution-attempt receipt including provider request ID, response class, timestamps, bound decision ID, and redacted metadata.

## Required future procedure

1. Fetch and verify signature, expiry, outcome, exact binding, and unconsumed state.
2. Atomically consume the decision for one attempt.
3. Invoke only the bound allowlisted provider tool.
4. Capture success or failure without secrets.
5. Generate post-execution evidence for independent verification.

## Stop conditions

Stop on any mismatch, replay, expiry, unavailable gate, provider ACL failure, parameter expansion, or request to merge/tag/release under a PR-create decision. This milestone's manifest deliberately sets `may_execute=false` and provides no provider MCP endpoint.

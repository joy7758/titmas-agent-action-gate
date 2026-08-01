---
name: execute-github-action
description: Execute one experimental GitHub provider invocation bound to an exact live ALLOW and retain the attempt receipt.
assign_when: The reviewed execution adapter receives an exact server-side ALLOW reference for one allowlisted GitHub action and the provider ACL independently permits it.
---

# Execute exact GitHub action

Status: `EXPERIMENTAL_REFERENCE_IMPLEMENTATION_NO_AUTONOMOUS_AGENT_AUTHORITY`.

## Inputs

- server-side decision reference, never model-pasted decision content;
- exact provider action, target, parameters, and idempotency key;
- provider identity and ACL managed outside prompts.

## Output

One append-only execution-attempt receipt including provider response data, timestamps, bound decision ID, and redacted metadata.

## Required procedure

1. Fetch and verify signature, expiry, outcome, exact binding, and unconsumed state.
2. Atomically consume the decision for one attempt.
3. Invoke only the bound allowlisted provider tool.
4. Capture success or failure without secrets.
5. Generate post-execution evidence for independent verification.

## Stop conditions

Stop on any mismatch, replay, expiry, unavailable gate, provider ACL failure, parameter expansion, or request to merge/tag/release under a PR-create decision. The manifest keeps `may_execute=false` because the Worker has no autonomous authority; the separate service/provider boundary consumes a valid decision and provider ACL for one attempt.

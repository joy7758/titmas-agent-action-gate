---
name: prepare-release-decision
description: Assemble post-execution evidence and request a new deterministic merge, tag, or release decision without granting it.
assign_when: A bounded GitHub action has an execution-attempt receipt and a later merge, tag, release, or submission-like action is proposed.
---

# Prepare release decision

## Inputs

- execution-attempt receipt and exact repository state;
- commit/diff/check artifacts and retained failures;
- proposed next action as a new action request.

## Output

A post-execution evidence reference, pinned verifier result, and a request for a new Action Gate decision.

## Procedure

1. Keep provider success, evidence verification, merge, tag, release, deployment, and competition submission separate.
2. Assemble immutable evidence without omitting failed attempts.
3. Request `verify_evidence` through the canonical adapter.
4. Submit a new exact action request and call the gate.
5. Report the returned outcome and explicit non-claims.

## Stop conditions

Stop when repository state is stale, checks are missing, evidence is invalid, scope changes, or approval is absent. Never merge, tag, publish, deploy, submit, certify, or claim production readiness.

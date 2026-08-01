---
name: use-action-gate
description: Submit versioned gate inputs, relay the deterministic outcome, and stop on BLOCK or REQUIRE_APPROVAL without model override.
assign_when: Schema-valid request, policy, and evidence inputs are ready for a pre-action or post-execution authorization decision.
---

# Use Action Gate

## Inputs

- action request;
- policy evaluation result;
- evidence verification result;
- optional scoped human approval.

## Output

The server-returned `action-gate-decision.v0.1` receipt and a routing instruction derived only from its outcome.

## Procedure

1. Confirm all records share the exact request binding.
2. Call `evaluate_action_gate` once with an idempotency key.
3. On `BLOCK`, retain reasons and stop.
4. On `REQUIRE_APPROVAL`, show the exact requested scope to the Human channel and stop; chat acknowledgement is not approval.
5. On `ALLOW`, hand the untouched decision reference to the narrow operator.

## Stop conditions

Stop on schema, digest, policy-version, signature, identity, expiry, or tuple mismatch. Never reinterpret reasons, upgrade a result, synthesize approval, or claim execution success.

---
name: verify-agent-evidence
description: Invoke the pinned agent-evidence verifier and return its immutable structured result without turning verification into authorization.
assign_when: An action request has an immutable evidence-bundle reference that must be verified before policy or release evaluation.
---

# Verify agent evidence

## Inputs

- request binding and required evidence types;
- immutable bundle reference and expected digest;
- pinned `agent-evidence==0.6.0` adapter identity.

## Output

An `evidence-verification-result.v0.1` record that preserves verifier name, version, distribution digest, status, checks, and bundle digest.

## Procedure

1. Attach the immutable reference without copying evidence claims into model text.
2. Call `verify_evidence`; the service invokes the pinned canonical dependency.
3. Return the receipt unchanged and identify unavailable or malformed results.
4. Treat missing, invalid, and tampered evidence as explicit non-success states.

## Stop conditions

Stop on mutable references, digest mismatch, verifier-version mismatch, unavailable verifier, or a request to rewrite a failure. Verification is not truth, policy, authorization, certification, compliance, execution success, or release permission.

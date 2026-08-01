# Action Gate decision specification v0.1

Status: `IMPLEMENTED_EXPERIMENTAL_REFERENCE`
Schema: [`../schemas/action-gate-decision.v0.1.schema.json`](../schemas/action-gate-decision.v0.1.schema.json)

## Inputs

The pure decision function consumes schema-valid canonical JSON:

1. `action_request`;
2. `policy_evaluation` produced by the pinned policy ruleset;
3. `evidence_verification_result` produced by the pinned `agent-evidence` adapter;
4. zero or one `human_approval`.

The implementation must compute SHA-256 over RFC 8785 JSON Canonicalization Scheme bytes for each input. A decision binds those digests and the exact request tuple:

```text
(request_id, action, provider, repository, resource_ref, parameters_sha256)
```

## Precedence

Rules are evaluated in this exact order. The first matching terminal rule wins.

| Order | Condition | Outcome | Required reason code |
|---:|---|---|---|
| 1 | Any required input is not schema-valid or request tuple/digest does not match | `BLOCK` | `INPUT_INVALID` or `INPUT_MISMATCH` |
| 2 | Policy effect is `DENY` | `BLOCK` | `POLICY_DENY` |
| 3 | Evidence status is `MISSING` | `BLOCK` | `EVIDENCE_MISSING` |
| 4 | Evidence status is `INVALID` | `BLOCK` | `EVIDENCE_INVALID` |
| 5 | Evidence status is `TAMPERED` | `BLOCK` | `EVIDENCE_TAMPERED` |
| 6 | A supplied approval is denied, revoked, expired, or does not bind the request tuple and policy | `BLOCK` | `APPROVAL_INVALID` |
| 7 | Policy requires human approval and no approval is supplied | `REQUIRE_APPROVAL` | `HUMAN_APPROVAL_REQUIRED` |
| 8 | Policy permits the action and all required evidence is `VALID`, with a valid approval when required | `ALLOW` | `ALL_BOUNDARIES_SATISFIED` |
| 9 | No earlier rule applies | `BLOCK` | `UNHANDLED_STATE` |

An empty or unreachable evidence provider does not become `REQUIRE_APPROVAL`; it is `BLOCK`. A human cannot approve tampered or missing evidence. Approval can satisfy a policy boundary but cannot rewrite verifier results.

## Outcomes

- `ALLOW`: sets `may_execute=true` for exactly one bounded attempt before `expires_at`. It does not mean the provider accepted the action.
- `BLOCK`: sets `may_execute=false`; retry requires a new or corrected input set and a new decision.
- `REQUIRE_APPROVAL`: sets `may_execute=false`; the caller may obtain a scoped human record and re-evaluate.

The engine must not accept free-form reason text as a decision input. It may emit explanatory text derived from stable reason codes.

## Idempotency and replay

`decision_id` is derived from the canonical input digests plus engine version. Re-evaluating identical inputs produces the same outcome and reason-code sequence. Execution consumes a separate idempotency key tied to `decision_id`. Reuse after expiry, consumption, target mutation, or policy-version change is blocked.

## Two-gate GitHub rule

Creating a branch, pushing a commit, opening a pull request, merging a pull request, creating a tag, and publishing a release are distinct actions. Each write needs its own request and decision. Post-execution evidence from one action may be evidence for another, but never authorization for it.

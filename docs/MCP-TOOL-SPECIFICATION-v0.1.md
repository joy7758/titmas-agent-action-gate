# MCP tool specification v0.1

Status: `SPECIFICATION_ONLY`
Manifest: [`../mcp/server-manifest.v0.1.json`](../mcp/server-manifest.v0.1.json)

## Server boundary

The planned `titmas-action-gate` MCP server is a deterministic contract adapter. It does not orchestrate agents and does not hold GitHub credentials. The provider GitHub MCP is separate and inaccessible until an exact `ALLOW` is validated by the execution adapter.

## Tools

| Tool | Purpose | Mutates external provider | Authorization semantics |
|---|---|---:|---|
| `submit_action_request` | Validate and persist a normalized request | no | none |
| `attach_evidence` | Associate an immutable evidence-bundle reference | no | none |
| `verify_evidence` | Invoke pinned `agent-evidence` and persist its receipt | no | verifies evidence only |
| `evaluate_action_gate` | Compute the deterministic decision | no | emits a bounded decision |
| `record_human_approval` | Persist a signed, scoped approval or denial | no | supplies one gate input |
| `get_action_state` | Read append-only request state and receipts | no | read only |

All tools require authenticated caller identity, correlation ID, idempotency key, schema version, and request-size limits at transport level. Tool output uses structured JSON; free-form model text is never interpreted as approval, policy, or evidence status.

## Error model

Transport and server failures use MCP errors and never default to `ALLOW`. Contract failures return a stable machine code such as `SCHEMA_INVALID`, `REQUEST_NOT_FOUND`, `DIGEST_MISMATCH`, `VERIFIER_UNAVAILABLE`, `POLICY_VERSION_UNKNOWN`, `APPROVAL_SCOPE_MISMATCH`, or `DECISION_ALREADY_CONSUMED`.

## Provider execution

The future execution adapter must:

1. fetch the decision from the gate, not accept a model-pasted decision;
2. verify server signature, expiry, unconsumed state, and exact tuple/digest;
3. mark the one-attempt decision consumed atomically;
4. invoke only the allowlisted provider tool with the bound arguments;
5. record request/response metadata without secrets;
6. produce an evidence bundle and submit it to a new verification and release gate.

MCP discovery means a tool exists. It never means the caller is allowed to use it.

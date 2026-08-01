# MCP tool specification v0.1

Status: `EXPERIMENTAL_REFERENCE_IMPLEMENTATION`
Manifest: [`../mcp/server-manifest.v0.1.json`](../mcp/server-manifest.v0.1.json)

## Server boundary

The `titmas-action-gate` MCP server is a deterministic contract adapter implemented with FastMCP. It supports stdio, SSE, and streamable HTTP, although only stdio is exercised in the retained integration test. It does not orchestrate agents, expose provider mutation tools, or hold GitHub credentials. The optional provider adapter is a separate process boundary reached only after an exact `ALLOW` is validated and atomically consumed.

## Tools

| Tool | Purpose | Mutates external provider | Authorization semantics |
|---|---|---:|---|
| `submit_action_request` | Validate and persist a normalized request | no | none |
| `attach_evidence` | Associate an immutable evidence-bundle reference | no | none |
| `verify_evidence` | Invoke pinned `agent-evidence` and persist its receipt | no | verifies evidence only |
| `evaluate_action_gate` | Compute the deterministic decision | no | emits a bounded decision |
| `record_human_approval` | Persist a signed, scoped approval or denial | no | supplies one gate input |
| `get_action_state` | Read append-only request state and receipts | no | read only |

All tools require authenticated identity. `record_human_approval` requires a credential distinct from the normal agent caller token; production deployments must map that credential to a verified Human identity. Requests retain correlation ID, idempotency key, and schema version, while network deployments must add transport request-size limits. Tool output uses structured JSON; free-form model text is never interpreted as approval, policy, or evidence status.

## Error model

Transport and server failures use MCP errors and never default to `ALLOW`. Contract failures return a stable machine code such as `SCHEMA_INVALID`, `REQUEST_NOT_FOUND`, `DIGEST_MISMATCH`, `VERIFIER_UNAVAILABLE`, `POLICY_VERSION_UNKNOWN`, `APPROVAL_SCOPE_MISMATCH`, or `DECISION_ALREADY_CONSUMED`.

## Provider execution

The experimental execution adapter:

1. fetch the decision from the gate, not accept a model-pasted decision;
2. verify server signature, expiry, unconsumed state, and exact tuple/digest;
3. mark the one-attempt decision consumed atomically;
4. invoke only the allowlisted provider tool with the bound arguments;
5. record request/response metadata without secrets;
6. produce an evidence bundle and submit it to a new verification and release gate.

The real-GitHub implementation allowlists one `owner/repository`, verifies the worktree top level and `origin`, validates an exact local commit and branch ref, and implements only branch push, PR create, and PR merge. The retained public run did not call merge.

MCP discovery means a tool exists. It never means the caller is allowed to use it.

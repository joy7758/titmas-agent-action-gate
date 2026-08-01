# Threat model v0.1

Status: design hypothesis, not a security assessment.

## Protected assets

- provider credentials and repository permissions;
- immutable action requests, policy snapshots, approvals, decisions, and evidence receipts;
- the correspondence between an `ALLOW` and the exact provider invocation;
- retained rejection and failure history;
- separation of analysis, approval, execution, and release.

## Threats and planned controls

| Threat | Example | Fail-closed control | Required evaluation |
|---|---|---|---|
| Prompt injection | issue text tells operator to skip the gate | treat all content as data; provider tool unavailable to analysts | malicious issue fixture |
| Confused deputy | Worker uses another request's approval | bind all records to tuple and digests | cross-request approval test |
| Scope expansion | approved PR creation becomes merge | separate action names and decisions | action mutation test |
| Evidence tampering | bundle bytes change after verification | content digest and pinned verifier receipt | tampered-evidence case |
| Missing evidence | timeout is treated as success | `MISSING -> BLOCK` | missing-evidence case |
| Stale/replayed authorization | reuse an old `ALLOW` | expiry, version pin, atomic consumption | replay and expiry tests |
| Approval spoofing | chat text is parsed as consent | signed Human record only | unsigned approval test |
| Self-approval | operator approves its own release | separate human identity and service account | identity separation test |
| Policy downgrade | caller selects an older permissive ruleset | server-controlled current policy and downgrade denial | policy rollback test |
| MCP substitution | same tool name points to attacker endpoint | pinned endpoint identity and gateway policy | endpoint identity test |
| Secret leakage | token appears in prompt/evidence/log | secret manager, redaction, no secret inputs | leak scanning |
| Audit deletion | rejected attempt disappears | append-only store and retention checks | deletion attempt test |

## Residual risk

Schemas cannot prove the correctness of policy, verifier, identity provider, storage, AgentTeams deployment, or GitHub configuration. A compromised gate service or provider credential can still violate intended boundaries. Runtime hardening, adversarial evaluation, independent review, recovery tests, and operational monitoring are required before any production-readiness claim.

## Explicit exclusions

Milestone 1 does not claim formal verification, sandbox escape resistance, supply-chain assurance, compliance, certification, or protection against every human administrator action.

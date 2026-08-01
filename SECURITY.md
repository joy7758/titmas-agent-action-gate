# Security policy

## Supported status

This repository is an experimental reference implementation. No version is currently supported for production use, compliance reliance, certification, or high-value credentials.

## Report a vulnerability

Do not open a public issue containing secrets, exploitable credentials, or private repository details. Use GitHub's private vulnerability reporting for this repository when available, or contact the repository owner through an established private channel. Include the affected commit, threat boundary, minimal reproduction, and whether external actions occurred.

## Important limitations

- demo record signatures and distinct caller/approver tokens use local static material and do not implement production key custody, identity proofing, rotation, revocation, or hardware protection;
- SQLite hash chaining detects many local mutations but is not an independently anchored immutable ledger;
- the retained AgentTeams evidence is a CRD-compatible local handoff harness, not a live Manager/Worker deployment;
- the MCP stdio test proves protocol interoperability, not hardened network authentication or multi-tenant isolation;
- `agent-evidence` verifies its evidence profile contract; verification is neither factual truth nor action authorization;
- a valid gate decision does not override GitHub permissions and does not imply execution success;
- a compromised gate process, provider credential, workstation, or administrator can bypass reference controls.

Before operational use, require independent security review, asymmetric service identities, secret management and rotation, authenticated transport, tenant isolation, durable externally anchored audit logs, incident recovery, policy governance, provider least privilege, and adversarial operational exercises.

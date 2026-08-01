# Canonical agent-evidence integration

The runtime depends on `agent-evidence[mcp]==0.6.0` and records the exact wheel SHA-256 in [`../governance/upstream-sources.json`](../governance/upstream-sources.json). `src/titmas_action_gate/evidence.py` is a thin adapter: it creates OAP profiles, calls the installed package's public validator, maps the result into the local evidence-result contract, and uses the package's `EvidenceRecorder` for the evidence event chain.

The published 0.6.0 wheel does not contain the default OAP schema path expected by its validator. The repository therefore retains the exact Apache-2.0 OAP schema from the pinned upstream tag and passes that path to the unmodified installed validator. The local schema digest is checked before every verification. No validator source was copied or reimplemented.

The boundary remains:

```text
agent-evidence VALID != factual truth
agent-evidence VALID != policy approval
agent-evidence VALID != Action Gate ALLOW
Action Gate ALLOW != provider success
```

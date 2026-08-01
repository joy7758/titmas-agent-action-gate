# Contract evaluation cases

These fixtures are reproducible inputs and expected decisions for the v0.1 specification. They do not invoke AgentTeams, `agent-evidence`, an MCP server, GitHub, or a release.

| Case | Expected outcome | Boundary |
|---|---|---|
| `valid-execution` | `ALLOW` | all versioned inputs align; execution is only permitted to be attempted |
| `missing-evidence` | `BLOCK` | missing evidence cannot be replaced by agent judgment or approval |
| `tampered-evidence` | `BLOCK` | failed integrity check has higher precedence than approval |
| `high-risk-approval` | `REQUIRE_APPROVAL` | evidence is valid, but merge policy requires a scoped Human record |

The validator checks each nested record against its schema, request bindings, parameters digest, required evidence set, and expected precedence result. Milestone 2 must implement the independent deterministic engine and run these same cases against it.

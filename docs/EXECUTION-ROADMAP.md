# Execution roadmap

Each milestone is gated. Later work cannot retroactively upgrade an earlier artifact into authorization or proof.

## M1 — specification baseline

Status: `COMPLETE` as a specification and contract baseline. Public commit and CI observation are recorded separately; they do not upgrade this into implementation.

- repository architecture and source pins;
- five AgentTeams identities and deployment template;
- five versioned reusable Skills with examples;
- MCP server/tool specification;
- deterministic decision contract and JSON Schemas;
- four reproducible contract fixtures;
- governance declaration and DBA management boundary;
- validators and CI contract plan.

Exit evidence: JSON/YAML/schema/link validation and unit tests. This proves only internal consistency.

## M2 — deterministic core

Status: `NOT_STARTED`.

- implement pure policy and Action Gate functions;
- implement canonical serialization, digest binding, expiry, revocation, and one-time consumption;
- retain negative decisions;
- add property, replay, mutation, and precedence tests.

Exit gate: deterministic conformance across all fixtures and adversarial cases. No external provider writes.

## M3 — evidence and MCP adapters

Status: `NOT_STARTED`.

- integrate pinned `agent-evidence==0.6.0` without copying its validator;
- implement the six MCP tools with authentication and structured errors;
- sign records and use append-only storage;
- add failure-injection and supply-chain checks.

Exit gate: positive and negative adapter evidence in a local isolated environment.

## M4 — AgentTeams and sandbox GitHub demo

Status: `NOT_STARTED`.

- deploy pinned AgentTeams resources in an isolated namespace;
- provision least-privilege identities and gateway rules;
- execute the full disposable-repository workflow;
- demonstrate all four required cases plus replay, injection, and scope mutation;
- independently rerun the agent recommendation gate.

Exit gate: validated evidence package and human review. Demo completion does not imply production readiness.

## M5 — competition material freeze

Status: `NOT_STARTED_NOT_AUTHORIZED`.

- produce architecture narrative, runnable instructions, evaluation report, limitations, SBOM, license audit, and material manifest/hashes;
- create an optional video only if the competition requires it;
- perform public-claim and secret reviews.

Material freeze, share link, portal upload, final submit, and public announcement are separate events. Each requires explicit authorization and retained evidence.

## M6 — operational review

Status: `OUT_OF_CURRENT_SCOPE`.

Production consideration would require independent security review, incident recovery, key rotation, policy governance, SLOs, observability, backups, multi-tenant isolation, and live operational evidence. The roadmap itself is not proof that these exist.

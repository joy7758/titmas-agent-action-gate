# Reusable Skill specification v0.1

Each Skill is an agent-readable directory with this minimum layout:

```text
skills/<skill-name>/
  SKILL.md
  manifest.json
  examples/example.json
```

## AgentTeams entrypoint

`SKILL.md` starts with YAML frontmatter containing:

- `name`: stable kebab-case identifier;
- `description`: concise capability and boundary;
- `assign_when`: routing condition that tells AgentTeams when delegation is appropriate.

The body must state inputs, outputs, procedure, stop conditions, external tools, authority limits, and non-claims. A Skill is an instruction surface, not permission.

## Versioned manifest

`manifest.json` conforms to [`../schemas/skill-manifest.v0.1.schema.json`](../schemas/skill-manifest.v0.1.schema.json) and pins:

- manifest schema version and semantic Skill version;
- lifecycle status (currently `EXPERIMENTAL` for the five reference Skills);
- AgentTeams compatibility;
- input/output schema references;
- named MCP tools;
- whether it may propose, decide, approve, or execute;
- tests and examples.

No milestone-1 Skill may set `decide`, `approve`, or `execute` to true. The future GitHub execution Skill may invoke a provider only through code that verifies and consumes a matching `ALLOW`; changing that capability requires a reviewed manifest version.

## Reuse and evolution

- Patch: editorial clarification without contract change.
- Minor: backward-compatible input, output, example, or tool addition.
- Major: changed authority, decision semantics, schema incompatibility, or removed guarantee.

Every manifest version is immutable after release. Examples contain synthetic data and no secrets. Tests validate schemas and negative boundaries; a passing example does not prove a deployed integration.

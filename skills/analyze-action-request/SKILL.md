---
name: analyze-action-request
description: Normalize an ambiguous external-action proposal into a versioned request while preserving uncertainty and granting no authority.
assign_when: A caller or agent proposes a GitHub or other high-impact external action that needs an explicit target, parameters digest, and evidence requirements.
---

# Analyze action request

## Inputs

- original request and source reference;
- authenticated caller and AgentTeams correlation IDs;
- current action taxonomy and request schema.

## Output

A candidate `action-request.v0.1` object plus unresolved uncertainty. Compute `parameters_sha256` from canonical parameters; do not invent missing target, credential, policy, evidence, approval, or success facts.

## Procedure

1. Separate requested outcome from the exact external action.
2. Name provider, repository, resource reference, and parameters.
3. Preserve unknowns in `uncertainty`.
4. List evidence requirements as proposals for deterministic policy evaluation.
5. Validate the schema and submit it through `submit_action_request`.

## Stop conditions

Stop on ambiguous target, unsupported action, secrets in input, identity conflict, or a request to treat analysis as permission. This Skill may propose a request; it never decides, approves, executes, releases, certifies, or submits.

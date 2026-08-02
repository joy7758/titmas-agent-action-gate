# M4 AgentTeams runtime blocker closure plan

Status: `AUTHORIZED_FOR_BOUNDED_LOCAL_DEVELOPMENT_NOT_YET_IMPLEMENTED`

Observed at: `2026-08-02T11:27:05+08:00`

Source base: `codex/close-m4-runtime-blockers@6f1c83bf87e6ee96a0eda281e1fa91b8f80a32e1`

Request digest: `sha256:4c49cd5972341431963138202b3ad7567058a986bc419b9b8923e67d2e176c26`

## Outcome and boundary

This work attempts one clean, reproducible, operator-unassisted AgentTeams `v1.2.0` reference run:

```text
Manager
  -> workflow-lead
  -> request-analyst
  -> evidence-verifier
  -> deterministic Action Gate
  -> github-operator
  -> cloud-context-inspector (typed read-only Resource Center preflight)
  -> release-steward
  -> canonical final evidence verification
  -> deterministic final decision
```

The first successful path uses `InMemoryGitHubProvider` only. It must not merge, release, deploy, tag, publish, submit to GOAI, alter the existing sandbox pull request, or exercise a real GitHub credential. One initial Manager task is permitted; recovery prompts or direct Worker prompts after start make the run fail with `intervention_count > 0`.

This plan does not change TITMAS core protocols. AgentTeams remains the orchestration layer, `agent-evidence==0.6.0` remains the canonical evidence validator, and deterministic code remains the sole source of `ALLOW`, `BLOCK`, and `REQUIRE_APPROVAL`.

## Confirmed runtime mismatch and evidence limit

The retained smoke manifest configured `workflow-lead` with `runtime: openclaw`. The pinned AgentTeams Team Leader contract requires `projectflow` and `taskflow`, whose pinned implementations are in the CoPaw runtime. This is a confirmed runtime/tool contract mismatch and matches the retained trace stopping after the first specialist assignment.

The historical run did not retain the complete Leader JSONL/tool loop or a replayable event-to-room map. The mismatch is therefore not claimed as the unique cause. Declared-only repository Skills, a historical room-membership deviation, one shared caller token, hard-coded audit actors, and absent assignment/correlation admission also make the retained run insufficient proof.

The old v0.1 manifest, schema, tests, and evidence remain immutable negative evidence. A new run always receives a new run ID and a separate v0.2 evidence artifact.

## Minimal architecture change

1. **Authenticated runtime principals**
   - derive the audit actor only from a verified Worker credential;
   - require unique credentials for the six Workers and a separate Human approver credential;
   - persist credential references or digests, never credential bytes;
   - reject claimed `actor` or `requested_by.agent_id` values that do not match the authenticated principal.

2. **Code-enforced Worker tool admission**
   - load the exact allowlist from `agents/registry.json`;
   - authorize before reading or mutating business state;
   - expose only the role's allowed MCP projection and repeat the check in service code;
   - retain a scoped security event with stable reason code and `business_state_delta=0` for every denial.

3. **Runtime scope admission**
   - add a versioned envelope carrying `run_id`, `correlation_id`, `task_id`, repository, commit, and assigned Worker;
   - bind `request_id` to this envelope on first admission;
   - require an exact match for every read, write, verification, decision, consumption, and finalization;
   - keep scoped audit chains independently verifiable even if global storage sequences interleave.

4. **Decision and evidence binding fixes**
   - reject a decision whose record request, payload request, current request, action tuple, or parameter digest differs;
   - check store integrity before decision consumption;
   - recompute the attached evidence bytes digest immediately before verification;
   - reject attachment replacement and request/subject mismatch before accepting a canonical validator result.

5. **Repository Skill materialization**
   - build deterministic per-Worker packages using AgentTeams package upload support;
   - include Skill name, version, source commit, schemas, instructions, examples, and deterministic digests;
   - read back the Worker package and retain runtime discovery/load receipts;
   - stop before the initial task on a missing Skill, version drift, extra undeclared Skill, or digest mismatch.

   The five first-party versioned Skills and the separately source-locked official Alibaba Cloud Skill are reported independently. The upstream Skill has no project manifest/version and has unresolved license declarations; its git revision plus per-file hashes form its identity, not a fabricated project version or license conclusion.

6. **Typed cloud-context boundary**
   - assign the exact official Alibaba Cloud Skill only to `cloud-context-inspector`;
   - expose only `inspect_alibabacloud_resources`; the Worker receives no cloud credential bytes or arbitrary shell credential;
   - permit only current-account `resourcecenter.search-resources` with user-confirmed parameters and `include_deleted_resources=false`;
   - retain only aggregates and opaque hashes, then apply a deterministic semantic check before `agent-evidence` integrity verification;
   - keep `CLOUD_CONTEXT_*` statuses separate from Action Gate outcomes and stop on missing credentials, denied permission, or source drift.

7. **Native orchestration contract**
   - create a new autonomous manifest with `workflow-lead.runtime: copaw`;
   - validate `projectflow` and `taskflow` discovery before the initial task;
   - use live Manager-to-Leader and Leader-to-Team room IDs and memberships;
   - let CoPaw's native project/task state machine advance a fixed DAG; do not add an intelligent central controller;
   - make Worker completion messages carry the exact AgentTeams task ID and Leader mention required by the pinned contract.

8. **Disposable native runner**
   - perform source/image/model/tool/Skill/room/ACL preflight;
   - apply resources and read them back;
   - prepare only fixture-bound evidence and isolated state;
   - record `run_started_at`, send one initial Manager stimulus, then monitor read-only;
   - destroy the temporary stack and transient credentials while retaining redacted evidence.

## Implementation order

1. credential-derived identity and per-Worker ACL;
2. run/correlation/task admission and scoped audit records;
3. decision/request/digest and evidence attachment/subject fixes;
4. deterministic Skill packages, attestations, and negative checks;
5. official Alibaba Cloud Skill source lock, typed adapter, sixth Worker, and negative checks;
6. CoPaw Leader manifest plus exact native handoff instructions;
7. A-H focused tests and v0.2 evidence schema/validator;
8. stable non-preview model capability probe;
9. one disposable native run with a separately authorized read-only cloud preflight;
10. full tests, governance validators, build, clean install, clean-install rerun, drift check, and recommendation-gate refresh.

## Adversarial exit matrix

The machine-readable source of truth is [`../evaluations/m4-native-exit-matrix.json`](../evaluations/m4-native-exit-matrix.json).

| Case | Required observation | Fail-closed result |
|---|---|---|
| A | one initial task completes the full native chain with `intervention_count=0` | retain the failed run; do not set autonomous exit fields |
| B | every unauthorized Worker/tool pair is denied before business logic | `MCP_TOOL_NOT_ALLOWED`, security audit only |
| C | cross-run/correlation/task reads, writes, consumption, and finalization are denied | `CROSS_RUN_ACCESS_DENIED` or `CORRELATION_MISMATCH` |
| D | all five first-party Skills plus the separately source-locked official Skill are materialized, discovered, loaded, and hash verified | `SKILL_MISSING`, `SKILL_DIGEST_MISMATCH`, or `SKILL_SCOPE_INVALID` before stimulus |
| E | attached and canonical evidence remains exact and subject-bound | deterministic `BLOCK` with evidence-tamper reason; provider calls remain zero |
| F | live `ALLOW` consumes exactly once and cannot be reused at or after expiry | `DECISION_EXPIRED`, preserving the historical decision unchanged |
| G | high-risk action stops at `REQUIRE_APPROVAL` without agent self-approval | no execution and no implicit approval |
| H | injection text changes no scope, ACL, evidence, policy, approval, or decision | unauthorized attempt denied and provider effect remains zero |

## Stop conditions

Stop and retain a failed run if any of the following occurs: pinned source or image drift; stable non-preview model capability failure; missing Leader tools; Skill mismatch; stale or invalid room membership; ACL or assignment-admission failure; any post-start operator prompt; an unexpected request; cross-run contamination; missing/tampered evidence; decision binding/expiry failure; a real provider path; or run timeout.

If no stable non-preview model is verified live, native execution is `NOT_ASSESSED` and stops. There is no silent model substitution.

## Exit facts and non-claims

Only retained native run evidence may set the M4 autonomous, ACL, Skill, isolation, stable-model, canonical-verifier, and deterministic-authority exit fields to true. Unit tests, a manifest, local harness output, a valid hash chain, or an agent saying it complied are insufficient.

Even after an M4 pass, these facts remain false unless separately proven and authorized:

```text
AGENTTEAMS_PERSISTENT_DEPLOYMENT=false
AGENTTEAMS_PRODUCTION_DEPLOYMENT=false
M4_AUTONOMOUS_RUN_REAL_PROVIDER_OR_WORKLOAD_WRITE_EXECUTED=false
IAM_CREDENTIAL_PROVISIONING_WRITE_EXECUTED=true
COMPETITION_SUBMITTED=false
RELEASE_CREATED=false
PRODUCTION_READY=false
TITMAS_CORE_PROTOCOLS_CHANGED=false
DBA_PORTFOLIO_ADMISSION_GRANTED=false
current_product_use=NOT_RECOMMENDED
```

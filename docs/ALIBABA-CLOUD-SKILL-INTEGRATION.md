# Official Alibaba Cloud Resource Center Skill integration

Status: `NATIVE_AGENTTEAMS_EXTERNAL_SKILL_LOAD_AND_BOUNDED_EMPTY_RESULT_INVOCATION_RETAINED`

Observed at: `2026-08-02T16:26:13+08:00`

## Exact upstream and installation

The installed upstream is `aliyun/alibabacloud-aiops-skills`, subtree `skills/migrationom/entconsole/alibabacloud-resourcecenter-search`, at exact revision `92bd723f7cc217b252feab574c1883fa0aa46b3c`. It is installed outside the repository and resolved through `TITMAS_OFFICIAL_ALIBABA_CLOUD_SKILL_PATH`; retained evidence uses only `external://titmas/skills/alibabacloud-resourcecenter-search`.

The canonical per-file hashes, installation timestamp, source path, Git tree, and installation method are in [`../governance/alibabacloud-resourcecenter-search-source-lock.json`](../governance/alibabacloud-resourcecenter-search-source-lock.json). Runtime loading resolves the external installation, rejects any path inside the repository, verifies all eight upstream files, and retains only name, external path reference, revision, source-lock digest, and load result.

The upstream root and target subtree contain no applicable `LICENSE`, `COPYING`, or `NOTICE` file. The English and Chinese READMEs contain both an Apache-2.0 section and a statement that all Skills use MIT, plus separate online terms. Therefore:

```text
SPDX_LICENSE_IDENTIFIER=NOASSERTION
LICENSE_CONCLUSION=NOT_ASSESSED
REDISTRIBUTION_PERMISSION=NOT_ASSESSED
LICENSE_COMPATIBILITY=NOT_ASSESSED
```

Installation and byte provenance do not establish redistribution permission or an open-source release claim. The upstream subtree is absent from the repository, Worker ZIP, wheel, and sdist. A public source release may include the source lock and installer guidance, but must not distribute these upstream bytes.

A clean checkout can materialize the Skill from the exact upstream revision, then verify every installed byte against the source lock:

```bash
TITMAS_OFFICIAL_ALIBABA_CLOUD_SKILL_PATH='<external-installation-directory>' \
python3 scripts/install_official_alibabacloud_skill.py
```

## Enforced capability shape

The upstream document contains read operations and also enable, disable, full-access, cross-account, installation, plugin-update, and arbitrary CLI examples. Those broader instructions are not runtime authority.

```text
AgentTeams cloud-context-inspector Worker
  -> authenticated load_external_alibabacloud_skill MCP tool
  -> external path resolution and exact source-lock SHA-256 verification
  -> minimal runtime load event
  -> authenticated inspect_alibabacloud_resources MCP tool
  -> server-side typed query validation
  -> exact resourcecenter.search-resources allowlist
  -> externally configured read-only CLI profile
  -> in-memory raw response
  -> aggregate-only sanitized result
  -> deterministic semantic check
  -> agent-evidence integrity verification
  -> CLOUD_CONTEXT evidence reference
  -> deterministic Action Gate
```

The target Worker receives no upstream Skill bytes. One native AgentTeams `qwen3.7-max` Worker turn used OpenClaw's installed `mcporter` bridge for exactly two authenticated selectors: load, then inspect. After the eight-file closed-set hash check, the load tool reads the external official `SKILL.md` and `references/related-apis.md`, confirms the prescribed AI-mode lifecycle, `AliyunResourceCenterReadOnlyAccess`, and `search-resources` operation, and identifies enable, disable, full-access, and cross-account operations as excluded scope. It returns only the minimal verified read-only load result; the inspect tool then calls the typed adapter. The Worker-facing surface receives no upstream bytes, Alibaba Cloud credential bytes, profile name, arbitrary endpoint, `next-token`, output path, or generic cloud API tool. The service rejects all non-search operations before starting a provider process or network call. The only provider operation permitted by code is current-account `resourcecenter search-resources`; `include_deleted_resources` must be false and only explicit `ResourceType` and `RegionId` filters are accepted.

Evidence scope is deliberately narrower than a full runtime attestation. The retained native artifact binds the official Worker image, applied deterministic Worker ZIP, source lock, Matrix event metadata, MCP records, and canonical evidence receipt. It does not bind the Manager or embedded Matrix image identity, and its repository source field is the pre-existing base commit rather than a signed snapshot of the dirty runtime code. The Worker filesystem check is a pre-turn exact whole-file-digest scan; the no-distribution conclusion instead rests on the external-only installation design plus independent tracked-Git, Worker ZIP, wheel, and sdist inspections. None of these observations is a certification or production-runtime claim.

The typed result schema has no Action Gate outcome field. `CLOUD_CONTEXT_AVAILABLE`, `NOT_ASSESSED_NO_VISIBLE_RESOURCE`, `NOT_ASSESSED`, `NOT_ASSESSED_PERMISSION_DENIED`, `BLOCKED_BY_SKILL_BOUNDARY`, `SKILL_LOAD_REJECTED`, and `INVOCATION_FAILED` are evidence statuses only. The Worker and Skill cannot produce `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`.

## Credential boundary

Credentials must be configured outside the Agent session in an Alibaba Cloud CLI profile for a dedicated RAM identity. Never paste an AccessKey ID, AccessKey secret, or STS token into a prompt, `.env.local`, evidence bundle, log, or Git file. The provisioning helper passed the newly created key directly from the RAM API response in memory to `aliyun configure`; it did not render or retain the key in repository artifacts.

The native runtime accepts only non-secret references:

```text
TITMAS_ALIBABA_CLOUD_PROFILE
TITMAS_ALIBABA_RAM_POLICY_OBSERVATION
```

These names identify server-side configuration; their values are not MCP inputs and are not returned to Workers. The policy observation must pass the versioned schema and deterministic checks for an assumed-role identity, the exact six observed allow patterns, zero deny statements, zero write-operation markers, and exactly four distinct successful provider readbacks. The complete role attachment set must be exactly one matching System policy, with zero Custom or unexpected policies. Immediately before each Resource Center query, the adapter calls `sts.GetCallerIdentity` with the same CLI profile and requires both the identity digest and normalized role digest to match the observation. A profile label or successful search alone is not proof that the identity cannot write.

The standalone producer performs those four fixed readbacks and emits only a sanitized observation for review or archival replay; that external file is not accepted as same-run release evidence. It accepts profile and role labels, never credential bytes:

```bash
python3 scripts/capture_alibabacloud_ram_policy_observation.py \
  --control-profile '<RAM-readback-profile-label>' \
  --query-profile '<read-only-query-profile-label>' \
  --role-name '<read-only-role-label>' \
  --run-id '<unique-run-id>' \
  --output '<new-private-observation-path>'
```

## Confirmed query

The official Skill forbids defaulting user-customizable parameters. The user's `2026-08-02` instruction to use the already logged-in Alibaba Cloud session confirmed the previously stated minimum query:

```json
{
  "operation": "resourcecenter.search-resources",
  "account_scope": "current account only",
  "filters": {},
  "max_results": 1,
  "include_deleted_resources": false,
  "cross_account": false,
  "retained_output": "counts, distinct resource-type count, distinct region count, next-token-present flag, hashed provider request ID"
}
```

No resource ID, resource name, account ID, tag, IP address, VPC/VSwitch identifier, raw stdout, raw stderr, HTTP header, signature, token, or credential is retained.

## Credential provisioning and actual invocation

The browser session was authenticated as the Alibaba Cloud account, but root identities cannot call STS `AssumeRole`. The setup therefore created a dedicated RAM caller whose only policy permits assuming one dedicated role. The role has the official Skill-recommended `AliyunResourceCenterReadOnlyAccess` system policy. A later provider readback retained system-policy version `v2`, its canonical document digest, six allowed action patterns, zero deny statements, zero write-operation markers, the entire one-policy role attachment set, and an `AssumedRoleUser` identity/role binding. The observed attachment counts were total=1, System=1, Custom=0, matching=1, unexpected=0. The role trust policy was restricted to that dedicated caller, and its role session duration is 900 seconds; the public artifact does not claim independent replay of the original provisioning writes.

This credential setup performed explicit RAM/IAM writes. Those writes are separately recorded and must not be hidden behind a global zero-write field. The narrower `RESOURCECENTER_WRITE_API_CALLS=0` means only that the retained search invoked no Resource Center write API. Credential bytes were passed in memory into the local Alibaba Cloud CLI configuration, whose file mode is `0600`; they were not printed, placed in an Agent prompt, included in MCP arguments or evidence, or written to this repository.

Aliyun CLI `3.4.11` enabled AI-mode, set the mandatory fixed User-Agent, verified the runtime profile, called STS to bind the live identity, executed the search, and disabled AI-mode on exit. The CLI executable and Resource Center plugin `0.7.0` are both pinned by SHA-256 and rechecked without installing or updating code at runtime. The official CLI plugin's `ResourceCenter/2022-12-01` public endpoint `resourcecenter.aliyuncs.com` is pinned in the adapter because this CLI/plugin combination did not resolve the global endpoint from region metadata. The endpoint is code-owned and is not an Agent input.

The retained invocation was:

```text
operation=resourcecenter.search-resources
filters={}
max_results=1
include_deleted_resources=false
cross_account=false
cli_exit_status=0
returned_resource_count=0
next_token_present=false
agent_evidence_status=VALID
semantic_cloud_context_usable_for_release=false
resourcecenter_write_api_calls=0
iam_control_plane_provisioning_writes_occurred=true
runtime_local_cli_config_writes=3
runtime_sts_identity_read_calls=1
runtime_cloud_read_calls=2
```

`returned_resource_count=0` means only that no resource was visible to this bounded identity. It does not prove that the account contains no resources. The deterministic semantic check therefore marks `NONEMPTY_VISIBLE_RESULT=false`; this receipt enters the evidence path but cannot satisfy a release request's `CLOUD_CONTEXT` requirement. No additional permissions were granted merely to produce a non-zero demo response.

The authenticated `cloud-context-inspector` called `inspect_alibabacloud_resources` through the FastMCP Streamable HTTP runtime. A control call from `request-analyst` was rejected as `MCP_TOOL_NOT_ALLOWED`. The runtime stored the sanitized preflight, invoked canonical `agent-evidence 0.6.0`, and received `VALID` for integrity. The public artifact retains the profile plus complete minimal record, security, and agent-evidence event chains. `scripts/validate_alibabacloud_runtime_evidence.py` fails closed unless it can recompute every workspace/file provenance digest, match the inline RAM observation to its source file, replay all three chains, and reproduce the agent-evidence receipt. `VALID` does not override the failed semantic nonempty-result check. No deterministic Gate decision was requested or returned by this Worker.

Public-safe evidence: [`../demo/evidence/alibabacloud-resourcecenter-preflight-20260802.json`](../demo/evidence/alibabacloud-resourcecenter-preflight-20260802.json).

Native AgentTeams Worker-turn evidence: [`../demo/evidence/agentteams-native-alibabacloud-skill-20260802.json`](../demo/evidence/agentteams-native-alibabacloud-skill-20260802.json). Its validator replays the record, security, and agent-evidence chains, verifies the canonical receipt, requires a strict final Worker report with no trailing correction, binds every response event to the observed Matrix trace, and fails closed for any retained gate outcome, scoped cloud write, or upstream package member. A separate sanitized receipt records a fixed-string scan of ten known current secret values across all six reachable commits and the 150-file candidate snapshot; it retains no value, value digest, or matching content and does not claim to detect unknown historical secrets: [`../demo/evidence/known-secret-git-history-scan-20260802.json`](../demo/evidence/known-secret-git-history-scan-20260802.json).

Append-only correction: [`../demo/evidence/agentteams-native-alibabacloud-skill-correction-20260802.json`](../demo/evidence/agentteams-native-alibabacloud-skill-correction-20260802.json). The original native artifact and its v0.1 schema remain byte-for-byte unchanged. The correction binds the original artifact digest and reclassifies only the unsupported prior credential-rotation assertion as `UNKNOWN`; no prior credential digest was retained, so rotation cannot be verified. It also records that the RAM observation was 5,791.862693 seconds old at the native evidence time, beyond the new 900-second maximum. Historical replay therefore remains structurally valid but release-ineligible.

The official Alibaba Cloud Skill sub-milestone is complete for this bounded evidence scope. The frozen set retains four separately hashed facts—official source lock, read-only RAM policy observation, historical adapter-only evidence, and the later native Worker evidence—and is cross-validated by [`../scripts/validate_alibabacloud_evidence_set.py`](../scripts/validate_alibabacloud_evidence_set.py). Full M4 remains incomplete; this freeze does not authorize merge, release, deployment, or GOAI submission.

Current truth:

```text
OFFICIAL_ALIBABA_CLOUD_SKILL_INSTALLED=true
ALIBABA_CLOUD_OFFICIAL_SKILL_SUBMILESTONE=COMPLETE
FULL_M4_COMPLETE=false
SKILL_SOURCE_AND_HASH_RETAINED=true
TYPED_READ_ONLY_BOUNDARY_TESTED=true
AGENTTEAMS_NATIVE_WORKER_TURN_RETAINED=true
OFFICIAL_SKILL_ACTUALLY_INVOKED=true
SKILL_BOUND_ADAPTER_ACTUALLY_INVOKED=true
READ_ONLY_RAM_IDENTITY_USED=true
RUNTIME_LOADING_PROVEN=true
SKILL_DIGEST_VERIFIED_BEFORE_INVOCATION=true
AUTHENTICATED_FASTMCP_WORKER_BOUNDARY_PROVEN=true
INVOCATION_TRACE_RETAINED=true
EMPTY_RESULT_INTERPRETED_CORRECTLY=true
AGENT_EVIDENCE_RECEIPT_VALID=true
RESOURCECENTER_WRITE_API_CALLS=0
WORKER_DECISION_RECORD_COUNT=0
UPSTREAM_SKILL_BYTES_DISTRIBUTED=false
IAM_CONTROL_PLANE_PROVISIONING_WRITES_OCCURRED=true
DETERMINISTIC_GATE_AUTHORITY_PRESERVED=true
SECRETS_COMMITTED=false
PRIOR_WORKER_CREDENTIAL_ROTATION_STATUS=UNKNOWN
POLICY_OBSERVATION_AT_NATIVE_RUN=STALE
HISTORICAL_REPLAY_STRUCTURALLY_VALID=true
HISTORICAL_REPLAY_RELEASE_ELIGIBLE=false
```

These facts apply to one disposable, direct specialist Worker turn. The query returned zero resources visible to the bounded identity; `EMPTY_RESULT` was correctly interpreted as `NOT_ASSESSED_NO_VISIBLE_RESOURCE`. This does not make the release cloud context semantically usable and does not close the broader autonomous M4 chain.

## Reproduction boundary

Future release-usable runs require a new v0.2 policy observation captured for the same unpredictable runner-generated `run_id`, containing the four ordered successful `ram.GetPolicy`, `ram.GetPolicyVersion`, `ram.ListPoliciesForRole`, and `sts.GetCallerIdentity` readbacks and consumed within 900 seconds. Both the adapter-only and native runners perform capture inside their own run before starting the MCP turn. Neither accepts an external observation, credential bytes, an operator-supplied prior Worker credential digest, or an existing output path. Output paths are atomically reserved before any provider call. The commands below describe the future real-run boundary; they were not executed by this correction commit:

```bash
python3 scripts/run_alibabacloud_skill_evaluation.py \
  --control-profile '<RAM-readback-profile-label>' \
  --profile '<read-only-profile-label>' \
  --role-name '<read-only-role-label>' \
  --confirmation-ref '<explicit-user-confirmation-reference>' \
  --output '<new-runtime-evidence-path>'
```

The observation and its producer are bound by SHA-256. Stale, future-dated, legacy, or different-run observations cannot satisfy release `CLOUD_CONTEXT`; the provider search is not invoked for stale or future-dated input. A successful query alone is not proof of a read-only identity.

## Negative behavior

The automated suite requires:

- a write or broader operation returns `BLOCKED_BY_SKILL_BOUNDARY` before executor invocation;
- missing credentials return `NOT_ASSESSED`;
- RAM permission denial returns `NOT_ASSESSED_PERMISSION_DENIED` and never means zero resources;
- stale or future-dated RAM observations return `NOT_ASSESSED_POLICY_OBSERVATION_STALE` before Resource Center invocation;
- a non-empty `Resources` item without non-empty string `ResourceId` and `ResourceType` returns `INVOCATION_FAILED`, while `Resources=[]` remains a valid `EMPTY_RESULT`;
- any modified official Skill byte returns `SKILL_LOAD_REJECTED` or `SKILL_DIGEST_MISMATCH`;
- credential/profile/identity literals are absent from returned data;
- only a semantically usable typed receipt can satisfy `CLOUD_CONTEXT` evidence;
- `agent-evidence VALID` proves receipt integrity, not cloud completeness, ownership, permission scope, deployment safety, compliance, or authorization.

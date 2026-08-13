# Threat model v0.1

Status: controls partially implemented and locally exercised; not an independent security assessment.

## Protected assets

- provider credentials and repository permissions;
- immutable action requests, policy snapshots, approvals, decisions, and evidence receipts;
- the correspondence between an `ALLOW` and the exact provider invocation;
- retained rejection and failure history;
- separation of analysis, approval, execution, and release.

## Threats and controls

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
| Role/tool drift | operator invokes a gate tool outside its registry allowlist | authenticated per-Worker MCP tool ACL; prompts are not enforcement | native role-boundary conformance test |
| Cross-task contamination | concurrent prompt writes an unrelated request into the same workflow | task/correlation-scoped admission and assignment checks | concurrent-request isolation test |
| Declarative reconciliation drift | model or Human update is accepted but not converged as expected | read-after-write status verification and pinned upgrade gate | AgentTeams update/re-apply test |
| Secret leakage | token appears in prompt/evidence/log | secret manager, redaction, no secret inputs | leak scanning |
| Gate-input time-of-check bypass | untrusted PR tests execute pre-existing dirty tracked bytes or rewrite task, policy, evidence, approval, Git state, Action configuration or reserved outputs before authorization | pre-test exact-HEAD tracked index/worktree admission; bounded declared untracked inputs; lexical relative-path admission before resolution; component-wise no-follow descriptor reads/creates; canonical in-memory snapshots; post-test path-ancestor, directory, inode, empty-content, digest, effective-config, exact-head and Git-state recheck; verified create-only outputs; any unavailable post-test security observation forces deterministic `BLOCK` | task/evidence/policy/approval/multi-input/dirty-HEAD/Git-state/post-recheck-error/in-place-output/directory-replacement/action/symlink-ancestor tests |
| PR test credential or execution-capability inheritance | untrusted tests inherit GitHub command files, OIDC, SSH, cloud, package-registry or effective repository/worktree/submodule Git command and credential configuration | minimal environment allowlist, fresh HOME/TMPDIR, complete value-free effective repository/worktree configuration preflight, recursive audit and pre/post digest freeze for every already-initialized nested submodule, `pull_request_target` rejection and process-group cleanup | fake credential, local/worktree/include/URL/SSH/filter config, nested-submodule credential/config mutation, event, aggregate-output and cleanup tests |
| PR test resource exhaustion | stdout and stderr independently evade a stated total capture limit | one synchronized server-owned 1 MiB aggregate capture budget, bounded prefix hashing and process-group termination | exact-limit, limit-plus-one, dual-stream and concurrent-stream tests |
| Cloud Skill scope expansion | upstream search Skill instructs enable/disable or full-access actions | server-side typed adapter permits only current-account `search-resources`; Worker has no credential bytes or arbitrary CLI | write-operation pre-process denial tests |
| Cloud permission ambiguity | permission denial is interpreted as an empty inventory | distinct `NOT_ASSESSED_PERMISSION_DENIED`; no zero-resource inference | denied RAM identity test |
| Stale cloud permission observation | a caller widens the freshness window, or a missing, timezone-naive, old, or future-dated RAM snapshot is reused as current policy proof | server-owned 900-second ceiling enforced at construction and invocation without clamping, non-null timezone-aware timestamp, same-run observation binding, and release-ineligible historical replay | type/range/ceiling/missing/naive/stale/future/same-run tests |
| Cloud response leakage | resource IDs, names, tags, IPs, tokens, or raw stderr enter evidence | aggregate allowlist, hashed request ID, no raw stdout/stderr retention | secret and sensitive-field absence tests |
| Cloud evidence semantic spoofing | Worker labels an incomplete, malformed, or denied query as valid context | deterministic typed receipt requires non-empty string `ResourceId` and `ResourceType`, then checks semantic usability before canonical integrity verification | forged, malformed, or unusable receipt rejection test |
| Cloud Skill supply-chain drift | installed Skill differs from pinned official revision | exact subtree revision and per-file SHA-256; package exact-member attestation | modified Skill load-rejection test |
| Audit deletion | rejected attempt disappears | append-only store and retention checks | deletion attempt test |

## Residual risk

Schemas cannot prove the correctness of policy, verifier, identity provider, storage, AgentTeams deployment, or GitHub configuration. The native smoke confirmed that prompt-defined roles do not enforce MCP tool access: one Worker used a tool outside its registry allowlist, and a concurrent request entered the global chain. A compromised gate service or provider credential can still violate intended boundaries. Runtime hardening, gateway ACLs, concurrency isolation, adversarial evaluation, independent review, recovery tests, and operational monitoring are required before any production-readiness claim.

## Explicit exclusions

This reference implementation does not claim formal verification, sandbox escape resistance, same-UID isolation, network denial, container-socket isolation, supply-chain assurance, compliance, certification, or protection against every human administrator action. The submodule audit covers only currently present initialized worktrees and never initializes or downloads missing submodules. The pre/post comparison cannot detect a modification that is fully restored between its observations. A process that escapes the managed process group is outside the demonstrated boundary. `TEST_PROCESS_ISOLATION_NE_PRODUCTION_SANDBOX=true`.

# P0 merge-blocking implementation gap list

Baseline: `joy7758/titmas-agent-action-gate@ce14edb82163091a3408ebc1a4258486d8bad596`
Observed: 2026-08-12T21:11:52+08:00

Customer-facing product sentence: **这是一个真正会阻止不可靠代码变更合并的证据闸门。**

## Reusable foundations

- `ActionGate` is the sole deterministic `ALLOW | BLOCK | REQUIRE_APPROVAL` authority.
- `AgentEvidenceAdapter` already uses pinned `agent-evidence==0.6.0` and verifies schema, integrity, attachment digest and exact action-request subject binding.
- `PolicyEngine`, scoped approval verification and the GitHub provider boundary already bind action, target and parameters digest.

## P0 gaps at the baseline

1. The CLI has no `verify-pr` command and does not bind repository, PR number, current head SHA, execution identity or test command to one action request.
2. Test and negative-check results are not fed into the deterministic decision path.
3. There is no stable public projection: `PASS`, `FAIL`, `INCOMPLETE`, `REVIEW_REQUIRED`, with all non-passing states returning nonzero.
4. Runs do not always emit `artifacts/titmas/receipt.json` and `artifacts/titmas/summary.md` with the required bindings, digests, reasons and versions.
5. The repository has no reusable root `action.yml` for clean GitHub Actions consumption.
6. There is no clean-environment replay for valid, failing-test, missing-evidence, and unapproved/approved high-risk cases.
7. No public required check currently proves that an evidence subject for commit A blocks PR head B despite ordinary tests passing.
8. No uninterrupted 90-second recording currently demonstrates the full blocked-then-corrected/approved workflow.

## Shortest bounded implementation

Add one PR-verification adapter around the existing policy, evidence, approval and Action Gate components; expose it through the existing CLI; add one composite Action; add regression fixtures/tests and a clean replay workflow. After local validation, use an already authorized public sandbox for the required-check proof. Do not add agents, protocols, Skills, providers, production credentials, releases, deployments, tags or GOAI submission behavior.

Until all eight items have retained proof, status remains `DESIGN_WITH_RUNTIME_COMPONENTS`.

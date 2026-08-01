# Contributing

Contributions should keep the project agent-readable and preserve the separation between analysis, evidence, policy, approval, execution, release, and submission.

Before opening a pull request:

1. update the relevant versioned schema, manifest, example, and machine-readable discovery surface;
2. retain fail-closed behavior for unknown or mismatched inputs;
3. add positive and negative tests for authorization-boundary changes;
4. do not change TITMAS core protocols from this repository;
5. run the commands in [`docs/RUNBOOK.md`](docs/RUNBOOK.md);
6. state external writes, migrations, compatibility changes, limitations, and non-claims explicitly.

An `agent-evidence` PASS is not policy authorization. An `ALLOW` is not execution success. CI PASS is not production readiness. Merge, release, deployment, competition upload, and final submission are separate authorized events.

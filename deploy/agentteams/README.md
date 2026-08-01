# AgentTeams deployment template

[`team.v1.2.0.yaml`](team.v1.2.0.yaml) is the reviewable, placeholder-bearing AgentTeams `v1.2.0` deployment shape. It remains unapplied because its production identities, endpoints, secrets, ACLs, Skill packages, and provider boundary have not been provisioned.

[`team.native-smoke.v1.2.0.yaml`](team.native-smoke.v1.2.0.yaml) records the narrower resource profile used for one temporary native smoke on macOS Docker Desktop. It:

- reused the installer-created `default` Manager and existing local admin identity;
- selected `qwen3.8-max-preview`, which is explicitly not a stable model contract;
- reached the host Action Gate through `host.docker.internal` and an explicit `TITMAS_ACTION_GATE_MCP_HOST=0.0.0.0` bind;
- gave every Worker the same Action Gate MCP endpoint, without enforced per-Worker tool ACLs;
- declared repository Skill names without independently proving that their packages were materialized inside the Workers;
- carried no GitHub/provider-action credential or provider authority.

The smoke profile is platform-specific, incomplete, and not idempotent. Re-applying an existing Human returned HTTP 405 in the observed v1.2.0 environment, and a model-only Worker update did not reconcile until another field changed. Use it as evidence input, not as a production deployment recipe.

Before any apply:

1. replace every `CONFIGURE_*` value through reviewed deployment configuration;
2. package and mount the local Skills using an AgentTeams-supported package path;
3. deploy an authenticated Action Gate MCP implementation;
4. map the Human subject to a verified identity provider;
5. enforce network/service-account/provider ACLs outside the prompt;
6. run schema, threat-model, dry-run, and disposable-environment checks;
7. obtain a separate deployment authorization.

An AgentTeams Human permission level controls collaboration access. It is not the same as a scoped Action Gate approval record.

The MCP server defaults to loopback. Binding to `0.0.0.0` expands network exposure and is allowed only by an explicit environment override for a disposable, isolated bridge smoke; it supplies neither transport authentication nor deployment authorization.

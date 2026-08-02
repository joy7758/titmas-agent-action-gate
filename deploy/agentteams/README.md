# AgentTeams deployment template

[`team.v1.2.0.yaml`](team.v1.2.0.yaml) is the reviewable, placeholder-bearing AgentTeams `v1.2.0` deployment shape. It remains unapplied because its production identities, endpoints, secrets, ACLs, Skill packages, and provider boundary have not been provisioned.

[`team.native-smoke.v1.2.0.yaml`](team.native-smoke.v1.2.0.yaml) records the narrower resource profile used for one temporary native smoke on macOS Docker Desktop. It:

- reused the installer-created `default` Manager and existing local admin identity;
- selected `qwen3.8-max-preview`, which is explicitly not a stable model contract;
- reached the host Action Gate through `host.docker.internal` and an explicit `TITMAS_ACTION_GATE_MCP_HOST=0.0.0.0` bind;
- gave every Worker the same Action Gate MCP endpoint, without enforced per-Worker tool ACLs;
- declared repository Skill names without independently proving that their packages were materialized inside the Workers;
- carried no GitHub/provider-action credential or provider authority.

[`team.native-autonomous.v1.2.0.yaml`](team.native-autonomous.v1.2.0.yaml) is the successor disposable-run template. It uses a CoPaw Team Leader, per-Worker authenticated MCP admission, deterministic Worker packages, a stable non-preview model identifier, and the bounded `cloud-context-inspector`. The cloud Worker package contains no upstream Alibaba Cloud Skill bytes. It resolves and verifies the external source lock through `load_external_alibabacloud_skill`, then invokes only the server-side `inspect_alibabacloud_resources` typed adapter; cloud credentials never enter the Worker. The retained native cloud evidence proves one direct Qwen Worker turn, runtime load, and an `EMPTY_RESULT` read-only query. It does not prove the broader autonomous M4 chain, persistent deployment, or production readiness.

The smoke profile is platform-specific, incomplete, and not idempotent. Re-applying an existing Human returned HTTP 405 in the observed v1.2.0 environment, and a model-only Worker update did not reconcile until another field changed. Use it as evidence input, not as a production deployment recipe.

Before any apply:

1. replace every `CONFIGURE_*` value through reviewed deployment configuration;
2. package first-party Skills and external-Skill reference metadata using an AgentTeams-supported package path; never vendor the official Alibaba Cloud Skill bytes;
3. deploy an authenticated Action Gate MCP implementation;
4. map the Human subject to a verified identity provider;
5. enforce network/service-account/provider ACLs outside the prompt;
6. run schema, threat-model, dry-run, and disposable-environment checks;
7. obtain a separate deployment authorization.

For the Alibaba Cloud preflight, also require explicit confirmation of every query parameter, a dedicated externally configured read-only RAM identity, permission evidence, fixed current-account `search-resources` scope, aggregate-only redaction, and an AI-mode disable receipt at every exit. Missing credentials or denied permission is `NOT_ASSESSED`, never an empty inventory.

An AgentTeams Human permission level controls collaboration access. It is not the same as a scoped Action Gate approval record.

The MCP server defaults to loopback. Binding to `0.0.0.0` expands network exposure and is allowed only by an explicit environment override for a disposable, isolated bridge smoke; it supplies neither transport authentication nor deployment authorization.

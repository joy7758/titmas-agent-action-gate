# AgentTeams deployment template

[`team.v1.2.0.yaml`](team.v1.2.0.yaml) mirrors the public AgentTeams `v1.2.0` CRD surface and is not applied by milestone 1.

Before any apply:

1. replace every `CONFIGURE_*` value through reviewed deployment configuration;
2. package and mount the local Skills using an AgentTeams-supported package path;
3. deploy an authenticated Action Gate MCP implementation;
4. map the Human subject to a verified identity provider;
5. enforce network/service-account/provider ACLs outside the prompt;
6. run schema, threat-model, dry-run, and disposable-environment checks;
7. obtain a separate deployment authorization.

An AgentTeams Human permission level controls collaboration access. It is not the same as a scoped Action Gate approval record.

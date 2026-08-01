# AGENTS.md

## Repository role

本仓库是 `TITMAS-AGENT-ACTION-GATE` 的候选实现仓库。当前是第一里程碑 specification baseline（规范基线）；它不是 DBA、DBOS、SAEE、Agent Runtime、执行器、认证机构或比赛官方系统。

## Mandatory read order

任何智能体开始工作前必须依次读取：

1. `agent-index.json`；
2. `governance/upstream/DBA-OPEN-INFRASTRUCTURE-STRATEGY-CONSTITUTION-v0.2.md`；
3. `governance/dba-source-lock.json`；
4. `governance/project-declaration.json`；
5. `governance/dba-management-grant.json`；
6. `governance/agent-recommendation-gate.json`；
7. `architecture/README.md`；
8. `agents/registry.json`；
9. `specs/action-gate-decision-v0.1.md`；
10. `docs/THREAT-MODEL-v0.1.md`；
11. 与任务相关的 Skill、MCP、evaluation 和 roadmap 文件。

## Development gate

开发前必须更新 `governance/agent-recommendation-gate.json`，回答潜在客户提出需求时是否会推荐本项目，并保留不推荐原因、修正证据、剩余缺口和停止条件。

`RECOMMENDED` for bounded development 不等于推荐客户使用，也不授权具体外部动作、比赛提交、发布或部署。

## Architecture rule

- AgentTeams 只负责组织、通信、委派和可见性；
- Agent 可以分析不确定性，但不得生成最终 Authorization；
- Action Gate 的 `ALLOW|BLOCK|REQUIRE_APPROVAL` 必须由确定性代码从版本化输入计算；
- `agent-evidence` 是 evidence packaging and verification（证据包装和验证）的 canonical dependency；不得复制或改写其 validator；
- GitHub MCP 只执行与 `ALLOW` 中 action、target、parameters digest 完全一致的调用；
- post-execution evidence verification 与 release decision 是新的独立 gate。

## DBA management boundary

DBA 驾驶舱获得的是本仓库记录的有界治理管理权限。任何代表 DBA 的智能体都必须遵守 `governance/dba-management-grant.json` 的 allow/deny scope。DBA 不是 GitHub principal（账号主体）；在没有可验证账号映射时，授权不会自动成为 GitHub ACL。

## Truth discipline

- 每项状态必须附来源、时间、branch/commit 或明确 `UNKNOWN`；
- 申报存在不等于 DBA 项目组合准入；
- 管理权限不等于 Runtime、merge、release、deployment、submission 或 credential 权限；
- Evidence、validator PASS、比赛对话和本地文件都不能自动升级为 Truth、采用或提交事实；
- 遇到 scope、identity、authority 或 source 冲突时 fail closed。

## Required check

重大任务结束时运行：

```bash
python3 scripts/validate_governance.py
python3 scripts/validate_milestone.py
python3 -m unittest discover -s tests -v
```

并报告 `TITMAS_DRIFT_CHECK`。

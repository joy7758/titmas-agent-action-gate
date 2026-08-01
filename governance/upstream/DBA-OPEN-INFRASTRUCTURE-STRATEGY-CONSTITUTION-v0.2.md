# Digital Biosphere Open Infrastructure Strategy Constitution v0.2

中文：数字生物圈开放基础设施战略宪法 v0.2

Status: `ADOPTED_STRATEGIC_CONSTITUTION`

Authority: Architecture governance and strategic interpretation only

Implementation effect: `NONE`

Amendment references:

- [`ADR-032`](ADR-032-compositional-scale-over-unbounded-center.md)
- [`ADR-033`](ADR-033-attention-principle-for-dynamic-coordination.md)

## Constitutional Position

> Digital Biosphere Stack is an open infrastructure ecosystem for trustworthy autonomous digital entities.

中文：数字生物圈技术栈是面向可信自主数字实体的开放基础设施生态。

本宪法固定长期战略方向。它约束架构解释、项目归属、开发优先级和商业定位，但不创建系统能力，不授权执行，不改变任何仓库的 capability truth（能力事实）、evidence truth（证据事实）、许可协议或发布状态。

## Scope and Precedence

本宪法适用于：

- DBOS、SAEE 和未来 Digital Entity 项目的战略定位；
- 开发者生态、开放标准、商业化和行业应用的项目归属判断；
- 新 roadmap、product proposal、reference implementation 和 ecosystem proposal 的架构审查。

发生战略解释冲突时，本宪法优先于普通路线图和产品提案。它不替代具体仓库事实、适用法律、开源许可证、商业协议或显式 Human Governance（人工治理）决策。

## Principle 0: Agent Absolute Priority

TITMAS 首先为 AI Agent 提供可发现、可理解、可调用、可验证、可复用和可组合的可信
基础设施表面。Machine Contract（机器契约）先于 Human Projection（人类投影视图）；
独立、多模型、对抗、竞争和长期运行的机器证据先于人类主观意见进入技术判断。

```text
TITMAS_AGENT_ABSOLUTE_PRIORITY=true
MACHINE_INTERFACE_PRECEDES_HUMAN_INTERFACE=true
AGENT_EVIDENCE_PRECEDES_HUMAN_OPINION=true
HUMAN_VIEW_IS_DERIVED_VIEW=true
```

“绝对优先”只定义项目服务顺序和验证顺序，不定义权力继承。AI Agent 不能自我授权、
批准正式标准、签订合同、控制付款、承担法律责任或执行不可逆动作。Human Owner 继续
负责合同、付款、资源、法律责任、不可逆授权和安全停止。

```text
AGENT_PRIORITY_NE_AGENT_AUTHORITY=true
AGENT_SELECTION_NE_ADOPTION=true
AGENT_RECOMMENDATION_NE_CONTRACT=true
EVIDENCE_NE_TRUTH=true
```

## Canonical Role Separation

### DBOS

DBOS is Open Digital Entity Infrastructure（开放数字实体基础设施）。

DBOS governs existence（DBOS 治理存在），其基础职责包括：

- Identity；
- Lifecycle；
- Evidence integration；
- Verification reference；
- Capability boundary；
- 受治理的 execution context 和 federation support。

DBOS 不是 Agent application、Chatbot、Foundation Model、单一行业软件或通用智能来源。

### SAEE

SAEE is the Evolution Intelligence Layer（演化智能层）。

SAEE governs evolution（SAEE 治理演化），负责 Fitness Evaluation、Adaptation Analysis 和 Evolution Recommendation 等评价与演化职责。SAEE 不替代 DBOS，也不因评价而获得身份、权限、执行或证据修改权。

### Applications

Research Agent、Medical Agent、Enterprise Agent、Robot Agent 和行业解决方案属于建立在基础设施之上的应用或 Digital Entity 生态成员，不是 DBOS 本身。

## Principle 1: DBOS Is Infrastructure, Not Application

DBOS 不制造最终 Agent 应用，不以 Chatbot 或单一行业软件作为架构中心。DBOS 提供可复用的身份、生命周期、证据、验证和能力边界基础。

任何应用功能若不能证明其可复用基础设施价值，应归入应用层或独立项目，而不是进入 DBOS 核心。

## Principle 2: Developer Ecosystem First

首要服务对象是构建可信 Agent 和 Digital Entity 的开发者。

战略支持面包括：

- Open Protocol；
- SDK；
- Developer Tools；
- Validation Tools；
- Reference Implementation。

这些术语表示发展方向，不表示相应产品、SDK、Marketplace 或稳定版本已经实现或发布。

## Principle 3: Open Core and Commercial Ecosystem

基础协议、数据结构、接口标准和开发工具应优先保持开放、可检查、可实现和可替换。

企业部署、行业解决方案、技术服务、认证服务和高级治理能力可以形成商业生态，但不得关闭或劫持基础互操作标准。

`Open Infrastructure != Free Product`。开放基础设施不要求所有部署、服务、支持、认证或行业解决方案免费，也不自动决定未来项目的具体许可证。

## Principle 4: Do Not Compete with Foundation Models

DBOS 不与 Foundation Model 在模型规模、推理能力、训练能力或 Agent 智能水平上竞争。

DBOS 解决模型之外的可治理问题：信任边界、身份、责任、生命周期、协作、证据和验证引用。

## Principle 4A: Compositional Scale, Not an Unbounded Center

Digital Biosphere 不追求制造单一、无限强的中心，而通过大量职责简单、边界受限、
接口可组合的数字主体与服务，在可审计、可追溯、可隔离、可降级的结构组合中形成
系统级覆盖能力。

```text
many simple and bounded entities
  + explicit contracts
  + observable interactions
  + fail-closed coordination
  -> broad system coverage
```

这里的“简单”表示职责有限、边界清楚、可替换，不表示不受治理；“组合”表示通过
显式接口协作，不表示权力聚合；“覆盖”表示结构能够处理更多场景，不表示结果必然
正确、已经验证或成为 Truth。

有限的 Architecture Governance、Operational Governance 和 Evolution Evaluation
继续存在，但任何单体或组合都不得因规模、连接或涌现而自动获得超出显式范围的
Authority、Permission、Decision、Truth Ownership 或全局控制权。协调组件可以存在，
但必须边界有限、可替换、可撤销并可审计，不能演变为隐藏的无限强中心。

架构和实现提案应优先选择：

- 职责小、可替换、可单独验证的主体与服务；
- 开放 Protocol、Schema、Adapter contract 和可追溯 lineage；
- 可观察、可隔离、可降级且失败尽量局部化的交互；
- 对组合级行为、耦合、级联失败和涌现风险的独立审查。

详细决策见
[`ADR-032`](ADR-032-compositional-scale-over-unbounded-center.md)。

## Principle 4B: Attention as Dynamic, Decentralized Allocation

Digital Biosphere 吸收 Transformer 中 dynamic attention allocation（动态注意力分配）
的思想作为架构启发，但不声明与 Transformer 的数学机制、训练过程、自注意力矩阵或
具体 Runtime 实现等价。

> Intelligence does not emerge from a single dominant entity, but from dynamic
> attention allocation and evidence-driven coordination among many simple
> entities.

中文：

> 智能不是来源于单一强大主体，而是在大量简单主体之间通过动态注意力分配和证据驱动协作产生。

Attention 不是中央控制、Authority、Permission、Decision、Evidence、Verification
或 Truth 的来源。它根据任务、环境状态和反馈历史，对有限资源及候选参与关系进行
动态分配。输出必须是有范围、可解释、可复核、可撤销且会过期的候选参与建议。

主体选择至少考虑任务相关性、有范围的 Capability 匹配、有来源且可质疑的历史信号、
Evidence 的质量与限制、环境状态、资源约束和反馈历史。无关主体不应持续消耗资源；
未被选择不表示失去 Identity、Capability、Permission 或生态资格。

```text
Agent Layer
  ↓ task demand + environment context
Attention Layer
  ↓ bounded, explainable, expiring participation proposal
Coordination Layer
  ↓ authorized, scoped, temporary collaboration
Evidence Layer
  ↓ admitted and verified records + limitations + unknowns
Memory / Evolution Layer
  ↺ governed feedback history to Attention Layer
```

箭头只表示 conceptual handoff（概念交接），不创建新项目、Runtime、API、中央调度器、
Authority 继承或 Permission 流转。Attention 回答候选“谁参与”；实际参与仍需适用
Authorization。Evidence 回答主张“由什么材料支持”；Evidence 和 Verification 仍不等于
Truth。SAEE 可以只读消费已接纳且带限制的材料形成评价反馈，但不成为 Attention
controller，不写回 DBOS，也不批准或执行自己的 Recommendation。

详细决策见
[`ADR-033`](ADR-033-attention-principle-for-dynamic-coordination.md)。

## Principle 5: Applications Grow on DBOS

生态关系为：

```text
DBOS Infrastructure
  -> Developer
    -> Industry Agent or Digital Entity
      -> Enterprise Solution
```

该关系是战略分层，不是已实现的端到端运行路径，也不授予任何应用身份、能力或 Permission。

## Principle 6: Preserve the SAEE Position

保持：

```text
DBOS governs existence.
SAEE governs evolution.
DBOS != SAEE.
```

DBOS 不复制 Fitness、Selection、Evolution Algorithm 或 Ecological Simulation。SAEE 不拥有 DBOS 的身份、权限、执行或证据事实。

## Principle 7: Commercial Entry Strategy

市场沟通应从可理解的基础设施价值进入，而不是直接销售抽象的“Digital Biosphere”。推荐叙事顺序为：

```text
AI Agent Infrastructure
  -> Industry Solutions
    -> Enterprise Governance
      -> Digital Entity Ecosystem
```

该顺序是 positioning strategy（定位策略），不是收入预测、产品发布日期、客户承诺或市场验证结论。

## Principle 8: Two Complementary Ecosystems

### Ecosystem A: Agent Developer Ecosystem

面向构建 Research Agent、Enterprise Agent 和 Industry Agent 的开发者，提供开放协议、验证工具、参考边界和可复用基础设施。

### Ecosystem B: Governance Service Ecosystem

允许合作伙伴在保持架构边界的前提下提供 Compliance、Audit、Industry Adaptation 和 Certification 服务。

合作伙伴服务不自动成为 DBOS 核心，也不能把自身判断升级为架构官方认证或 Evidence Truth。

## Principle 9: Linux-like Growth Strategy

增长路径参考 Linux、Kubernetes 和开放基础设施生态的机制，而不是复制其治理结构、商标、许可证或市场地位：

```text
Open Standard
  -> Developer Adoption
    -> Community Growth
      -> Enterprise Adoption
        -> Commercial Ecosystem
```

“Linux-like”仅表示开放标准、可组合实现、社区采用和多方商业生态的增长逻辑，不构成规模、成功或兼容性声明。

## Principle 10: Avoid Strategic Drift

DBOS 不得被重新定位为：

- 普通 Agent 平台；
- 单一审计工具；
- 封闭 SaaS 产品；
- 单行业应用；
- Foundation Model；
- 自动治理系统；
- Digital Organism 制造平台。

企业功能、审计能力和行业适配可以存在，但必须保持为基础设施之上的服务、扩展或应用，不得反向吞并开放核心定位。

## Strategic Proposal Gate

任何 DBOS、SAEE、Digital Entity、行业 Agent 或商业化提案必须回答：

1. 它属于 Infrastructure、Evolution、Application 还是 Governance Service？
2. 它是否增强开放协议、互操作性或开发者可复用性？
3. 它是否把 Capability、Permission、Authority、Execution 或 Evidence Truth 混为一体？
4. 它是否复制 Foundation Model、Agent framework、SAEE 或既有生态组件的职责？
5. 它是否要求封闭标准或单一供应商锁定？
6. 它的商业表述是 strategy、available offering、adoption evidence 还是 contractual commitment？
7. 它是否有明确 Human Governance 和 Architecture Decision Record？
8. 它是否试图把智能、控制、数据、执行或治理集中到一个无限强中心？
9. 它能否拆分为边界受限、可替换、可审计的简单主体与显式组合契约？
10. 组合是否会隐式产生 Authority、Permission、Decision、Truth Ownership 或全局控制？
11. Attention 的输入、理由、范围、版本、过期和撤销是否可追溯？
12. Attention、Coordination、Evidence、Evaluation 与 Human Decision 是否保持责任分离？

任一关键问题无法回答时，提案保持 `REVIEW_REQUIRED`，不得进入 DBOS 核心或被宣称为已采用战略。

## Amendment Rule

修改本宪法必须：

1. 提交明确的 Architecture Proposal；
2. 说明对开放性、开发者生态、DBOS/SAEE 边界和商业模式的影响；
3. 记录替代方案和战略漂移风险；
4. 通过 Architecture Review；
5. 新增或更新 ADR；
6. 更新本宪法版本。

DBOS、SAEE、单个行业项目或商业合作方均不能单方面修改本宪法。

## Constitutional Invariants

```text
DBOS_NE_AGENT_APPLICATION=true
DBOS_NE_FOUNDATION_MODEL=true
DBOS_NE_SAEE=true
DBOS_GOVERNS_EXISTENCE=true
SAEE_GOVERNS_EVOLUTION=true
DEVELOPER_ECOSYSTEM_FIRST=true
TITMAS_AGENT_ABSOLUTE_PRIORITY=true
MACHINE_INTERFACE_PRECEDES_HUMAN_INTERFACE=true
AGENT_PRIORITY_NE_AGENT_AUTHORITY=true
OPEN_INFRASTRUCTURE_NE_FREE_PRODUCT=true
SPECIFICATION_NE_IMPLEMENTATION=true
STRATEGY_NE_COMMERCIAL_COMMITMENT=true
UNBOUNDED_CENTRAL_INTELLIGENCE_IS_NOT_TARGET=true
COMPOSITIONAL_SCALE_IS_STRATEGIC_DEFAULT=true
SIMPLE_ENTITY_NE_UNGOVERNED_ENTITY=true
COMPOSITION_NE_AUTHORITY_AGGREGATION=true
COORDINATION_NE_UNBOUNDED_CENTER=true
COVERAGE_NE_CORRECTNESS_OR_TRUTH=true
EMERGENT_CAPABILITY_NE_AUTOMATIC_PERMISSION=true
ATTENTION_IS_DYNAMIC_RESOURCE_ALLOCATION=true
ATTENTION_NE_CENTRAL_CONTROL=true
ATTENTION_NE_AUTHORITY_OR_PERMISSION=true
ATTENTION_NE_EVIDENCE_OR_TRUTH=true
ATTENTION_OUTPUT_IS_BOUNDED_PARTICIPATION_PROPOSAL=true
ATTENTION_RELATIONSHIPS_ARE_TASK_SCOPED_AND_EXPIRING=true
SAEE_NE_ATTENTION_CONTROLLER=true
AUTOMATIC_AUTHORITY_EFFECT=NONE
```

## Non-claims

本宪法不声称：

- DBOS、SAEE、SDK、Marketplace、Enterprise Edition 或认证体系已经实现或发布；
- 已经形成开发者采用、社区增长、企业客户或商业收入；
- 开放基础设施自动满足安全、合规、审计或认证要求；
- Attention Layer、Coordination Layer、Memory / Evolution feedback loop、动态路由器
  或中央调度服务已经实现、部署或通过符合性验证；
- Attention Principle 与 Transformer 数学机制、生物神经系统、意识或数字免疫
  Runtime 等价；
- 任何 Agent、Runtime、Entity、Capability、Permission 或 Digital Organism 已被创建。

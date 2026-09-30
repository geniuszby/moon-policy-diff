# MoonPolicyDiff

MoonPolicyDiff 0.2.0 是基于 [MoonPolicy](https://github.com/Eisem/moon_policy) 的权限回归与发布风险审查扩展。主要流程直接依赖 Mooncakes 的 eisem/moon_policy 0.1.0，复用其 JSON 解析、授权求值、策略差异和用例回放；本项目增加有限属性域生成、租户隔离及禁止动作不变量、按动作变更预算和回归用例导出。

公开代码：[GitHub](https://github.com/geniuszby/moon-policy-diff)；包：[Mooncakes](https://mooncakes.io/docs/geniuszby/moon-policy-diff)。

## 推荐流程：MoonPolicy 扩展

    moon run cmd/main -- release-audit examples/moonpolicy/saas/before.json examples/moonpolicy/saas/after.json examples/moonpolicy/saas/seeds.json examples/moonpolicy/saas/plan.json

此例生成 6 个属性样本，发现 1 个新增跨租户授权，返回退出码 1。完整的 SaaS、数据平台和 AI 工具运行、用例导出及回放说明见 [MoonPolicy 示例](examples/moonpolicy/README.md)。

| 责任范围 | 实现来源 |
| --- | --- |
| 策略 JSON、角色继承、属性条件、拒绝语义、原始决策轨迹、基础差异及原生用例回放 | eisem/moon_policy 0.1.0 |
| 声明有限属性取值，枚举缺失、布尔、整数边界等组合，超限不输出部分样本 | release_samples.mbt、release_plan.mbt |
| 检查所有新版允许请求的租户隔离与禁止动作不变量，缺失租户元数据返回不确定 | release_audit.mbt |
| 分动作设置新增授权和撤权预算；重复请求只计一次 | release_audit.mbt |
| 导出上游原生回归用例，输出采样范围与机器可读审查报告 | release_run.mbt、release_audit.mbt |

这些扩展不改写 MoonPolicy 授权语义，不提供其他引擎的语义转换。采样完整性只针对用户声明的有限域；域外属性、其他身份资源及真实租户元数据需调用方保证。租户策略以请求顶层字符串属性 tenant 为默认来源，可以配置其他非保留顶层键。禁止动作使用精确名称。

### 库接入

在使用方同时导入 geniuszby/moon-policy-diff 和 eisem/moon_policy。调用 parse_release_plan 读取审查配置，随后将上游 Policy 和 Request 交给 run_release_plan；run_moonpolicy_json 可直接处理三份上游 JSON 文本。release_regression_cases 返回上游 PolicyCase 数组，可交给 Policy.run_cases。接口见 pkg.generated.mbti。

## 0.1 兼容流程

以下旧文本 DSL、求值和分析接口保留给现有使用者。它们使用本项目的旧模型，不会自动转换为 MoonPolicy 策略；两套流程不能混用。旧版求值、diff、verify、coverage、lint 等与生态项目存在功能重叠，不作为本次扩展独创性的依据。反事实归因、结构差异和见证分组目前仍仅适用于旧模型。

## 快速运行

安装 MoonBit 工具链后，在仓库根目录执行：

```sh
moon run cmd/main -- audit examples/saas/before.policy examples/saas/after.policy examples/saas/universe.txt
moon run cmd/main -- audit examples/ai-tools/before.policy examples/ai-tools/after.policy examples/ai-tools/universe.txt
moon run cmd/main -- audit examples/finance/before.policy examples/finance/after.policy examples/finance/universe.txt json
moon run cmd/main -- audit examples/finance/before.policy examples/finance/after.policy examples/finance/universe.txt attribution
moon run cmd/main -- verify examples/finance/before.policy examples/finance/universe.txt examples/finance/expected-before.txt
moon run cmd/main -- impact examples/saas/after.policy examples/saas/universe.txt
moon run cmd/main -- audit examples/saas/before.policy examples/saas/after.policy examples/saas/universe.txt groups
moon run cmd/main -- audit examples/saas/before.policy examples/saas/after.policy examples/saas/universe.txt witnesses
moon run cmd/main -- scope examples/saas/universe.txt read,export
moon run cmd/main -- audit examples/finance/before.policy examples/finance/after.policy examples/finance/universe.txt structural
```

两个示例都会报告新增授权，因此严格门禁退出码为 1。退出码 0 表示通过，2 表示输入无效或结论不确定。

## 输入格式

策略文件每行一个指令：

```text
policy NAME
inherit CHILD_ROLE PARENT_ROLE
rule ID permit|deny ROLES ACTIONS RESOURCE_KINDS RESOURCE_IDS any|same|other CONDITIONS
```

列表使用逗号分隔，单个 `-` 表示不限。条件格式为 `principal:KEY:eq:VALUE`、`resource:KEY:neq:VALUE` 或 `request:KEY:exists:-`。同一条规则的所有条件必须满足；拒绝规则优先于允许规则，未命中时默认拒绝。

请求样本文件：

```text
principal ID TENANT ROLE1,ROLE2 KEY=VALUE,...
resource ID KIND TENANT KEY=VALUE,...
request PRINCIPAL_ID ACTION RESOURCE_ID KEY=VALUE,...
matrix ACTION1,ACTION2
```

属性为空时使用 `-`。`matrix` 将主体、动作和资源做笛卡尔积，最多生成 100000 条显式请求；超过上限会报错，不输出部分结果。示例见 [examples/saas](examples/saas)、[examples/ai-tools](examples/ai-tools) 和 [examples/finance](examples/finance)。

## 能力与边界

- 角色继承、通配符匹配、资源类型、租户关系和主体/资源/请求属性条件。
- 对显式请求集做确定性新旧对比，保留每个变更的主体、动作、资源和决定性规则。
- 严格门禁默认拒绝任何新增授权、撤权或跨租户新增授权。
- JSON 报告包含请求、决策、规则命中轨迹和门禁发现。
- MoonBit 库 API 可按动作分别设置新增授权和撤权预算；未配置的动作默认预算为零。
- 两因素反事实归因可区分规则修订和角色继承修订对样本请求的影响；结论仅针对这两种变更维度。
- `verify` 读取 `expect PRINCIPAL ACTION RESOURCE allow|deny` 断言，检查单版策略是否满足既定权限基线。
- `impact` 逐条移除规则重算样本，给出每条规则被删除后新增或失去访问的数量及见证请求。
- `groups` 按主体租户、资源租户和动作汇总样本变更，便于查看跨租户授权集中在哪些场景。
- `witnesses` 按变更类型、动作、资源类型、跨租户关系和决定性规则合并同类请求，保留每组一个可复现见证；完整结果仍可用 `text` 或 `json` 查看。
- `scope` 对给定动作检查“主体 × 动作 × 资源”三元组覆盖情况，明确列出缺失示例；属性取值组合仍需单独设计样本。
- `structural` 列出规则和角色继承边的增删改，与基于请求的行为对比互补。
- 分析只覆盖输入的请求集合；未采样请求不构成安全保证。
- 当前不提供认证、令牌签发、在线授权服务或其他策略语言的兼容解释器。

## 验证

```sh
moon check --target js
moon test --target js
moon build --target js
moon info
moon fmt
```

GitHub Actions 在 push 和 PR 上运行检查、测试、构建和格式检查。

## 原创性与许可

本项目新增部分为原创 MoonBit 扩展代码，授权基础复用 MoonPolicy，而不是宣称基础权限引擎和策略差异为本项目独有。上游源码通过包依赖使用，没有复制到本仓库；来源和重叠能力见 [RELATED_WORK.md](RELATED_WORK.md)。本项目和 MoonPolicy 均采用 Apache-2.0；依赖、更新和验证记录见 [THIRD_PARTY.md](THIRD_PARTY.md)、[CHANGELOG.md](CHANGELOG.md) 和 [TEST_RECORD.md](TEST_RECORD.md)。

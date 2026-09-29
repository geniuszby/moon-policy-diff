# MoonPolicyDiff

MoonPolicyDiff 是 MoonBit 实现的离线权限策略变更审计工具。输入新旧策略和一组明确列出的请求，程序分别求值，找出新增授权、撤销授权、命中的规则，并用退出码供 CI 拦截。适用于多租户 SaaS、数据访问和 AI 工具权限的发布前检查。

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
- 两因素反事实归因可区分规则修订和角色继承修订对样本请求的影响；结论仅针对这两种变更维度。
- `verify` 读取 `expect PRINCIPAL ACTION RESOURCE allow|deny` 断言，检查单版策略是否满足既定权限基线。
- `impact` 逐条移除规则重算样本，给出每条规则被删除后新增或失去访问的数量及见证请求。
- `groups` 按主体租户、资源租户和动作汇总样本变更，便于查看跨租户授权集中在哪些场景。
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

项目为原创 MoonBit 实现，借鉴通用 RBAC/ABAC 概念，不移植现有引擎代码。与相关公开项目的边界、来源见 [RELATED_WORK.md](RELATED_WORK.md)。源码采用 Apache-2.0；MoonBit x 库为外部依赖，其许可证以依赖仓库为准。

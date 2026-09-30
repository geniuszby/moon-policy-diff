# MoonPolicy 发布审查示例

这三组策略直接使用 eisem/moon_policy 0.1.0 的 JSON 格式。授权和策略差异由该依赖计算，扩展负责有限属性域、权限不变量、动作预算和回归用例。旧文本 DSL 不参与这些示例。

| 示例 | 生成样本 | 新增授权 | 门禁失败原因 |
| --- | ---: | ---: | --- |
| saas | 6 | 1 | 移除租户条件后允许跨租户导出，虽然动作预算允许这 1 次变更，租户不变量仍失败 |
| data-platform | 6 | 2 | 风险阈值从 20 调整至 30，21 和 30 两种样本新增授权，超过该动作的 1 次预算 |
| ai-tools | 3 | 3 | 动作预算允许变更，但独立的禁止动作不变量拒绝 shell 执行能力 |

在仓库根目录执行：

    moon run cmd/main -- release-audit examples/moonpolicy/saas/before.json examples/moonpolicy/saas/after.json examples/moonpolicy/saas/seeds.json examples/moonpolicy/saas/plan.json
    moon run cmd/main -- release-audit examples/moonpolicy/data-platform/before.json examples/moonpolicy/data-platform/after.json examples/moonpolicy/data-platform/seeds.json examples/moonpolicy/data-platform/plan.json
    moon run cmd/main -- release-audit examples/moonpolicy/ai-tools/before.json examples/moonpolicy/ai-tools/after.json examples/moonpolicy/ai-tools/seeds.json examples/moonpolicy/ai-tools/plan.json

三组门禁都返回退出码 1，这是预期审查结果。退出码 2 表示输入无效、缺少必要租户元数据或样本域超限；这些情况不能作为门禁通过。

导出并重放 SaaS 回归用例：

    moon run cmd/main -- release-cases examples/moonpolicy/saas/before.json examples/moonpolicy/saas/after.json examples/moonpolicy/saas/seeds.json examples/moonpolicy/saas/plan.json > cases.json
    moon run cmd/main -- release-replay examples/moonpolicy/saas/before.json cases.json
    moon run cmd/main -- release-replay examples/moonpolicy/saas/after.json cases.json

导出步骤仍返回门禁退出码 1，并输出合法用例数组。旧策略回放通过，新策略回放失败。用例使用上游原生 cases 格式，也可直接交给 MoonPolicy 的 cases_from_json/run_cases。

计划文件中 null 表示缺失属性。生成器只替换声明的顶层属性；每个域最多 64 个取值，总计最多 32 个域，生成上限最高 100000。超限不产生部分样本。请求按全部属性内容去重，属性对象的插入顺序不影响计数。未配置的动作预算为零。

完整性只表示声明的有限域已全部处理；实际租户数据、身份资源清单及其他属性取值由调用者保证，结论不是未采样请求的全局安全证明。回归用例保留旧决策；发现租户或禁止动作不变量违规时改为预期拒绝，不会自动改写策略。

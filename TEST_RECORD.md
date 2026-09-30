# 验证记录

## 2026-09-30：MoonPolicy 扩展 0.2.0

- 实际下载并锁定 eisem/moon_policy 0.1.0；新流程使用该发布包的原生解析、授权、差异及回放接口。
- moon info、moon fmt、moon check --target js、moon build --target js 均成功。
- moon test --target js：98 项测试全部通过，含 20 项新流程测试。
- SaaS：6 个样本、1 个新增授权，TENANT_ISOLATION，退出码 1。
- 数据平台：6 个样本、2 个新增授权，ACTION_GRANT_BUDGET，退出码 1。
- AI 工具：3 个样本、3 个新增授权，FORBIDDEN_ACTION，退出码 1。
- SaaS 原生回归用例导出后，旧策略回放 1 项通过（退出码 0），新策略回放 1 项失败（退出码 1）。
- 代码统计：5494 行非空 MoonBit 源码与测试，排除依赖与构建产物；该总数包含旧兼容流程，不等于本次新增工作量。
- [GitHub CI 运行 36710530977](https://github.com/geniuszby/moon-policy-diff/actions/runs/36710530977)通过，对应功能提交 2d1d2a4c897188f3a9fc3f5760834937f966ac1f，包含新流程和原生回放检查。
- moon publish 返回 HTTP 200；[Mooncakes 发布清单](https://mooncakes.io/api/v0/manifest/geniuszby/moon-policy-diff)确认最新版本 0.2.0、构建成功，以及 eisem/moon_policy 0.1.0 和 moonbitlang/x 0.4.49 依赖。

## 2026-09-30：覆盖分析索引

- moon info、moon fmt、moon check --target js、moon build --target js 均成功。
- moon test --target js：78 项测试全部通过。
- 回归用例验证重复动作、同一请求的属性变体不重复计数，含冒号的标识符不发生键冲突；10000 个组合中正确识别 9980 个已覆盖组合和 20 个缺口，缺口示例仍限制为 10 条。
- 本次为 GitHub 开发版本更新，Mooncakes 上的已发布版本仍为 0.1.0。

## 2026-09-29：初始发布

2026-09-29，在 Windows 本地开发环境运行 moon check --target js、moon test --target js、moon build --target js、moon info 和 moon fmt。

结果：检查与构建成功；73 个 MoonBit 测试全部通过。[GitHub Actions 运行记录](https://github.com/geniuszby/moon-policy-diff/actions/runs/36556617531)的检查、测试、构建、命令行示例和格式步骤全部成功。Mooncakes 发布返回 HTTP 200，0.1.0 包页面可访问。

命令行示例已验证：SaaS 方案报告 3 个新增授权，其中 2 个跨租户；AI 工具方案报告 1 个新增授权；财务方案报告 2 个因角色继承产生的新增授权。严格门禁对这三种变更均返回退出码 1，财务旧版策略通过 3 项基线断言。

# 验证记录

## 2026-09-30：覆盖分析索引

- moon info、moon fmt、moon check --target js、moon build --target js 均成功。
- moon test --target js：78 项测试全部通过。
- 回归用例验证重复动作、同一请求的属性变体不重复计数，含冒号的标识符不发生键冲突；10000 个组合中正确识别 9980 个已覆盖组合和 20 个缺口，缺口示例仍限制为 10 条。
- 本次为 GitHub 开发版本更新，Mooncakes 上的已发布版本仍为 0.1.0。

## 2026-09-29：初始发布

2026-09-29，在 Windows 本地开发环境运行 moon check --target js、moon test --target js、moon build --target js、moon info 和 moon fmt。

结果：检查与构建成功；73 个 MoonBit 测试全部通过。[GitHub Actions 运行记录](https://github.com/geniuszby/moon-policy-diff/actions/runs/36556617531)的检查、测试、构建、命令行示例和格式步骤全部成功。Mooncakes 发布返回 HTTP 200，0.1.0 包页面可访问。

命令行示例已验证：SaaS 方案报告 3 个新增授权，其中 2 个跨租户；AI 工具方案报告 1 个新增授权；财务方案报告 2 个因角色继承产生的新增授权。严格门禁对这三种变更均返回退出码 1，财务旧版策略通过 3 项基线断言。

# 验证记录

2026-09-29，在 Windows 本地开发环境运行 moon check --target js、moon test --target js、moon build --target js、moon info 和 moon fmt。

结果：检查与构建成功；73 个 MoonBit 测试全部通过。GitHub Actions 在每次推送时重跑检查、测试、构建和格式校验；实际远端结果以 [Actions 页面](https://github.com/geniuszby/moon-policy-diff/actions) 为准。

命令行示例已验证：SaaS 方案报告 3 个新增授权，其中 2 个跨租户；AI 工具方案报告 1 个新增授权；财务方案报告 2 个因角色继承产生的新增授权。严格门禁对这三种变更均返回退出码 1，财务旧版策略通过 3 项基线断言。

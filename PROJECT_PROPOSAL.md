# MoonPolicyDiff 项目申报书

## 基本信息

- 项目名称：MoonPolicyDiff——MoonBit 权限策略变更审计与见证工具
- 参赛者：赵舶阳
- 联系方式：以报名表填写的信息为准
- GitHub 仓库链接：https://github.com/geniuszby/moon-policy-diff
- Mooncakes 链接：https://mooncakes.io/docs/geniuszby/moon-policy-diff
- 项目方向：安全基础组件、权限策略分析与开发者工具
- 是否为移植项目：否，原创项目

## 项目简介

MoonPolicyDiff 是一个以 MoonBit 为主要实现语言的离线权限策略变更审计工具。项目对同一组主体、动作、资源请求分别运行新旧策略，报告新增授权、撤销授权及导致变化的规则，并给出可复现的请求见证。它提供命令行程序、文本与 JSON 报告、自动化测试及可运行示例，便于在发布前和 CI 中审查权限变化。

## 项目方向与适用场景

项目面向 SaaS API、企业后台、数据平台及 AI 工具权限。完整场景包括：多租户 SaaS 调整导出规则时检查跨租户新增授权；财务系统调整岗位继承后验证既有权限基线；AI 代理开放工具调用前审查新增执行权限。首版边界为显式有界请求集上的离线分析，不提供在线认证或对未采样请求的安全保证。

## 拟实现的核心功能

- 角色继承、资源与租户匹配、属性条件、拒绝优先的确定性求值；
- 新旧策略决策比较、规则解释、结构差异及变更原因归因；
- 请求矩阵、覆盖缺口、代表性见证、规则删除影响和权限基线断言；
- 新增授权、撤权与跨租户风险门禁，支持按动作配置预算；
- audit、coverage、lint、impact、scope、verify 等 CLI 命令及文本/JSON 输出；
- 当前完成 4080 行非空 MoonBit 源码与测试、73 项通过的测试、25 次以上真实 Git 提交，GitHub Actions CI 已通过，0.1.0 已发布至 Mooncakes。

## 原创及开源项目参考说明

MoonPolicyDiff 为原创项目，不移植或复制第三方策略引擎代码。RBAC/ABAC 是通用技术概念，本项目聚焦策略修改前后的实际授权后果；与已公开的凭证验证、爬虫意图审查和依赖清单审计项目的用途区别见仓库 RELATED_WORK.md。项目采用 Apache-2.0，运行时仅依赖 MoonBit 官方扩展包 moonbitlang/x 的文件与进程接口，其许可证和来源见 THIRD_PARTY.md。

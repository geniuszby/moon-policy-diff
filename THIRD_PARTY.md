# 第三方依赖与来源

## MoonPolicy 授权基础

0.2.0 的 release-audit/release-cases/release-replay 流程真实依赖 [eisem/moon_policy 0.1.0](https://mooncakes.io/docs/eisem/moon_policy), [上游仓库](https://github.com/Eisem/moon_policy)，作者/维护者 Eisem。该版本由 Mooncakes 下载，moon.mod 锁定版本；许可证为 [Apache-2.0](https://github.com/Eisem/moon_policy/blob/master/LICENSE)。

复用范围：上游 JSON 策略/请求/属性解码、Policy.authorize、Policy.access_changes、决策及轨迹序列化、PolicyCase 原生用例回放。扩展范围：有限属性取值枚举、审查预算、租户和禁止动作不变量、失败处理、回归用例组织及 CLI。没有将上游源码复制到本仓库，也没有修改上游的授权语义。旧 DSL 的独立实现仍保留兼容，两套流程没有自动转换。

运行时文件读取及退出码使用 [moonbitlang/x](https://github.com/moonbitlang/x) 的 fs、sys 包。moon.mod 锁定版本 0.4.49；该模块声明采用 [Apache-2.0](https://raw.githubusercontent.com/moonbitlang/x/main/moon.mod)。项目没有复制其源码。

CI 使用 [hustcer/setup-moonbit](https://github.com/hustcer/setup-moonbit) 安装工具链，该 Action 声明采用 MIT 许可证。MoonPolicy 示例策略、种子请求及审查计划由本项目编写，不包含外部图片素材。

<p align="center"><img src="https://raw.githubusercontent.com/celestia-island/celestia-island.github.io/main/res/logos/kotama.webp" alt="Kotama" width="180"/></p>

<h1 align="center">Kotama</h1>

<div align="center">
<strong>逆向工程工具库：静态拆解出可读的 C，活体会话里读、扫、冻结，打包成各平台的注入库</strong>
</div>

<br />

<div align="center">

[![CI](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/ci.yml?label=CI)](https://github.com/celestia-island/kotama/actions/workflows/ci.yml)
[![depspec](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/depspec-lint.yml?label=depspec)](https://github.com/celestia-island/kotama/actions/workflows/depspec-lint.yml)
[![License: SySL 1.0](https://img.shields.io/badge/license-SySL%201.0-blue)](../../LICENSE)

</div>

<br />

<div align="center">

[English](../../README.md) · **简体中文** · [繁體中文](../zh-Hant/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Русский](../ru/README.md) · [العربية](../ar/README.md)

</div>

名字来自《蔚蓝档案》千年科学学园 Veritas 社团的**音瀬コタマ**——Veritas 的通信与情报担当，
专长是窃听。对这个仓的语义是"把程序看清，把它说的话录下来"。既是 CLI 也是库，
同时是 shittim-chest / hikari 的一个视图。

## 当前状态

**P0 静态管线已跑通**（2026-11-23 首提交，`master` 单主干）。
`kotama analyze <文件>` 对一个 ELF/PE 文件做装载 → 函数发现 → 基本块级反编译。

已实证的范围：

| 维度 | 现状 |
| --- | --- |
| 容器 | ELF32 / ELF64 / PE32 / PE64（x86 与 x64） |
| 函数发现 | 五路证据（symtab / dynsym / PE64 `.pdata` / entry / 直接 call 目标），每行带 provenance |
| 边界 | 精确边界优先（符号长度、`.pdata`）；推断边界用线性扫描精化，共享尾块不再切断真函数 |
| 反编译 | 基本块 + 地址锚注释；**稠密 switch 的跳转表可恢复**（ELF64 夹具 10/10 分支、置信度 100%） |
| 确定性 | 同一输入两次输出逐字节相同（差分与知识库复用的前提） |
| 已验证 | 24 个矩阵夹具 + `/bin/true`、`/bin/ls` 等 strip 系统二进制 |

已知边界（P1 范围）：PE 的精确函数边界依赖 PDB（当前 mingw 夹具无 PDB，靠 call 目标 + 线性扫描）；
类型推断、结构体恢复、Ghidra 差分 oracle 尚未接入。

设计决策与过程记录在 PR 描述中（设计文档不进仓树）。

## 能力地图

| 块 | 内容 | 阶段 |
| --- | --- | --- |
| 静态 | 装载 → 函数发现 → 基本块反编译 ✅ / 类型推断 · 结构体 · 差分 oracle | P0 ✅ / P1 |
| 动态 | 注入（Windows / Linux 双线）→ 内存/栈/快照 → 扫描/冻结 → hook / trace | P2–P4 |
| 打包 | `hooks.toml` + hook 源码 → 各平台注入库 + 清单（ABI / 能力 / 摘要） | P4 |
| 面 | 服务（REST / WS / MCP）+ hikari web UI + evernight 远程节点 | P5–P6 |

两条地基，其它一切建在其上：

1. **一套地址空间抽象**：文件映像、活体进程、内存快照实现同一个 `AddressSpace`，函数发现与反编译
   对三者跑同一条管线。
1. **内容寻址的函数身份**：`kotama://<模块指纹>/<rva>` 跨 ASLR / 重启 / 换机器稳定，注释与结论因此
   能在节点之间共享。

## 快速上手

```bash
just gate                                  # fmt + clippy + test + deny
cargo run -p kotama-cli -- --version       # 版本 + 载荷 ABI 版本
cargo run -p kotama-cli -- analyze <文件>  # 函数表 JSON（带证据）
cargo run -p kotama-cli -- analyze <文件> --decompile --limit 8   # 附伪 C
python3 tools/build_fixtures.py --run --host-samples   # 四目标靶子矩阵 + 运行冒烟
```

夹具矩阵：`x86_64-linux-gnu / x86-linux-gnu / x86_64-windows-gnu / x86-windows-gnu`
× `-O2/-O0` × 6 个靶子（loops / switch / indirect / strings / float / recurs）。ELF 本机直跑，
PE 默认经 wine（`KOTAMA_WINE`，见仓内 AGENTS「本机运行时依赖」）。

## 边界

只对授权目标使用：自有软件、自有设备、或用户显式指定的研究样本。本仓**不做**免杀 / 反检测 /
持久化 / 凭据窃取 / 反作弊绕过；写内存与冻结默认关闭，需要显式能力声明——只读分析是默认态。

## 参与

合并门槛高，欢迎聚焦的贡献——见 [CONTRIBUTING.md](../../CONTRIBUTING.md)。
安全问题**不要**开公开 issue——见 [SECURITY.md](../../SECURITY.md)。

## 许可

[SySL 1.0](../../LICENSE)。

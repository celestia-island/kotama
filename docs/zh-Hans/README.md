<p align="center"><img src="../../res/logo.webp" alt="Kotama" width="180"/></p>

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

**Windows 原生车道已落地**（2026-11-23，Win10 Pro x64）：原生 host attach/scan/write/freeze、
命名管道或回环 TCP 的 LoadLibrary 注入、PE exception/unwind 与 MSVC RTTI、RSDS 身份校验的 PDB
并用 dbghelp 交叉验证、GNU/MSVC 夹具与打包车道。Windows 宿主上运行 `just bench-windows`
（追加 `--oracle` 纳入真实 Ghidra 差分；设置 `KOTAMA_IDA` 后追加 `--ida` 纳入 IDA 差分）。

本阶段剩余：常驻 Windows CI runner（尚未注册）与 GUI/服务面（P5–P6）。任务面见 PR #1。

已实证的范围：

| 维度 | 现状 |
| --- | --- |
| 容器 | ELF32 / ELF64 / PE32 / PE64（x86 与 x64） |
| 函数发现 | 五路证据（symtab / dynsym / PE exception directory 或 `.pdata` / entry / 直接 call 目标），每行带 provenance |
| PE 元数据 | exception directory + `.xdata` unwind/handler/chain、MSVC vtable/RTTI 类名与继承位移、RSDS 身份校验的伴生 PDB |
| 活体 Windows | Toolhelp 模块、原生内存扫描/冻结、命名管道或回环 TCP 注入、StackWalk64 + dbghelp 线程栈 |
| 边界 | 精确边界优先（符号长度、exception directory、PDB）；推断边界用线性扫描精化，共享尾块不再切断真函数 |
| 反编译 | 基本块 + 地址锚注释；**稠密 switch 的跳转表可恢复**（ELF64 夹具 10/10 分支、置信度 100%） |
| 确定性 | 同一输入两次输出逐字节相同（差分与知识库复用的前提） |
| 已验证 | 24 个矩阵夹具 + `/bin/true`、`/bin/ls` 等 strip 系统二进制 |

已知边界：类型推断与结构体恢复仍属 P1；无 PDB 的 PE 边界依赖 exception directory + call 目标；
通用 vtable 扫描仍窄于 MSVC RTTI；Windows 注入仅 x64→x64；`--pid` attach 限同用户、目标未设
`KOTAMA_PAYLOAD_*`，并按 `.exe` 路径解析主镜像；GUI/服务面尚未开始。

设计决策与过程记录在 PR 描述中（设计文档不进仓树）。

## 能力地图

| 块 | 内容 | 阶段 |
| --- | --- | --- |
| 静态 | 装载 → 函数发现 → 基本块反编译 → SEH/RTTI/PDB 证据与 Ghidra 差分 ✅ / 类型推断 · 结构体 | P0 ✅ / P1 |
| 动态 | Windows 注入（命名管道 / TCP）→ 内存/栈快照 → 扫描/冻结 ✅；hook / trace 与 Linux 注入矩阵待补 | P2–P4 |
| 打包 | GNU x64/x86 与 MSVC 的 agent + manifest 车道 ✅；`hooks.toml` hook ABI 待补 | P4 |
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
cargo run -p kotama-cli -- analyze <文件> --rtti                # MSVC RTTI/虚表事实
cargo run -p kotama-cli -- live inject --payload dist/x86_64-pc-windows-gnu/kotama_agent.dll -- <目标>  # Windows：拉起+注入+握手
cargo run -p kotama-cli -- live inject --payload dist/x86_64-pc-windows-gnu/kotama_agent.dll --pid <pid>       # Windows：注入已运行目标
just bench-windows                          # 原生 Windows 台架（追加 --oracle 纳入 Ghidra）
KOTAMA_IDA=/path/to/idat.exe just bench-windows --oracle --ida   # 可选 IDA 差分
python3 tools/build_fixtures.py --run --host-samples   # 四目标靶子矩阵 + 运行冒烟
```

夹具矩阵：`x86_64-linux-gnu / x86-linux-gnu / x86_64-windows-gnu / x86-windows-gnu`
× `-O2/-O0`，另有原生 `x86_64-windows-msvc / x86-windows-msvc`（`/Zi` + 伴生 PDB）。
ELF 本机直跑；PE 在 Linux 上经 wine（`KOTAMA_WINE`），在 Windows 上原生运行。

## 边界

只对授权目标使用：自有软件、自有设备、或用户显式指定的研究样本。本仓**不做**免杀 / 反检测 /
持久化 / 凭据窃取 / 反作弊绕过；写内存与冻结默认关闭，需要显式能力声明——只读分析是默认态。

## 参与

合并门槛高，欢迎聚焦的贡献——见 [CONTRIBUTING.md](../../CONTRIBUTING.md)。
安全问题**不要**开公开 issue——见 [SECURITY.md](../../SECURITY.md)。

## 许可

[SySL 1.0](../../LICENSE)。

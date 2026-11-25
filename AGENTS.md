# AGENTS.md — kotama 不变量

> 规则本体来自工作区 `/mnt/codespace/AGENTS.md`；本文件只写本仓特有、且**改动时应先读**的约束。

## 提交署名

- 作者/提交者一律 = 伊欧 `<langyo.china@gmail.com>`。
- 智能体经手的提交追加尾注 `Co-authored-by: demiurge <demiurge@celestia.world>`——额外署名，不顶替作者。

## 分支与远端（2026-11-24 起开源）

- `origin` = `github.com/celestia-island/kotama`（公开仓）；`master` 单主干，只经 PR + squash merge 前进。
- 迭代一律经 `wt_new.py` 新建 feature worktree/分支；本地 `dev` 分支已随收敛删除。

## 许可边界（硬约束）

- 本仓许可 = SySL 1.0（`LICENSE`）。
- **禁 AGPL / GPL / LGPL 的 Rust 依赖**：`deny.toml` 的 allow-list 是判据，`just licenses` 必须绿。
- **外接反编译引擎一律独立进程**：Ghidra headless（Apache-2.0）只经子进程与文件交互，不链接、不 vendored、
  不进本仓树。若将来引入 Frida-gum 这类上游 C 库，按工作区「vendored 上游副本」登记。
- **参考实现是参考，不是依赖**：`retour`（BSD-2-Clause）允许读实现与抄结构；抄进本仓的代码就是本仓代码，
  PR 里写明出处与改动点。直接依赖一个预发布线需要理由（`dep-spec` 的预发布豁免）。

## 门禁

`just gate` = `cargo fmt --check` → `cargo clippy --workspace --all-targets -- -D warnings` →
`cargo test --workspace` → `cargo deny check licenses bans sources`。

`ci.yml` 仅 `workflow_dispatch`（编译 + deny 道，自托管 runner）；`depspec-lint` / `family-versions` /
`verify-versions` 在 `master` 推送时跑。

## 代码边界（crate 契约）

- 根包 `kotama`（`src/lib.rs`）：纯身份与数据（模块指纹、函数身份、地址空间 trait）。
  **无 I/O、无 `unsafe`**。是库形态的唯一入口——外部以库调用 kotama 时依赖的就是它。
- 静态管线（`scan` / `lift` / `decomp`）：输入 `AddressSpace`，输出可序列化事实；**必须确定性**
  （排序稳定、无时间戳、同一输入两次输出逐字节相同），否则差分与知识库复用全部失效。
- `kotama-payload`（注入载荷，cdylib + rlib）：登记点（`.init_array` / DllMain）**只做登记**——
  Linux 用裸 `pthread_create` 起线程（loader lock 里不碰 std 锁）；后续 hook 回调内**禁止**
  分配、加锁、I/O 与阻塞（lock-free ring 车道随 hook 原语引入）；写方法与宿主 capability
  门禁成对开放。
- `kotama-host`：会话与注入。**唯一**持有目标进程句柄的地方。
- `kotama-server`：面（REST / WS / MCP），不直接碰目标进程；所有写能力经 capability 校验。
- 跨语言契约只从 Rust 声明；TS/前端类型是生成物，禁止先写 TS 再回填。

## 安全与伦理边界（红线）

- 只对**授权目标**动手：自有软件、自有设备（evernight roster 内）、或用户显式指定的研究样本。
- **不做**免杀、anti-detection、持久化、凭据窃取、反作弊绕过。这条既是伦理边界，也是工程边界：
  一旦开始追检测，工具就永远修不完。
- 写内存 / 冻结 / 远程注入默认关闭，需显式 capability；只读分析是默认态。
- 真实凭据只落 `/mnt/codespace/_secure/`，不进本仓、不进 PR、不进日志/截图。

## 本机运行时依赖（2026-11-23 就绪；路径是事实，改动就地更新）

- **Ghidra 12.2** = `/mnt/work/ghidra/ghidra_12.2_PUBLIC`（zip sha256 `2c2cd776…`）。
  **JDK 必须 25**（`application.java.min=25`；bookworm apt 无 21/25）→ Temurin 25 = `/mnt/work/jdk`，
  调用时 `JAVA_HOME=/mnt/work/jdk`。调用样例 = `support/ghidra/KotamaDecompile.java`（headless
  postScript，批量反编译到 C）。⚠️ python `zipfile` 解包会扒掉执行位：`support/` 下脚本与
  `Ghidra/Features/*/os/linux_x86_64/*` 的本地二进制都要 `chmod +x`（已修）。
- **zig 0.17.1** = `/mnt/work/zig-x86_64-linux-0.17.1/zig`（env `KOTAMA_ZIG`）。两个坑：
  32 位 x86 的 triple 是 `x86-*`（`i386` 已除名）；`zig cc` 的 `-target` 用**空格**形式。
  ⚠️ 2026-11-23 发现该目录曾被整目录清走（tarball 仍在 `/mnt/work/downloads/` 可秒级恢复；
  ghidra/jdk 同期无恙）——根因未查，若再消失先怀疑磁盘回收类定时器，恢复 = 重解 tarball。
- **wine 8.0**（Debian 包，wine32 + wine64 全装）= loader 直用 `/usr/lib/wine/wine64`
  （env `KOTAMA_WINE`；它自带 WOW64，**32 位 PE 也走它**）。坑：`/usr/bin/wine` 包装脚本对
  headless 环境不可靠；`~/.wine` 前缀必须 `WINEARCH=win64` 显式重建才有 `syswow64`
  （默认首建会缺 32 位 dll，症状 = kernel32 c0000135）。
- **夹具车道**：`python3 tools/build_fixtures.py --run --host-samples`——四目标
  （x86_64/x86 × linux/windows-gnu）× O2/O0 × 6 靶子源码；ELF 本机直跑、PE 经 wine 跑，
  退出码全断言；产物在 `fixtures/generated/`（gitignored，随建随有）。
- ⚠️ **任务级 CARGO_HOME 的 registry 软链可能被 cargo 悄悄替换成真目录**（2026-11-23 实踩：
  pdb 首次拉取后 57M 卡在本地，容器车道离线解析不到）。处置：fetch 后 `ls -la` 核对软链仍在；
  被换就把 `cache/src/index` 三个子树 `cp -rn` 合并回 `/mnt/work/runner-shared/cargo-home/registry/`
  再重建软链。**容器车道命令带 `--offline --locked`**（工作区标准），不带时新依赖会去解析
  DNS 直接红。

- **Windows 原生台架（2026-11-23，Win10 Pro x64）**：
  - Ghidra 12.2 = `D:\源代码\工程项目\celestia\_scratch\kotama-tools\ghidra_12.2_PUBLIC`；
    Temurin 25 = `D:\源代码\工程项目\celestia\_scratch\kotama-tools\jdk25\jdk-25.0.5.1+2`；
    zig 0.17.1 = `D:\源代码\工程项目\celestia\_scratch\kotama-tools\zig-x86_64-windows-0.17.1\zig.exe`。
    分别经 `KOTAMA_GHIDRA_HOME` / `KOTAMA_JDK_HOME` / `KOTAMA_ZIG` 注入，不改全局 `JAVA_HOME`。
  - Ghidra 12.2 的 `launch.bat` 会错码非 ASCII JDK 路径；backend 对这种路径直调官方
    `AnalyzeHeadless` 主类。Ghidra home 本身在非 ASCII 路径时还会出现 log4j XML include 警告，
    本机实测退出码与函数清单正常，但不能把该警告写成已修复。
  - IDA Professional 9.1 = `C:\Program Files\IDA Professional 9.1\idat.exe`，只作独立进程差分参照，
    不进依赖树；IDAPython 9.1 的函数迭代器是 `idautils.Functions()`。
  - MSVC 由 `tools/build_fixtures.py` 经 vswhere + `VsDevCmd.bat` 自动发现（VS 2026 + WinSDK）；
    `python tools/build_fixtures.py --targets x86_64-windows-msvc x86-windows-msvc --run` 出
    x64/x86、O2/Od、`/Zi` + 伴生 PDB 并原生运行。Windows smoke 只执行 `.exe`。
  - 一键验收 = `just bench-windows`；追加 `--oracle` 纳入真实 Ghidra PE 差分，追加
    `--ida`（需 `KOTAMA_IDA`）纳入 IDA 差分。常驻 CI runner 尚未注册（2026-11-23 用户裁决），
    本机通过不等于常驻 CI 项完成。
  - 注入支持 x64→x64 与 x64→x86（WOW64）：跨位宽时按目标进程里的 32 位 kernel32 导出表
    解析 `LoadLibraryW`；x86 载荷 = `dist/i686-pc-windows-gnu/kotama_agent.dll`（pack 车道
    经 `tools/build_windows_agent.py --target x86-windows-gnu` 产出），attach 矩阵与 host live
    e2e 各含一条 x86 目标车道（夹具 `x86-windows-gnu/-O2/spin.exe`）。
  - 符号无关对比（2026-11-25 实测）：把 PE 的 `IMAGE_DIRECTORY_ENTRY_DEBUG` 数据目录清零，
    IDA 就找不到伴生 PDB。同一份 `x86_64-windows-msvc/-O2/loops.exe` 上，无 PDB 的 kotama 覆盖
    PDB 真值 0.845、无 PDB 的 IDA 9.1 只有 0.751（x86 上 0.820 对 0.796）。所以「无 PDB 夹具
    recall 0.845」是符号信息上限，不是欠采样；不要再为它加无引用的 `ret` 之后起点规则。
  - ⚠️ 各 worktree 的 `fixtures/generated` 是指向 `_worktree/kotama/windows-phase/fixtures/generated` 的 junction（2026-11-25 实踩）：
    `git worktree remove` 会**穿过 junction** 把共享夹具删空。移除 worktree 前先 `cmd /c rmdir <wt>\fixtures\generated`
    （只删链接），再 remove；被删空后用 `tools/build_fixtures.py --run` 与 `--targets x86_64-windows-msvc x86-windows-msvc --run` 重建。


## 版本声明

两段式（`^1` / `^0.1`）；禁三段式、`~` 区间、`^*`、`^0.*`、裸 `*`、`latest`。`devDependencies` 是唯一槽位豁免。

#!/usr/bin/env python3
"""构建 windows 载荷（C agent + loader），走 zig cc 交叉编译。

产物（默认落 `dist/<target>/`，支持 x86_64-windows-gnu 与 x86-windows-gnu）：
  - `kotama_agent.dll`   —— 载荷本体（DllMain 起线程，TCP 回环说话）
  - `kotama_load.exe`    —— wine 下的装载器（LoadLibrary 预载 + 拉起目标）

为什么是 C 而不是 Rust 版：rust 的 windows-gnu 目标，std 会拖进
`synchronization` / `msvcrt` / `libpthread.a` 等系统库，而 zig 自带的 mingw 集结
早于这些库且以源码形态提供（rustc 要精确文件名）。C 版由 zig cc 直接出 dll，
已在 wine 实测可 LoadLibrary 并被 Linux 宿主原生握手（见 host 的 wine e2e）。

用法：
  python3 tools/build_windows_agent.py            # 构建 x64 两个产物
  python3 tools/build_windows_agent.py --target x86-windows-gnu  # 构建 32 位产物
  python3 tools/build_windows_agent.py --check    # 只校验工具链在位
环境：KOTAMA_ZIG（zig 路径）。
"""

from __future__ import annotations
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent  # resolve() 已吃掉 ..
SOURCE_DIR = REPO / "support" / "windows-agent"
DEFAULT_TARGET = "x86_64-windows-gnu"
WINDOWS_TARGETS = ("x86_64-windows-gnu", "x86-windows-gnu")
DEFAULT_ZIG = "/mnt/work/zig-x86_64-linux-0.17.1/zig"

def find_zig(override: str | None) -> str:
    candidates = [override] if override else []
    candidates.append(os.environ.get("KOTAMA_ZIG", ""))
    candidates.append(shutil.which("zig") or "")
    candidates += sorted(str(path) for path in Path("/mnt/work").glob("zig-*/zig"))

    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate

    candidates_checked = ", ".join(filter(None, candidates)) or "<none>"
    sys.exit(f"build_windows_agent: no zig found (checked: {candidates_checked})")

def compile_one(zig: str, source: Path, output: Path, shared: bool, target: str) -> None:
    command = [zig, "cc", "-target", target, "-O2"]

    if shared:
        command.append("-shared")

    command += ["-o", str(output), str(source), "-lws2_32"]
    completed = subprocess.run(command, capture_output = True, text = True)

    if completed.returncode != 0:
        sys.exit(f"build_windows_agent: {source.name} failed:\n{completed.stderr}")

    print(f"ok   {output.name} ({output.stat().st_size} B)")

def main() -> int:
    parser = argparse.ArgumentParser(prog = "build_windows_agent")
    parser.add_argument("--zig")
    parser.add_argument("--target", choices = WINDOWS_TARGETS, default = DEFAULT_TARGET)
    parser.add_argument("--check", action = "store_true", help = "only verify toolchain")
    parser.add_argument("--out-dir", help = "override output directory (default dist/<target>)")
    args = parser.parse_args()

    zig = find_zig(args.zig)
    version = subprocess.run([zig, "version"], capture_output = True, text = True).stdout.strip()
    print(f"# zig {version} @ {zig}; target {args.target}")

    if args.check:
        print("# toolchain ok")
        return 0

    out_dir = Path(args.out_dir) if args.out_dir else REPO / "dist" / args.target
    out_dir.mkdir(parents = True, exist_ok = True)
    compile_one(zig, SOURCE_DIR / "kotama_agent.c", out_dir / "kotama_agent.dll", True, args.target)
    compile_one(zig, SOURCE_DIR / "kotama_load.c", out_dir / "kotama_load.exe", False, args.target)
    print(f"build_windows_agent: artifacts in {out_dir}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

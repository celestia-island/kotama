#!/usr/bin/env python3
"""原生 Windows 台架的一键验收车道。

只运行仓库自己构建的夹具；不写注册表、不安装服务、不接触未授权目标。
默认顺序：gnu/ELF 夹具 → MSVC 夹具 → just gate → pack/load e2e → host live e2e。
Ghidra 较慢且依赖外部安装，使用 --oracle 显式加入。

工具路径通过 --zig / KOTAMA_ZIG、KOTAMA_PYTHON、KOTAMA_GHIDRA_HOME 与
KOTAMA_JDK_HOME 提供；仓内不写死任何本机路径。
"""

from __future__ import annotations
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def run_step(name: str, command: list[str], env: dict[str, str], timeout: int = 1800) -> None:
    print(f"\n=== windows-bench: {name} ===", flush = True)
    print("+ " + " ".join(command), flush = True)
    try:
        completed = subprocess.run(command, cwd = REPO, env = env, timeout = timeout)
    except subprocess.TimeoutExpired:
        raise SystemExit(f"windows-bench: {name} exceeded {timeout}s") from None
    if completed.returncode != 0:
        raise SystemExit(f"windows-bench: {name} failed with exit {completed.returncode}")


def main() -> int:
    parser = argparse.ArgumentParser(prog = "windows_bench")
    parser.add_argument("--zig", help = "path to zig 0.17.1 (or set KOTAMA_ZIG)")
    parser.add_argument("--skip-msvc", action = "store_true", help = "skip the native MSVC fixture lane")
    parser.add_argument("--skip-pack", action = "store_true", help = "skip pack + LoadLibrary e2e")
    parser.add_argument("--skip-live", action = "store_true", help = "skip native host live e2e")
    parser.add_argument("--oracle", action = "store_true", help = "also run the real Ghidra PE oracle tests")
    args = parser.parse_args()

    if os.name != "nt":
        raise SystemExit("windows-bench: this lane requires a native Windows host")
    for tool in ("cargo", "just"):
        if shutil.which(tool) is None:
            raise SystemExit(f"windows-bench: {tool} not found on PATH")

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["KOTAMA_REQUIRE_FIXTURES"] = "1"
    env["KOTAMA_PACK_E2E"] = "1"
    env["KOTAMA_LIVE_E2E"] = "1"
    if args.zig:
        env["KOTAMA_ZIG"] = args.zig
    env.setdefault("KOTAMA_PYTHON", sys.executable)
    if not env.get("KOTAMA_ZIG") and not shutil.which("zig"):
        raise SystemExit("windows-bench: pass --zig or set KOTAMA_ZIG")

    # 构建四种 gnu/ELF 目标；Windows 原生运行 PE，ELF 仅保留给静态管线测试。
    run_step("gnu and ELF fixture matrix", [
        sys.executable, "tools/build_fixtures.py", "--run",
    ], env)
    if not args.skip_msvc:
        run_step("native MSVC fixture matrix", [
            sys.executable, "tools/build_fixtures.py", "--targets",
            "x86_64-windows-msvc", "x86-windows-msvc", "--run",
        ], env)

    run_step("just gate with required fixtures", ["just", "gate"], env)
    if not args.skip_pack:
        run_step("pack and native LoadLibrary e2e", [
            "cargo", "test", "-p", "kotama-pack", "pack_windows", "--", "--test-threads=1",
        ], env)
    if not args.skip_live:
        run_step("native host live e2e", [
            "cargo", "test", "-p", "kotama-host", "--", "--test-threads=1",
        ], env)
    if args.oracle:
        for variable in ("KOTAMA_GHIDRA_HOME", "KOTAMA_JDK_HOME"):
            if not env.get(variable):
                raise SystemExit(f"windows-bench: --oracle requires {variable}")
        env["KOTAMA_GHIDRA_E2E"] = "1"
        run_step("real Ghidra PE oracle", [
            "cargo", "test", "-p", "kotama-backend-ghidra", "--", "--test-threads=1",
        ], env, timeout = 2400)

    print("\nwindows-bench: all selected lanes are green", flush = True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

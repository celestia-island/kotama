#!/usr/bin/env python3
"""原生 Windows 台架的一键验收车道。

只运行仓库自己构建的夹具；不写注册表、不安装服务、不接触未授权目标。
默认顺序：gnu/ELF 夹具 → MSVC 夹具 → pack/load（先生成 dist 载荷）→ host live e2e
（紧接 pack，缩短产物窗口）→ just gate → 可选 Ghidra/IDA。每个 e2e 开关只作用于对应步骤。
Ghidra/IDA 较慢且依赖外部安装，分别使用 --oracle / --ida 显式加入。

工具路径通过 --zig / KOTAMA_ZIG、KOTAMA_PYTHON、KOTAMA_GHIDRA_HOME 与
KOTAMA_JDK_HOME 提供；仓内不写死任何本机路径。
"""

from __future__ import annotations
import argparse
import json
import os
import time
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


def cli_injection_smoke(env: dict[str, str]) -> None:
    agent = REPO / "dist" / "x86_64-pc-windows-gnu" / "kotama_agent.dll"
    spin = REPO / "fixtures" / "generated" / "x86_64-windows-gnu" / "-O2" / "spin.exe"
    for path in (agent, spin):
        if not path.is_file():
            raise SystemExit(f"windows-bench: CLI injection input missing: {path}")

    print("\n=== windows-bench: CLI launch-then-inject smoke ===", flush = True)
    for transport in ("pipe", "tcp"):
        command = [
            "cargo", "run", "--quiet", "-p", "kotama-cli", "--", "live", "inject",
            "--payload", str(agent), "--transport", transport, "--", str(spin), "30",
        ]
        print("+ " + " ".join(command), flush = True)
        try:
            completed = subprocess.run(
                command, cwd = REPO, env = env, capture_output = True,
                text = True, encoding = "utf-8", timeout = 180,
            )
        except subprocess.TimeoutExpired:
            raise SystemExit(f"windows-bench: CLI inject {transport} exceeded 180s") from None
        if completed.returncode != 0:
            print(completed.stdout + completed.stderr)
            raise SystemExit(f"windows-bench: CLI inject {transport} failed with {completed.returncode}")
        report = json.loads(completed.stdout)
        if report.get("proto_version") != 3:
            raise SystemExit(f"windows-bench: CLI inject {transport} proto mismatch: {report}")
        if report.get("payload_main_base") != report.get("target_main_base"):
            raise SystemExit(f"windows-bench: CLI inject {transport} main base mismatch: {report}")
        if report.get("image_magic") != "4d5a":
            raise SystemExit(f"windows-bench: CLI inject {transport} did not read MZ: {report}")
        print(
            f"# cli inject {transport}: pid={report['pid']} "
            f"base={report['payload_main_base']} magic={report['image_magic']}",
            flush = True,
        )


def cli_attach_smoke(env: dict[str, str]) -> None:
    agent = REPO / "dist" / "x86_64-pc-windows-gnu" / "kotama_agent.dll"
    spin = REPO / "fixtures" / "generated" / "x86_64-windows-gnu" / "-O2" / "spin.exe"
    for path in (agent, spin):
        if not path.is_file():
            raise SystemExit(f"windows-bench: CLI attach input missing: {path}")

    child_env = env.copy()
    child_env.pop("KOTAMA_PAYLOAD_PIPE", None)
    child_env.pop("KOTAMA_PAYLOAD_TCP", None)
    child = subprocess.Popen(
        [str(spin), "30"], cwd = REPO, env = child_env,
        stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL,
    )
    try:
        time.sleep(0.5)
        command = [
            "cargo", "run", "--quiet", "-p", "kotama-cli", "--", "live", "inject",
            "--payload", str(agent), "--pid", str(child.pid),
        ]
        print("\n=== windows-bench: CLI attach-then-inject smoke ===", flush = True)
        print("+ " + " ".join(command), flush = True)
        completed = subprocess.run(
            command, cwd = REPO, env = env, capture_output = True,
            text = True, encoding = "utf-8", timeout = 180,
        )
        if completed.returncode != 0:
            print(completed.stdout + completed.stderr)
            raise SystemExit(f"windows-bench: CLI attach failed with {completed.returncode}")
        report = json.loads(completed.stdout)
        if report.get("transport") != "pipe":
            raise SystemExit(f"windows-bench: CLI attach used the wrong transport: {report}")
        if report.get("payload_main_base") != report.get("target_main_base"):
            raise SystemExit(f"windows-bench: CLI attach main base mismatch: {report}")
        if report.get("image_magic") != "4d5a":
            raise SystemExit(f"windows-bench: CLI attach did not read MZ: {report}")
        print(
            f"# cli attach: pid={report['pid']} base={report['payload_main_base']} "
            f"magic={report['image_magic']}",
            flush = True,
        )
    finally:
        child.terminate()
        try:
            child.wait(timeout = 5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def cli_attach_case(label, command, payload, extra_env, env, settle = 0.5):
    child_env = env.copy()
    child_env.pop("KOTAMA_PAYLOAD_PIPE", None)
    child_env.pop("KOTAMA_PAYLOAD_TCP", None)
    child_env.update(extra_env)
    child = subprocess.Popen(
        command, cwd = REPO, env = child_env,
        stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL,
    )
    try:
        time.sleep(settle)
        cli = [
            "cargo", "run", "--quiet", "-p", "kotama-cli", "--", "live", "inject",
            "--payload", str(payload), "--pid", str(child.pid),
        ]
        print("+ " + label + ": " + " ".join(cli), flush = True)
        completed = subprocess.run(
            cli, cwd = REPO, env = env, capture_output = True,
            text = True, encoding = "utf-8", timeout = 180,
        )
        if completed.returncode != 0:
            print(completed.stdout + completed.stderr)
            raise SystemExit("windows-bench: CLI attach " + label + " failed with " + str(completed.returncode))
        report = json.loads(completed.stdout)
        if report.get("proto_version") != 3:
            raise SystemExit("windows-bench: CLI attach " + label + " proto mismatch: " + str(report))
        if report.get("payload_main_base") != report.get("target_main_base"):
            raise SystemExit("windows-bench: CLI attach " + label + " main base mismatch: " + str(report))
        if report.get("image_magic") != "4d5a":
            raise SystemExit("windows-bench: CLI attach " + label + " did not read MZ: " + str(report))
        print("# cli attach " + label + ": pid=" + str(report.get("pid")) + " base=" + str(report.get("payload_main_base")), flush = True)
    finally:
        child.terminate()
        try:
            child.wait(timeout = 5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def cli_attach_matrix(env):
    agent = REPO / "dist" / "x86_64-pc-windows-gnu" / "kotama_agent.dll"
    rust_payload = REPO / "dist" / "x86_64-pc-windows-msvc" / "kotama_payload.dll"
    spin = REPO / "fixtures" / "generated" / "x86_64-windows-gnu" / "-O2" / "spin.exe"
    for path in (agent, rust_payload, spin):
        if not path.is_file():
            raise SystemExit("windows-bench: CLI attach input missing: " + str(path))
    print("\n=== windows-bench: CLI attach matrix ===", flush = True)
    cli_attach_case("spin/c-agent", [str(spin), "30"], agent, {}, env)
    cli_attach_case("spin/rust-empty-env", [str(spin), "30"], rust_payload, {"KOTAMA_PAYLOAD_PIPE": ""}, env)
    pwsh = shutil.which("pwsh")
    if pwsh:
        cli_attach_case("pwsh/low-base-exe", [pwsh, "-NoProfile", "-Command", "Start-Sleep 30"], agent, {}, env, settle = 2.0)


def main() -> int:
    parser = argparse.ArgumentParser(prog = "windows_bench")
    parser.add_argument("--zig", help = "path to zig 0.17.1 (or set KOTAMA_ZIG)")
    parser.add_argument("--skip-msvc", action = "store_true", help = "skip the native MSVC fixture lane")
    parser.add_argument("--skip-pack", action = "store_true", help = "skip pack + LoadLibrary e2e")
    parser.add_argument("--skip-live", action = "store_true", help = "skip native host live e2e")
    parser.add_argument("--oracle", action = "store_true", help = "also run the real Ghidra PE oracle tests")
    parser.add_argument("--ida", action = "store_true", help = "also run the real IDA PE cross-check")
    args = parser.parse_args()

    if os.name != "nt":
        raise SystemExit("windows-bench: this lane requires a native Windows host")
    for tool in ("cargo", "just"):
        if shutil.which(tool) is None:
            raise SystemExit(f"windows-bench: {tool} not found on PATH")

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["KOTAMA_REQUIRE_FIXTURES"] = "1"
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
        run_step("dbghelp versus pdb-crate cross-check", [
            sys.executable, "tools/pdb_crosscheck.py",
        ], env)

    if not args.skip_live and args.skip_pack:
        raise SystemExit("windows-bench: live e2e needs the pack artifacts; drop --skip-pack or add --skip-live")

    # pack/load 必须早于 gate：gate 本身不设 live 开关，但 host live e2e 依赖 dist 里的
    # C agent/loader 与 MSVC Rust payload；干净 worktree 没有历史 dist。
    if not args.skip_pack:
        pack_env = env.copy()
        pack_env["KOTAMA_PACK_E2E"] = "1"
        run_step("pack and native LoadLibrary e2e", [
            "cargo", "test", "-p", "kotama-pack", "pack_windows", "--", "--test-threads=1",
        ], pack_env)

    if not args.skip_live:
        live_env = env.copy()
        live_env["KOTAMA_LIVE_E2E"] = "1"
        run_step("native host live e2e", [
            "cargo", "test", "-p", "kotama-host", "--", "--test-threads=1",
        ], live_env)
        cli_injection_smoke(env)
        cli_attach_smoke(env)
        cli_attach_matrix(env)

    run_step("just gate with required fixtures", ["just", "gate"], env)
    if args.oracle:
        for variable in ("KOTAMA_GHIDRA_HOME", "KOTAMA_JDK_HOME"):
            if not env.get(variable):
                raise SystemExit(f"windows-bench: --oracle requires {variable}")
        oracle_env = env.copy()
        oracle_env["KOTAMA_GHIDRA_E2E"] = "1"
        run_step("real Ghidra PE oracle", [
            "cargo", "test", "-p", "kotama-backend-ghidra", "--", "--test-threads=1",
        ], oracle_env, timeout = 2400)
    if args.ida:
        if not env.get("KOTAMA_IDA"):
            raise SystemExit("windows-bench: --ida requires KOTAMA_IDA=<idat.exe>")
        run_step("real IDA PE cross-check", [
            sys.executable, "tools/ida_crosscheck.py",
        ], env, timeout = 1200)

    print("\nwindows-bench: all selected lanes are green", flush = True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""kotama 夹具车道：把 fixtures/src/*.c 交叉编译成四目标靶子矩阵。

目标矩阵（默认）：x86_64-linux-gnu / i386-linux-gnu / x86_64-windows-gnu /
i386-windows-gnu，各出 -O2 与 -O0 两档（-g 常开——DWARF 是静态管线的测试面之一）。
产物一律落 fixtures/generated/（gitignored，可随时重建）。

用法：
  python3 tools/build_fixtures.py                 # 全矩阵编译
  python3 tools/build_fixtures.py --run           # 编译 + 本机 ELF 直跑 / PE 经 wine 跑（退出码必须 0）
  python3 tools/build_fixtures.py --targets x86_64-linux-gnu
  python3 tools/build_fixtures.py --host-samples  # 顺手拷几个本机真实 ELF 进 host-samples/
  python3 tools/build_fixtures.py --list

工具链发现顺序：--zig > $KOTAMA_ZIG > PATH > /mnt/work/zig-*/zig。
wine 发现顺序：--wine > $KOTAMA_WINE > PATH（wine64 > wine）。32 位 PE 在纯 wine64（无
wine32）环境下会跑不动——脚本探测失败时按 lane-skip 报告，不算失败。原生 Windows
宿主直接运行 PE，不要求 wine；ELF 的运行在 Windows 上按 lane-skip 报告。
"""

from __future__ import annotations
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC_DIR = REPO / "fixtures" / "src"
OUT_ROOT = REPO / "fixtures" / "generated"

DEFAULT_TARGETS = ["x86_64-linux-gnu", "x86-linux-gnu", "x86_64-windows-gnu", "x86-windows-gnu"]
OPT_LEVELS = ["O2", "O0"]
HOST_SAMPLES = ["/bin/true", "/bin/cat", "/usr/bin/yes"]

def find_zig(override: str | None) -> str:
    candidates = []

    if override:
        candidates.append(override)

    if os.environ.get("KOTAMA_ZIG"):
        candidates.append(os.environ["KOTAMA_ZIG"])

    candidates.append(shutil.which("zig") or "")
    candidates += sorted(str(p) for p in Path("/mnt/work").glob("zig-*/zig"))

    for cand in candidates:
        if cand and Path(cand).exists():
            return cand

    sys.exit("build_fixtures: no zig found (pass --zig or set KOTAMA_ZIG)")

def find_wine(override: str | None) -> str | None:
    candidates = []

    if override:
        candidates.append(override)

    if os.environ.get("KOTAMA_WINE"):
        candidates.append(os.environ["KOTAMA_WINE"])

    for name in ("wine64", "wine"):
        found = shutil.which(name)

        if found:
            candidates.append(found)

    for cand in candidates:
        if cand and Path(cand).exists():
            return cand

    return None

def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output = True, text = True, **kw)

def build_all(zig: str, targets: list[str], opt_levels: list[str]) -> int:
    sources = sorted(SRC_DIR.glob("*.c"))

    if not sources:
        sys.exit(f"build_fixtures: no sources under {SRC_DIR}")

    cpp_sources = sorted(SRC_DIR.glob("*.cpp"))
    failures = 0

    for target in targets:
        is_windows = target.endswith("-windows-gnu")

        for opt in opt_levels:
            out_dir = OUT_ROOT / target / f"-{opt}"
            out_dir.mkdir(parents = True, exist_ok = True)

            for src in sources + cpp_sources:
                # C++ 走 zig c++（libc++ 静态随链）；vtable/RTTI 按语言默认开。
                compiler = "c++" if src.suffix == ".cpp" else "cc"
                exe = out_dir / (src.stem + (".exe" if is_windows else ""))
                cmd = [zig, compiler, "-target", target, f"-{opt}", "-g", "-Wall", "-Wextra", "-o", str(exe), str(src)]
                proc = run(cmd)

                if proc.returncode != 0:
                    failures += 1
                    print(f"FAIL {target}/-{opt}/{src.stem}\n{proc.stderr.strip()}")
                else:
                    size = exe.stat().st_size
                    print(f"ok   {target}/-{opt}/{exe.name} ({size} B)")

    return failures

def smoke_run(targets: list[str], opt_levels: list[str], wine: str | None) -> int:
    failures = 0
    native_windows = os.name == "nt"

    for target in targets:
        is_windows = target.endswith("-windows-gnu")

        if is_windows and not native_windows and (wine is None):
            print(f"lane-skip {target}: PE smoke runs need a Windows host or wine")
            continue
        if not is_windows and native_windows:
            print(f"lane-skip {target}: ELF smoke runs need a Linux host")
            continue

        for opt in opt_levels:
            out_dir = OUT_ROOT / target / f"-{opt}"

            for exe in sorted(out_dir.iterdir()):
                if not exe.is_file():
                    continue

                # mingw 目标带 -g 会顺带产出 <name>.pdb（调试符号伴生文件），不是可执行。
                if exe.suffix == ".pdb":
                    continue

                cmd = ([wine] if is_windows and not native_windows else []) + [str(exe)]
                proc = run(cmd, timeout = 60)
                name = f"{target}/-{opt}/{exe.name}"

                if proc.returncode == 0:
                    out = (proc.stdout or proc.stderr or "").strip().splitlines()
                    detail = out[0] if out else "(no output)"
                    print(f"pass {name}: {detail}")
                else:
                    failures += 1
                    print(f"FAIL {name}: rc={proc.returncode} " f"{(proc.stderr or '').strip()[:200]}")

    return failures

def copy_host_samples() -> None:
    out_dir = OUT_ROOT / "host-samples"
    out_dir.mkdir(parents = True, exist_ok = True)

    for sample in HOST_SAMPLES:
        src = Path(sample)

        if src.exists():
            shutil.copy2(src, out_dir / src.name)
            print(f"ok   host-samples/{src.name}")
        else:
            print(f"skip {sample}: not present")

def main() -> int:
    ap = argparse.ArgumentParser(prog = "build_fixtures")
    ap.add_argument("--zig", help = "path to the zig binary")
    ap.add_argument("--wine", help = "path to wine for PE smoke runs")
    ap.add_argument("--targets", nargs = "*", default = DEFAULT_TARGETS)
    ap.add_argument("--opt", choices = ["O2", "O0", "all"], default = "all")
    ap.add_argument("--run", action = "store_true", help = "smoke-run after build")
    ap.add_argument("--host-samples", action = "store_true")
    ap.add_argument("--list", action = "store_true")
    args = ap.parse_args()

    if args.list:
        for target in args.targets:
            for opt in (OPT_LEVELS if args.opt == "all" else [args.opt]):
                print(f"{target}/-{opt}")

        return 0

    zig = find_zig(args.zig)
    ver = run([zig, "version"]).stdout.strip()
    print(f"# zig {ver} @ {zig}")
    opt_levels = OPT_LEVELS if args.opt == "all" else [args.opt]

    failures = build_all(zig, args.targets, opt_levels)

    if args.host_samples:
        copy_host_samples()

    if args.run:
        wine = find_wine(args.wine)

        if wine:
            print(f"# wine {run([wine, '--version']).stdout.strip()} @ {wine}")

        failures += smoke_run(args.targets, opt_levels, wine)

    if failures:
        print(f"build_fixtures: {failures} failure(s)")
        return 1

    print("build_fixtures: all green")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

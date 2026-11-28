#!/usr/bin/env python3
"""kotama 夹具车道：把 fixtures/src/*.c 交叉编译成四目标靶子矩阵。

目标矩阵（默认）：x86_64-linux-gnu / i386-linux-gnu / x86_64-windows-gnu /
i386-windows-gnu，各出 -O2 与 -O0 两档（-g 常开——DWARF 是静态管线的测试面之一）。
产物一律落 fixtures/generated/（gitignored，可随时重建）。

用法：
  python3 tools/build_fixtures.py                 # 全矩阵编译
  python3 tools/build_fixtures.py --run           # 编译 + 本机 ELF 直跑 / PE 经 wine 跑（退出码必须 0）
  python3 tools/build_fixtures.py --targets x86_64-linux-gnu
  python3 tools/build_fixtures.py --targets x86_64-windows-msvc x86-windows-msvc --run
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
import urllib.request
import tarfile
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

def is_windows_target(target: str) -> bool:
    return target.endswith(("-windows-gnu", "-windows-msvc"))

def decode_console(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("mbcs", errors = "replace")

def msvc_environment(target: str) -> dict[str, str]:
    if os.name != "nt":
        sys.exit(f"build_fixtures: {target} currently needs a native Windows MSVC host")

    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / \
        "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        sys.exit(f"build_fixtures: vswhere not found at {vswhere}")

    query = run([
        str(vswhere), "-latest", "-products", "*", "-requires",
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath",
    ])
    installation = query.stdout.strip()
    if query.returncode != 0 or not installation:
        sys.exit("build_fixtures: no Visual Studio C++ toolchain found")

    dev_cmd = Path(installation) / "Common7" / "Tools" / "VsDevCmd.bat"
    arch = "x86" if target.startswith("x86-") else "x64"
    command = f'"{dev_cmd}" -arch={arch} -host_arch=x64 && set'
    probe = subprocess.run(command, shell = True, capture_output = True)
    stdout = decode_console(probe.stdout)
    stderr = decode_console(probe.stderr)
    if probe.returncode != 0:
        sys.exit(f"build_fixtures: VsDevCmd failed:\n{stdout}\n{stderr}")

    # Windows 环境变量大小写不敏感；VsDevCmd 常输出 Path 而非 PATH。
    env = {name.upper(): value for name, value in os.environ.items()}
    for line in stdout.splitlines():
        name, separator, value = line.partition("=")
        if separator and name and not name.startswith("="):
            env[name.upper()] = value
    if shutil.which("cl", path = env.get("PATH")) is None:
        sys.exit(f"build_fixtures: VsDevCmd did not provide cl.exe for {target}")
    print(f"# msvc {installation} arch={arch}")
    return env

def build_msvc_target(target: str, opt_levels: list[str], sources: list[Path]) -> int:
    env = msvc_environment(target)
    compiler = shutil.which("cl", path = env.get("PATH"))
    failures = 0

    for opt in opt_levels:
        out_dir = OUT_ROOT / target / f"-{opt}"
        out_dir.mkdir(parents = True, exist_ok = True)

        for src in sources:
            exe = out_dir / f"{src.stem}.exe"
            obj = out_dir / f"{src.stem}.obj"
            pdb = out_dir / f"{src.stem}.pdb"
            cmd = [
                compiler, "/nologo", "/utf-8", "/Zi", "/W4", "/D_CRT_SECURE_NO_WARNINGS",
                "/O2" if opt == "O2" else "/Od",
            ]
            if src.suffix == ".cpp":
                cmd += ["/EHsc", "/GR"]
            # /Brepro on both ends: the compiler stamps the COFF header with a
            # content hash instead of the clock, and the linker does the same for
            # the PE timestamp. Without it two builds of the same source differ in
            # every .obj and .exe, and every PE test is passing on different bytes
            # each time. The .obj and .pdb still carry a fresh debug GUID each build
            # — Microsoft's design for debug-info uniqueness — so the .exe is what
            # the reproducibility check holds to.
            cmd += [
                "/Brepro",
                f"/Fo{obj}", f"/Fe{exe}", str(src), "/link", "/DEBUG:FULL", "/Brepro",
                "/INCREMENTAL:NO", f"/PDB:{pdb}",
            ]
            proc = run(cmd, cwd = out_dir, env = env)

            if proc.returncode != 0 or not exe.is_file():
                failures += 1
                output = (proc.stdout + proc.stderr).strip()
                print(f"FAIL {target}/-{opt}/{src.stem}\n{output}")
            else:
                print(f"ok   {target}/-{opt}/{exe.name} ({exe.stat().st_size} B)")

    return failures

def build_all(zig: str | None, targets: list[str], opt_levels: list[str]) -> int:
    sources = sorted(SRC_DIR.glob("*.c"))

    if not sources:
        sys.exit(f"build_fixtures: no sources under {SRC_DIR}")

    cpp_sources = sorted(SRC_DIR.glob("*.cpp"))
    failures = 0

    for target in targets:
        if target.endswith("-windows-msvc"):
            failures += build_msvc_target(target, opt_levels, sources + cpp_sources)
            continue
        if zig is None:
            sys.exit("build_fixtures: zig is required for non-MSVC targets")
        is_windows = is_windows_target(target)

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

def build_shared(zig: str | None, targets: list[str], opt_levels: list[str]) -> int:
    """Build the shared-library fixtures under fixtures/src/shared/.

    These are never run. They exist so that export-table consumers (runtime
    mounting, proxy mirrors) have a real .so/.dll to read instead of a synthetic
    table, and so that an ELF *executable* exporting nothing is a separate,
    pinned fact rather than an accident of which fixture was loaded.
    """
    shared_dir = SRC_DIR / "shared"
    sources = sorted(shared_dir.glob("*.c")) if shared_dir.is_dir() else []
    if not sources:
        return 0
    failures = 0
    for target in targets:
        if zig is None:
            sys.exit("build_fixtures: zig is required for shared-library targets")
        is_windows = is_windows_target(target)
        for opt in opt_levels:
            out_dir = OUT_ROOT / target / f"-{opt}"
            out_dir.mkdir(parents = True, exist_ok = True)
            for src in sources:
                lib = out_dir / ("lib" + src.stem + (".dll" if is_windows else ".so"))
                cmd = [zig, "cc", "-target", target, f"-{opt}", "-shared", "-fPIC", "-fvisibility=hidden", "-o", str(lib), str(src)]
                proc = run(cmd)
                if proc.returncode != 0:
                    failures += 1
                    print(f"FAIL {target}/-{opt}/{lib.name}\n{proc.stderr.strip()}")
                else:
                    print(f"ok   {target}/-{opt}/{lib.name} ({lib.stat().st_size} B)")
    return failures


CROSS_LANES = [
    # (name, zig target, extra cc flags, source stem, output stem)
    ("riscv64-norvc", "riscv64-linux-musl", ["-nostdlib", "-mcpu=generic_rv64"], "riscv", "norvc"),
    ("riscv64-rvc", "riscv64-linux-musl", ["-nostdlib", "-mcpu=generic_rv64+c"], "riscv", "rvc"),
    ("riscv64-strings", "riscv64-linux-musl", ["-nostdlib", "-mcpu=generic_rv64+c", "-fno-builtin"], "riscv_strings", "strings"),
    # RV32 shares the RV64 encoding minus the 64-bit-only forms and with c.jal
    # restored to its RV32 meaning; it is the next architecture to lift, and until
    # then it is the regression sample for "unsupported must not crash".
    ("riscv32-noc", "riscv32-linux-musl", ["-nostdlib", "-mcpu=generic_rv32", "-fno-builtin"], "riscv", "norvc"),
    ("riscv32-c", "riscv32-linux-musl", ["-nostdlib", "-mcpu=generic_rv32+c", "-fno-builtin"], "riscv", "rvc"),
    ("arm-a32", "arm-linux-musleabi", [], "arm", "a32"),
    ("arm-thumb", "thumb-linux-musleabi", [], "arm", "thumb"),
    ("arm-strings", "arm-linux-musleabi", [], "arm_strings", "a32"),
    ("arm-strings-thumb", "thumb-linux-musleabi", [], "arm_strings", "thumb"),
    ("aarch64-elf", "aarch64-linux-musl", [], "macho", "elf"),
    ("aarch64-macho", "aarch64-macos", ["-nostdlib", "-fno-sanitize=all"], "macho", "macho"),
]

def build_cross(zig: str | None) -> int:
    """Cross-compile the non-x86 samples under fixtures/src/cross/.

    These exercise the lifters (A64, RISC-V, ARM/Thumb) and the frame-section
    discovery on real binaries. They are never run here — the host cannot execute
    them — so each is linked with -s to drop the symbol table, which is the stripped
    shape the lifters exist for.
    """
    cross_dir = SRC_DIR / "cross"
    if not cross_dir.is_dir():
        return 0
    if zig is None:
        sys.exit("build_fixtures: zig is required for cross lanes")
    failures = 0
    out_root = OUT_ROOT / "cross"
    for name, target, extra, src_stem, out_stem in CROSS_LANES:
        src = cross_dir / f"{src_stem}.c"
        if not src.exists():
            print(f"skip {name}: {src.name} missing")
            continue
        out_dir = out_root / name
        out_dir.mkdir(parents = True, exist_ok = True)
        exe = out_dir / out_stem
        static_flag = [] if target.endswith("-macos") else ["-static"]
        cmd = [zig, "cc", "-target", target, "-O2", "-s", *static_flag, "-fno-sanitize=all", *extra, "-o", str(exe), str(src)]
        proc = run(cmd)
        if proc.returncode != 0:
            failures += 1
            print(f"FAIL cross/{name}\n{proc.stderr.strip()}")
        else:
            print(f"ok   cross/{name}/{out_stem} ({exe.stat().st_size} B)")
    return failures


LUA_VERSIONS = ["5.4.7", "5.3.6", "5.1.5"]

def build_lua(zig: str | None) -> int:
    """Build the official Lua releases as ELF shared libraries under fixtures/generated/lua/.

    Each release is a different answer to "what does the Lua C API export". The 5.4
    table is checked against 5.4; the version-absence list is checked against all three.
    Sources are the official tarballs from lua.org (each under 400 KB), unpacked once
    into a cache directory and never committed.
    """
    if zig is None:
        sys.exit("build_fixtures: zig is required for the lua lane")
    cache = OUT_ROOT / "_lua-src"
    out_root = OUT_ROOT / "lua"
    failures = 0
    for version in LUA_VERSIONS:
        stem = f"lua-{version}"
        src_dir = cache / stem / "src"
        if not src_dir.exists():
            cache.mkdir(parents = True, exist_ok = True)
            tarball = cache / f"{stem}.tar.gz"
            if not tarball.exists():
                url = f"https://www.lua.org/ftp/{stem}.tar.gz"
                print(f"fetch {url}")
                with urllib.request.urlopen(url, timeout = 60) as response:
                    tarball.write_bytes(response.read())
            with tarfile.open(tarball) as archive:
                archive.extractall(cache, filter = "data")
        out = out_root / f"liblua-{version}.so"
        out.parent.mkdir(parents = True, exist_ok = True)
        sources = sorted(p.name for p in src_dir.glob("*.c") if not p.name.startswith("lua"))
        cmd = [zig, "cc", "-target", "x86_64-linux-musl", "-O2", "-fPIC", "-shared", "-DLUA_USE_LINUX", "-o", str(out)] + [str(src_dir / name) for name in sources] + ["-lm"]
        proc = run(cmd)
        if proc.returncode != 0:
            failures += 1
            print(f"FAIL lua/{version}\n{proc.stderr.strip()[-400:]}")
        else:
            print(f"ok   lua/liblua-{version}.so ({out.stat().st_size} B)")
    return failures


def smoke_run(targets: list[str], opt_levels: list[str], wine: str | None) -> int:
    failures = 0
    native_windows = os.name == "nt"

    for target in targets:
        is_windows = is_windows_target(target)

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

                # Windows 只执行 .exe；PDB/obj/lib/ilk 等伴生产物不是夹具程序。
                if is_windows and exe.suffix.lower() != ".exe":
                    continue
                if not is_windows and exe.suffix == ".pdb":
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

    needs_zig = any(not target.endswith("-windows-msvc") for target in args.targets)
    zig = find_zig(args.zig) if needs_zig else None
    if zig:
        ver = run([zig, "version"]).stdout.strip()
        print(f"# zig {ver} @ {zig}")
    opt_levels = OPT_LEVELS if args.opt == "all" else [args.opt]

    failures = build_all(zig, args.targets, opt_levels)
    # Shared libraries are built for every lane: they are never run, so they cost
    # only the compile, and export-table consumers need them per target.
    failures += build_shared(zig, args.targets, opt_levels)
    failures += build_cross(zig)
    failures += build_lua(zig)

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

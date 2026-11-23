#!/usr/bin/env python3
"""Cross-check kotama's function discovery against an IDA headless listing.

IDA is an external, independently installed tool. This script launches idat.exe
on an owned PE fixture, exports its function list to a temporary database, and
compares RVA/size facts with kotama's own analyze JSON. It is Windows-only and
opt-in: the repository never links or vendors IDA.
"""

from __future__ import annotations
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_IMAGE = REPO / "fixtures/generated/x86_64-windows-msvc/-O0/loops.exe"
ANCHORS = ("sum_squares", "count_down", "main", "mainCRTStartup")


def find_ida(override: str | None) -> str:
    candidates = [override] if override else []
    candidates.append(os.environ.get("KOTAMA_IDA", ""))
    candidates.append(shutil.which("idat.exe") or "")
    candidates.append(shutil.which("idat64.exe") or "")
    for candidate in candidates:
        if candidate and pathlib.Path(candidate).is_file():
            return candidate
    raise SystemExit("ida_crosscheck: set KOTAMA_IDA or pass --ida <idat.exe>")


def run(command: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output = True, text = True, **kw)


def parse_ida(path: pathlib.Path) -> dict[int, tuple[str, int]]:
    out = {}
    for line in path.read_text(encoding = "utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        out[int(fields[0])] = (fields[1], int(fields[2]) if len(fields) > 2 else 0)
    return out


def parse_kotama(text: str) -> dict[int, tuple[str, int]]:
    data = json.loads(text)
    return {
        int(function["rva"], 16): (function.get("name") or "", int(function.get("size") or 0))
        for function in data.get("functions", [])
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog = "ida_crosscheck")
    parser.add_argument("--image", type = pathlib.Path, default = DEFAULT_IMAGE)
    parser.add_argument("--ida", help = "path to idat.exe (or set KOTAMA_IDA)")
    args = parser.parse_args()
    if sys.platform != "win32":
        raise SystemExit("ida_crosscheck: IDA headless lane requires Windows")
    image = args.image.resolve()
    if not image.is_file():
        raise SystemExit(f"missing fixture: {image}; run tools/build_fixtures.py --targets x86_64-windows-msvc --run")
    ida = find_ida(args.ida)
    script = REPO / "support/ida/KotamaFunctionList.py"

    with tempfile.TemporaryDirectory(prefix = "kotama-ida-") as temp:
        temp_dir = pathlib.Path(temp)
        listing = temp_dir / "functions.txt"
        database = temp_dir / "analysis.i64"
        log = temp_dir / "ida.log"
        env = os.environ.copy()
        env["KOTAMA_IDA_OUT"] = str(listing)
        command = [
            ida, "-A", f"-S{script}", f"-o{database}", f"-L{log}", str(image),
        ]
        print("+ " + " ".join(command), flush = True)
        completed = subprocess.run(command, cwd = temp_dir, env = env, capture_output = True, text = True, timeout = 600)
        if completed.returncode != 0 or not listing.is_file():
            print(completed.stdout)
            print(completed.stderr)
            if log.is_file():
                print(log.read_text(encoding = "utf-8", errors = "replace")[-4000:])
            return 1
        theirs = parse_ida(listing)

    analyzed = run(
        ["cargo", "run", "--quiet", "-p", "kotama-cli", "--", "analyze", str(image)],
        cwd = REPO,
    )
    if analyzed.returncode != 0:
        print(analyzed.stdout + analyzed.stderr)
        return 1
    ours = parse_kotama(analyzed.stdout)

    matched = len(set(ours) & set(theirs))
    union = len(set(ours) | set(theirs))
    jaccard = matched / union if union else 1.0
    print(f"ida={len(theirs)} kotama={len(ours)} matched={matched} jaccard={jaccard:.6f}")

    failures = 0
    if jaccard < 0.90:
        failures += 1
        print(f"FAIL: RVA agreement below 0.90; only_ida={sorted(set(theirs) - set(ours))[:20]} only_kotama={sorted(set(ours) - set(theirs))[:20]}")
    for name in ANCHORS:
        mine = sorted((rva, size) for rva, (symbol, size) in ours.items() if symbol == name)
        reference = sorted((rva, size) for rva, (symbol, size) in theirs.items() if symbol == name)
        if mine != reference or not mine:
            failures += 1
            print(f"FAIL: anchor {name}: kotama={mine} ida={reference}")
    if failures:
        print(f"ida-crosscheck: {failures} failure(s)")
        return 1
    print("ida-crosscheck: all green")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

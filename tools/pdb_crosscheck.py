#!/usr/bin/env python3
"""Cross-check kotama's pdb-crate lane against the system dbghelp oracle.

Runs the owned MSVC fixture through both tools and requires the function RVA
sets to agree closely, with exact agreement on a few named anchor functions.
This is a Windows bench test: the production parser never links dbghelp.
"""

from __future__ import annotations
import argparse
import json
import pathlib
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_IMAGE = REPO / "fixtures/generated/x86_64-windows-msvc/-O0/loops.exe"
ANCHORS = ("sum_squares", "count_down", "main", "mainCRTStartup")


def run(command: list[str]) -> subprocess.CompletedProcess:
    print("+ " + " ".join(command), flush = True)
    return subprocess.run(command, cwd = REPO, capture_output = True, text = True)


def parse_kotama(text: str) -> dict[int, tuple[str, int]]:
    data = json.loads(text)
    return {
        int(function["rva"], 16): (function.get("name") or "", int(function.get("size") or 0))
        for function in data.get("functions", [])
    }


def parse_dbghelp(path: pathlib.Path) -> dict[int, tuple[str, int]]:
    out = {}
    for line in path.read_text(encoding = "utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        out[int(fields[0])] = (fields[1].rstrip("\x00"), int(fields[2]) if len(fields) > 2 else 0)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(prog = "pdb_crosscheck")
    parser.add_argument("--image", type = pathlib.Path, default = DEFAULT_IMAGE)
    args = parser.parse_args()
    if sys.platform != "win32":
        raise SystemExit("pdb cross-check requires Windows")
    image = args.image.resolve()
    if not image.is_file():
        raise SystemExit(f"missing fixture: {image}; run tools/build_fixtures.py --targets x86_64-windows-msvc --run")

    with tempfile.TemporaryDirectory(prefix = "kotama-pdb-") as temp:
        listing = pathlib.Path(temp) / "dbghelp.txt"
        dbghelp = run([sys.executable, "tools/dbghelp_symbols.py", str(image), str(listing)])
        if dbghelp.returncode != 0:
            print(dbghelp.stdout + dbghelp.stderr)
            return 1
        analyzed = run(["cargo", "run", "--quiet", "-p", "kotama-cli", "--", "analyze", str(image)])
        if analyzed.returncode != 0:
            print(analyzed.stdout + analyzed.stderr)
            return 1
        ours = parse_kotama(analyzed.stdout)
        theirs = parse_dbghelp(listing)

    matched = len(set(ours) & set(theirs))
    union = len(set(ours) | set(theirs))
    jaccard = matched / union if union else 1.0
    print(f"dbghelp={len(theirs)} kotama={len(ours)} matched={matched} jaccard={jaccard:.6f}")

    failures = 0
    if jaccard < 0.99:
        failures += 1
        print(f"FAIL: RVA agreement below 0.99; only_dbghelp={sorted(set(theirs) - set(ours))[:20]} only_kotama={sorted(set(ours) - set(theirs))[:20]}")
    for name in ANCHORS:
        mine = [(rva, size) for rva, (symbol, size) in ours.items() if symbol == name]
        reference = [(rva, size) for rva, (symbol, size) in theirs.items() if symbol == name]
        if mine != reference or not mine:
            failures += 1
            print(f"FAIL: anchor {name}: kotama={mine} dbghelp={reference}")
    if failures:
        print(f"pdb-crosscheck: {failures} failure(s)")
        return 1
    print("pdb-crosscheck: all green")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

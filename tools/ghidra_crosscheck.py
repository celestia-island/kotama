#!/usr/bin/env python3
"""Run the real Ghidra differential on a PDB-less copy of an owned fixture.

Ghidra is an external headless process. This script copies the fixture into a
temporary directory WITHOUT its companion PDB, runs the CLI oracle command on
that copy, and asserts the reported Jaccard between kotama's function discovery
and Ghidra's function list. Windows-only and opt-in; no Ghidra libraries are
linked or vendored.
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
DEFAULT_IMAGE = REPO / "fixtures/generated/x86_64-windows-gnu/-O2/loops.exe"
MIN_JACCARD = 0.95


def main() -> int:
    parser = argparse.ArgumentParser(prog = "ghidra_crosscheck")
    parser.add_argument("--image", type = pathlib.Path, default = DEFAULT_IMAGE)
    parser.add_argument("--min-jaccard", type = float, default = MIN_JACCARD)
    args = parser.parse_args()
    if sys.platform != "win32":
        raise SystemExit("ghidra_crosscheck: Ghidra headless lane requires Windows")
    image = args.image.resolve()
    if not image.is_file():
        raise SystemExit(f"missing fixture: {image}; run tools/build_fixtures.py --run")

    with tempfile.TemporaryDirectory(prefix = "kotama-ghidra-") as temp:
        temp_dir = pathlib.Path(temp)
        image_copy = temp_dir / image.name
        shutil.copy2(image, image_copy)
        if any(temp_dir.glob("*.pdb")):
            raise SystemExit("ghidra_crosscheck: temporary copy unexpectedly contains a PDB")
        command = [
            "cargo", "run", "--quiet", "-p", "kotama-cli", "--", "oracle", str(image_copy),
        ]
        print("+ " + " ".join(command), flush = True)
        completed = subprocess.run(
            command, cwd = REPO, capture_output = True, text = True, timeout = 1200,
        )
        if completed.returncode != 0:
            print(completed.stdout)
            print(completed.stderr)
            return 1
        report = json.loads(completed.stdout)

    ours = int(report["ours"])
    theirs = int(report["ghidra"])
    matched = int(report["matched"])
    jaccard = float(report["jaccard"])
    print(
        f"ghidra={theirs} kotama={ours} matched={matched} jaccard={jaccard:.6f} pdb=none"
    )
    failures = 0
    if jaccard < args.min_jaccard:
        failures += 1
        print(f"FAIL: Jaccard below {args.min_jaccard}")
    if matched < min(ours, theirs) * args.min_jaccard:
        failures += 1
        print("FAIL: matched count is inconsistent with the Jaccard floor")
    if failures:
        print(f"ghidra-crosscheck: {failures} failure(s)")
        return 1
    print("ghidra-crosscheck: all green (PDB-less differential)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

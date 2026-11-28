#!/usr/bin/env python3
"""Refresh dist/ from current source: the C agents and the Rust payload.

Nothing else does. build_windows_agent.py writes dist/ but nothing calls it on a
change; cargo writes target/<triple>/release/ but nothing copies it to dist/;
and bench-windows only checks the files exist. So the live e2e can pass against
a payload built days before the source it is testing — it did, for three days.

Run by `just dist-refresh`, then the live e2e (`KOTAMA_LIVE_E2E=1`). Prints the
hash of each artefact so two runs can be compared.
"""

from __future__ import annotations
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ZIG = os.environ.get("KOTAMA_ZIG") or "zig"
# (zig target for the C agent, dist directory = Rust triple)
AGENTS = (("x86_64-windows-gnu", "x86_64-pc-windows-gnu"), ("x86-windows-gnu", "i686-pc-windows-gnu"))
PAYLOAD = ("x86_64-pc-windows-msvc", "release")


def run(command: list[str]) -> None:
    proc = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        sys.exit(f"dist-refresh: {' '.join(command)} failed:\n{proc.stdout[-400:]}{proc.stderr[-400:]}")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def main() -> int:
    for zig_target, dist_dir in AGENTS:
        run([sys.executable, str(REPO / "tools" / "build_windows_agent.py"), "--target", zig_target])
    triple, profile = PAYLOAD
    run(["cargo", "build", "-q", "-p", "kotama-payload", "--target", triple, "--" + profile])
    built = REPO / "target" / triple / profile / "kotama_payload.dll"
    if not built.is_file():
        sys.exit(f"dist-refresh: cargo did not produce {built}")
    (REPO / "dist" / triple).mkdir(parents=True, exist_ok=True)
    shutil.copy2(built, REPO / "dist" / triple / "kotama_payload.dll")
    print("dist refreshed from current source:")
    for path in sorted((REPO / "dist").rglob("*.dll")):
        if path.parent.name in {d for _, d in AGENTS} | {PAYLOAD[0]}:
            print(f"  {path.relative_to(REPO)}  {sha(path)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

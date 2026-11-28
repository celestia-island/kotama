#!/usr/bin/env python3
"""Prove the fixture lanes are byte-reproducible: build twice, hash between.

A test that reads a fixture is only as reproducible as the fixture. If two builds
of the same source differ — a timestamp in a PDB, a build ID, an embedded path —
then a test that passed yesterday is passing on different bytes today, and
"reproducible" is a word rather than a fact. This builds the lanes twice through
`build_fixtures.py` and asserts every produced file hashes the same both times.

Run by `just fixture-repro`. It is not in `gate`: it rebuilds every lane twice,
which is minutes, and the fixture directory is shared between worktrees.
"""

from __future__ import annotations
import hashlib
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
LANES = ["cross", "lua", "shared", "x86_64-linux-gnu", "x86_64-windows-gnu"]
# The MSVC lane: its .obj and .pdb carry a fresh debug GUID per build by design,
# so only the .exe — the thing every PE test reads — is held to byte identity.
MSVC_LANE = "x86_64-windows-msvc"
MSVC_SUFFIX = ".exe"
BUILD_ARGS = ["--targets", "x86_64-linux-gnu", "x86_64-windows-gnu", "x86_64-windows-msvc", "--opt", "O2"]


def snapshot(root: pathlib.Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for lane in [*LANES, MSVC_LANE]:
        base = root / lane
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or "_lua-src" in path.parts:
                continue
            if lane == MSVC_LANE and path.suffix != MSVC_SUFFIX:
                continue
            data = path.read_bytes()
            if lane == MSVC_LANE:
                data = mask_pdb_age(data)
            out[str(path.relative_to(root))] = hashlib.sha256(data).hexdigest()
    return out


def mask_pdb_age(data: bytes) -> bytes:
    """Zero the 4-byte PDB age inside the PE debug directory's RSDS record.

    The MSVC linker increments the age on every link — by design, so a debugger
    can tell a stale PDB from a fresh one — and writes it into both the PDB and
    the PE. It is the only byte that differs between two `/Brepro` builds of the
    same source; everything else, timestamp and debug GUID included, is already
    content-derived. Masking it lets the check assert what is actually
    reproducible instead of failing forever on a counter that is meant to move.
    """
    rsds = data.find(b"RSDS")
    if rsds == -1 or rsds + 24 > len(data):
        return data
    masked = bytearray(data)
    masked[rsds + 20 : rsds + 24] = bytes(4)
    return bytes(masked)


def build() -> int:
    return subprocess.run(
        [sys.executable, str(HERE / "build_fixtures.py"), *BUILD_ARGS],
        cwd=REPO, capture_output=True,
    ).returncode


def main() -> int:
    if build() != 0:
        print("FAIL first build")
        return 1
    first = snapshot(REPO / "fixtures" / "generated")
    if build() != 0:
        print("FAIL second build")
        return 1
    second = snapshot(REPO / "fixtures" / "generated")
    if first.keys() != second.keys():
        only1 = sorted(first.keys() - second.keys())
        only2 = sorted(second.keys() - first.keys())
        print(f"FAIL file set differs: only-first={only1[:5]} only-second={only2[:5]}")
        return 1
    differing = sorted(name for name in first if first[name] != second[name])
    if differing:
        print(f"FAIL {len(differing)} of {len(first)} files differ between two builds:")
        for name in differing[:10]:
            print(f"  {name}")
        return 1
    print(f"ok   {len(first)} fixture files byte-identical across two builds")
    return 0


if __name__ == "__main__":
    sys.exit(main())

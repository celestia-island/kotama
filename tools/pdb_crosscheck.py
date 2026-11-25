#!/usr/bin/env python3
"""Cross-check kotama's pdb-crate lane against the system dbghelp oracle.

Runs the owned MSVC fixture through both tools and requires the function RVA
sets to agree closely, with exact agreement on a few named anchor functions.
This is a Windows bench test: the production parser never links dbghelp.

The PDB procedure table never lists linker-generated jump thunks (import
trampolines `jmp [slot]` and `jmp rel` stubs), yet they are real executable
entries and kotama reports them. Entries that only kotama reports are therefore
excused when their first bytes have exactly that shape and the byte after the
stub is padding (or the next entry is the following thunk of an array);
everything else still has to clear the 0.99 Jaccard bar.
"""

from __future__ import annotations
import argparse
import json
import pathlib
import struct
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_IMAGE = REPO / "fixtures/generated/x86_64-windows-msvc/-O0/loops.exe"
ANCHORS = ("sum_squares", "count_down", "main", "mainCRTStartup")
PADDING = (b"\xcc", b"\x90", b"\x00")
THUNK_SHAPES = ((b"\xff\x25", 6), (b"\xe9", 5), (b"\xeb", 2))


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


def image_sections(image: pathlib.Path) -> tuple[bytes, list[tuple[int, int, int, int]]]:
    """Return the file bytes plus (virtual address, extent, raw pointer, raw size) per section."""
    data = image.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional = struct.unpack_from("<H", data, pe + 20)[0]
    table = pe + 24 + optional
    sections = []
    for index in range(count):
        offset = table + index * 40
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", data, offset + 8)
        sections.append((virtual_address, max(virtual_size, raw_size), raw_pointer, raw_size))
    return data, sections


def read_at(data: bytes, sections: list[tuple[int, int, int, int]], rva: int, length: int) -> bytes:
    """Read `length` bytes at `rva`; empty when the range is not backed by file data."""
    for virtual_address, extent, raw_pointer, raw_size in sections:
        if virtual_address <= rva < virtual_address + extent:
            offset = rva - virtual_address
            if offset + length > raw_size:
                return b""
            start = raw_pointer + offset
            return data[start : start + length]
    return b""


def classify_extras(
    extras: list[int],
    ours: dict[int, tuple[str, int]],
    data: bytes,
    sections: list[tuple[int, int, int, int]],
) -> tuple[list[int], list[int]]:
    """Split kotama-only entries into linker thunks and unexplained ones."""
    thunks, unexplained = [], []
    for rva in extras:
        prefix = read_at(data, sections, rva, 6)
        shape = next(((pattern, length) for pattern, length in THUNK_SHAPES if prefix.startswith(pattern)), None)
        if shape is None:
            unexplained.append(rva)
            continue
        length = shape[1]
        following = read_at(data, sections, rva + length, 1)
        # A thunk is followed by padding, or by the next thunk of a contiguous array.
        if following in PADDING or (rva + length) in ours:
            thunks.append(rva)
        else:
            unexplained.append(rva)
    return thunks, unexplained


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

    data, sections = image_sections(image)
    thunks, unexplained = classify_extras(sorted(set(ours) - set(theirs)), ours, data, sections)
    filtered = set(ours) - set(thunks)
    matched = len(filtered & set(theirs))
    union = len(filtered | set(theirs))
    jaccard = matched / union if union else 1.0
    print(
        f"dbghelp={len(theirs)} kotama={len(ours)} linker_thunks={len(thunks)} "
        f"matched={matched} jaccard={jaccard:.6f}"
    )

    failures = 0
    if unexplained:
        failures += 1
        print(f"FAIL: {len(unexplained)} kotama-only entries are not linker thunks: {unexplained[:20]}")
    if jaccard < 0.99:
        failures += 1
        print(f"FAIL: RVA agreement below 0.99; only_dbghelp={sorted(set(theirs) - set(ours))[:20]}")
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

#!/usr/bin/env python3
"""Cross-check kotama's function discovery against an IDA headless listing.

IDA is an external, independently installed tool. This script copies the owned
PE fixture into a temporary directory WITHOUT its companion PDB, runs both
idat.exe and kotama analyze on that copy, and compares RVA/size facts. This
keeps the oracle independent of the PDB lane: no sidecar is visible to either
consumer, and the entry-point anchor comes from the PE header. Windows-only and
opt-in; the repository never links or vendors IDA.
"""

from __future__ import annotations
import argparse
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_IMAGE = REPO / "fixtures/generated/x86_64-windows-gnu/-O0/loops.exe"
MIN_JACCARD = 0.95


def find_ida(override: str | None) -> str:
    candidates = [override] if override else []
    candidates.append(os.environ.get("KOTAMA_IDA", ""))
    candidates.append(shutil.which("idat.exe") or "")
    candidates.append(shutil.which("idat64.exe") or "")
    for candidate in candidates:
        if candidate and pathlib.Path(candidate).is_file():
            return candidate
    raise SystemExit("ida_crosscheck: set KOTAMA_IDA or pass --ida <idat.exe>")


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


def parse_kotama(text: str) -> tuple[dict[int, tuple[str, int]], bool]:
    data = json.loads(text)
    functions = data.get("functions", [])
    pdb_evidence = bool(data.get("pdb")) or any(
        "pdb" in (function.get("evidence") or []) for function in functions
    )
    parsed = {
        int(function["rva"], 16): (function.get("name") or "", int(function.get("size") or 0))
        for function in functions
    }
    return parsed, pdb_evidence


def pe_entry_rva(image: pathlib.Path) -> int:
    data = image.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise SystemExit(f"not a PE image: {image}")
    optional = pe_offset + 4 + 20
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in (0x10B, 0x20B):
        raise SystemExit(f"unsupported PE optional-header magic {magic:#x}")
    return struct.unpack_from("<I", data, optional + 16)[0]


def covering(functions: dict[int, tuple[str, int]], rva: int) -> tuple[int, int] | None:
    for start, (_, size) in functions.items():
        if start <= rva < start + size:
            return start, size
    return None


def main() -> int:
    parser = argparse.ArgumentParser(prog = "ida_crosscheck")
    parser.add_argument("--image", type = pathlib.Path, default = DEFAULT_IMAGE)
    parser.add_argument("--ida", help = "path to idat.exe (or set KOTAMA_IDA)")
    args = parser.parse_args()
    if sys.platform != "win32":
        raise SystemExit("ida_crosscheck: IDA headless lane requires Windows")
    image = args.image.resolve()
    if not image.is_file():
        raise SystemExit(f"missing fixture: {image}; run tools/build_fixtures.py --run")
    ida = find_ida(args.ida)
    script = REPO / "support/ida/KotamaFunctionList.py"
    entry = pe_entry_rva(image)

    with tempfile.TemporaryDirectory(prefix = "kotama-ida-") as temp:
        temp_dir = pathlib.Path(temp)
        # Copy only the image: no companion PDB can leak into either consumer.
        image_copy = temp_dir / image.name
        shutil.copy2(image, image_copy)
        if any(temp_dir.glob("*.pdb")):
            raise SystemExit("ida_crosscheck: temporary copy unexpectedly contains a PDB")
        listing = temp_dir / "functions.txt"
        database = temp_dir / "analysis.i64"
        log = temp_dir / "ida.log"
        env = os.environ.copy()
        env["KOTAMA_IDA_OUT"] = str(listing)
        command = [
            ida, "-A", f"-S{script}", f"-o{database}", f"-L{log}", str(image_copy),
        ]
        print("+ " + " ".join(command), flush = True)
        completed = subprocess.run(command, cwd = temp_dir, env = env, capture_output = True, text = True, timeout = 600)
        if completed.returncode != 0 or not listing.is_file():
            print(completed.stdout)
            print(completed.stderr)
            if log.is_file():
                print(log.read_text(encoding = "utf-8", errors = "replace")[-4000:])
            return 1
        if not log.is_file():
            print("FAIL: IDA did not produce the -L log; refusing a vacuous PDB check")
            return 1
        ida_log = log.read_text(encoding = "utf-8", errors = "replace")
        if "PDB: loading" in ida_log or "PDB: loaded" in ida_log:
            print("FAIL: IDA loaded a PDB from the supposedly PDB-less copy")
            print(ida_log[-2000:])
            return 1
        theirs = parse_ida(listing)

        analyzed = subprocess.run(
            ["cargo", "run", "--quiet", "-p", "kotama-cli", "--", "analyze", str(image_copy)],
            cwd = REPO, capture_output = True, text = True,
        )
        if analyzed.returncode != 0:
            print(analyzed.stdout + analyzed.stderr)
            return 1
        ours, pdb_evidence = parse_kotama(analyzed.stdout)
        if pdb_evidence:
            print("FAIL: kotama consumed PDB evidence from the supposedly PDB-less copy")
            return 1

    matched = len(set(ours) & set(theirs))
    union = len(set(ours) | set(theirs))
    jaccard = matched / union if union else 1.0
    print(f"entry=0x{entry:x} ida={len(theirs)} kotama={len(ours)} matched={matched} jaccard={jaccard:.6f} pdb=none")

    failures = 0
    if jaccard < MIN_JACCARD:
        failures += 1
        print(f"FAIL: RVA agreement below {MIN_JACCARD}; only_ida={sorted(set(theirs) - set(ours))[:20]} only_kotama={sorted(set(ours) - set(theirs))[:20]}")
    mine_entry = covering(ours, entry)
    reference_entry = covering(theirs, entry)
    if mine_entry is None or reference_entry is None:
        failures += 1
        print(f"FAIL: entry RVA 0x{entry:x}: kotama={mine_entry} ida={reference_entry}")
    elif mine_entry != reference_entry:
        failures += 1
        print(f"FAIL: entry function size differs: kotama={mine_entry} ida={reference_entry}")
    if failures:
        print(f"ida-crosscheck: {failures} failure(s)")
        return 1
    print("ida-crosscheck: all green (PDB-less, entry anchor)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

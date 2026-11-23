#!/usr/bin/env python3
"""Windows dbghelp symbol oracle for the kotama PDB lane.

Loads an owned PE image with the system dbghelp DLL, enumerates CodeView
function symbols and writes "<rva-decimal>\t<name>\t<size>" so the result can be
compared with `pdb`-crate and IDA/Ghidra function lists. This is a test oracle,
not a production dependency: it only talks to the OS DLL and local PDB files.
"""

from __future__ import annotations
import argparse
import ctypes
from ctypes import wintypes
import pathlib
import struct
import sys

SYMOPT_UNDNAME = 0x00000002
SYMOPT_DEFERRED_LOADS = 0x00000004
SYMOPT_LOAD_LINES = 0x00000010
SYM_TAG_FUNCTION = 5


class SymbolInfoW(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.ULONG),
        ("TypeIndex", wintypes.ULONG),
        ("Reserved", ctypes.c_ulonglong * 2),
        ("Index", wintypes.ULONG),
        ("Size", wintypes.ULONG),
        ("ModBase", ctypes.c_ulonglong),
        ("Flags", wintypes.ULONG),
        ("Value", ctypes.c_ulonglong),
        ("Address", ctypes.c_ulonglong),
        ("Register", wintypes.ULONG),
        ("Scope", wintypes.ULONG),
        ("Tag", wintypes.ULONG),
        ("NameLen", wintypes.ULONG),
        ("MaxNameLen", wintypes.ULONG),
        ("Name", wintypes.WCHAR * 1),
    ]


def pe_facts(path: pathlib.Path) -> tuple[int, int, int]:
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise SystemExit(f"{path}: not a PE")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\0\0":
        raise SystemExit(f"{path}: bad PE signature")
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    optional = pe + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
        size_of_image = struct.unpack_from("<I", data, optional + 56)[0]
    elif magic == 0x10B:
        image_base = struct.unpack_from("<I", data, optional + 28)[0]
        size_of_image = struct.unpack_from("<I", data, optional + 56)[0]
    else:
        raise SystemExit(f"{path}: unknown optional header magic {magic:#x}")
    return machine, image_base, size_of_image


def load_dbghelp():
    if sys.platform != "win32":
        raise SystemExit("dbghelp oracle requires Windows")
    dbghelp = ctypes.WinDLL("dbghelp.dll")
    dbghelp.SymSetOptions.argtypes = [wintypes.DWORD]
    dbghelp.SymSetOptions.restype = wintypes.DWORD
    dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
    dbghelp.SymInitializeW.restype = wintypes.BOOL
    dbghelp.SymLoadModuleExW.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_ulonglong,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    dbghelp.SymLoadModuleExW.restype = ctypes.c_ulonglong
    dbghelp.SymEnumSymbolsW.argtypes = [
        wintypes.HANDLE,
        ctypes.c_ulonglong,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    dbghelp.SymEnumSymbolsW.restype = wintypes.BOOL
    dbghelp.SymCleanup.argtypes = [wintypes.HANDLE]
    dbghelp.SymCleanup.restype = wintypes.BOOL
    return dbghelp


def main() -> int:
    parser = argparse.ArgumentParser(prog = "dbghelp_symbols")
    parser.add_argument("image", type = pathlib.Path)
    parser.add_argument("output", type = pathlib.Path)
    args = parser.parse_args()

    image = args.image.resolve()
    if not image.is_file():
        raise SystemExit(f"missing image: {image}")
    machine, image_base, size_of_image = pe_facts(image)
    architecture = {0x8664: "x64", 0x14C: "x86"}.get(machine, hex(machine))
    print(f"# dbghelp image {image} arch={architecture} base={image_base:#x} size={size_of_image:#x}")

    dbghelp = load_dbghelp()
    process = ctypes.c_void_p(-1)  # GetCurrentProcess() pseudo-handle
    dbghelp.SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES)
    if not dbghelp.SymInitializeW(process, str(image.parent), False):
        raise SystemExit(f"SymInitializeW failed: {ctypes.WinError()}")
    loaded = dbghelp.SymLoadModuleExW(
        process, None, str(image), None, image_base, size_of_image, None, 0
    )
    if not loaded:
        dbghelp.SymCleanup(process)
        raise SystemExit(f"SymLoadModuleExW failed: {ctypes.WinError()}")

    rows: list[tuple[int, str, int]] = []
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.POINTER(SymbolInfoW), wintypes.ULONG, ctypes.c_void_p)

    def on_symbol(symbol_ptr, _size, _context):
        symbol = symbol_ptr.contents
        if symbol.Tag != SYM_TAG_FUNCTION or not symbol.Address:
            return True
        name_at = ctypes.addressof(symbol) + SymbolInfoW.Name.offset
        name = ctypes.wstring_at(name_at, symbol.NameLen) if symbol.NameLen else ctypes.wstring_at(name_at)
        rva = int(symbol.Address) - image_base
        if rva >= 0:
            rows.append((rva, name, int(symbol.Size)))
        return True

    callback = callback_type(on_symbol)
    try:
        if not dbghelp.SymEnumSymbolsW(process, loaded, None, ctypes.cast(callback, ctypes.c_void_p), None):
            raise SystemExit(f"SymEnumSymbolsW failed: {ctypes.WinError()}")
    finally:
        dbghelp.SymCleanup(process)

    rows = sorted(set(rows))
    args.output.parent.mkdir(parents = True, exist_ok = True)
    with args.output.open("w", encoding = "utf-8", newline = "\n") as out:
        out.write("# rva-decimal\tname\tsize\n")
        for rva, name, size in rows:
            out.write(f"{rva}\t{name}\t{size}\n")
    print(f"# dbghelp wrote {len(rows)} functions to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

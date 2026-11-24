#!/usr/bin/env python3
"""IDA headless function exporter for the kotama differential oracle.

Run through idat.exe:  -A -S<this file>  and read the output path from
KOTAMA_IDA_OUT. The format is the same RVA/name/size TSV used by the IDA
cross-check and the dbghelp oracle: decimal RVA, name, byte size.

This is an independent-process oracle only: no IDA libraries are linked or
vendored, and the repository does not depend on IDA to build or test.
"""

import os

import ida_auto
import ida_funcs
import idaapi
import idautils
import idc

ida_auto.auto_wait()
out_path = os.environ["KOTAMA_IDA_OUT"]
image_base = idaapi.get_imagebase()
count = 0
with open(out_path, "w", encoding = "utf-8", newline = "\n") as out:
    out.write("# rva-decimal\tname\tsize\n")
    for address in idautils.Functions():
        function = ida_funcs.get_func(address)
        name = ida_funcs.get_func_name(address) or ""
        size = (function.end_ea - function.start_ea) if function else 0
        out.write(f"{address - image_base}\t{name}\t{size}\n")
        count += 1
print(f"Kotama IDA oracle: wrote {count} functions to {out_path}")
idc.qexit(0)

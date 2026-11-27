#!/usr/bin/env python3
"""Self-test for genericity_scan.py: it must catch what the rule forbids and spare
what the rule allows. Run by `just genericity` so a broken scanner cannot pass silently."""

from __future__ import annotations
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
SCANNER = HERE / "genericity_scan.py"
# Assembled at run time so this file does not carry the names it tests for.
PRODUCT = "Red" + " Alert"
STUDIO = "Pop" + "Cap"


def run(root: pathlib.Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(SCANNER), "--root", str(root)],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return proc.returncode, proc.stdout


def main() -> int:
    failures = 0

    def check(name: str, condition: bool, detail: str = "") -> None:
        nonlocal failures
        if condition:
            print(f"ok   {name}")
        else:
            failures += 1
            print(f"FAIL {name} {detail}")

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="kotama-genericity-"))
    try:
        (tmp / "lib.rs").write_text("fn f() { let l = \"" + PRODUCT + "\"; }", encoding="utf-8")
        rc, out = run(tmp)
        check("product name in a source file is caught", rc == 1 and PRODUCT.split()[0] in out, out)

        (tmp / "lib.rs").unlink()
        allowed = tmp / "examples" / "engine-formats"
        allowed.mkdir(parents=True)
        (allowed / "x.rs").write_text("// " + PRODUCT, encoding="utf-8")
        rc, out = run(tmp)
        check("the same name under examples/engine-formats is allowed", rc == 0, out)

        (allowed / "x.rs").unlink()
        (tmp / "lib.rs").write_text("// DDS, TGA, SWF, ELF, PE, Mach-O", encoding="utf-8")
        rc, out = run(tmp)
        check("generic format words are not flagged", rc == 0, out)

        (tmp / "lib.rs").write_text("// from a " + STUDIO + " note", encoding="utf-8")
        rc, out = run(tmp)
        check("a studio name in a comment is caught", rc == 1 and STUDIO in out, out)

        (tmp / "lib.rs").write_text("// general registers and flags", encoding="utf-8")
        rc, out = run(tmp)
        check("ordinary English is not flagged", rc == 0, out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

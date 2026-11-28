#!/usr/bin/env python3
"""Self-test for mutate.py: every guard must fire on the shape it exists for.

The engine's four guards each answer to a wrong number that was once reported as
a right one. This builds a throwaway cargo project — one function, one test —
and drives the engine through each guard against it, so a broken guard cannot
pass silently. Run by `just mutate-selftest`.
"""

from __future__ import annotations
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ENGINE = HERE / "mutate.py"

LIB_RS = """pub fn double(x: u32) -> u32 {
    x * 2
}

#[cfg(test)]
mod tests {
    #[test]
    fn doubles() {
        assert_eq!(super::double(21), 42);
    }
}
"""

CARGO_TOML = """[package]
name = "mutate-selftest-probe"
version = "0.1.0"
edition = "2021"
"""


def make_project(root: pathlib.Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "Cargo.toml").write_text(CARGO_TOML, encoding="utf-8")
    (root / "src" / "lib.rs").write_text(LIB_RS, encoding="utf-8", newline="\n")


def write_spec(root: pathlib.Path, test: list[str], mutations: list[dict]) -> pathlib.Path:
    # root must be explicit: the probe project is not the one the engine lives in.
    spec = {"root": str(root), "test": test, "files": {"lib": "src/lib.rs"}, "mutations": mutations}
    path = root / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


def run(spec: pathlib.Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(ENGINE), str(spec)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
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

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="kotama-mutate-"))
    try:
        make_project(tmp)
        lib = tmp / "src" / "lib.rs"
        original = lib.read_bytes()

        # A mutation the test must catch.
        caught = write_spec(tmp, [], [{"name": "double becomes identity", "find": "    x * 2", "repl": "    x"}])
        code, out = run(caught)
        check("a caught mutant exits 0 and reports CAUGHT", code == 0 and "CAUGHT" in out, f"{code} {out}")
        check("the file is restored byte for byte", lib.read_bytes() == original)

        # A mutation the test cannot see: the engine must say MISSED and exit 1.
        survived = write_spec(tmp, [], [{"name": "unobserved change", "find": "pub fn double", "repl": "pub fn doubled"}])
        lib.write_text(LIB_RS.replace("assert_eq!(super::double(21), 42);", "assert_eq!(1, 1);"), encoding="utf-8")
        code, out = run(survived)
        check("a surviving mutant exits 1 and reports MISSED", code == 1 and "MISSED" in out, f"{code} {out}")
        lib.write_bytes(original)

        # An anchor that is not there: ANCHOR, not MISSED, and never exit 0.
        missing = write_spec(tmp, [], [{"name": "no such anchor", "find": "THIS IS NOT IN THE FILE", "repl": ""}])
        code, out = run(missing)
        check("a missing anchor reports ANCHOR and does not exit 0", code != 0 and "ANCHOR n=0" in out, f"{code} {out}")

        # A red baseline: the engine must refuse before mutating anything.
        broken = write_spec(tmp, [], [{"name": "never applied", "find": "    x * 2", "repl": "    x"}])
        lib.write_text(LIB_RS.replace("x * 2", "x * 2 +"), encoding="utf-8")
        code, out = run(broken)
        check("a red baseline is refused with exit 3", code == 3, f"{code} {out}")
        lib.write_bytes(original)

        # A selection that matches no test: cargo exits 0, so the engine must
        # count tests rather than trust the exit code.
        zero = write_spec(tmp, ["--", "no_such_test_anywhere"], [{"name": "never applied", "find": "    x * 2", "repl": "    x"}])
        code, out = run(zero)
        check("a zero-test baseline is refused with exit 4", code == 4, f"{code} {out}")
        check("a refused baseline leaves the file untouched", lib.read_bytes() == original)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

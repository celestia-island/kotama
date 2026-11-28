#!/usr/bin/env python3
"""Self-test for engine_survey.py's verdict logic, on fixtures rather than the
network. The three distinctions the survey makes are each pinned on a made-up
directory: a real engine ABI, hook-only exports, and a pure Rust API."""

from __future__ import annotations
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import engine_survey  # noqa: E402


def make(tmp: pathlib.Path, name: str, manifest: str, source: str) -> pathlib.Path:
    crate = tmp / name
    crate.mkdir()
    (crate / "Cargo.toml").write_text(manifest, encoding="utf-8")
    (crate / "lib.rs").write_text(source, encoding="utf-8")
    return crate


def main() -> int:
    failures = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
        failures += 0 if ok else 1

    with tempfile.TemporaryDirectory(prefix="kotama-survey-test-") as raw:
        tmp = pathlib.Path(raw)
        # An engine-shaped ABI: exported names that are not infrastructure.
        engine = make(tmp, "engine", '[package]\nname = "engine"\n[lib]\ncrate-type = ["cdylib"]\n', '''
            #[no_mangle] pub extern "C" fn engine_eval(x: i32) -> i32 { x }
            #[no_mangle] pub extern "C" fn engine_gc() {}
        ''')
        cdylib, externs, exported = engine_survey.c_abi_evidence(engine)
        check("an engine ABI is mountable", engine_survey.verdict("MIT", cdylib, externs, exported).startswith("mountable: 2"), engine_survey.verdict("MIT", cdylib, externs, exported))
        check("cdylib is seen in the manifest", cdylib)
        # Hook-only exports: the rune shape.
        hooks = make(tmp, "hooks", '[package]\nname = "hooks"\n', '''
            #[no_mangle] extern "C" fn __x_alloc_take(n: usize) -> bool { n > 0 }
            #[no_mangle] extern "C" fn __x_budget_get() -> usize { 0 }
        ''')
        cdylib, externs, exported = engine_survey.c_abi_evidence(hooks)
        v = engine_survey.verdict("MIT", cdylib, externs, exported)
        check("hook-only exports are not an engine ABI", v.startswith("cdylib hooks only"), v)
        # A pure Rust API with FFI declarations (extern "C" blocks, no exports).
        pure = make(tmp, "pure", '[package]\nname = "pure"\n', '''
            extern "C" { fn strlen(s: *const u8) -> usize; }
            pub fn len(s: &[u8]) -> usize { 0 }
        ''')
        cdylib, externs, exported = engine_survey.c_abi_evidence(pure)
        v = engine_survey.verdict("MIT", cdylib, externs, exported)
        check("FFI declarations without exports are embeddable only", v == "embeddable, not mountable", v)
        check("an extern block still counts as extern-C", externs == 1, str(externs))
        # Licences: OR is permissive if a side is; the allow-list is deny.toml's.
        check("MIT OR Apache-2.0 is allowed", not engine_survey.verdict("MIT OR Apache-2.0", False, 0, []).startswith("out"))
        check("a copyleft licence is out", engine_survey.verdict("GPL-3.0", False, 0, []).startswith("out: licence"))
        check("the allow-list is read from deny.toml", "Apache-2.0 WITH LLVM-exception" in engine_survey.ALLOWED, str(engine_survey.ALLOWED))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

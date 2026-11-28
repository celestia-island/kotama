#!/usr/bin/env python3
"""Survey the Rust-ecosystem script engines a runtime mount could target.

The question for each candidate is narrow: does it expose a C ABI a hook
planner can address by exported symbol? A pure-Rust API (trait methods,
generics) is not mountable by the means this project has — there is no symbol
to intercept — so the survey reports what each crate *exports*, not what it
*implements*.

For every candidate it records: version and licence from crates.io, whether
the crate declares cdylib, and how many `extern "C"` entry points its source
holds together with whether `#[no_mangle]` appears. Verdicts:

  - mountable: extern "C" + no_mangle present (a symbol table exists)
  - cdylib, no extern-C seen: it links as a library but exports nothing C-shaped
  - embeddable, not mountable: a Rust API only
  - out: licence: copyleft, regardless of ABI

Output is a Markdown table on stdout. `just engine-survey` refreshes it; the
crates.io step needs the network and each crate is fetched once into the local
registry cache.
"""

from __future__ import annotations
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import urllib.request

CANDIDATES = [
    "quickjs",
    "quickjs_runtime",
    "quickjs-oxide",
    "deft-quick-js",
    "mlua",
    "rhai",
    "rune",
    "koto",
    "wasmtime",
]

CRATES_IO = "https://crates.io/api/v1/crates/{name}"
LAST_RESOLUTION_NOTE = ""
HERE = pathlib.Path(__file__).resolve().parent.parent


def allowed_licences() -> set[str]:
    """The repository's own allow-list, read from deny.toml so the survey cannot
    disagree with the gate about what is permissive."""
    text = (HERE / "deny.toml").read_text(encoding="utf-8")
    block = text[text.index("allow = ["):]
    return set(re.findall(r'"([^"]+)"', block[: block.index("]")]))


ALLOWED = allowed_licences()
MANIFEST = """[package]
name = "kotama-engine-survey"
version = "0.0.0"
edition = "2021"

[dependencies]
{name} = "={version}"
"""


def crates_io(name: str) -> tuple[str, str, str]:
    try:
        request = urllib.request.Request(
            CRATES_IO.format(name=name),
            headers={"User-Agent": "kotama-engine-survey (local research tool)"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.load(response)
        crate = data["crate"]
        # The top-level licence field is empty on current crates.io; the first
        # version entry (the newest) carries it.
        licence = next((v.get("license") for v in data.get("versions", []) if v.get("num") == crate["max_version"]), "")
        return crate["max_version"], licence or "?", "ok"
    except Exception as error:  # network down, crate renamed, rate limit
        return "?", "?", f"fetch failed: {error.__class__.__name__}"


def source_dir(name: str, version: str) -> pathlib.Path | None:
    """Fetch the crate into the local registry and return its unpacked source."""
    with tempfile.TemporaryDirectory(prefix="kotama-survey-") as tmp:
        manifest = pathlib.Path(tmp) / "Cargo.toml"
        manifest.write_text(MANIFEST.format(name=name, version=version), encoding="utf-8")
        # cargo refuses a package with no target; an empty lib satisfies it.
        (pathlib.Path(tmp) / "src").mkdir()
        (pathlib.Path(tmp) / "src" / "lib.rs").write_text("", encoding="utf-8")
        subprocess.run(
            ["cargo", "fetch", "--manifest-path", str(manifest)],
            capture_output=True,
        )
        proc = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--manifest-path", str(manifest)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if proc.returncode != 0:
            return None
        try:
            metadata = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return None
    for package in metadata.get("packages", []):
        if package["name"] == name:
            return pathlib.Path(package["manifest_path"]).parent
    # cargo drops a dependency it cannot use and says why in a warning; surface
    # that rather than "not resolvable" — an empty placeholder crate on crates.io
    # is a real finding (the `quickjs` name is one).
    global LAST_RESOLUTION_NOTE
    match = re.search(r"ignoring invalid dependency[^*]*?(missing a lib target|[^\n]+)", proc.stderr)
    LAST_RESOLUTION_NOTE = match.group(1).strip() if match else "not in cargo metadata output"
    return None


def c_abi_evidence(directory: pathlib.Path) -> tuple[bool, int, list[str]]:
    """(declares crate-type cdylib, number of extern-C entry points, has no_mangle)."""
    manifest = (directory / "Cargo.toml").read_text(encoding="utf-8", errors="replace")
    cdylib = bool(re.search(r"crate-type\s*=\s*\[[^\]]*cdylib", manifest))
    externs = 0
    exported: list[str] = []
    for path in directory.rglob("*.rs"):
        text = path.read_text(encoding="utf-8", errors="replace")
        externs += len(re.findall(r'extern\s+"C"\s*\{', text))
        externs += len(re.findall(r'extern\s+"C"\s+fn', text))
        # A function is exported when a no_mangle attribute is followed by an
        # extern "C" fn within a few lines; capture its name.
        for match in re.finditer(r'#\[(?:unsafe\()?no_mangle\)?\]\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"\s+(?:safe\s+)?fn\s+(\w+)', text):
            exported.append(match.group(1))
    return cdylib, externs, exported


def verdict(licence: str, cdylib: bool, externs: int, exported_names: list[str]) -> str:
    # "MIT OR Apache-2.0" is permissive if either side is; "Apache-2.0 WITH
    # LLVM-exception" is a single SPDX expression the allow-list names as-is.
    alternatives = {part.strip() for part in licence.split(" OR ")}
    if not any(alt in ALLOWED for alt in alternatives):
        return f"out: licence ({licence})"
    if exported_names:
        # Exported names, not just attributes: rune exports seven `__rune_alloc_*`
        # / `__rune_budget_*` hooks for a wasm host — a real C ABI, but not an
        # engine API a hook planner can intercept a script through. An engine
        # surface is named like the engine (JS_*, lua_*, *_eval, *_pcall).
        engine_like = [n for n in exported_names if not n.startswith("__")]
        if engine_like:
            return f"mountable: {len(engine_like)} engine exports"
        return f"cdylib hooks only ({len(exported_names)}), not an engine ABI"
    if cdylib:
        return "cdylib, no extern-C seen"
    return "embeddable, not mountable"


def main() -> int:
    print("| crate | version | licence | cdylib | extern-C | exported names | verdict |")
    print("|---|---|---|---|---|---|---|")
    for name in CANDIDATES:
        version, licence, status = crates_io(name)
        if status != "ok":
            print(f"| {name} | {version} | {licence} | - | - | - | {status} |")
            continue
        directory = source_dir(name, version)
        if directory is None:
            print(f"| {name} | {version} | {licence} | - | - | - | not resolvable: {LAST_RESOLUTION_NOTE} |")
            continue
        cdylib, externs, exported = c_abi_evidence(directory)
        names = ", ".join(exported[:4]) + ("…" if len(exported) > 4 else "")
        print(
            f"| {name} | {version} | {licence} | {'yes' if cdylib else 'no'} | {externs} | "
            f"{names or 'none'} | {verdict(licence, cdylib, externs, exported)} |"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

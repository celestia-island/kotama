#!/usr/bin/env python3
"""One-token mutation runner: apply each mutation, run the tests, expect red.

Every mutation is the same shape and differs only in which files, which tests,
and what to replace. This is that shape, written once, driven by a JSON spec:

    {
      "test": ["-p", "kotama-proxy"],
      "files": {"plan": "crates/proxy/src/hook_plan.rs"},
      "mutations": [
        {"name": "...", "file": "plan", "find": "...", "repl": "..."}
      ]
    }

"root" is optional and defaults to the repository this script lives in; an
explicit root is only for a worktree outside the tree.

Rules the engine enforces, each learned from a mistake that produced a wrong
number before the rule existed:

  - The baseline must be green AND run at least one test. A broken build makes
    every mutant look CAUGHT (reported as 4/4 twice), and a selection that
    matches nothing makes every mutant look MISSED (cargo exits 0).
  - Every anchor must match exactly once. A silent no-op makes a mutant look
    MISSED when it never applied.
  - ANCHOR and MISSED are different verdicts, so an equivalence claim can only
    be made about a mutant that actually ran.
  - Files are restored after each mutant and the tree is re-verified green.

Exit code: 0 when every mutant that ran was caught and the tree is green;
1 when some mutant that ran survived; 3 or 4 when the baseline is refused.
"""

from __future__ import annotations
import json
import os
import pathlib
import re
import subprocess
import sys


def run_tests(root: pathlib.Path, test_args: list[str], env: dict[str, str]) -> tuple[int, int]:
    """Run the selection; return (exit code, number of tests that ran)."""
    proc = subprocess.run(
        ["cargo", "test", "-q", *test_args],
        cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
    )
    ran = sum(int(n) for n in re.findall(r"(\d+) passed", proc.stdout + proc.stderr))
    return proc.returncode, ran


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    spec = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    root = (
        pathlib.Path(spec["root"])
        if "root" in spec
        else pathlib.Path(__file__).resolve().parent.parent
    )
    env = dict(os.environ, KOTAMA_REQUIRE_FIXTURES="1")
    # Keep the original bytes, not the decoded text: a restore that re-encodes
    # changes line endings and leaves the worktree dirty after a clean run.
    originals = {key: (root / rel).read_bytes() for key, rel in spec["files"].items()}

    baseline, ran = run_tests(root, spec["test"], env)
    print(f"baseline: {baseline} ({ran} tests)")
    if baseline != 0:
        print("REFUSED: baseline is not green; a red build makes every mutant look caught")
        return 3
    if ran == 0:
        print("REFUSED: the selection ran zero tests; a mutant cannot be caught by nothing")
        return 4

    results: list[tuple[str, str]] = []
    for mutation in spec["mutations"]:
        key = mutation.get("file") or next(iter(spec["files"]))
        path = root / spec["files"][key]
        raw = originals[key]
        source = raw.decode("utf-8")
        eol = "\r\n" if "\r\n" in source else "\n"
        find = mutation["find"].replace("\n", eol)
        repl = mutation["repl"].replace("\n", eol)
        count = source.count(find)
        if count != 1:
            results.append((mutation["name"], f"ANCHOR n={count}"))
            continue
        # Write the mutant with the file's own line endings so only the mutation differs.
        mutated = source.replace(find, repl)
        path.write_bytes(mutated.encode("utf-8"))
        code, _ = run_tests(root, spec["test"], env)
        path.write_bytes(raw)
        results.append((mutation["name"], "CAUGHT" if code != 0 else "MISSED"))

    for name, verdict in results:
        print(f"  {verdict:<12} {name}")
    caught = sum(1 for _, v in results if v == "CAUGHT")
    ran = sum(1 for _, v in results if v in ("CAUGHT", "MISSED"))
    print(f"caught {caught}/{ran} ran, {len(results) - ran} anchor failure(s)")
    restored, _ = run_tests(root, spec["test"], env)
    print(f"restored: {restored}")
    return 0 if restored == 0 and caught == ran else 1


if __name__ == "__main__":
    sys.exit(main())

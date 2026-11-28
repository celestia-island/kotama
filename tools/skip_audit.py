#!/usr/bin/env python3
"""Audit which tests skipped under the gate's environment, and why.

A test that skips is a test that passed without checking anything. Some skips
are deliberate — the live-injection e2e needs a real process, the Ghidra oracle
needs Ghidra — and are named below so they are an accounted exception. Every
other skip reason is a test that was meant to run and did not: a fixture the
builder should have produced, a toolchain a fallback should have found.

Run by `just skip-audit` after `just gate`. It reads the test output with
`--nocapture` so the `skip:` lines are visible, groups them by reason, and
fails if any reason is outside the allow-list. The allow-list is the contract:
adding a line to it is a decision that the skip is intended, not a fix for red.
"""

from __future__ import annotations
import collections
import os
import re
import subprocess
import sys

# Deliberate skips: each needs an external resource the gate does not have.
ALLOWED = (
    "KOTAMA_LIVE_E2E",   # a live target process to inject into
    "KOTAMA_GHIDRA_E2E", # the Ghidra install
    "KOTAMA_PACK_E2E",   # the packaging lane's toolchain
)
SKIP_LINE = re.compile(r"^skip[: ]\s*(.+)$", re.M)


def main() -> int:
    env = dict(os.environ, KOTAMA_REQUIRE_FIXTURES="1")
    proc = subprocess.run(
        ["cargo", "test", "--workspace", "--all-features", "--no-fail-fast", "--", "--nocapture"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
    )
    text = proc.stdout + proc.stderr
    reasons = collections.Counter(m.group(1).strip() for m in SKIP_LINE.finditer(text))
    passed = sum(int(m.group(1)) for m in re.finditer(r"test result: ok\. (\d+) passed", text))
    print(f"skips under gate env: {sum(reasons.values())} across {passed} passing tests")
    unaccounted = {}
    for reason, count in reasons.most_common():
        allowed = next((a for a in ALLOWED if a in reason), None)
        mark = f"allowed ({allowed})" if allowed else "UNACCOUNTED"
        print(f"  {count:3d}x [{mark}] {reason}")
        if not allowed:
            unaccounted[reason] = count
    if unaccounted:
        print(f"\nFAIL {len(unaccounted)} skip reason(s) outside the allow-list")
        return 1
    print("\nok   every skip is an accounted exception")
    return 0


if __name__ == "__main__":
    sys.exit(main())

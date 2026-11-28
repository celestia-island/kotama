#!/usr/bin/env python3
"""Lint hook bodies against the contract: no allocation, no locking, no I/O.

The crate rule is stated once and enforced in pieces. Allocation is counted at
run time by `payload::hook_guard`; the C forwarding runtime's three functions
were pinned by slicing their source in #180. This is the same slicing, made
declarative: a table names each hook body by file and function, and the calls
it must not make. A new hook body is a row in the table, not a new test.

The lock-free ring and the interlocked ops are allowed by omission: the table
lists what is forbidden, and a hook body that stays inside the allowed set is
clean. When a body needs something not on either list, the table is the place
the decision is recorded.

Run by `just hook-body-lint`; in `gate`.
"""

from __future__ import annotations
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent

# file, function, forbidden calls. The function body is sliced from its
# signature to the first line that is a bare closing brace at the same indent.
HOOK_BODIES = [
    # The forwarding mirror's hook body: runs on the caller's thread inside its
    # lock hierarchy. #180 pinned it by hand; the row is the same assertion.
    (
        "crates/cli/src/proxy.rs",
        "void kotama_log_entry(",
        ["WriteFile", "CreateFile", "LoadLibrary", "InitOnceExecuteOnce", "malloc", "HeapAlloc", "EnterCriticalSection", "WaitFor", "snprintf"],
    ),
]


def slice_body(text: str, signature: str) -> str | None:
    start = text.find(signature)
    if start == -1:
        return None
    # The body ends at the first "\n}" or "\n}" followed by a blank line.
    end = text.find("\n}\n", start)
    return None if end == -1 else text[start:end]


def main() -> int:
    violations = 0
    for rel, signature, forbidden in HOOK_BODIES:
        path = REPO / rel
        text = path.read_text(encoding="utf-8")
        body = slice_body(text, signature)
        if body is None:
            print(f"FAIL {rel}: cannot slice {signature!r} — the row is stale")
            violations += 1
            continue
        hits = [call for call in forbidden if re.search(r"\b" + re.escape(call) + r"\b", body)]
        if hits:
            print(f"FAIL {rel} {signature!r}: forbidden {hits}")
            violations += 1
        else:
            print(f"ok   {rel} {signature!r}: clean against {len(forbidden)} calls")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())

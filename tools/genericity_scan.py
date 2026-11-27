#!/usr/bin/env python3
"""Genericity scan: the repository must stay free of product, series, studio and
engine-generation names outside the one place they are allowed.

This is the mechanical half of the genericity rule in AGENTS.md. It scans the
source/config/document files of the repository for names that would tie a generic
capability to a specific work or engine generation, and fails if any is found
outside `examples/engine-formats` (which exists precisely to hold such content and
is `publish = false`).

The term list is deliberately explicit and auditable: every entry names a work, a
series, a studio or an engine generation, and nothing else. Additions belong here,
not in a reviewer's memory.
"""

from __future__ import annotations
import argparse
pathlib = __import__("pathlib")
import re
import sys

# Terms that must not appear in generic capability code. Each is a work, series,
# studio or engine-generation name; generic format words (SWF, DDS, PE, ELF...) are
# not here because naming a format is exactly what the rule asks for.
FORBIDDEN = [
    # works and series
    r"\bPvZ\b",
    r"Plants?\s+vs\.?\s+Zombies?",
    r"\bRA[23]\b",
    r"Red\s+Alert",
    r"Command\s*&\s*Conquer",
    r"\bC&C\b",
    r"\bBattlefield\b",
    r"\bSimCity\b",
    r"\bThe\s+Sims\b",
    r"\bMass\s+Effect\b",
    r"\bDragon\s+Age\b",
    r"\bHalf[- ]Life\b",
    r"\bPortal\b",
    r"\bSkyrim\b",
    r"\bFallout\b",
    r"\bMinecraft\b",
    r"\bFortnite\b",
    r"\bOverwatch\b",
    r"\bWorld\s+of\s+Warcraft\b",
    r"\bStarCraft\b",
    r"\bDiablo\b",
    # studios and publishers
    r"\bEA\s+(BIG|FESL)|Electronic\s+Arts|\bPopCap\b|\bWestwood\b",
    r"\bBlizzard\b",
    r"\bValve\b",
    r"\bBioWare\b",
    r"\bBethesda\b",
    r"\bMojang\b",
    r"\bEpic\s+Games\b",
    r"\b id\s+Software\b",
    # engines and middleware
    r"\bSAGE\s+Engine\b",
    r"\bRenderWare\b",
    r"\bGamebryo\b",
    r"\bCryEngine\b",
    r"\bFrostbite\b",
    r"\bUnreal\s+Engine\b",
    r"\bUnity(?:\s+3D)?\s+Engine\b",
    r"\bSource\s+Engine\b",
    r"\bHavok\b",
    r"\bFMOD\b",
    r"\bWwise\b",
    r"\bBink\b",
    r"\bSpeedTree\b",
]
COMPILED = [re.compile(term, re.IGNORECASE) for term in FORBIDDEN]

SCAN_SUFFIXES = {".rs", ".toml", ".md", ".json", ".yml", ".yaml", ".py", ".ts", ".js", ".c", ".cpp", ".h"}
SKIP_DIRS = {"target", "node_modules", ".git", "dist", "fixtures"}
ALLOWED_PREFIXES = ("examples/engine-formats",)


def scan(root: pathlib.Path) -> list[tuple[str, int, str, str]]:
    """Return (relative path, line, matched term, line text) for every hit."""
    hits: list[tuple[str, int, str, str]] = []
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file() or path.suffix not in SCAN_SUFFIXES:
            continue
        rel = path.relative_to(root).as_posix()
        if rel.startswith(ALLOWED_PREFIXES):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for pattern in COMPILED:
                if pattern.search(line):
                    hits.append((rel, number, pattern.pattern, line.strip()[:120]))
                    break
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=None, help="repository root (default: this file's parent's parent)")
    args = parser.parse_args()
    root = pathlib.Path(args.root) if args.root else pathlib.Path(__file__).resolve().parent.parent
    hits = scan(root)
    if not hits:
        print(f"genericity: clean ({len(FORBIDDEN)} terms, {len(SCAN_SUFFIXES)} file kinds)")
        return 0
    print(f"genericity: {len(hits)} hit(s) outside {', '.join(ALLOWED_PREFIXES)}")
    for rel, number, term, line in hits:
        print(f"  {rel}:{number}: /{term}/  {line}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

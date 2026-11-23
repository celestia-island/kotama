set shell := ["bash", "-c"]
set windows-shell := ["pwsh", "-NoProfile", "-Command"]

_default:
    @just --list

# Type-check all targets.
check:
    cargo check --workspace --all-targets

# Lint with clippy (deny warnings).
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Run all tests.
test:
    cargo test --workspace

# Format check.
fmt:
    cargo fmt --all -- --check

# Format write.
fmt-write:
    cargo fmt --all

# Dependency licences: permissive only, no AGPL/GPL/LGPL in the tree.
licenses:
    cargo deny check licenses bans sources

# One-shot gate.
gate: fmt lint test licenses

# Native Windows bench: fixtures, gate, pack/load and live e2e.
bench-windows *args:
    python tools/windows_bench.py {{args}}

# Cross-check the PDB lane against the system dbghelp oracle.
pdb-crosscheck:
    python tools/pdb_crosscheck.py

# Cross-check function discovery against an IDA headless oracle.
ida-crosscheck:
    python tools/ida_crosscheck.py
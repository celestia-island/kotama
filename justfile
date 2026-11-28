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
    cargo clippy -p kotama-resource --all-targets --all-features -- -D warnings
    cargo clippy -p kotama-cli --all-targets --all-features -- -D warnings
    cargo clippy -p kotama-engine-formats --all-targets --all-features -- -D warnings

# Run all tests.
test:
    cargo test --workspace
    cargo test -p kotama-resource --all-features
    cargo test -p kotama-cli --all-features
    cargo test -p kotama-engine-formats --all-features

# Format check.
fmt:
    cargo fmt --all -- --check
# Genericity: no product, series, studio or engine-generation names outside
# examples/engine-formats. The mechanical half of the AGENTS.md rule.
genericity:
    python tools/genericity_scan.py
    python tools/genericity_selftest.py
    python tools/mutate_selftest.py

# Dependency licences: permissive only, no AGPL/GPL/LGPL in the tree.
licenses:
    cargo deny check licenses bans sources

# Mutation: replay a spec of one-token mutations the tests are required to
# catch. A surviving mutant that is not a documented equivalence is a hole in
# the tests. Not part of `gate` — it edits source files while it runs, so it
# must not overlap a build.
mutate-selftest:
    python tools/mutate_selftest.py

mutate *specs:
    python tools/mutate.py {{specs}}

# One-shot gate.
gate: fmt lint genericity test licenses

# Build the optional desktop shells (Tauri frontend must be built first).
ui-build:
    cargo build --manifest-path ui/Cargo.toml --workspace

# Check the optional desktop shells (format, clippy, tests).
# A tracked dist/.gitkeep lets Tauri codegen resolve frontendDist on a clean
# checkout; ui-build still refuses to package that placeholder.
ui-check:
    cargo fmt --all --manifest-path ui/Cargo.toml -- --check
    cargo clippy --manifest-path ui/Cargo.toml --workspace --all-targets -- -D warnings
    cargo test --manifest-path ui/Cargo.toml --workspace

# Native Windows bench: fixtures, gate, pack/load and live e2e.
bench-windows *args:
    python tools/windows_bench.py {{args}}

# Cross-check the PDB lane against the system dbghelp oracle.
pdb-crosscheck:
    python tools/pdb_crosscheck.py

# Cross-check function discovery against an IDA headless oracle.
ida-crosscheck:
    python tools/ida_crosscheck.py

# Run the real Ghidra differential on a PDB-less fixture.
ghidra-crosscheck:
    python tools/ghidra_crosscheck.py
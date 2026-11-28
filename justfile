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

# Survey: which Rust-ecosystem script engines expose a C ABI a hook plan can
# address. Reads crates.io and the local registry; needs the network once per
# crate. The table is the research record — re-run to refresh it.
# Fixture reproducibility: build every lane twice, hash between. Not in `gate`
# (minutes, and the fixture directory is shared across worktrees). Run it when a
# lane changes.
fixture-repro:
    python tools/fixture_reproducibility.py

# Skip audit: which tests skipped under the gate env, and whether each skip is an
# accounted exception. Run after \`gate\`; fails on an unaccounted skip.
# Hook-body lint: a declarative table of hook bodies and the calls each must not
# make. A new hook body is a row, not a new test. In gate.
hook-body-lint:
    python tools/hook_body_lint.py

skip-audit:
    python tools/skip_audit.py

# Refresh dist/ from current source: both C agents and the Rust payload. Nothing else
# does — bench only checks the files exist — so run this before the live e2e or it
# tests a payload built days before the source.
dist-refresh:
    python tools/dist_refresh.py

engine-survey:
    python tools/engine_survey.py
    python tools/engine_survey_selftest.py
# One-shot gate.
gate: fmt lint genericity hook-body-lint test licenses

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
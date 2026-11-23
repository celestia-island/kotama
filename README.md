<p align="center"><img src="res/logo.webp" alt="Kotama" width="180"/></p>

<h1 align="center">Kotama</h1>

<div align="center">
<strong>Reverse-engineering toolkit: dissect binaries into readable C, then read, scan and freeze live sessions — packaged into per-platform injection libraries</strong>
</div>

<br />

<div align="center">

[![CI](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/ci.yml?label=CI)](https://github.com/celestia-island/kotama/actions/workflows/ci.yml)
[![depspec](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/depspec-lint.yml?label=depspec)](https://github.com/celestia-island/kotama/actions/workflows/depspec-lint.yml)
[![License: SySL 1.0](https://img.shields.io/badge/license-SySL%201.0-blue)](LICENSE)

</div>

<br />

<div align="center">

**English** · [简体中文](docs/zh-Hans/README.md) · [繁體中文](docs/zh-Hant/README.md) · [日本語](docs/ja/README.md) · [한국어](docs/ko/README.md) · [Español](docs/es/README.md) · [Français](docs/fr/README.md) · [Русский](docs/ru/README.md) · [العربية](docs/ar/README.md)

</div>

The name comes from **Kotama** (音瀬コタマ) of the Veritas club at Millennium Science School in
*Blue Archive* — the club's communications and intelligence specialist, an expert listener.
For this repository it reads as: *see the program clearly, and record what it says.*
Both a CLI and a library — and a view inside shittim-chest / hikari.

## Status

**The P0 static pipeline is working** (first commit 2026-11-23, single `master` trunk).
`kotama analyze <file>` loads an ELF/PE file → discovers functions → decompiles them to
basic-block-level pseudo-C.

**The native Windows lanes are implemented** (2026-11-23, Win10 Pro x64): native host
attach/scan/write/freeze, LoadLibrary injection over named pipes or loopback TCP, PE
exception/unwind and MSVC RTTI recovery, RSDS-authenticated PDBs cross-checked with dbghelp,
and GNU/MSVC fixture plus packaging lanes. Run `just bench-windows` on Windows (append
`--oracle` for the real Ghidra differential, `--ida` plus `KOTAMA_IDA` for the IDA one).

Remaining for this phase: a persistent Windows CI runner (not registered yet) and the
GUI/service surface (P5–P6). Tasks are tracked in PR #1.

Proven scope:

| Dimension | State |
| --- | --- |
| Containers | ELF32 / ELF64 / PE32 / PE64 (x86 and x64) |
| Function discovery | Five evidence channels (symtab / dynsym / PE exception directory or `.pdata` / entry / direct call targets), each row carries provenance |
| PE metadata | Exception directory + `.xdata` unwind/handler/chain facts, MSVC vtable/RTTI classes and inheritance offsets, RSDS-authenticated companion PDBs |
| Live Windows | Toolhelp modules, native memory scan/freeze, LoadLibrary injection over named pipes or loopback TCP, thread stacks walked with StackWalk64 + dbghelp |
| Boundaries | Exact boundaries first (symbol lengths, exception directory, PDB); inferred boundaries refined by linear sweep — shared tail blocks no longer truncate real functions |
| Decompilation | Basic blocks + address-anchor comments; **jump tables of dense switches are recovered** (10/10 branches on the ELF64 fixture matrix, 100% confidence) |
| Determinism | Same input, byte-identical output on every run (the precondition for diffing and knowledge reuse) |
| Verified on | 24 fixture-matrix targets plus stripped system binaries such as `/bin/true` and `/bin/ls` |

Known limits: type inference and struct recovery are still P1; PDB-less PE boundaries rely on
the exception directory plus call targets; the generic vtable scan stays narrower than MSVC
RTTI; Windows injection is x64-to-x64; `--pid` attach is same-user, expects no non-empty
`KOTAMA_PAYLOAD_*` in the target, and resolves the main `.exe` by path; the GUI/service surface is not started.

Design decisions and process records live in pull-request descriptions (design documents do
not enter the source tree).

## Capability map

| Area | Content | Stage |
| --- | --- | --- |
| Static | load → function discovery → basic-block decompilation → SEH/RTTI/PDB evidence and Ghidra differential ✅ / type inference · structs | P0 ✅ / P1 |
| Dynamic | Windows injection (named pipe / TCP) → memory / stack snapshots → scan / freeze ✅; hook / trace and Linux injection matrix pending | P2–P4 |
| Packaging | per-platform agent + manifest lanes for GNU x64/x86 and MSVC ✅; `hooks.toml` hook ABI pending | P4 |
| Surface | services (REST / WS / MCP) + hikari web UI + evernight remote nodes | P5–P6 |

Two foundations, everything else stands on them:

1. **One address-space abstraction.** File images, live processes and memory snapshots
   implement the same `AddressSpace`; function discovery and decompilation run one pipeline
   against all three.
1. **Content-addressed function identity.** `kotama://<module-fingerprint>/<rva>` stays stable
   across ASLR, restarts and machines — so annotations and conclusions can travel between nodes.

## Quick start

```bash
just gate                                  # fmt + clippy + test + deny
cargo run -p kotama-cli -- --version       # version + payload ABI version
cargo run -p kotama-cli -- analyze <file>  # function table as JSON (with evidence)
cargo run -p kotama-cli -- analyze <file> --decompile --limit 8   # plus pseudo-C
cargo run -p kotama-cli -- analyze <file> --rtti                # MSVC RTTI/vtable facts
cargo run -p kotama-cli -- live inject --payload dist/x86_64-pc-windows-gnu/kotama_agent.dll -- <target>  # Windows: launch + inject + handshake
cargo run -p kotama-cli -- live inject --payload dist/x86_64-pc-windows-gnu/kotama_agent.dll --pid <pid>       # Windows: attach to a running target
just bench-windows                          # native Windows bench (add --oracle for Ghidra)
KOTAMA_IDA=/path/to/idat.exe just bench-windows --oracle --ida   # optional IDA cross-check
python3 tools/build_fixtures.py --run --host-samples   # fixture matrix + run smoke
```

Fixture matrix: `x86_64-linux-gnu / x86-linux-gnu / x86_64-windows-gnu / x86-windows-gnu`
× `-O2/-O0`, plus native `x86_64-windows-msvc / x86-windows-msvc` with `/Zi` PDBs.
ELF runs natively; PE runs under wine on Linux (`KOTAMA_WINE`) or natively on Windows.
See the repository AGENTS for local runtime dependencies.

## Boundaries

Use it only on authorized targets: your own software, your own devices, or research samples
you have been explicitly granted. This repository does **not** do evasion, anti-detection,
persistence, credential theft or anti-cheat bypass. Memory writes and freezing are off by
default and require an explicit capability grant — read-only analysis is the default posture.

## Contributing

High merge bar; focused contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
For security issues do **not** open public issues — see [SECURITY.md](SECURITY.md).

## License

[SySL 1.0](LICENSE).

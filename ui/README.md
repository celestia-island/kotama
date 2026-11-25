# kotama overlay shells

Two minimal shells over the shared `kotama-overlay` crate:

- `egui-shell/` — eframe/egui, transparent always-on-top window, framebuffer screenshot support.
- `tauri-shell/` — Tauri 2 + Hikari Vue (Vue JSX transform), transparent always-on-top window.

Both load the same action manifest (`../demo-actions.json`) and only draw snapshots plus forward
pointer/key events. Action ids are printed to stdout; neither shell owns a target process. The real
PvZ adapter stays local in `_scratch` and never enters this repository.

## Build

```sh
# Tauri frontend (Hikari is consumed from npm)
cd ui/tauri-shell
npm install
npm run build

# Rust shells
cd ../
cargo build -p kotama-overlay-egui
cargo build -p kotama-overlay-tauri
```

## Run

```sh
# egui: click rows; Escape closes
./target/debug/kotama-overlay-egui --setup ../demo-actions.json --seconds 10

# egui capture mode (local screenshots)
./target/debug/kotama-overlay-egui --setup ../demo-actions.json --expanded \
  --screenshot /tmp/egui.png --seconds 5

# Tauri: frontend assets are embedded at compile time
./target/debug/kotama-overlay-tauri
```

## Action adapter

Both shells can hand an **allowed** action id to an explicitly configured external program:

```sh
# egui
./target/debug/kotama-overlay-egui --setup actions.json --grant-write \
  --adapter /path/to/python --adapter-arg /path/to/adapter.py --invoke my.action

# Tauri
./target/debug/kotama-overlay-tauri --adapter /path/to/python --adapter-arg /path/to/adapter.py
```

The shell appends the action id to the configured argv and runs it with `Command` (no shell
interpolation). The program runs only after `authorize` returns `Allowed`, so the read-only default
still blocks write actions until `--grant-write` / the Hikari `write` control grants capability.
The repository ships no adapter implementation; game- or product-specific code stays outside.

`--invoke <id>` is a headless demo/test hook that applies one action on the first frame.

Environment switches used by capture harnesses:

- `KOTAMA_OVERLAY_EXPANDED=1` starts the Tauri shell expanded (and resizes on the first snapshot).
- `KOTAMA_UI_DEBUG=<path>` writes the egui shell's computed initial size.

## Check

```sh
cargo fmt --all --manifest-path ui/Cargo.toml -- --check
cargo clippy --manifest-path ui/Cargo.toml --workspace --all-targets -- -D warnings
cargo test --manifest-path ui/Cargo.toml --workspace
```

The root `just gate` covers `kotama-overlay`; UI shells are a separate workspace because native
Tauri/egui dependencies are platform-specific.

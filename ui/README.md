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

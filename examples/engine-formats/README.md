# engine-formats (example, not published)

Study crate for resource formats tied to a particular engine or studio. It is kept here,
outside the published toolkit, so the toolkit itself cannot be mistaken for targeting any
specific product.

Nothing in this directory is published or reachable from the `kotama` library entry point.
The published `kotama-resource` crate carries only vendor-neutral formats (SWF, VBS, DOS COM,
DDS, TGA).

## Contents

- Library: identification and parsing for APT, BIG, W3D, CSF, asset tables, import tables,
  VP6 and FESL message framing, each behind its own cargo feature.
- Binary: `engine-formats-cli`, a standalone inspection CLI with the same subcommand shape
  as the published one (`resource identify|info|entries|chunks|mesh|apt|csf|...`).
- Tests: synthetic fixtures only. No game data, no offsets from any shipped product.

## Run

    cargo run -p kotama-engine-formats --all-features --bin engine-formats-cli -- resource identify <file>
    cargo test -p kotama-engine-formats --all-features

Format knowledge was derived clean-room from public format documentation and from reading
GPL-licensed reference implementations for structure only. No third-party code is copied,
vendored or linked; `cargo deny` stays green.

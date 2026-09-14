# Vendored crates

## fuser 0.18.0

`vendor/fuser` is [fuser](https://github.com/cberner/fuser) 0.18.0 as published on crates.io, carrying `src/`, `build.rs`, `Cargo.toml`, `rustfmt.toml`, `LICENSE.md`, `README.md` and `CHANGELOG.md`; the examples, the shell-driven test suites, the Dockerfiles and the toolchain pin are not carried, and the `[[example]]` stanzas were removed from `Cargo.toml` to match. The dev-dependencies were cut to `tempfile`, the one the carried unit tests use. `Cargo.toml` also gained a `[lints]` table allowing the warnings upstream's code raises under a newer toolchain, since a path crate is not lint-capped the way a registry crate is. It is a workspace member so its unit tests run with `cargo test --workspace` (or alone with `cargo test -p fuser`), which means clippy lints it too and one of its tests performs a real FUSE mount.

Upstream no longer accepts pull requests, so the changes below live here. Each hunk is marked `jackalopefs: local patch` in the source.

### Local patches

None yet.

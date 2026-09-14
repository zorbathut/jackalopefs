# Vendored crates

## fuser 0.18.0

`vendor/fuser` is [fuser](https://github.com/cberner/fuser) 0.18.0 as published on crates.io, carrying `src/`, `build.rs`, `Cargo.toml`, `rustfmt.toml`, `LICENSE.md`, `README.md` and `CHANGELOG.md`; the examples, the shell-driven test suites, the Dockerfiles and the toolchain pin are not carried, and the `[[example]]` stanzas were removed from `Cargo.toml` to match. The dev-dependencies were cut to `tempfile`, the one the carried unit tests use. `Cargo.toml` also gained a `[lints]` table allowing the warnings upstream's code raises under a newer toolchain, since a path crate is not lint-capped the way a registry crate is. It is a workspace member so its unit tests run with `cargo test --workspace` (or alone with `cargo test -p fuser`), which means clippy lints it too and one of its tests performs a real FUSE mount.

Upstream no longer accepts pull requests, so the changes below live here. Each hunk is marked `jackalopefs: local patch` in the source.

### Local patches

- **`FUSE_INTERRUPT` is dispatched to `Filesystem::interrupt(&self, req, unique)`** (`src/lib.rs`, `src/request.rs`) instead of being answered with `ENOSYS`. The default implementation does nothing, and nothing is ever sent in reply to the interrupt: the kernel takes an `ENOSYS` reply as "this filesystem never handles interrupts" and stops sending them for the life of the mount, after which not even `SIGKILL` frees a process blocked in a request. That is upstream's behaviour and it must not come back with a rebase. The interrupt is also added to the operations exempt from the session's uid check, because the kernel sends it with a zeroed header.

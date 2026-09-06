# Changelog

## [unreleased]

### Added

- `jackalopefs-proto`: wire protocol as a Cap'n Proto schema (the language-neutral protocol spec, with `docs/design.md`) plus plain Rust message types, conversions that validate every name, path and token as they are parsed, length-prefixed single-segment framing (directory listings are budgeted by their actual wire size, so a page holds fewer entries than a byte count would suggest), and certificate fingerprint helpers.
- `jackalopefs-server`: exports one directory over QUIC as an unprivileged user. Paths are resolved with `openat2` confined to the export; sessions survive a dropped connection for 60 s so a reconnecting client keeps its open files; a recursive inotify watch pushes debounced change events to clients without echoing a client's own changes; optional `--token` authentication; a persistent self-signed certificate whose fingerprint is logged at startup; per-session handle and detached-session caps, non-blocking opens, and deadlines on every request read and reply write so no client can park a server thread or pin memory.
- `jackalopefs-client`: a FUSE mount that never blocks the FUSE session thread on the network. Every operation has a deadline (`--op-timeout`, `ETIMEDOUT` on expiry); the connection is re-established with backoff and the session resumed or handles reopened and verified (`ESTALE` on mismatch); server events invalidate the kernel's entry and data caches; hardlinks share `st_ino` and `st_ino` is stable; readdir uses real directory cookies; `--fingerprint` pins the server certificate, `--insecure` skips it.
- Documentation: `docs/design.md` (protocol, architecture, timeouts, limitations) and `docs/research-fusex.md` (the research notes behind the design).

### Fixed

- `fstat`, `fchmod`, `fchown` and `futimens` on a file unlinked while open returned `ESTALE`; the kernel sends those requests without a handle, and the client now answers from a handle it still holds on the inode.
- The server passed the export filesystem's `f_namelen` through unclamped; it is now capped at the protocol's `NAME_MAX` (255), which `pathconf(_PC_NAME_MAX)` is answered from.

# Changelog

## [unreleased]

### Added

- `jackalopefs-proto`: wire protocol as a Cap'n Proto schema (the language-neutral protocol spec, with `docs/design.md`) plus plain Rust message types, conversions that validate every name, path and token as they are parsed, length-prefixed single-segment framing (directory listings are budgeted by their actual wire size, so a page holds fewer entries than a byte count would suggest), certificate fingerprint helpers, and a protocol revision (the hash of the schema file) that both ends compare in the handshake.
- `jackalopefs-server`: exports one directory over QUIC as an unprivileged user, on 127.0.0.1:1933 unless `--listen` says otherwise. Paths are resolved with `openat2` confined to the export; sessions survive a dropped connection for 60 s so a reconnecting client keeps its open files; a recursive inotify watch pushes debounced change events to clients without echoing a client's own changes; optional `--token` authentication; a persistent self-signed certificate whose fingerprint is logged at startup; per-session handle and detached-session caps, non-blocking opens, and deadlines on every request read and reply write so no client can park a server thread or pin memory.
- `jackalopefs-client`: a FUSE mount that never blocks the FUSE session thread on the network. Every operation has a deadline (`--op-timeout`, `ETIMEDOUT` on expiry); the connection is re-established with backoff and the session resumed or handles reopened and verified (`ESTALE` on mismatch); server events invalidate the kernel's entry and data caches; hardlinks share `st_ino` and `st_ino` is stable; readdir uses real directory cookies; `--fingerprint` pins the server certificate, `--insecure` skips it; the server is named as `host`, `host:port` or an IP address (an IPv6 address with a port in brackets), the port defaulting to 1933, and every address that name resolves to is tried in turn (the one that answers first from then on), each on its own `--connect-timeout`.
- Client and server built from different protocol revisions refuse each other before any authentication and both log the two revisions; a first connection refused that way makes the client exit with them, a later one is retried so a server rollback recovers the mount.
- Documentation: `docs/design.md` (protocol, architecture, timeouts, limitations) and `docs/research-fusex.md` (the research notes behind the design).
- `jackalopefs-client --default-permissions`: the kernel enforces mode bits against the reported attributes, which a mount shared through `--allow-other` needs to enforce anything; the client warns when `--allow-other` is given without it.
- `scripts/validate/`: repeatable validation runs against a fresh server and mount: pjdfstest (POSIX conformance, with a checked-in expected-failure baseline per mode), xfstests' fsx and fsstress, fio with verification, plus resilience (server stopped, killed and restarted under load) and coherence (two mounts of one export) checks of our own; a rootless podman image for the root-only parts. `docs/validation.md` explains the runs and the baseline.

### Fixed

- Both binaries wrote terminal colour codes into redirected logs; colour is now used only on a terminal.
- A client running as root exited with status 1 (`unmounting: Invalid argument`) when its mount point had already been detached with `fusermount3 -uz`; that is now a clean exit, as it already was for an unprivileged client.
- `fstat`, `fchmod`, `fchown` and `futimens` on a file unlinked while open returned `ESTALE`; the kernel sends those requests without a handle, and the client now answers from a handle it still holds on the inode.
- A failed connection said only what went wrong, never which address it was talking to; every connect error now names it, and the client names the server as typed.
- Unmounting while the client was between connections waited for the whole connect attempt (up to `--connect-timeout`) and logged `connection manager did not stop in time`; the attempt is now abandoned as soon as the unmount is signalled.
- The server passed the export filesystem's `f_namelen` through unclamped; it is now capped at the protocol's `NAME_MAX` (255), which `pathconf(_PC_NAME_MAX)` is answered from.
- The server's own directory listings and file opens counted toward its change queue, so a large export produced spurious `Overflow` events at startup and under read load.

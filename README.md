# jackalopefs

A client/server network mount for Linux, kin to NFS and sshfs, over QUIC. Both ends run as ordinary users; the client mounts through FUSE. The server pushes change notifications so the client's kernel cache stays honest, every operation has a deadline so a vanished server never leaves processes stuck, and a connection that comes back resumes the session with every open file intact.

`docs/design.md` describes the architecture, the wire format (Cap'n Proto over QUIC; the schema in `crates/proto/schema/` plus that document is the protocol spec), and the known limitations. `docs/research-fusex.md` holds the research notes the design grew out of.

## Requirements

- Linux 5.6 or later on the server (`openat2`).
- On the client: `/dev/fuse` and `fusermount3` (package `fuse3`). Mounting as a user needs no special configuration; `--allow-other` additionally needs `user_allow_other` in `/etc/fuse.conf`.
- Rust 1.88 or later and the Cap'n Proto compiler (`capnp` 1.0 or later; package `capnproto` on Arch and Debian) to build. The wire format is generated from `crates/proto/schema/jackalopefs.capnp` at build time.

## Usage

Server:

```
jackalopefs-server --export /srv/share --listen 0.0.0.0:4433 [--token SECRET]
```

On first start it generates a certificate under `$XDG_STATE_HOME/jackalopefs` (or `~/.local/state/jackalopefs`) and logs its fingerprint. The default listen address is loopback; anything else without `--token` lets every host that can reach the port read and write the export as the server user.

Client:

```
jackalopefs-client server:4433 /mnt/share --fingerprint sha256:… [--token SECRET]
```

`--fingerprint` pins the server certificate; `--insecure` skips that check (the connection is still encrypted). Other options: `--op-timeout 30s`, `--connect-timeout 10s`, `--entry-timeout 1s`, `--attr-timeout 1s`, `--allow-other`, `--auto-unmount`, `--default-permissions`. The client runs in the foreground and unmounts on `SIGINT`/`SIGTERM`.

`--default-permissions` has the kernel enforce mode bits against the attributes the server reports before it forwards a request. The server only ever checks its own access, so a mount shared through `--allow-other` enforces nothing without it. It costs extra attribute fetches, bounded by `--attr-timeout`, and a `chmod` made on the server side is honoured only after that timeout or the change event. The client warns at startup when `--allow-other` is given without it.

Set `RUST_LOG=debug` (or `trace`) on either side for more detail.

## When the server goes away

- A filesystem call blocked on the server fails with `ETIMEDOUT` after `--op-timeout`; a call that was in flight when the connection dropped fails with `EIO` unless it is safe to retry, in which case it is retried once on the next connection.
- The client reconnects with exponential backoff for as long as it is mounted. If the server kept the session (up to 60 s), open files continue exactly where they were; otherwise each open file is reopened by path and verified to be the same inode, and a handle whose file changed underneath it fails with `ESTALE`.
- To give up on a mount: `fusermount3 -uz /mnt/share` detaches the mount point, and killing `jackalopefs-client` fails every pending and future call with `ENOTCONN` immediately. Nothing needs root and nothing can wedge in uninterruptible sleep beyond the operation deadline.

## Semantics

Single client: hardlinks share `st_ino`, `st_ino` is stable, unlink-while-open works, `O_APPEND` appends atomically, `readdir` uses real directory cookies, POSIX and BSD locks are handled by the local kernel. Writes go through immediately (no writeback cache), so a reconnect never loses data, at the cost of one round trip per `write(2)`.

Several clients: each sees the others' changes through server push plus the cache TTL; locks are not shared. See `docs/design.md` for the full list of limitations.

## Building and testing

```
cargo build --release
cargo test --workspace
```

The test suite runs real servers on loopback and, where `/dev/fuse` and `fusermount3` are available, real FUSE mounts; the mount tests skip themselves otherwise. `pjdfstest` can be pointed at a mount for a broader POSIX check; most of it needs root, the non-root subset is the relevant part here.

## License

MIT.

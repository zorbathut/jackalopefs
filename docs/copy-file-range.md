# Server-side copy: forwarding `copy_file_range`

Status: implemented. Proposed and built 2026-09-21; kernel behaviour below was read from `fs/fuse/file.c` and `fs/read_write.c` as of Linux 7.2.

## Problem

`mv` on a jackalope mount, between two bcachefs subvolumes of the exported filesystem, sent the whole file over the network twice: once read down to the client, once written back. Run on the server itself, the same `mv` reflinks the file and moves no data at all.

## What happened before

1. `renameat2` is forwarded (`crates/client/src/fuse.rs`, `fn rename`); on the server bcachefs refuses a rename across subvolumes with `EXDEV`. That is correct and stays: nothing can turn this into a rename.
2. `mv` falls back to copy + unlink. coreutils ≥ 9 tries `FICLONE` first. FUSE has no `remap_file_range`, so the kernel fails `FICLONE` before any request reaches the daemon (our `ioctl` handler would refuse it with `ENOTTY` anyway). **Reflink through FUSE is impossible; don't try.**
3. coreutils then tries `copy_file_range(2)`, and the kernel sends `FUSE_COPY_FILE_RANGE`. fuser's default handler replied `ENOSYS` and logged `[Not Implemented] copy_file_range(...)`.
4. On `ENOSYS` the kernel sets `fc->no_copy_file_range` for the life of the mount, and from then on `fuse_copy_file_range` falls back to `splice_copy_file_range` by itself: the syscall *succeeds*, and every byte crosses the network twice as ordinary reads and writes. Nothing in userspace sees a failure, which matters for testing: a forward that silently stopped working would look exactly like one that works.

## What was built

`FUSE_COPY_FILE_RANGE` is forwarded to the server, which calls `copy_file_range(2)` on its own descriptors.

- **proto**: `Request::CopyFileRange { fh_in, offset_in, fh_out, offset_out, len }`, answered by `Response::Copied(u32)`.
- **client** (`fuse.rs`, `client.rs`): `copy_file_range` in the style of `write`. The request names two handles, so `Request::fhs()` lists every handle a request names and a call fails with `ESTALE` if either is dead.
- **server** (`ops.rs`): look up both handles, record the destination in the change log as `Write` does, call `copy_file_range(2)` once with at most `MAX_COPY` (64 MiB), return the count.

### Why this gets a reflink on the server

`vfs_copy_file_range`: when both files are on the same superblock and the filesystem has `->remap_file_range`, it tries the remap first (`REMAP_FILE_CAN_SHORTEN`), then the filesystem's own `->copy_file_range` if it has one, then an in-kernel splice. bcachefs implements `remap_file_range`, so a same-filesystem copy on the server is a reflink. On any other filesystem it is at worst a local copy on the server, which is still no network traffic. Across filesystems the syscall splices or returns `EXDEV`; either goes back to the client as it is (on `EXDEV` the client's kernel splices through the mount, as before).

## Decisions

**The server copies at most 64 MiB per request.** The server does not notice a request its client has abandoned: the blocking task runs to the end whatever happens to the stream. A client abandons a request on a signal (`FUSE_INTERRUPT`), on `--op-timeout`, and when the connection drops, and bcachefs's remap loop stops only for a fatal signal to the *server*. So whatever one request may do is what may still be happening after the caller has moved on, and for a copy that means writing into the destination: interrupt a `cp`, rewrite the destination, and the old copy can land on top of the new contents. A write has the same exposure at 1 MiB. A bcachefs reflink is not O(1) either (`bch2_remap_range` runs a transaction per source extent; a fragmented file, such as a torrent download, can take minutes for a few GiB), so an unbounded request would also hold one of the server's 512 blocking threads, shared by every session, and the client kernel's lock on the destination inode, for that long, and would turn a user's `--op-timeout` into `ETIMEDOUT` where read/write used to work. At 64 MiB a request is a second or two even in the bad cases, and a 60 GB file costs about a thousand round trips, which is nothing beside the copy. That is still some sixty times the work of any other request: one client can have 1024 requests in flight, so enough concurrent slow copies can occupy the whole blocking pool and make every session's requests queue behind them for that second or two. If that ever shows, lower the clamp; nothing else depends on it. A short count is ordinary for `copy_file_range(2)`: the kernel passes it through and every caller loops. The clamp is a power of two so a reflink stays block-aligned. It is the server's own choice and not part of the protocol, which says only that the count may be short; it lives in `crates/server/src/ops.rs`.

**The reply is its own variant, `copied`, and 32 bits.** A `u32` union member shares the word `written` uses, so replies do not grow, and the clamp guarantees the fit. It is not `written` because the client's perf table counts `written` as payload: the rows one opens to check that a copy stayed off the network would report the whole file. The client's `call` row counts nothing for a copy; its kernel-level (`fuse`) row and the server's row count the bytes the server copied. The request's `len` is 64 bits.

**No flags on the wire.** `copy_file_range(2)` defines none, and the syscall refuses any before FUSE is asked. The client answers non-empty flags with `EINVAL` so a flag a later kernel adds is refused rather than ignored.

**The request is an inline group like every other**, which grew every request by 24 bytes (`docs/design.md`, "Layout choices").

**Opcode 53 is left to fuser's `ENOSYS`.** The kernel first tries `FUSE_COPY_FILE_RANGE_64` (Linux 6.18+, 64-bit length and result). The vendored fuser does not know it and answers `ENOSYS`; the kernel sets `no_copy_file_range_64` and retries with opcode 47 in the same call, for the life of the mount. That costs one extra trip to the daemon per mount and caps a kernel request just under 4 GiB, far above what the server copies per request anyway. Supporting 53 means patching the vendored fuser (`vendor/README.md`) and is pointless unless the server's clamp ever exceeds 4 GiB.

## Things to know

- **Retry.** A copy whose reply was lost with the connection is sent again, like a write: it is positional, so the same ranges give the same bytes, and overlapping ranges of one file are `EINVAL` both times. The retry may run beside its own orphan; they serialise on the server's inode lock and write identical data.
- **Interrupts.** The caller gets `EINTR` at once; the server finishes the request in hand (see the clamp above).
- **Page cache.** The client's kernel writes back dirty pages of both ranges before sending the request, holds the destination's inode lock across it, and afterwards drops the destination's cached pages over the copied range and updates its size and mtime. The daemon does none of that. The destination's attributes are looked up afresh after its last close, as for any file written through the mount.
- **Change events.** The destination is recorded in the change log before the syscall, as a write is, so the copying session is not told about its own change. A record is consumed by the first matching event and forgotten after a second. A reflink reports one modification, when the syscall ends, so only a request slower than a second is echoed to its own session; a splice copy reports one per batch it writes, and every one after the first is echoed. An echo costs an attribute invalidation on a file the client holds open for writing (its pages are skipped). Recording again afterwards would race the watcher and could swallow someone else's change.
- **Handle modes.** The client's kernel refuses an unreadable source, an unwritable or `O_APPEND` destination, and overlapping ranges of one file before sending anything, and the server opens every writer `O_RDWR` and never `O_APPEND`. The server's `EBADF` and `EINVAL` therefore answer only a client that is not the Linux kernel; the errno is passed through.
- **Offsets are always explicit** in the server's syscall. A session's requests share one descriptor per handle, and a null offset would move its file position.
- **Logs.** The per-request trace describes a copy by its destination handle and offset; the source is not in the line.

## Tests

- `crates/server/src/ops.rs`: copy between two handles, short counts at the end of the source, a length no file has, and the refusals.
- `crates/client/tests/roundtrip.rs`: `Client::copy_file_range` over a real connection, and `ESTALE` when either handle died in a reconnect.
- `crates/client/tests/mount.rs`: `copy_file_range(2)` between two files on the mount. It asserts that the request *reached the daemon* and that the server calls moved almost no bytes, because the contents come out right either way (see step 4 above). It is also what shows the 53 → 47 fallback working on the running kernel.
- `scripts/validate/fsx.sh` checks copies within one file, mapped I/O and the kernel's write cache included, against its shadow copy.
- Not covered: the reflink itself, a copy long enough to meet the clamp (a compile-time assertion keeps the clamp inside the reply's 32 bits), and a resend after a lost reply (the test harness has no server that loses a reply and then recovers).

**Manual end-to-end check on bcachefs.** On the client, run `strace -e trace=renameat2,ioctl,copy_file_range mv <big file> <other subvol>`. Expected: `renameat2` fails with `EXDEV`, `FICLONE` fails with `EOPNOTSUPP`, then `copy_file_range` returns 64 MiB per call while the network stays idle. On the server, `cat /proc/<server pid or thread>/stack` during a call should show `bch2_remap_range`. The client's perf report (`SIGUSR1`) shows `copy_file_range` rows and no `read`/`write` traffic to match.

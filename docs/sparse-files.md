# Sparse files and preallocation: forwarding `fallocate` and `lseek`

Kernel behaviour below was read from `fs/fuse/file.c` and `fs/open.c` as of Linux 7.2.

## `fallocate`

### Problem

fuser's default handler answered `FUSE_FALLOCATE` with `ENOSYS`. The kernel then sets `fc->no_fallocate` for the life of the mount and every `fallocate(2)` fails with `EOPNOTSUPP`. For `FALLOC_FL_PUNCH_HOLE` and `FALLOC_FL_ZERO_RANGE` that is the end of it. For a plain allocation it is worse than a failure: glibc's `posix_fallocate` takes `EOPNOTSUPP` as its cue to emulate, writing a byte into every block of the range, so preallocating a file, which torrent clients do for every download, sent the whole file over the network and *succeeded*. As with `copy_file_range` (`docs/copy-file-range.md`), nothing in userspace sees the difference, so the tests assert that the request reached the daemon.

### What was built

`Request::Fallocate { fh, offset, len, mode }`, answered `Ok`; the server calls `fallocate(2)` on the handle's descriptor.

**Modes.** `fuse_file_fallocate` forwards `FALLOC_FL_KEEP_SIZE`, `FALLOC_FL_PUNCH_HOLE` and `FALLOC_FL_ZERO_RANGE` and refuses every other bit itself, so those three are what the protocol carries. The server refuses anything else with `EOPNOTSUPP`, which is what `vfs_fallocate` answers for a mode a filesystem lacks. It never trims an unknown bit the way it trims open flags: a punch without its punch bit is an allocation. A filesystem's own `EOPNOTSUPP` (tmpfs has no zero-range; ZFS has little beyond punch) goes back to the caller as it is; the kernel remembers only `ENOSYS`, so that stays a per-call answer.

**64 MiB per request.** `fallocate` is not metadata-only work: tmpfs allocates the range a page at a time, and bcachefs, btrfs and ext4 loop over it an extent at a time with a transaction each. And two of the modes destroy data. The server does not notice a request its client has abandoned (a signal, `--op-timeout`, a lost connection), so an unbounded request would hold one of the blocking threads every session shares, and go on punching or zeroing a file whose caller has moved on, for as long as the range takes. A `fallocate` cannot be answered short, but every mode the protocol carries can be split: an allocation grows the file to the same end whichever way the range is cut, and punch and zero are defined per byte. So the client sends a long range as consecutive requests of at most `MAX_FALLOCATE`, 64 MiB for the reasons a copy is limited to that (`docs/copy-file-range.md`), and stops at the first error, and the server refuses a longer one with `EINVAL`, as it does a write over `MAX_IO`. What is lost is atomicity when a call fails or is interrupted part-way, the part before stays done, which `fallocate(2)` does not promise either (a filesystem that runs out of space part-way keeps what it allocated). The limit is a power of two, so the cuts fall on block boundaries when the caller's offset does.

### Things to know

- **Page cache.** Before a punch or zero the kernel writes back the range's dirty pages and waits for those writes to be answered, so the request cannot overtake data it is meant to destroy; afterwards it drops the affected pages, and for a call that extends the file it updates the size itself. It holds the inode lock across the request. The daemon does none of that. An allocation past dirty pages the server has not seen yet is safe: allocating zeroes nothing that exists, and the writeback lands positionally afterwards.
- **Retry.** A request whose reply was lost with the connection is sent again, like a `setattr`: each mode is absolute, so applying it twice is applying it once.
- **Abandoned requests.** The caller gets `EINTR` at once; the server finishes the request in hand, at most 64 MiB of it, which for a punch or zero can land after the caller's next write to that range. A write and a copy have the same exposure at their own limits.
- **Change events.** The file is recorded in the change log before the syscall, as for a write, so the session is not told about its own change, unless the request takes longer than the second a record is remembered for; then it is, which costs an attribute invalidation.
- **Where the export's filesystem has no `fallocate`**, the caller gets its `EOPNOTSUPP` and `posix_fallocate` emulates as before, over the network. That is the filesystem's answer, not a regression.
- **Handle modes.** The client's kernel refuses a descriptor not open for writing before sending anything, so the server's `EBADF` answers only a client that is not the Linux kernel.

### Tests

- `crates/server/src/ops.rs`: every mode is held against the same `fallocate(2)` made directly on a twin file in the same directory (result, contents and block count), because what a filesystem does with a mode is its own business; and the refusals. Where tests run on tmpfs, which has no zero-range, the two zero-range rows compare refusals; fsx covers the mode on a real filesystem.
- `crates/client/tests/roundtrip.rs`: an allocation, and a punch longer than two requests' worth arriving as three.
- `crates/client/tests/mount.rs`: `posix_fallocate` and a punch through the mount, asserting the requests reached the daemon and that next to no payload moved.
- `scripts/validate/fsx.sh` runs with fallocate, keep-size, punch-hole and zero-range on, against mapped I/O and the kernel's write cache; `fsstress.sh` issues them concurrently and then compares the mount with the export.
- Not covered: a resend after a lost reply; a range long enough to be split, through the mount (the split is tested at the client).

**Manual check.** `strace -e trace=fallocate,pwrite64 python3 -c 'import os; fd=os.open("<file on the mount>", os.O_CREAT|os.O_RDWR); os.posix_fallocate(fd, 0, 8<<30)'` shows one `fallocate` returning 0 and no `pwrite64` storm, while the network stays idle; the client's perf report (`SIGUSR1`) shows one kernel-level `fallocate`, the 128 calls it became, and no `write` rows.

## `lseek` for data and holes

### Problem

fuser's default handler answered `FUSE_LSEEK` with `ENOSYS`. The kernel then sets `fc->no_lseek` and answers `SEEK_DATA` and `SEEK_HOLE` by itself from the file's size: all data, one hole at the end. Every sparse file on the export read as dense through the mount, so anything that skips holes by seeking (`cp`, `tar --sparse`, `qemu-img`) read every zero over the network. The other whences never reach the daemon.

### What was built

`Request::Lseek { fh, offset, whence }` with `whence` an enum of two (`data`, `hole`), answered by `Response::Seeked(u64)`; the server calls `lseek(2)` on the handle's descriptor. `ENXIO` (nothing at or after the offset) goes back as it is. `whence` is an enum where `flags`, `mode` and `mask` are raw Linux values because it is a closed set, not a bitfield handed to a syscall; an unknown value is a decode error like any other.

`seeked` is the first 64-bit member of `Response`, so every reply is eight bytes larger (`docs/design.md`, "Layout choices").

### The seek is refused while this client may hold unwritten data

`fuse_file_llseek` takes the inode lock and sends `FUSE_LSEEK`; it writes nothing back first. This mount caches writes, so the kernel can hold pages the server has not seen, and to the server's filesystem that range is still a hole, or past the end. Measured with the refusal taken out: a reader seeking for data from the offset of a write made a moment before, through another descriptor, was sent past it to the next data the server knew of. A copy that skips holes would have dropped the write, silently.

So the daemon answers `EINVAL`, without asking the server, while any handle on the inode that was opened for writing has not been released by the kernel (`HandleTable::may_be_dirty`).

- **Why that condition.** Dirty pages need a writer. `close(2)` writes them back synchronously (`fuse_flush`), and under the writeback cache `fuse_release` does so again before it sends `RELEASE`, which covers a shared mapping that outlives its descriptor. So once the last handle opened for writing is released, the kernel holds nothing the server lacks; until the release arrives the daemon refuses, which is the safe side. A handle that died in a reconnect still counts: the kernel's pages are as dirty as they were. So does a writer that opened the file by another name: a node is the file, whatever name it was reached by, so hardlinks share one node and one page cache. The condition is wider than the truth (a handle opened read-write that never wrote), and it cannot be narrowed to "has written": a cached `write(2)` sends the daemon nothing until writeback.
- **Why `EINVAL`.** It is what `lseek` answered for these whences before Linux 3.1 and what callers take to mean "this file cannot be searched for holes": coreutils `cp` falls back to reading the file, which is what happened before this change. POSIX lists `EINVAL` for `lseek` and not `EOPNOTSUPP`.
- **Why not answer "all data" from the daemon.** The kernel passes the daemon's offset to the caller without holding it against its own size, and the daemon knows only the server's size, which the kernel's can be ahead of: a `SEEK_HOLE` answered with it ends a copy early. `SEEK_DATA` answered with the offset itself never returns the `ENXIO` that ends a caller's loop.
- **Why not `ENOSYS`.** The kernel would stop asking, for every file on the mount, for good.
- **Why not write back first.** The daemon's only means is `inval_inode`, which writes dirty pages back as a side effect, from another thread, into an inode the kernel holds locked for the seek, once for every extent a caller walks.

In the same experiment a `cp` started after the write copied it correctly, refusal or no: it opens the file afresh, and an open that does not keep the cache drops the file's cached pages, writing the dirty ones back first. The danger is a descriptor opened before the write. A change made by another client, or on the server, is ordinary staleness: the answer is the server's at the time, like a read.

### Things to know

- **The descriptor's position.** There is no positional `lseek`, so the server's call moves the file position of a descriptor every request on the handle shares. Nothing reads it: reads, writes and copies carry their offsets.
- **Retry.** A pure query; sent again if its reply is lost.
- **Negative offsets** are answered `ENXIO` by the daemon, as Linux does.
- **Logs.** The per-request trace carries a seek's handle and offset, not whether it looked for data or a hole.

### Tests

- `crates/server/src/ops.rs`: both whences from a spread of offsets, held against the same `lseek(2)` on the export's file, since where a filesystem draws its extents is its own business; `ENXIO` at the end; the refusals; and that a read after a seek still starts where it says.
- `crates/client/src/handles.rs`: `may_be_dirty` counts a dead writer and forgets a released one.
- `crates/client/tests/roundtrip.rs`: `Client::lseek` over a real connection against the local answer; `ESTALE` for a handle that died in a reconnect.
- `crates/client/tests/mount.rs`: seeks through the mount equal seeks on the export and reach the daemon; with a writer open they are `EINVAL` and ask the server nothing; after its release the server is asked again.
- `scripts/validate/sparse.sh`: the mount's map of a sparse file (`xfs_io`'s `seek -a`) equals the export's; a copy off the mount is right; and with data freshly written into a hole and still only in the kernel's cache, a seek through a descriptor opened earlier finds it or is refused; that seek is the check that fails with the refusal removed (in practice it is always refused, so the "finds it" branch never runs). A copy made at that moment is compared too, though it is right either way, for the reason above. fsx does no hole seeking, so this is the only validation `lseek` gets.

**Manual check.** `strace -e trace=lseek cp <sparse file on the mount> /tmp/x` shows `SEEK_DATA`/`SEEK_HOLE` returning the file's real extents, and the client's perf report shows `lseek` rows and `read` bytes close to the file's data, not its size.

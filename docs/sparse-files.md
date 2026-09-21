# Sparse files and preallocation: forwarding `fallocate`

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

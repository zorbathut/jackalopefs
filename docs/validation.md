# Validation runs

`scripts/validate/` runs external filesystem test suites and two checks of our own against a fresh server and mount, so the runs can be repeated after any change. They complement `cargo test`: the Rust suite covers the protocol and the client and server at the API level, these runs cover what the kernel and real programs see through the mount.

| Suite | Covers | Does not cover |
|---|---|---|
| `pjdfstest.sh` | POSIX semantics and errnos of every metadata call (chmod, chown, link, mkdir, mkfifo, mknod, open, rename, rmdir, symlink, truncate, unlink, utimensat) | data; anything needing chflags, lchmod or birthtime (Linux has none) |
| `fsx.sh` | single-file data integrity: random reads, writes, truncates, mapped I/O, every read checked against a shadow copy, file size after every operation | concurrency |
| `fsstress.sh` | many processes doing random metadata and data operations at once: crashes, hangs, a mount that stops answering, a tree that disagrees with the export | data contents (fsstress verifies nothing itself) |
| `fio.sh` | concurrent verified I/O: eight processes writing their own files and reading every block back against a checksum | file sizes (fsx owns those); the weakest of the four |
| `resilience.sh` | a server that stops answering, dies and restarts under load: deadlines, recovery, open files across a restart, lazy detach | multi-client behaviour |
| `coherence.sh` | two mounts of one export with 60 s cache TTLs: changes pushed within 2 s, fsstress on one while the other reads | conflicting writers |
| `permissions.sh` | root only: the kernel enforcing modes and sticky bits against the server's attributes for another uid, setuid stripping | anything else |

Not used, and why: the rest of xfstests needs `TEST_DEV`/`SCRATCH_DEV` block devices; LTP's filesystem tests need root and target kernels; pynfs is NFS-only. None of the runs exercises `--fingerprint` or `--token`: the mounts use `--insecure` on loopback, and the Rust suite covers the trust path.

## Prerequisites

- `cargo build --workspace` (every suite runs it before starting, so a run always tests the working tree; the debug profile is used on purpose so overflow checks and debug assertions are live).
- The external tools, built once at pinned revisions by `scripts/validate/tools.sh validation/tools`: pjdfstest at commit `85a8aea9` and xfstests `v2026.09.02` (for `fsx` and `fsstress`), both tarballs checked against a pinned SHA-256. The script names the Arch packages it needs when something is missing (`base-devel perl fuse3 fio xfsprogs acl attr libaio liburing gdbm libcap`; other distributions map the names).
- `fio`, `fusermount3`, `prove` (package `perl`), GNU coreutils and `util-linux`.
- For the root-only parts: rootless `podman` (see "Deep mode").

`validation/` is ignored by git; it holds the tools and the results.

## Running

```
scripts/validate/all.sh            # every suite that can run unprivileged, summary table at the end
scripts/validate/fsx.sh            # one suite
scripts/validate/container.sh      # every suite as root in a container, pjdfstest's full set and permissions.sh included
```

Each suite exits non-zero on any failure and leaves everything in `validation/results/<suite>/` (`results-root/` for the container): `server.log`, `client-*.log`, `env.txt` (kernel, sysctls, export filesystem, tool versions, client options), the tool's own output, and on a hang a `hang/` directory with every thread's state, wait channel and syscall, the mount table and the log tails. `all.sh` keeps each suite's console output in `validation/results/<suite>.txt`.

A suite passes only if its own checks pass *and* the teardown was clean: the client exits on `SIGTERM` within 30 s and the mount is gone, the server exits, and neither log contains an `ERROR` or a panic. A run that had to detach or kill anything is a failure even when the suite's checks passed. On a desktop host, something else (an indexer, a file manager) can hold a file on the fresh mount for a while and keep the client from exiting; `hang/holders.txt` names it, and the container has no such thing.

Tunables, all environment variables: `FSX_OPS` (20000), `FSSTRESS_OPS` (1000 per process), `FSSTRESS_PROCS` (4), `FSSTRESS_SEED` (1), `JFS_OP_TIMEOUT` (15s, the client's `--op-timeout` for the run; `resilience.sh` fixes its own at 3 s because its assertions are built on that number), `JFS_TOOL_TIMEOUT` (600, seconds as a bare number: the deadline on each external tool run inside a suite; `all.sh` gives every suite three of them plus five minutes, so the inner deadline, the one that collects diagnostics, always fires first), `RUST_LOG` (passed to both binaries; `info,jackalopefs_client=debug,fuser=debug` shows every kernel request). `JFS_TOOLS`, `JFS_BIN` and `JFS_RESULTS` relocate the tools, the binaries and the results; `container.sh` and `pjdfstest-nodev.sh` are built on them, and with `JFS_BIN` set nothing is rebuilt.

`scripts/validate/selftest.sh` tests the harness's own logic (the TAP parser and the baseline diff) against fixtures.

## pjdfstest

The mode follows the uid. Unprivileged, the default and the configuration people actually run: the test files that never switch uid (151 of 238; the rest call the setuid helper with `-u 65534` and fail rather than skip without root), on a plain mount. As root, through `container.sh`: every file, on a mount with `--allow-other --default-permissions` so other uids reach it and the kernel enforces modes.

The verdict is not prove's exit status but a diff against the checked-in baseline for the mode, `scripts/validate/pjdfstest.baseline.user` or `.root`: one line per expected failure, `dir/file.t:N` plus the failing check's detail, grouped under a comment that names the mechanism. The values in a detail that differ between runs or hosts are normalised by the parser so one baseline holds everywhere: pjdfstest's random names become `NAME`, inode numbers `INODE_A`, `INODE_B` and so on (the same letter for the same number within a line, so a mismatch stays a mismatch), and an owner reported as the uid or gid the server runs under `SERVER_UID`/`SERVER_GID` (the harness starts the server as the user running it, so that is the identity every file created through the mount gets). The script reports:

- **regressions**: checks failing that are not in the baseline (exit 1);
- **harness failures**: a test file missing from the log, one that emitted fewer results than its plan, or one prove judged dubious (exit 1; these are never counted as passing, so a truncated run cannot look like an improvement);
- **now passing**: baseline entries that no longer fail (exit 0, with the entries to remove; the baseline is deliberately not self-updating).

To update a baseline after an intended change, take the lines from `validation/results/pjdfstest/failed.txt` and put each under the reason that explains it. An entry without a reason is a bug to report, not a line to add. Do not attribute by errno: in the files that mix causes (a test that switches uid and loops over every file type), a refused device and a refused chmod cascade into the same `ENOENT`s, `EEXIST`s and unexpected successes. `scripts/validate/pjdfstest-nodev.sh` (or `container.sh pjdfstest-nodev.sh`) runs the same files with block and character devices replaced by regular files, into `validation/results/nodev/`, and sorts the real run's failures into three lists there: those that vanish without devices (device cascades), those that fail differently (expectations only a device meets, such as `major,minor`), and those that persist unchanged, which have another cause. Both baselines were attributed that way, mechanically. A pjdfstest bump renumbers the checks, so a baseline is regenerated wholesale from a run plus that attribution rather than edited line by line. `tests/conf` is pinned to `fs="FUSE"` by `tools.sh` because pjdfstest otherwise reads the name from `df`, which differs between a fusermount3 mount and a direct root mount.

Why the unprivileged baseline has what it has (224 checks):

- **Device nodes** (214): the server refuses `S_IFBLK`/`S_IFCHR` with `EPERM` whatever its privilege (design.md). Each refused `mknod` is one failure and the checks that then expect the device cascade: `ENOENT` where it should be, an `EEXIST` or `ENOTDIR` not raised because nothing or a directory is there, and the cleanup that follows. Only 57 of the 214 are the refusals themselves.
- **Chown to another uid or gid** (10): needs `CAP_CHOWN`, which the unprivileged server does not have.

Why the root baseline has what it has (1958 checks):

- **Device nodes** (1798): the same refusal, but every file that switches uid loops over all six file types, so the cascades multiply. Its least obvious members are the checks that expected a denial and got success: `rename/10.t` renames into a sticky directory owned by someone else over a target that should have been a device; with no target there, only the directory's permission applies and the rename succeeds. Where the target exists the sticky check does deny (the same file's other cases pass), and `permissions.sh` covers mode enforcement for another uid directly.
- **Ownership** (160): the protocol carries no requester uid or gid, so a file created by uid 65534 through the mount belongs to the server user, and everything pjdfstest asserts about the owner of what it created, and the permission checks that follow from that ownership, fails. The unexpected successes here are `open/06.t`'s: the chmod by uid 65534 on the file it just created is refused because root owns it, the file keeps its 0644 creation mode, and the read-only open that expected `EACCES` is allowed. Removing this class means forwarding the requester's identity, a protocol and authentication change that is deliberately deferred. The host's `fs.protected_hardlinks`, `protected_symlinks`, `protected_regular` and `protected_fifos` sysctls (recorded in `env.txt`) apply inside the container too; every check they cost is in this class, because each one turns on the object belonging to someone other than uid 65534.

Not a bug, do not baseline it: `EOPNOTSUPP` from the server for opening a FIFO or socket is unreachable through a mount, the kernel never sends `OPEN` for special files. The `PATH_MAX` checks build a 4095-byte relative path from `pathconf` values, which fits the protocol's 4096-byte joined-path limit by one byte; the client's own depth limit (2048 components) is not a constraint.

## fsx

Three passes of xfstests' `fsx` on fresh files with fixed seeds (1, 2, 3), so a failure reproduces: mapped reads and writes on with a 4 MiB maximum file; the same with `-R -W` (no mapped I/O); and `-X`, which re-reads and compares the whole file after every operation, on the default 256 KiB file with a quarter of the operations; with the kernel caching writes this is the pass that reads back through the page cache what was just written into it. The shadow image and log go to the results directory (`-P`), not the mount, and a failure names its seed and leaves `<pass>.fsxlog`.

Disabled explicitly because the client implements none of them: `-F` fallocate, `-H` punch hole, `-z` zero range, `-Y` write zeroes, `-C` collapse, `-I` insert, `-J` clone, `-B` dedupe, `-0` exchange. Left to fsx's own probing, which also disables them (the lines are printed at the end of the run): `FALLOC_FL_KEEP_SIZE` and `FALLOC_FL_UNSHARE_RANGE`, `RWF_DONTCACHE`, atomic writes. `copy_file_range` stays on because the kernel falls back to a read/write copy for FUSE, which is worth exercising. fsx picks uniformly among its 18 operation kinds without redistributing disabled ones, so roughly a third of `FSX_OPS` does work; post-EOF zero checks happen only on mapped reads. `-c` (close/reopen with `drop_caches`) is not used: it needs a writable `/proc/sys`.

## fsstress

`fsstress -d mnt/stress -p 4 -n 1000 -s 1 -v`, then: exit status 0 (it exits 1 on a setup failure or an `EIO` from its own directory), the mount still present, at least a fifth of the operations succeeded, the tree through the mount identical to the export (names, types, sizes, link counts, modes, mtimes, symlink targets, regular-file contents; not block counts, not xattrs), and a clean teardown. The failed operations are printed as an op → errno histogram for information; expected there are the fallocate family, clone, dedupe, exchange and the XFS ioctls (`EOPNOTSUPP`/`ENOTTY`), `chown` to random uids (`EPERM`), `mknod` of devices (`EPERM`), `rmdir` on non-empty directories, `rename` of a directory into itself (`EINVAL`), and xattr lookups on files that have none (`ENODATA`). fuser logs every unimplemented ioctl at warn level; the teardown counts warnings beyond those.

## fio

`verify.fio`: `ioengine=psync`, `verify=crc32c`, `verify_fatal=1`, four `randwrite` jobs with 4 KiB to 64 KiB blocks and four sequential 1 MiB `write` jobs, 32 MiB each, `fsync_on_close`. fio writes, then reads back and checks every block; a mismatch or I/O error is fatal. fio runs from the results directory so its state files stay off the mount. It checks block contents only.

## resilience

The client runs with `--op-timeout 3s` under a writer appending numbered lines and a reader comparing a file, both tolerating errors. Then: the server is `SIGSTOP`ped and a lookup, a create and another lookup must each fail with `ETIMEDOUT` in about 3 s; `SIGCONT` and reads resume; the server is `SIGKILL`ed and restarted on the same state directory and a file opened before the kill must read correctly after (its handle was reopened on the new session), the appended log must match the export and be a gap-tolerant increasing sequence (failed appends leave gaps, never torn or duplicated lines); finally the server is stopped again and `fusermount3 -uz` must detach the mount within 2 s with a read blocked on it, with no process left in uninterruptible sleep.

Two things learnt writing it, both true of any FUSE filesystem: fuser unmounts lazily, so on `SIGTERM` the client keeps serving processes that still hold files on the mount open and exits when they close them (`SIGKILL` or `fusermount3 -uz` plus `SIGKILL` is the immediate way out, as the README says); and a process started while a file on the mount is open inherits that descriptor, so the harness starts the server and client with descriptors 3 to 9 closed.

## coherence

Two clients on one export, both with 60 s entry and attribute TTLs, so anything the second mount sees within 2 s came through server push, not expiry: a file created, appended, renamed and deleted on the first mount, and one written directly on the export. Then fsstress runs on the first mount while the second loops `find` and `cat` over the same tree; names vanishing under the reader (`ENOENT`) is expected, any other error is not, and afterwards the second mount's view must equal the export.

## Deep mode

`scripts/validate/container.sh [suite.sh …]` builds `localhost/jackalopefs-validate` from `scripts/validate/Dockerfile` (an `archlinux:base` image pinned by digest, the packages above, `tools.sh` into `/opt/tools`; the resolved package versions land in `versions.txt`) and runs the suites as root inside rootless podman with `--device /dev/fuse --cap-add SYS_ADMIN --network none`. The repository is bind-mounted, so the binaries are the host's debug build, the export stays on the host's filesystem (the client uses the server's `st_ino` as the FUSE node id, which container overlay storage would not keep stable), and the results land in `validation/results-root/`. Inside, uid 65534 is a real host subordinate uid.

What is and is not being tested there: `--default-permissions` makes the kernel answer `access(2)` itself, so `FUSE_ACCESS` never reaches the client in this mode; the client's `access` path is exercised only unprivileged. fuser mounts with `nosuid,nodev`. The server runs as root in the container, so it can chown and create anything, but files still get the server's uid because the protocol carries no requester identity, which `permissions.sh` asserts so that it fails, and gets rewritten, the day that changes.

The image is built once; after a change to `tools.sh` or its pins, `podman rmi localhost/jackalopefs-validate` makes the next run rebuild it.

On other distributions: docker's default AppArmor profile denies `mount` (`--security-opt apparmor=unconfined`), and the server's `openat2` needs a seccomp profile that knows the syscall (libseccomp 2.5 or later). Only podman is wired up.

## First run, 2026-09-06

Kernel 7.1.1, ext4 export, all four `fs.protected_*` sysctls set, debug binaries.

| Suite | Outcome | Wall time |
|---|---|---|
| pjdfstest (unprivileged, 151 files, 1151 checks) | 224 expected failures, no regressions, no harness failures | 30 s |
| fsx (3 passes, 20 000 + 20 000 + 5 000 ops) | pass | 50 s |
| fsstress (4 × 1000) | pass; 2223 operations succeeded, 155 files | 10 s |
| fio (8 × 32 MiB) | pass | 12 s |
| resilience | pass | 35 s |
| coherence | pass | 8 s |
| pjdfstest (root, 238 files, 8798 checks) | 1958 expected failures, no regressions, no harness failures | 3.5 min |
| fsx, fsstress, fio, resilience, coherence (root) | pass | 2 min together |
| permissions (root) | pass | 5 s |

Found by the runs:

- `fstat` on a file unlinked while open returned `ESTALE` (pjdfstest `unlink/14.t:4`). The kernel sends that `GETATTR` without a handle, and the client had only the path, which was gone. Fixed: the client answers from any handle still open on the inode.
- The server passed the export's `f_namelen` through unclamped although the protocol caps names at 255. Fixed by clamping.
- A client running as root exited with status 1 after the harness's `fusermount3 -uz` (`resilience.sh` in the container): fuser unmounts through `umount2` as root, which answers `EINVAL` for a mount point that is no longer one, while the fusermount3 path an unprivileged client takes ignores that. Fixed: the client treats it as already detached.
- Open, not fixed: a joined path longer than 4096 bytes gets `ESTALE` from the client instead of `ENAMETOOLONG`, because the node table reports "no path" for both an unlinked node and an over-long join. pjdfstest does not reach it (its longest path is 4095 bytes).

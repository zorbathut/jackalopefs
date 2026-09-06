# FUSEX: a network mount with working change notification

*Research notes supplied at project start. They may or may not be accurate; the actual design is in `design.md`.*

A design sketch for a FUSE-based network filesystem that stays recoverable when
the server misbehaves, and that delivers real `inotify` events to unmodified
client programs.

Status: unbuilt. This is a writeup of a design, not a report on a working
system. Sections marked **VERIFY** are things I believe to be true but have not
tested.

---

## 1. The problem

Mounting a remote directory on Linux currently forces a choice between two
properties that ought to be independent.

**Kernel clients (NFS, SMB/cifs) give you correct semantics and lose
recoverability.** With a `hard` mount — the default, and the only safe setting
for writes — a process blocked on an unresponsive server sits in
uninterruptible sleep. `kill -9` does nothing. `umount` blocks. `umount -f`
usually blocks too. Anything that stats the mount joins the pile: your shell
prompt, your file manager, `df`, systemd units with dependencies on the path.
The practical recovery is a reboot of the client.

`soft` mounts avoid this by returning `EIO` on timeout, but `soft` can silently
lose writes, so it is only appropriate for read-mostly mounts.

**FUSE clients (sshfs, rclone) stay recoverable and lose change
notification.** A FUSE connection can be aborted at any time:

```bash
CONN=$(awk -v mp="$MOUNTPOINT" '$5 == mp {split($3,a,":"); print a[2]}' /proc/self/mountinfo)
echo 1 | sudo tee /sys/fs/fuse/connections/$CONN/abort
fusermount3 -uz "$MOUNTPOINT"
```

Every pending and future request immediately returns `ENOTCONN`. Blocked
processes get an error and continue. Nothing spreads, nothing wedges, no
reboot.

The cost is that SFTP has no way to tell the client that anything changed.
Freshness becomes a timeout: rclone's `--dir-cache-time` defaults to five
minutes, and dropping it to ten seconds trades round trips for staleness
without ever eliminating the window.

**The gap being closed here:** keep FUSE's abortability, add real change
notification.

### 1.1 Why the obvious alternatives don't fit

| Option | Notification | Abortable | Verdict |
|---|---|---|---|
| NFSv4 | File delegations only; no directory delegations on Linux | No | Wedges client |
| SMB3 / cifs | Real (`CHANGE_NOTIFY` + directory leases) | No | Wedges client |
| rclone SMB, smbnetfs | None wired up | Yes | SFTP with extra steps |
| 9P (diod) | None | No | Kernel client, weaker caching |
| JuiceFS, SeaweedFS | Timeout-based for non-writing clients | Yes | Restructures storage into chunks |
| CephFS (`ceph-fuse`) | Correct (MDS capabilities) | Yes | Absurd for a single node |
| sshfs | None | Yes | Effectively unmaintained since 2022 |

SMB is the only widely deployed protocol with genuine server-push
notification, and it lives in the kernel client — precisely the component
that has to go.

### 1.2 Two features that keep getting conflated

The rest of this document depends on separating these:

**(A) Cache invalidation.** When the server changes, the client's cached view
becomes correct. `ls` shows the new file. A file manager refresh works. Any
program with a polling fallback starts seeing truth.

**(B) Event delivery.** A program that called `inotify_add_watch()` on the
mount receives an event.

(A) is entirely solvable in userspace and is worth roughly a weekend.
(B) requires kernel code. Most discussion of "inotify over network
filesystems" silently means one or the other.

---

## 2. Prior art, and why it stalled

**The primitive for (A) already exists.** FUSE has a reverse channel:
`FUSE_NOTIFY_INVAL_ENTRY`, `INVAL_INODE`, `DELETE`, `STORE`, `POLL`, exposed by
libfuse as `fuse_lowlevel_notify_inval_entry()` and friends, present since
FUSE protocol 7.18. A FUSE server can push invalidation into the kernel client
whenever it likes. rclone doesn't do this over SFTP because SFTP can't tell
rclone anything happened — the hole is in the backend, not the layer.

rclone already has a `ChangeNotify` interface with an implementation for the
local backend built on fsnotify. What's missing is a backend that pairs
rclone-on-client with an agent on the server.

**FUSE-as-wire-protocol is proven.** virtiofs is the FUSE protocol carried
over a transport rather than a local socket. Shipping FUSE ops across a link
is not hypothetical.

**(B) was attempted and did not land.** There is a 2021 RFC series to make
fsnotify work over FUSE, motivated by virtiofs, because Kata Containers needs
`inotify` to work for unmodified workloads inside guest VMs. Its approach:

- a new `FUSE_FSNOTIFY` opcode and a `FUSE_NOTIFY_FSNOTIFY` reverse notification
- new `inode_operations` entries — a change to `include/linux/fs.h`
- a hook inside the `inotify_add_watch` syscall so watch registration forwards
  to the server
- a hook in `fsnotify_detach_mark`, because watches are removed both explicitly
  and automatically on process exit
- duplicate suppression: with remote notify active, locally generated events for
  FUSE inodes must be dropped or every local operation fires twice
- new UAPI mask bits (`IN_REMOTE`, `FAN_REMOTE`), a permanent public interface
  commitment
- fanotify excluded, since its permission-decision capabilities conflict with
  the server's own access control

That is core VFS surgery across `fs/notify/`, the inotify syscall path, and
`fs/fuse`. It had a concrete corporate use case and a Red Hat engineer behind
it. It stalled.

The same gap appears from the other side in the kernel's cifs TODO, which still
lists finishing inotify support so KDE and GNOME file windows autorefresh as an
open item — in a protocol that has had server-push notification since the
1990s. The blocker is not the transport and never was. It's that the last mile
crosses three subsystem boundaries and belongs to nobody.

### 2.1 One accidental exception

`fuse_lowlevel_notify_delete()` will, as of kernel 4.8, inform registered
inotify watchers of the deletion when the child inode matches the cached
dentry. So deletes propagate today; creates and modifies are silent. One event
type works by implementation accident and the rest don't, which is arguably
worse than uniform silence.

---

## 3. Architecture

Three components. The wire protocol and the server agent are identical in both
modes; only the client's kernel interface differs.

```
   ┌────────────────────────────────────────┐
   │ SERVER                                 │
   │                                        │
   │  local filesystem (inotify works here) │
   │                 │                      │
   │           fusex-agent                  │
   └─────────────────┬──────────────────────┘
                     │  wire protocol
                     │  (data + event stream)
   ┌─────────────────┴──────────────────────┐
   │ CLIENT                                 │
   │                                        │
   │           fusex-client                 │
   │            │            │              │
   │      /dev/fuse     /dev/fusex          │
   │      (mode A)      (mode B)            │
   │            │            │              │
   │   invalidation only   + fsnotify()     │
   └────────────────────────────────────────┘
```

### 3.1 The key insight about detection

Detection was never the hard part. It just has to happen on the correct side of
the wire.

The server runs a local filesystem, where `inotify` works normally. Watching a
FUSE mount on the *client* fails; watching the real directory on the *server*
succeeds. Move the watcher and the problem disappears.

### 3.2 Server agent

Watches the exported tree and streams events to connected clients.

Start with `inotify`, understanding the limits: `inotifywait -r` installs one
watch per directory and walks the entire tree at startup — slow on a large
array, and it will hit `fs.inotify.max_user_watches` (bump to 524288, or narrow
the export root).

For large trees, `fanotify` with `FAN_MARK_FILESYSTEM` watches a whole
filesystem with a single mark and no tree walk. It requires `CAP_SYS_ADMIN` and
`FAN_REPORT_FID`, and turning returned handles back into paths via
`open_by_handle_at` is real work. This needs the filesystem to implement
`export_operations` (the same requirement as NFS export). **VERIFY** for any
given backing filesystem before depending on it.

Design points:

- **Debounce.** A `tar -x` on the server must not become ten thousand messages.
  Coalesce per directory over a ~1s window.
- **Coalesce to directories, not files.** For mode A the unit of invalidation is
  a directory; for mode B, name plus mask.
- **Don't echo.** Changes attributable to a client's own writes should not be
  sent back to that client. This is what replaces the RFC's in-kernel duplicate
  suppression (see §4.3).
- **Events during a disconnect are lost.** There is no replay log. The client
  keeps a moderate `dir-cache-time` as a backstop rather than trusting the
  stream absolutely.

Transport: SSH is the boring choice and reuses existing auth. QUIC is the
interesting one — independent streams mean a large `READ` doesn't
head-of-line-block a `LOOKUP`, which is what NFS's `nconnect=8` crudely
approximates with multiple TCP connections; plus connection migration and 0-RTT
resume after a blip. The industry agrees on the transport direction: Samba now
supports SMB over QUIC, and the cifs TODO lists SMB3.1.1 over QUIC as wanted.

Transport choice is orthogonal to everything else here and can be deferred.

### 3.3 Client, mode A — plain FUSE

Runs on stock `/dev/fuse`. No module, no kernel changes, works everywhere
today.

On receiving an event, call `fuse_lowlevel_notify_inval_entry()` (or the
rclone-VFS equivalent) for the affected parent and name. The kernel's
dentry/attr cache is separate from the userspace VFS cache, but `--attr-timeout`
defaults to 1s — long enough to avoid excessive callbacks, short enough that the
kernel re-asks almost immediately. Net latency from `close_write` on the server
to visible on the client is roughly the debounce window plus a second.

One documented footgun: the notify calls must not be invoked while executing a
related filesystem operation or while holding a lock such an operation might
need, or you deadlock.

Note that `--attr-timeout 0` is not the fix it appears to be. In theory 0 is
correct for filesystems that change outside the kernel's control; in practice it
causes excessive memory use, breaks serving files to Samba, and makes listings
very slow. FUSE's cache model is built on timeouts precisely because
invalidation isn't wired up by default.

**What mode A delivers:** `ls`, file managers, editors reopening files, and —
importantly — every program with a polling fallback. Because this hole has
existed in NFS, SMB and sshfs forever, most software that watches files already
ships one: KDE's `KDirWatch` drops to stat-polling on non-local mounts, GIO does
the same, VS Code has a polling watcher for network drives, Rust's `notify`
crate has `PollWatcher`, most build tools expose `--poll`.

This is where invalidation earns its keep in a non-obvious way. Without it, a
poller stats every second and reads the same stale cache for five minutes. With
it, the poller's next stat after a change returns truth. Mode A doesn't hand
programs events; it makes the fallback they already have actually correct.

**What mode A does not deliver:** `inotifywait` on the client stays silent.

Worth being clear that this is not a degraded stand-in. If rclone shipped
`ChangeNotify` for SFTP tomorrow, it would land in exactly the same place —
invalidation reaches the VFS and the dentry cache and stops. It never becomes an
fsnotify event.

### 3.4 Client, mode B — FUSEX module

A DKMS-shipped fork of `fs/fuse` that additionally injects events into
fsnotify.

`fsnotify()` is `EXPORT_SYMBOL_GPL`, so a GPL module may call it directly to
emit an event for an inode it owns. That is the entire mechanism.

FUSE already has the hard part. `fuse_reverse_inval_entry()` takes a parent
nodeid plus a name and resolves it to a live `struct inode` in order to
invalidate the dentry. The core FUSEX change is: at that same point, having
already resolved the parent, also call `fsnotify()` with the translated mask.
Not a new subsystem — a few lines in a function that already does the lookup.

Inode availability resolves itself. `inotify_add_watch()` pins the inode via its
mark, so anything watched is by definition in cache and findable by nodeid. And
events for newly created remote files are directory events on the parent, which
needs no child inode at all.

**VERIFY:** the exact `fsnotify()` call shape against the target kernel. The
signature has churned across 5.x and 6.x — parameters for `dir`, `file_name` and
`inode` have come and gone. Expect version shims; expect them to be the
recurring maintenance cost.

---

## 4. What a module can and can't reach

`FSNOTIFY` and `INOTIFY_USER` are `bool` in Kconfig — compiled into vmlinux, not
modular. So the question is which of the RFC's changes fit inside module code.

The direction that matters is reachable: `fsnotify()` is exported, so injection
works from a module. Three pieces are not reachable, and each has a workaround
that trades precision for shippability.

### 4.1 Watch forwarding — dropped

The RFC hooks `inotify_add_watch` to tell the server which inodes have
watchers, which required a new `inode_operations` entry. That's a struct layout
change, an ABI break for every other module on the system. Unreachable, and
undesirable.

Workaround: the server watches the whole exported tree unconditionally. You pay
watch descriptors and idle bandwidth; you need no syscall hook and no struct
change. For a home server this is nothing.

Partial reclaim, if the bandwidth ever matters: the module can inspect
`i_fsnotify_marks` on inodes it owns and report which nodeids currently have
watchers. Periodic rather than event-driven, ugly, entirely within module reach.

### 4.2 Mark teardown — not needed

The RFC hooks `fsnotify_detach_mark` because watches disappear both via
`inotify_rm_watch` and automatically on process exit. With no watch forwarding,
there is nothing to tear down.

### 4.3 Duplicate suppression — moved to the server

The RFC drops locally generated events for FUSE inodes in-kernel, because
virtiofs wanted the server to be the single authority for all events, guest and
host. The `fsnotify` wrapper is a static inline in `include/linux/fsnotify.h`,
compiled into every call site including built-in VFS code, so a module can't
intercept it.

Workaround: let the VFS keep handling local operations normally, and inject only
remote ones. Then there is nothing to suppress in-kernel — the server agent just
doesn't echo back changes this client caused. Imperfect under concurrent access
by multiple clients; invisible in practice for a single-user setup.

### 4.4 `IN_REMOTE` / `FAN_REMOTE` — dropped

You want events that look local. That is the entire point of supporting
unmodified programs. Dropping the UAPI bits also removes the part most likely to
attract a long upstream argument.

### 4.5 Net effect

A module-only FUSEX loses precision on watch registration and dedup. It loses
nothing that matters for "unmodified programs see events."

### 4.6 A misleading analogy, corrected

"bcachefs is DKMS and supports inotify, so a module can do this" — true
conclusion, wrong reasoning, worth stating because it's an easy trap.

bcachefs contains essentially no fsnotify code. It gets inotify because the
**VFS** generates events above it: `vfs_create()` calls `fsnotify_create()`,
`vfs_unlink()` calls `fsnotify_unlink()`, from static inlines in
`include/linux/fsnotify.h`. The filesystem is a passive participant, and any
module filesystem gets this for free without trying.

FUSE already gets the same free ride. Write *through* the mount and inotify
fires normally, because the operation traversed the client's VFS. The gap is
only for changes that never touched the client — there is no VFS operation to
hang an event on. bcachefs never has that problem because there is no remote.

The module-can-inject conclusion holds, but it rests on `EXPORT_SYMBOL_GPL` on
`fsnotify()`, not on the bcachefs precedent.

---

## 5. Packaging

**Do not replace `fuse.ko`.** Register a distinct filesystem type and a distinct
char device: `fusex`, `/dev/fusex`. Coexist with in-tree FUSE.

Otherwise every AppImage, gvfs mount, Flatpak and stray sshfs on the machine is
suddenly running your fork, and one regression takes the whole desktop with it.
A rename is cheap; blast radius isn't.

**Client probes and degrades.** Try `/dev/fusex`, fall back to `/dev/fuse`.
Negotiate the fsnotify capability in the INIT handshake so the server agent
knows whether to send full event detail or directory-level invalidation only.

**Userspace cost.** If building on rclone: it uses `bazil.org/fuse`, which talks
to `/dev/fuse` directly in Go, so mode B means forking that too. Not hard, but
it means maintaining a kernel module, a Go library fork, and a server agent
against a moving `fs/fuse`.

**DKMS tax.** Secure Boot MOK enrollment, breakage on kernel bumps, GPL
licensing (mandatory anyway — see below). For anyone already building custom
kernels, carrying patches directly is easier and allows the cleaner design
(real watch forwarding, in-kernel dedup) that DKMS can't reach.

---

## 6. Licensing

Not legal advice; worth a lawyer's eye before shipping. The layout below is
believed sound.

| Component | License | Why |
|---|---|---|
| FUSEX module | GPL-2.0-only | Derivative of `fs/fuse`; calls `EXPORT_SYMBOL_GPL` symbols |
| Wire protocol spec | Anything | A protocol description derives from nothing |
| Client library | MIT | Crosses a syscall boundary; shares no kernel code |
| Server agent | MIT | Same |
| Shared UAPI header | Written from scratch, permissive | See caveat below |

The `/dev/fusex` boundary is a syscall boundary. Linux's `COPYING` carries
Linus's note that userspace using kernel services by normal syscalls doesn't
make the program a derived work — the same carve-out under which every
proprietary Linux application exists.

Note what that means: the userspace client is fine **regardless** of the
module's license. It isn't contagion being broken by a boundary; no contagion
ever crossed it.

The GPL obligation runs the other way. The module is GPL because it forks
`fs/fuse` (GPL-2.0-only) and because GPL-only exported symbols are refused at
load time for modules without a GPL-compatible `MODULE_LICENSE`. That is a
comfortable position, and notably *not* how ZFS-on-Linux is structured — which
is why that project carries a decade of licensing argument.

**The one thing that isn't clean:** shared headers. If your protocol header is a
copy or derivative of `include/uapi/linux/fuse.h`, it inherits that file's
license (GPL-2.0 WITH `Linux-syscall-note`). Functionally fine for userspace
use, but it isn't MIT and shouldn't be labeled as such. Write your extension
opcodes in a fresh header, dual-license it permissively, and have the module
include it rather than the reverse. Never paste struct definitions out of
`fuse.h` into a file stamped MIT.

The precedent a reviewer will recognize: `libfuse` (LGPL) against `fs/fuse`
(GPL) — the same split, working for twenty years.

---

## 7. Why this doesn't already exist

For the general FUSE audience, "no kernel module required" *is* the value
proposition. Ship DKMS and you've destroyed the reason anyone chose FUSE over
fixing cifs. That's the real reason the project doesn't exist — not difficulty,
but that it appears to defeat its own premise.

The two-mode design is the answer to that objection. Mode A needs no module and
is already a strictly better sshfs. Mode B is an optional upgrade for people who
need event delivery specifically. Nobody is blocked on a kernel patch, and the
degraded mode is genuinely good rather than a stub.

The secondary reason: the halves have different owners. Mode A lives entirely
inside one FUSE server — rclone could ship it tomorrow without asking anyone.
Mode B is a kernel change whose benefit accrues to every network filesystem
equally, which makes it nobody's specific problem.

---

## 8. Build order

Value lands in this sequence, and each stage is useful standing alone.

1. **Server agent + mode A invalidation.** Shippable and useful by itself.
   Proves the wire protocol. Turns every polling watcher on the client from
   useless to fine. No kernel code.
2. **Recovery tooling.** Script the abort-and-remount path; make it a one-liner.
   This is the property that motivated the whole design and it should be
   exercised deliberately, not discovered during an outage.
3. **FUSEX module.** Makes an already-working thing better. If it never
   materializes, stage 1 still stands.
4. **Transport work (QUIC).** Orthogonal, deferrable, and the least likely to
   matter on a LAN.

### Known unknowns

- `fsnotify()` signature churn across kernel versions — expect shims, expect
  maintenance
- fanotify path viability on the backing filesystem (`export_operations`)
- Behavior of the injected events under concurrent multi-client writes, where
  the server-side dedup approximation is weakest
- Whether `fuse_reverse_inval_entry()`'s locking constraints permit the
  `fsnotify()` call at that exact point, or whether it needs deferring to a
  workqueue

---

## 9. Honest scope

This does not produce a fast filesystem. It produces something roughly as fast
as sshfs that also keeps its cache honest, and optionally delivers real events.
Chattiness — a `LOOKUP` per path component, synchronous — remains. That's fine
at the sshfs bar, which is the bar; 9P is the cautionary tale for anyone hoping
a thin op-level tunnel scales to high-latency links.

There is also no recovery state machine. NFSv4 has client IDs, leases, grace
periods, reboot recovery; SMB has durable and persistent handles. A FUSE tunnel
has none of it, and FUSE's nodeid-plus-generation inode identity makes reconnect
render every cached reference meaningless — inventing stable file handles is
exactly what NFS file handles are and why `export_operations` exists.

"Any blip kills all your open fds" is, for this design's motivating use case,
the desired property rather than a defect. It is also unacceptable to the
enterprise storage world that funds network filesystem development, which is
part of why the people with resources to build this built NFS and SMB instead.

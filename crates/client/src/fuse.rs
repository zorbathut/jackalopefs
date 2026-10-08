//! The FUSE backend: every kernel request is copied out of the session thread and answered from a tokio task, so the session thread never waits on the network.

use crate::client::{CallNow, Client, Error, RequestKernel};
use crate::inodes::{KeyNode, NodeTable, ROOT};
use crate::invalidate::Work;
use crate::perf::{Outcome, Slowpath, TRACE_TARGET};
use crate::signals;
use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, InitFlags,
    KernelConfig, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus,
    ReplyEmpty, ReplyEntry, ReplyIoctl, ReplyLseek, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr,
    Request, RequestId,
};
use jackalopefs_perf::stall::{Ended, ErrorLockHeld, ModeScan, Progress, LOCK_PATIENCE};
use jackalopefs_proto::{
    Attr, DirEntry, FileKind, Name, Path, SetAttr, TimeOrNow, TimeSpec, Whence, MAX_IO,
};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Bytes of directory entries fetched from the server per request; the kernel asks for far less at a time, and the rest is served from the handle's buffer. The first fetch of a listing is smaller, since many readers stop after a few entries (an emptiness check, a file manager's "has children" probe) and every entry fetched is one the server described.
const READDIR_FETCH: u32 = 1024 * 1024;
const READDIR_FETCH_FIRST: u32 = 256 * 1024;

/// Concurrent background requests (readahead and the writeback of cached pages) the kernel may keep in flight; it bounds how many writes a flush has on the wire at once.
const MAX_BACKGROUND: u16 = 64;

/// State shared between the session thread and the request tasks.
pub struct Shared {
    pub client: Arc<Client>,
    pub nodes: Mutex<NodeTable>,
    dirs: Mutex<HashMap<u64, DirState>>,
    /// What the last attributes said about each inode's extended attribute names, kept for the attribute TTL; answers only the absence of a name and the list itself, never a value. Bounded by the node table: an entry leaves when the kernel forgets the inode.
    xattrs: Mutex<HashMap<u64, KnownXattrs>>,
    /// The size and mtime the server last reported for each regular file. The kernel discards both for a file it already holds (its writeback cache may be ahead of the server), so when a fresh reply disagrees and this client does not hold the file open, the file is taken away from the kernel by name and looked up afresh; that is what bounds an external change to the attribute TTL. A file this client wrote is dropped from the kernel, record included, when its last handle closes: what the server reported while our own writes were landing says nothing about what the kernel holds, and the kernel's own mtime may be behind the server's.
    reported: Mutex<HashMap<u64, AttrReported>>,
    /// Where to queue such invalidations; set while the invalidator runs.
    invalidations: Mutex<Option<std::sync::mpsc::SyncSender<Work>>>,
    /// The kernel requests being answered right now, by id, so an interrupt reaches the task answering one. Bounded by what the kernel keeps in flight. A request is registered on the session thread before its task is spawned, and the session has one thread, so the interrupt for a request is always read after the request was registered.
    inflight: Mutex<HashMap<u64, Answering>>,
    /// Kernel requests answered, and when the last one was.
    pub progress: Progress,
    /// Requests reported as stalled that have since been answered, for the watchdog to log.
    pub ended: Ended,
    /// The FUSE session thread, which reads every request off `/dev/fuse`; 0 until the first request after `init`.
    pub session_tid: AtomicI32,
    /// Set when this client starts unmounting, after which the session thread is meant to end.
    pub unmounting: AtomicBool,
    /// The invalidation thread's notifier call in progress, if one is; such a call is a blocking write to `/dev/fuse` that waits on kernel locks.
    pub notifier_busy: Mutex<Option<NotifierWork>>,
    /// Whether an interrupt stands for a signal (`crate::signals`).
    judge: signals::Judge,
    pub entry_ttl: Duration,
    pub attr_ttl: Duration,
}

/// A notifier call the invalidation thread is making.
#[derive(Clone, Copy, Debug)]
pub struct NotifierWork {
    pub kind: &'static str,
    /// The inode it is about: the parent directory for an entry.
    pub ino: u64,
    pub since: Instant,
}

/// A kernel request being answered, as a scan found it.
#[derive(Clone, Debug)]
pub struct Pending {
    pub key: KeyPerf,
    pub age: Duration,
    /// Whether its task has run at all.
    pub started: bool,
    /// The call it is making; `Err` when the call's lock was held past the watchdog's patience.
    pub call: Result<Option<CallNow>, ErrorLockHeld>,
}

/// What a scan of the in-flight table found.
#[derive(Clone, Debug)]
pub struct ScanPending {
    /// Kernel requests being answered.
    pub count: usize,
    /// The ones the scan selected, oldest first.
    pub found: Vec<Pending>,
}

struct KnownXattrs {
    names: Vec<Vec<u8>>,
    until: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct AttrReported {
    size: u64,
    mtime: TimeSpec,
}

/// Entries fetched from the server but not yet handed to the kernel, each tagged with the cookie that yields it. Every fetch carries attributes, so one buffer serves either kind of page.
type DirBuffer = VecDeque<(u64, DirEntry)>;

/// What a directory handle holds between kernel requests.
struct DirState {
    ino: u64,
    buffer: DirBuffer,
    /// When the buffer was fetched: its attributes are as old as that, and a readdirplus page hands them to the kernel to cache.
    fetched: Instant,
    /// The cookie after the last entry of a fetch that said the directory ended; a read there is answered empty without a round trip. A handle left at its end after a full listing reads there again, so a name added under the directory, by this client or reported by the server, clears it; the next fetch replaces it, and offset 0 always goes to the server so `rewinddir` sees everything regardless.
    end: Option<u64>,
}

pub struct Backend {
    shared: Arc<Shared>,
    runtime: tokio::runtime::Handle,
}

/// What identifies a kernel request in the trace line and the stall watchdog's.
#[derive(Clone, Copy, Debug)]
pub struct KeyPerf {
    pub op: &'static str,
    pub unique: u64,
    /// The thread blocked in the request, as the FUSE header gives it: 0 for one outside the mounter's pid namespace.
    pub pid: u32,
    pub ino: u64,
    pub fh: Option<u64>,
    pub offset: Option<u64>,
    pub size: Option<u64>,
}

impl KeyPerf {
    fn of(op: &'static str, req: &Request, ino: u64) -> KeyPerf {
        KeyPerf {
            op,
            unique: req.unique().0,
            pid: req.pid(),
            ino,
            fh: None,
            offset: None,
            size: None,
        }
    }
}

/// A kernel request being answered: the task's handle on it; what it is, including the thread blocked in it, which an interrupt for it is judged by (the FUSE header's pid is the kernel's task pid, a thread id); when it arrived; and the age at which the watchdog last reported it (zero if never).
struct Answering {
    request: Arc<RequestKernel>,
    key: KeyPerf,
    arrived: Instant,
    reported: Duration,
}

/// Takes a request out of the in-flight table when the task answering it ends, however it ends.
struct Registered {
    shared: Arc<Shared>,
    unique: u64,
    done: bool,
}

impl Registered {
    /// Take the request out of the table; it says whether the watchdog had reported it as stalled.
    fn finish(mut self) -> Option<Answering> {
        self.done = true;
        self.shared.inflight.lock().remove(&self.unique)
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        if !self.done {
            self.shared.inflight.lock().remove(&self.unique);
        }
    }
}

impl Backend {
    pub fn new(
        client: Arc<Client>,
        entry_ttl: Duration,
        attr_ttl: Duration,
        runtime: tokio::runtime::Handle,
    ) -> (Backend, Arc<Shared>) {
        let shared = Arc::new(Shared {
            client,
            nodes: Mutex::new(NodeTable::new()),
            dirs: Mutex::new(HashMap::new()),
            xattrs: Mutex::new(HashMap::new()),
            reported: Mutex::new(HashMap::new()),
            invalidations: Mutex::new(None),
            inflight: Mutex::new(HashMap::new()),
            progress: Progress::default(),
            ended: Ended::default(),
            session_tid: AtomicI32::new(0),
            unmounting: AtomicBool::new(false),
            notifier_busy: Mutex::new(None),
            judge: signals::Judge::for_this_process(),
            entry_ttl,
            attr_ttl,
        });
        (
            Backend {
                shared: shared.clone(),
                runtime,
            },
            shared,
        )
    }

    /// Answer one kernel request from a task, counting it as in flight until it is answered and recording what it took. The task's end is the moment the kernel has its answer: fuser replies with a synchronous `writev` to `/dev/fuse`, and every handler replies last.
    fn spawn<F: std::future::Future<Output = Outcome> + Send + 'static>(&self, key: KeyPerf, f: F) {
        // This runs on the session thread; fuser makes `init` on the mounting thread instead, so the first request is where the session thread can be named.
        if self.shared.session_tid.load(Ordering::Relaxed) == 0 {
            self.shared
                .session_tid
                .store(nix::unistd::gettid().as_raw(), Ordering::Relaxed);
        }
        let perf = self.shared.client.perf().clone();
        let started = Instant::now();
        let request = RequestKernel::new(key.unique);
        let registered = Registered {
            shared: self.shared.clone(),
            unique: key.unique,
            done: false,
        };
        self.shared.inflight.lock().insert(
            key.unique,
            Answering {
                request: request.clone(),
                key,
                arrived: started,
                reported: Duration::ZERO,
            },
        );
        let shared = self.shared.clone();
        self.runtime.spawn(async move {
            let inflight = perf.start();
            let outcome = request.scope(f).await;
            let answered = registered.finish();
            let total = started.elapsed();
            shared.progress.record();
            perf.record_fuse(key.op, &outcome, total);
            if answered.is_some_and(|a| !a.reported.is_zero()) {
                shared.ended.push(|| {
                    format!(
                        "fuse {} ino {} (unique {}) answered after {}, errno {}",
                        key.op,
                        key.ino,
                        key.unique,
                        jackalopefs_perf::fmt_duration(total),
                        outcome.errno
                    )
                });
            }
            if tracing::enabled!(target: TRACE_TARGET, tracing::Level::TRACE) {
                tracing::trace!(
                    target: TRACE_TARGET,
                    unique = key.unique,
                    pid = key.pid,
                    op = key.op,
                    ino = key.ino,
                    fh = key.fh,
                    offset = key.offset,
                    size = key.size,
                    bytes = outcome.bytes,
                    items = outcome.items,
                    errno = outcome.errno,
                    total_us = total.as_micros() as u64,
                    inflight = perf.inflight(),
                    "fuse"
                );
            }
            drop(inflight);
        });
    }
}

/// A reply that can carry an error, so one helper can both send it and report it as the request's outcome.
trait ReplyError {
    fn send_error(self, e: Errno);
}

macro_rules! reply_error {
    ($($reply:ty),*) => {
        $(impl ReplyError for $reply {
            fn send_error(self, e: Errno) {
                self.error(e)
            }
        })*
    };
}

reply_error!(
    ReplyAttr,
    ReplyCreate,
    ReplyData,
    ReplyDirectory,
    ReplyDirectoryPlus,
    ReplyEmpty,
    ReplyEntry,
    ReplyIoctl,
    ReplyLseek,
    ReplyOpen,
    ReplyStatfs,
    ReplyWrite,
    ReplyXattr
);

fn fail<R: ReplyError>(reply: R, e: Errno) -> Outcome {
    reply.send_error(e);
    Outcome::errno(i32::from(e))
}

fn errno(e: &Error) -> Errno {
    Errno::from_i32(e.errno())
}

fn system_time(t: TimeSpec) -> SystemTime {
    let base = if t.sec >= 0 {
        UNIX_EPOCH + Duration::from_secs(t.sec as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(t.sec.unsigned_abs())
    };
    base + Duration::from_nanos(t.nsec as u64)
}

fn timespec(t: SystemTime) -> TimeSpec {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => TimeSpec {
            sec: d.as_secs() as i64,
            nsec: d.subsec_nanos(),
        },
        Err(before) => {
            let d = before.duration();
            if d.subsec_nanos() == 0 {
                TimeSpec {
                    sec: -(d.as_secs() as i64),
                    nsec: 0,
                }
            } else {
                TimeSpec {
                    sec: -(d.as_secs() as i64) - 1,
                    nsec: 1_000_000_000 - d.subsec_nanos(),
                }
            }
        }
    }
}

fn time_or_now(t: fuser::TimeOrNow) -> TimeOrNow {
    match t {
        fuser::TimeOrNow::SpecificTime(t) => TimeOrNow::Time(timespec(t)),
        fuser::TimeOrNow::Now => TimeOrNow::Now,
    }
}

fn file_type(kind: FileKind) -> FileType {
    match kind {
        FileKind::Regular => FileType::RegularFile,
        FileKind::Directory => FileType::Directory,
        FileKind::Symlink => FileType::Symlink,
        FileKind::Fifo => FileType::NamedPipe,
        FileKind::Socket => FileType::Socket,
        FileKind::CharDevice => FileType::CharDevice,
        FileKind::BlockDevice => FileType::BlockDevice,
    }
}

/// Every node keeps this generation for ever: a node's number is never given to another file while the kernel remembers it, which is all a generation is for.
const GENERATION: Generation = Generation(0);

/// The kernel's attributes for the node `id`, which is also the `st_ino` userspace sees (fuser has one field for both).
fn file_attr(id: u64, attr: &Attr) -> FileAttr {
    FileAttr {
        ino: INodeNo(id),
        size: attr.size,
        blocks: attr.blocks,
        atime: system_time(attr.atime),
        mtime: system_time(attr.mtime),
        ctime: system_time(attr.ctime),
        crtime: system_time(attr.ctime),
        kind: file_type(attr.kind),
        perm: attr.perm,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: attr.rdev as u32,
        blksize: attr.blksize,
        flags: 0,
    }
}

/// Attributes for `.`/`..` in a readdirplus reply; the kernel ignores everything but the inode number for those two names.
fn dir_placeholder(ino: u64) -> FileAttr {
    FileAttr {
        ino: INodeNo(ino),
        size: 0,
        blocks: 0,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::Directory,
        perm: 0o755,
        nlink: 2,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

/// Whether a setattr has the shape of the kernel's own flush of the times it keeps for a written file: a modification time given as a value, and nothing else that reaches the handler (the change time that comes with it is not settable and is dropped before this). A `utimensat` that sets only the modification time has the same shape.
fn setattr_flushes_times(set: &SetAttr) -> bool {
    matches!(set.mtime, Some(TimeOrNow::Time(_)))
        && set.atime.is_none()
        && set.mode.is_none()
        && set.uid.is_none()
        && set.gid.is_none()
        && set.size.is_none()
}

/// Attributes for the reply to a time flush that was not sent (see [`Shared::unlinked_file`]); the kernel ignores them.
fn unlinked_placeholder(ino: u64) -> FileAttr {
    FileAttr {
        kind: FileType::RegularFile,
        perm: 0,
        nlink: 0,
        ..dir_placeholder(ino)
    }
}

/// The open flags the server gets. With the kernel caching writes, it reads through write handles (to fill the rest of a partially written page) and positions appends itself from its own idea of the size, so the server's descriptor must be readable and must not append on its own: a server-side `O_APPEND` would put every re-flushed page at the end. The price is that a file writable but not readable (mode 0222) cannot be opened for writing through the mount.
fn flags_for_server(flags: i32) -> i32 {
    let flags = flags & !libc::O_APPEND;
    if flags & libc::O_ACCMODE == libc::O_WRONLY {
        (flags & !libc::O_ACCMODE) | libc::O_RDWR
    } else {
        flags
    }
}

fn name_of(os: &OsStr) -> Result<Name, Errno> {
    Name::try_from(os).map_err(|e| match e {
        jackalopefs_proto::ErrorName::TooLong => Errno::ENAMETOOLONG,
        _ => Errno::EINVAL,
    })
}

impl Shared {
    /// Whether `/proc` is this process's pid namespace's, so the thread ids the kernel sends and this process's own name threads there.
    pub fn proc_ours(&self) -> bool {
        self.judge.proc_ours()
    }

    /// The kernel requests being answered that `mode` selects, oldest first. The table's lock is waited for at most [`LOCK_PATIENCE`] and held only to copy entries out; each call's lock is then taken alone, never inside it. `Err` when the table's lock was held longer than that, which in a hang is itself the finding.
    pub fn scan_pending(&self, now: Instant, mode: ModeScan) -> Result<ScanPending, ErrorLockHeld> {
        let (count, selected) = {
            let mut inflight = self
                .inflight
                .try_lock_for(LOCK_PATIENCE)
                .ok_or(ErrorLockHeld)?;
            let count = inflight.len();
            let selected: Vec<(KeyPerf, Duration, Arc<RequestKernel>)> = inflight
                .values_mut()
                .filter_map(|a| {
                    let age = now.saturating_duration_since(a.arrived);
                    mode.selects(age, &mut a.reported)
                        .then(|| (a.key, age, a.request.clone()))
                })
                .collect();
            (count, selected)
        };
        let mut found: Vec<Pending> = selected
            .into_iter()
            .map(|(key, age, request)| Pending {
                key,
                age,
                started: request.started(),
                call: request.call_now(LOCK_PATIENCE),
            })
            .collect();
        found.sort_by_key(|i| std::cmp::Reverse(i.age));
        Ok(ScanPending { count, found })
    }

    fn path_of(&self, ino: u64) -> Result<Path, Errno> {
        self.nodes.lock().path_of(ino).ok_or(Errno::ESTALE)
    }

    /// The path and handle for an operation that may carry a handle. An unlinked-but-open file has no path, and then a handle is all the server gets: the one the kernel sent, or any handle still open on the inode, because `fstat` and the `f*` attribute calls (`fchmod`, `fchown`, `futimens`) arrive without one. Any live handle serves: attributes are read and set through the descriptor whatever it was opened for, and a size change always carries the kernel's own handle.
    fn path_for_handle_op(
        &self,
        ino: u64,
        fh: Option<u64>,
    ) -> Result<(Option<Path>, Option<u64>), Errno> {
        if let Some(path) = self.nodes.lock().path_of(ino) {
            return Ok((Some(path), fh));
        }
        match fh.or_else(|| self.client.handles().any_live_for(ino)) {
            Some(fh) => Ok((None, Some(fh))),
            None => Err(Errno::ESTALE),
        }
    }

    /// Whether `ino` is a regular file this client can no longer address by any name it knew. With no handle open either, the kernel's flush of the file's times (see [`setattr_flushes_times`]) has nowhere to go and is answered without the server: the kernel ignores that reply, while an error would be recorded against the whole mount and fail its next `syncfs`. `docs/design.md`, "Node table", has what that gives up.
    fn unlinked_file(&self, ino: u64) -> bool {
        self.nodes
            .lock()
            .get(ino)
            .is_some_and(|node| node.unlinked && node.kind == FileKind::Regular)
    }

    /// Whether `attr`, the reply to a request that addressed node `id` by path, describes the file the node is. Nothing else checks: the kernel takes whatever attributes it is given for the inode it asked about, inode number included. The root is whatever the server says it is, there being no other way to reach it.
    fn describes(&self, id: u64, attr: &Attr) -> bool {
        if id == ROOT {
            return true;
        }
        let nodes = self.nodes.lock();
        let known = nodes.get(id).and_then(|node| node.key.as_ref());
        if known.is_some_and(|key| key.describes(attr)) {
            return true;
        }
        tracing::debug!(node = id, was = ?known, now = ?KeyNode::of(attr), "the path to a node led to another file");
        self.client.perf().count(Slowpath::AliasStale);
        false
    }

    /// `path`, by which node `id` was addressed, led to another file (see [`Self::describes`]): forget that name here and in the kernel, so the next request for the node goes by another name, or fails with `ESTALE` if it has none, and the next lookup of the name finds what is there now.
    fn alias_was_wrong(&self, id: u64, path: &Path) {
        let Some((parent, name)) = self.nodes.lock().alias_was_wrong(id, path) else {
            return;
        };
        match self.invalidations.lock().as_ref() {
            Some(tx) => {
                if let Err(e) = tx.try_send(Work::Entry(parent, name)) {
                    tracing::debug!(node = id, "cannot queue an entry invalidation: {e}");
                }
            }
            None => tracing::debug!(node = id, "no invalidation queue to drop the name through"),
        }
    }

    /// For an open of node `id` by `path`: the node, if `attr` describes its file. If not, the name goes (see [`Self::alias_was_wrong`]), `wrong_name` says so, and the open is refused, for the caller to try the node's next name.
    fn same_file(
        &self,
        id: u64,
        path: &Path,
        attr: &Attr,
        wrong_name: &AtomicBool,
    ) -> Result<u64, Error> {
        if self.describes(id, attr) {
            return Ok(id);
        }
        self.alias_was_wrong(id, path);
        wrong_name.store(true, Ordering::Relaxed);
        Err(Error::Stale)
    }

    fn parent_of(&self, ino: u64) -> u64 {
        self.nodes
            .lock()
            .get(ino)
            .and_then(|n| n.aliases.last().map(|(p, _)| *p))
            .unwrap_or(ROOT)
    }

    /// Keep what the attributes say about the inode's xattr names for the attribute TTL; attributes that did not look replace whatever was known, since the server may since have declined to say.
    fn xattr_remember(&self, id: u64, attr: &Attr) {
        let mut xattrs = self.xattrs.lock();
        match &attr.xattr_names {
            Some(names) => {
                xattrs.insert(
                    id,
                    KnownXattrs {
                        names: names.clone(),
                        until: Instant::now() + self.attr_ttl,
                    },
                );
            }
            None => {
                xattrs.remove(&id);
            }
        }
    }

    pub fn xattr_forget(&self, ino: u64) {
        self.xattrs.lock().remove(&ino);
    }

    pub fn invalidations_set(&self, tx: std::sync::mpsc::SyncSender<Work>) {
        *self.invalidations.lock() = Some(tx);
    }

    pub fn invalidations_clear(&self) {
        *self.invalidations.lock() = None;
    }

    /// Record what the server reports about a regular file's size and mtime; when that differs from last time and this client is not writing the file, someone else changed it, and the kernel, which keeps its own view of a file it holds, is made to drop the file by name so an unopened one is looked up afresh.
    fn attr_reported(&self, id: u64, attr: &Attr) {
        if attr.kind != FileKind::Regular {
            return;
        }
        let now = AttrReported {
            size: attr.size,
            mtime: attr.mtime,
        };
        let changed = {
            let mut reported = self.reported.lock();
            match reported.get(&id) {
                Some(before) => *before != now,
                None => {
                    reported.insert(id, now);
                    false
                }
            }
        };
        // A file held open cannot be evicted, and while we write it the server's view is noise; the record stays behind so the first reply after the last close detects the change and drops the file then.
        if !changed || self.client.handles().any_live_for(id).is_some() {
            return;
        }
        // The record moves only once the invalidation is queued; until then it stays behind so the next reply detects the same change again.
        if self.drop_by_name(id) {
            self.client.perf().count(Slowpath::FileDroppedFromKernel);
            self.reported.lock().insert(id, now);
        }
    }

    /// Queue an entry invalidation for every name the kernel knows `ino` by, which evicts the inode if nothing holds it, so the next access looks it up afresh; false if the queue is full or gone, with the reason logged.
    fn drop_by_name(&self, ino: u64) -> bool {
        let aliases = self
            .nodes
            .lock()
            .get(ino)
            .map(|node| node.aliases.clone())
            .unwrap_or_default();
        let invalidations = self.invalidations.lock();
        let Some(tx) = invalidations.as_ref() else {
            tracing::debug!(ino, "no invalidation queue to drop the file through");
            return false;
        };
        for (parent, name) in aliases {
            if let Err(e) = tx.try_send(Work::Entry(parent, name)) {
                tracing::debug!(ino, "cannot queue an entry invalidation: {e}");
                return false;
            }
        }
        true
    }

    fn reported_forget(&self, ino: u64) {
        self.reported.lock().remove(&ino);
    }

    pub fn xattr_clear(&self) {
        self.xattrs.lock().clear();
    }

    /// Whether fresh names say the inode has no attribute called `name`; anything less certain means asking the server.
    fn xattr_known_absent(&self, ino: u64, name: &[u8]) -> bool {
        match self.xattrs.lock().get(&ino) {
            Some(known) => known.until > Instant::now() && !known.names.iter().any(|n| n == name),
            None => false,
        }
    }

    /// The `listxattr` reply (each name followed by a NUL) when the names are known and fresh.
    fn xattr_known_list(&self, ino: u64) -> Option<Vec<u8>> {
        match self.xattrs.lock().get(&ino) {
            Some(known) if known.until > Instant::now() => Some(
                known
                    .names
                    .iter()
                    .flat_map(|n| n.iter().copied().chain(std::iter::once(0)))
                    .collect(),
            ),
            _ => None,
        }
    }

    /// Register a successful entry reply and return the node it describes.
    fn register(&self, parent: u64, name: Name, attr: &Attr) -> Result<u64, Errno> {
        let id = self
            .nodes
            .lock()
            .insert_lookup(parent, name, attr.into())
            .ok_or(Errno::EIO)?;
        self.xattr_remember(id, attr);
        self.attr_reported(id, attr);
        Ok(id)
    }

    /// Answer a request that created `name` under `parent`: the directory grew, then as `reply_entry`.
    fn reply_created(&self, reply: ReplyEntry, parent: u64, name: Name, attr: &Attr) -> Outcome {
        self.dir_grew(parent);
        self.reply_entry(reply, parent, name, attr)
    }

    /// Answer an entry-producing request: register the node and reply with its attributes and generation.
    fn reply_entry(&self, reply: ReplyEntry, parent: u64, name: Name, attr: &Attr) -> Outcome {
        match self.register(parent, name, attr) {
            Ok(id) => {
                reply.entry_with_ttls(
                    &self.attr_ttl,
                    &self.entry_ttl,
                    &file_attr(id, attr),
                    GENERATION,
                );
                Outcome::default()
            }
            Err(e) => fail(reply, e),
        }
    }

    /// A page starting at `offset`: the buffer when it continues where the kernel left off, and the server otherwise; for a readdirplus page (`plus`), whose attributes the kernel caches, only a buffer younger than the attribute TTL. A handle without a buffer has been released.
    async fn dir_page(&self, fh: u64, offset: u64, plus: bool) -> Result<DirBuffer, Error> {
        {
            let mut dirs = self.dirs.lock();
            let state = dirs.get_mut(&fh).ok_or(Error::Remote(libc::EBADF))?;
            let fresh = !plus || state.fetched.elapsed() < self.attr_ttl;
            if offset != 0
                && fresh
                && state
                    .buffer
                    .front()
                    .is_some_and(|(cookie, _)| *cookie == offset)
            {
                return Ok(std::mem::take(&mut state.buffer));
            }
            state.buffer.clear();
            if offset != 0 && state.end == Some(offset) {
                return Ok(DirBuffer::new());
            }
        }
        let fetch = if offset == 0 {
            READDIR_FETCH_FIRST
        } else {
            READDIR_FETCH
        };
        let (entries, end) = self.client.readdir(fh, offset, fetch).await?;
        if let Some(state) = self.dirs.lock().get_mut(&fh) {
            state.fetched = Instant::now();
        }
        self.note_end(fh, entries.last().map(|e| e.next_offset), end);
        Ok(tag_with_cookies(entries, offset, |e| e.next_offset).into())
    }

    /// Keep what the kernel's buffer did not take for its next request on the handle.
    fn stash(&self, fh: u64, rest: DirBuffer) {
        if let Some(state) = self.dirs.lock().get_mut(&fh) {
            state.buffer = rest;
        }
    }

    /// Record where a fetch said the directory ended, or that it did not end at its last entry. A fetch with no entries says nothing about the cookies it did not cover, and it has already paid the round trip that recording could save.
    fn note_end(&self, fh: u64, last: Option<u64>, end: bool) {
        let Some(last) = last else { return };
        if let Some(state) = self.dirs.lock().get_mut(&fh) {
            state.end = end.then_some(last);
        }
    }

    /// A name was added under `ino`: a handle parked at the directory's end must ask the server again.
    pub(crate) fn dir_grew(&self, ino: u64) {
        for state in self.dirs.lock().values_mut() {
            if state.ino == ino {
                state.end = None;
            }
        }
    }

    /// Anything may have been added anywhere: every parked handle must ask the server again.
    pub(crate) fn dirs_grew_all(&self) {
        for state in self.dirs.lock().values_mut() {
            state.end = None;
        }
    }

    /// Hand a plain page to the kernel until its buffer is full; what it did not take comes back to be stashed.
    fn add_plain(
        &self,
        reply: &mut ReplyDirectory,
        ino: u64,
        entries: DirBuffer,
    ) -> (usize, DirBuffer) {
        let mut entries = entries.into_iter();
        let mut added = 0;
        let parent = self.parent_of(ino);
        let nodes = self.nodes.lock();
        while let Some((cookie, entry)) = entries.next() {
            let Some(number) = plain_number(&nodes, ino, parent, &entry) else {
                tracing::warn!(dir = ino, name = %String::from_utf8_lossy(&entry.name), "directory entry without attributes; skipped");
                continue;
            };
            // The dots are directories, and every other entry numbered has attributes.
            let kind = entry
                .attr
                .as_ref()
                .map_or(FileKind::Directory, |attr| attr.kind);
            if reply.add(
                INodeNo(number),
                entry.next_offset,
                file_type(kind),
                OsStr::from_bytes(&entry.name),
            ) {
                let mut rest = VecDeque::from([(cookie, entry)]);
                rest.extend(entries);
                return (added, rest);
            }
            added += 1;
        }
        (added, VecDeque::new())
    }
}

/// The number a plain page lists an entry of directory `dir` (whose parent is `parent`) under: the one the node table gives the file, which is what a lookup of it registers and `stat` then reports, substitute included, without registering anything, since a plain page takes no lookup count. `None` for an entry without attributes, which cannot be numbered.
fn plain_number(nodes: &NodeTable, dir: u64, parent: u64, entry: &DirEntry) -> Option<u64> {
    match entry.name.as_slice() {
        b"." => Some(dir),
        b".." => Some(parent),
        _ => entry.attr.as_ref().map(|attr| nodes.id_for(attr.into())),
    }
}

/// Pair each entry with the cookie that yields it: the request offset for the first, the previous entry's `next_offset` after that.
fn tag_with_cookies<T>(entries: Vec<T>, first: u64, next: impl Fn(&T) -> u64) -> Vec<(u64, T)> {
    let mut cookie = first;
    entries
        .into_iter()
        .map(|e| {
            let tagged = (cookie, e);
            cookie = next(&tagged.1);
            tagged
        })
        .collect()
}

impl Filesystem for Backend {
    /// Each setter answers with the previous value when it accepts and the ceiling when it refuses, so what is logged is the value asked for or the ceiling it hit. The kernel proposes its own readahead (the mount's `bdi` setting, 128 KiB by default) and lets the daemon only lower it, so the readahead cap is the usual outcome and it bounds every read the kernel will ever issue; the effective values are read from sysfs after mounting.
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        let max_write = config
            .set_max_write(MAX_IO as u32)
            .map_or_else(|limit| limit, |_| MAX_IO as u32);
        let max_readahead = config
            .set_max_readahead(MAX_IO as u32)
            .map_or_else(|limit| limit, |_| MAX_IO as u32);
        let max_background = config
            .set_max_background(MAX_BACKGROUND)
            .map_or_else(|limit| limit, |_| MAX_BACKGROUND);
        let wanted = InitFlags::FUSE_ATOMIC_O_TRUNC
            | InitFlags::FUSE_ASYNC_READ
            | InitFlags::FUSE_PARALLEL_DIROPS
            | InitFlags::FUSE_AUTO_INVAL_DATA
            | InitFlags::FUSE_DO_READDIRPLUS
            | InitFlags::FUSE_READDIRPLUS_AUTO
            | InitFlags::FUSE_WRITEBACK_CACHE;
        let supported = wanted & config.capabilities();
        let missing = wanted - supported;
        if !missing.is_empty() {
            tracing::warn!(
                ?missing,
                "kernel does not offer some wanted FUSE capabilities"
            );
        }
        if let Err(rejected) = config.add_capabilities(supported) {
            tracing::debug!(?rejected, "kernel rejected capabilities it advertised");
        }
        tracing::info!(
            max_write,
            max_readahead,
            max_background,
            capabilities = ?supported,
            "FUSE parameters: asked for {MAX_IO} bytes of write and readahead and {MAX_BACKGROUND} background requests"
        );
        Ok(())
    }

    /// The kernel interrupts a request whenever the thread blocked in it has a signal pending by its reckoning, which counts task work (an io_uring completion, a freezer, a tracer's stop) as well as signals. Only a real signal abandons the call, with `EINTR` (`signals::Judge`). Otherwise the call goes on, and since the kernel sends no second interrupt for a request, a watcher looks for a real signal until the request is answered. A request already answered is ignored, as the kernel does.
    fn interrupt(&self, _req: &Request, unique: RequestId) {
        let Some((request, tid)) = self
            .shared
            .inflight
            .lock()
            .get(&unique.0)
            .map(|a| (a.request.clone(), a.key.pid))
        else {
            tracing::trace!(
                unique = unique.0,
                "interrupt for a request already answered"
            );
            return;
        };
        let stands = self.shared.judge.stands(tid);
        let perf = self.shared.client.perf();
        perf.count(Slowpath::Interrupt);
        if !stands {
            perf.count(Slowpath::InterruptIgnored);
        }
        if stands {
            request.interrupt();
            return;
        }
        tracing::debug!(unique = unique.0, tid, "interrupt without a pending signal (task work such as an io_uring completion); the call goes on");
        // The in-flight table and the task answering the request hold it; once both let go it is answered, and the watcher stops.
        let request = Arc::downgrade(&request);
        let shared = self.shared.clone();
        self.runtime.spawn(async move {
            loop {
                tokio::time::sleep(signals::RECHECK).await;
                let Some(request) = request.upgrade() else {
                    return;
                };
                if shared.judge.signal_came(tid) {
                    request.interrupt();
                    return;
                }
            }
        });
    }

    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let shared = self.shared.clone();
        let name = match name_of(name) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        self.spawn(KeyPerf::of("lookup", req, parent.0), async move {
            let path = match shared.path_of(parent.0) {
                Ok(path) => path,
                Err(e) => return fail(reply, e),
            };
            match shared.client.lookup(path, name.clone()).await {
                Ok(attr) => shared.reply_entry(reply, parent.0, name, &attr),
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        if self.shared.nodes.lock().forget(ino.0, nlookup) {
            self.shared.xattr_forget(ino.0);
            self.shared.reported_forget(ino.0);
        }
    }

    fn getattr(&self, req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        let shared = self.shared.clone();
        let fh = fh.map(|f| f.0);
        let key = KeyPerf {
            fh,
            ..KeyPerf::of("getattr", req, ino.0)
        };
        self.spawn(key, async move {
            // A reply by handle is the handle's file. One by path is whatever the path leads to now, and if that is another file the node is tried by its next name.
            let attr = loop {
                let (path, fh) = match shared.path_for_handle_op(ino.0, fh) {
                    Ok(path) => path,
                    Err(e) => return fail(reply, e),
                };
                match shared.client.getattr(path.clone(), fh).await {
                    Ok(attr) if fh.is_some() || shared.describes(ino.0, &attr) => break Ok(attr),
                    Ok(_) => shared.alias_was_wrong(ino.0, &path.unwrap_or_else(Path::root)),
                    Err(e) => break Err(e),
                }
            };
            match attr {
                Ok(attr) => {
                    if ino.0 == ROOT {
                        shared.nodes.lock().root_seen(&attr.identity);
                    }
                    shared.xattr_remember(ino.0, &attr);
                    shared.attr_reported(ino.0, &attr);
                    reply.attr(&shared.attr_ttl, &file_attr(ino.0, &attr));
                    Outcome::default()
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        // ctime cannot be set on Linux and the remaining fields are macOS-only; they are dropped on purpose.
        let shared = self.shared.clone();
        let fh = fh.map(|f| f.0);
        // A setattr that sets neither size nor mtime only observes them, and what it observes is checked like any other reply.
        let observes_only = size.is_none() && mtime.is_none();
        let set = SetAttr {
            mode,
            uid,
            gid,
            size,
            atime: atime.map(time_or_now),
            mtime: mtime.map(time_or_now),
        };
        let key = KeyPerf {
            fh,
            size,
            ..KeyPerf::of("setattr", req, ino.0)
        };
        let flushes_times = setattr_flushes_times(&set);
        self.spawn(key, async move {
            // As for getattr, except that a change sent down a path that led elsewhere has been made to that other file by the time the reply says so; it is made again to the right one.
            let attr = loop {
                let (path, fh) = match shared.path_for_handle_op(ino.0, fh) {
                    Ok(path) => path,
                    Err(e) => {
                        if flushes_times && shared.unlinked_file(ino.0) {
                            tracing::debug!(
                                ino = ino.0,
                                "times of an unlinked file are not flushed"
                            );
                            reply.attr(&Duration::ZERO, &unlinked_placeholder(ino.0));
                            return Outcome::default();
                        }
                        return fail(reply, e);
                    }
                };
                match shared.client.setattr(path.clone(), fh, set).await {
                    Ok(attr) if fh.is_some() || shared.describes(ino.0, &attr) => break Ok(attr),
                    Ok(_) => shared.alias_was_wrong(ino.0, &path.unwrap_or_else(Path::root)),
                    Err(e) => break Err(e),
                }
            };
            match attr {
                Ok(attr) => {
                    shared.xattr_remember(ino.0, &attr);
                    if observes_only {
                        shared.attr_reported(ino.0, &attr);
                    } else {
                        // Our own change: the kernel already knows the new size and time, so only the record moves.
                        shared.reported.lock().insert(
                            ino.0,
                            AttrReported {
                                size: attr.size,
                                mtime: attr.mtime,
                            },
                        );
                    }
                    reply.attr(&shared.attr_ttl, &file_attr(ino.0, &attr));
                    Outcome::default()
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn readlink(&self, req: &Request, ino: INodeNo, reply: ReplyData) {
        let shared = self.shared.clone();
        self.spawn(KeyPerf::of("readlink", req, ino.0), async move {
            let path = match shared.path_of(ino.0) {
                Ok(path) => path,
                Err(e) => return fail(reply, e),
            };
            match shared.client.readlink(path).await {
                Ok(target) => {
                    reply.data(&target);
                    Outcome::bytes(target.len())
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        let shared = self.shared.clone();
        let name = match name_of(name) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        self.spawn(KeyPerf::of("mknod", req, parent.0), async move {
            let path = match shared.path_of(parent.0) {
                Ok(path) => path,
                Err(e) => return fail(reply, e),
            };
            match shared
                .client
                .mknod(path, name.clone(), mode, rdev as u64)
                .await
            {
                Ok(attr) => shared.reply_created(reply, parent.0, name, &attr),
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let shared = self.shared.clone();
        let name = match name_of(name) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        self.spawn(KeyPerf::of("mkdir", req, parent.0), async move {
            let path = match shared.path_of(parent.0) {
                Ok(path) => path,
                Err(e) => return fail(reply, e),
            };
            match shared.client.mkdir(path, name.clone(), mode).await {
                Ok(attr) => shared.reply_created(reply, parent.0, name, &attr),
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let shared = self.shared.clone();
        let name = match name_of(name) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        self.spawn(KeyPerf::of("unlink", req, parent.0), async move {
            let path = match shared.path_of(parent.0) {
                Ok(path) => path,
                Err(e) => return fail(reply, e),
            };
            match shared.client.unlink(path, name.clone()).await {
                Ok(()) => {
                    shared.nodes.lock().unlink(parent.0, &name);
                    reply.ok();
                    Outcome::default()
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let shared = self.shared.clone();
        let name = match name_of(name) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        self.spawn(KeyPerf::of("rmdir", req, parent.0), async move {
            let path = match shared.path_of(parent.0) {
                Ok(path) => path,
                Err(e) => return fail(reply, e),
            };
            match shared.client.rmdir(path, name.clone()).await {
                Ok(()) => {
                    shared.nodes.lock().unlink(parent.0, &name);
                    reply.ok();
                    Outcome::default()
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &std::path::Path,
        reply: ReplyEntry,
    ) {
        let shared = self.shared.clone();
        let name = match name_of(link_name) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        let target = target.as_os_str().as_bytes().to_vec();
        self.spawn(KeyPerf::of("symlink", req, parent.0), async move {
            let path = match shared.path_of(parent.0) {
                Ok(path) => path,
                Err(e) => return fail(reply, e),
            };
            match shared.client.symlink(path, name.clone(), target).await {
                Ok(attr) => shared.reply_created(reply, parent.0, name, &attr),
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: fuser::RenameFlags,
        reply: ReplyEmpty,
    ) {
        let shared = self.shared.clone();
        let (name, newname) = match (name_of(name), name_of(newname)) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => return reply.error(e),
        };
        let exchange = flags.contains(fuser::RenameFlags::RENAME_EXCHANGE);
        let flags = flags.bits();
        self.spawn(KeyPerf::of("rename", req, parent.0), async move {
            let (path, newpath) = match (shared.path_of(parent.0), shared.path_of(newparent.0)) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => return fail(reply, e),
            };
            match shared
                .client
                .rename(path, name.clone(), newpath, newname.clone(), flags)
                .await
            {
                Ok(()) => {
                    let mut nodes = shared.nodes.lock();
                    if exchange {
                        nodes.exchange(parent.0, &name, newparent.0, &newname);
                    } else {
                        nodes.rename(parent.0, &name, newparent.0, newname);
                    }
                    drop(nodes);
                    shared.dir_grew(newparent.0);
                    reply.ok();
                    Outcome::default()
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn link(
        &self,
        req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let shared = self.shared.clone();
        let newname = match name_of(newname) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        self.spawn(KeyPerf::of("link", req, ino.0), async move {
            let (path, newpath) = match (shared.path_of(ino.0), shared.path_of(newparent.0)) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => return fail(reply, e),
            };
            match shared
                .client
                .link(path.clone(), newpath, newname.clone())
                .await
            {
                Ok(attr) => {
                    // The reply describes the file that was linked. If the path led to another than the one meant, the new name is that other file's, and is registered as such.
                    if !shared.describes(ino.0, &attr) {
                        shared.alias_was_wrong(ino.0, &path);
                    }
                    shared.reply_created(reply, newparent.0, newname, &attr)
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: fuser::OpenFlags, reply: ReplyOpen) {
        let shared = self.shared.clone();
        let flags = flags_for_server(flags.0);
        self.spawn(KeyPerf::of("open", req, ino.0), async move {
            // A path that led to another file costs the node that name, and the open is tried by the next.
            let opened = loop {
                let path = match shared.path_of(ino.0) {
                    Ok(path) => path,
                    Err(e) => return fail(reply, e),
                };
                let (meant, by, wrong_name) =
                    (shared.clone(), path.clone(), AtomicBool::new(false));
                let opened = shared
                    .client
                    .open(path, flags, |attr| {
                        meant.same_file(ino.0, &by, attr, &wrong_name)
                    })
                    .await;
                if !wrong_name.load(Ordering::Relaxed) {
                    break opened;
                }
            };
            match opened {
                Ok((fh, attr)) => {
                    shared.xattr_remember(ino.0, &attr);
                    shared.attr_reported(ino.0, &attr);
                    reply.opened(FileHandle(fh), FopenFlags::empty());
                    Outcome::default()
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let shared = self.shared.clone();
        let name = match name_of(name) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        let flags = flags_for_server(flags);
        self.spawn(KeyPerf::of("create", req, parent.0), async move {
            let path = match shared.path_of(parent.0) {
                Ok(path) => path,
                Err(e) => return fail(reply, e),
            };
            let mut node = None;
            let registering = shared.clone();
            let created = shared
                .client
                .create(path, name.clone(), mode, flags, |attr| {
                    registering.dir_grew(parent.0);
                    let registered = registering
                        .register(parent.0, name, attr)
                        .map_err(|e| Error::Remote(i32::from(e)))?;
                    node = Some(registered);
                    Ok(registered)
                })
                .await;
            match (created, node) {
                (Ok((fh, attr)), Some(id)) => {
                    reply.created(
                        &shared.entry_ttl.min(shared.attr_ttl),
                        &file_attr(id, &attr),
                        GENERATION,
                        FileHandle(fh),
                        FopenFlags::empty(),
                    );
                    Outcome::default()
                }
                (Ok(_), None) => {
                    tracing::error!(
                        "a create succeeded without registering its node; this is a bug"
                    );
                    fail(reply, Errno::EIO)
                }
                (Err(e), _) => fail(reply, errno(&e)),
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let shared = self.shared.clone();
        let key = KeyPerf {
            fh: Some(fh.0),
            offset: Some(offset),
            size: Some(size as u64),
            ..KeyPerf::of("read", req, ino.0)
        };
        self.spawn(key, async move {
            match shared.client.read(fh.0, offset, size).await {
                Ok(data) => {
                    reply.data(&data);
                    Outcome::bytes(data.len())
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        let shared = self.shared.clone();
        let data = data.to_vec();
        let key = KeyPerf {
            fh: Some(fh.0),
            offset: Some(offset),
            size: Some(data.len() as u64),
            ..KeyPerf::of("write", req, ino.0)
        };
        self.spawn(key, async move {
            match shared.client.write(fh.0, offset, data).await {
                Ok(n) => {
                    reply.written(n);
                    Outcome::bytes(n as usize)
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn copy_file_range(
        &self,
        req: &Request,
        _ino_in: INodeNo,
        fh_in: FileHandle,
        offset_in: u64,
        ino_out: INodeNo,
        fh_out: FileHandle,
        offset_out: u64,
        len: u64,
        flags: fuser::CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        let shared = self.shared.clone();
        let key = KeyPerf {
            fh: Some(fh_out.0),
            offset: Some(offset_out),
            size: Some(len),
            ..KeyPerf::of("copy_file_range", req, ino_out.0)
        };
        self.spawn(key, async move {
            // `copy_file_range(2)` defines no flags; one a later kernel adds must be refused, not ignored.
            if !flags.is_empty() {
                return fail(reply, Errno::EINVAL);
            }
            let copied = shared
                .client
                .copy_file_range(fh_in.0, offset_in, fh_out.0, offset_out, len)
                .await;
            match copied {
                Ok(n) => {
                    reply.written(n);
                    Outcome::bytes(n as usize)
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn fallocate(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        let shared = self.shared.clone();
        let key = KeyPerf {
            fh: Some(fh.0),
            offset: Some(offset),
            size: Some(length),
            ..KeyPerf::of("fallocate", req, ino.0)
        };
        self.spawn(key, async move {
            match shared.client.fallocate(fh.0, offset, length, mode).await {
                Ok(()) => {
                    reply.ok();
                    Outcome::default()
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    /// The kernel asks only for `SEEK_DATA` and `SEEK_HOLE`, and without writing anything back first, so while it may hold pages the server has not seen, the server's answer could call data just written a hole, or past the end, and a copy that skips holes would drop it. The seek is refused then, with the errno of a filesystem that cannot look for holes; callers fall back to reading the file.
    fn lseek(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: i64,
        whence: i32,
        reply: ReplyLseek,
    ) {
        let shared = self.shared.clone();
        let key = KeyPerf {
            fh: Some(fh.0),
            offset: u64::try_from(offset).ok(),
            ..KeyPerf::of("lseek", req, ino.0)
        };
        self.spawn(key, async move {
            let whence = match whence {
                libc::SEEK_DATA => Whence::Data,
                libc::SEEK_HOLE => Whence::Hole,
                _ => return fail(reply, Errno::EINVAL),
            };
            // A negative offset is past every end to Linux too.
            let Ok(offset) = u64::try_from(offset) else {
                return fail(reply, Errno::ENXIO);
            };
            if shared.client.handles().may_be_dirty(ino.0) {
                return fail(reply, Errno::EINVAL);
            }
            match shared.client.lseek(fh.0, offset, whence).await {
                Ok(found) => match i64::try_from(found) {
                    Ok(found) => {
                        reply.offset(found);
                        Outcome::default()
                    }
                    Err(_) => {
                        tracing::warn!(fh = fh.0, found, "lseek reply is past any file offset");
                        fail(reply, Errno::EIO)
                    }
                },
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    /// By the time a `close(2)` reaches us the kernel has written back the file's dirty pages and reported their errors to the caller, and this daemon buffers nothing of its own; the request still counts, so the op mix shows every close.
    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        let started = Instant::now();
        reply.ok();
        self.shared
            .client
            .perf()
            .record_fuse("flush", &Outcome::default(), started.elapsed());
    }

    fn release(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let shared = self.shared.clone();
        let key = KeyPerf {
            fh: Some(fh.0),
            ..KeyPerf::of("release", req, ino.0)
        };
        self.spawn(key, async move {
            let writer = shared
                .client
                .handles()
                .get(fh.0)
                .is_some_and(|rec| rec.flags & libc::O_ACCMODE != libc::O_RDONLY);
            match shared.client.release(fh.0).await {
                Ok(()) => {
                    // The kernel keeps its own size and mtime for a file it wrote, and does not always push the mtime (a write in the same clock tick as the file's last change leaves the inode clean); once the last handle is gone the server's view is the truth, and dropping the file by name makes the next access fetch it. The record goes with it: the next reply is the first for the fresh inode.
                    if writer && shared.client.handles().any_live_for(ino.0).is_none() {
                        shared.reported_forget(ino.0);
                        shared.drop_by_name(ino.0);
                    }
                    reply.ok();
                    Outcome::default()
                }
                Err(e) => {
                    tracing::debug!(fh = fh.0, "release failed: {e}");
                    fail(reply, errno(&e))
                }
            }
        });
    }

    fn fsync(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let shared = self.shared.clone();
        let key = KeyPerf {
            fh: Some(fh.0),
            ..KeyPerf::of("fsync", req, ino.0)
        };
        self.spawn(key, async move {
            match shared.client.fsync(fh.0, datasync).await {
                Ok(()) => {
                    reply.ok();
                    Outcome::default()
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn opendir(&self, req: &Request, ino: INodeNo, _flags: fuser::OpenFlags, reply: ReplyOpen) {
        let shared = self.shared.clone();
        self.spawn(KeyPerf::of("opendir", req, ino.0), async move {
            let opened = loop {
                let path = match shared.path_of(ino.0) {
                    Ok(path) => path,
                    Err(e) => return fail(reply, e),
                };
                let (meant, by, wrong_name) =
                    (shared.clone(), path.clone(), AtomicBool::new(false));
                let opened = shared
                    .client
                    .opendir(path, |attr| meant.same_file(ino.0, &by, attr, &wrong_name))
                    .await;
                if !wrong_name.load(Ordering::Relaxed) {
                    break opened;
                }
            };
            match opened {
                Ok((fh, _)) => {
                    shared.dirs.lock().insert(
                        fh,
                        DirState {
                            ino: ino.0,
                            buffer: DirBuffer::new(),
                            fetched: Instant::now(),
                            end: None,
                        },
                    );
                    reply.opened(FileHandle(fh), FopenFlags::empty());
                    Outcome::default()
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn readdir(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let shared = self.shared.clone();
        let key = KeyPerf {
            fh: Some(fh.0),
            offset: Some(offset),
            ..KeyPerf::of("readdir", req, ino.0)
        };
        self.spawn(key, async move {
            let page = match shared.dir_page(fh.0, offset, false).await {
                Ok(page) => page,
                Err(e) => return fail(reply, errno(&e)),
            };
            let (added, rest) = shared.add_plain(&mut reply, ino.0, page);
            shared.stash(fh.0, rest);
            reply.ok();
            Outcome::items(added)
        });
    }

    fn readdirplus(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let shared = self.shared.clone();
        let key = KeyPerf {
            fh: Some(fh.0),
            offset: Some(offset),
            ..KeyPerf::of("readdirplus", req, ino.0)
        };
        self.spawn(key, async move {
            let mut entries = match shared.dir_page(fh.0, offset, true).await {
                Ok(entries) => entries.into_iter(),
                Err(e) => return fail(reply, errno(&e)),
            };
            let mut added = 0;
            for (cookie, entry) in entries.by_ref() {
                let name = OsStr::from_bytes(&entry.name);
                let full = match (entry.name.as_slice(), &entry.attr) {
                    (b".", _) => reply.add(
                        INodeNo(ino.0),
                        entry.next_offset,
                        name,
                        &shared.entry_ttl,
                        &dir_placeholder(ino.0),
                        GENERATION,
                    ),
                    (b"..", _) => {
                        let parent = shared.parent_of(ino.0);
                        reply.add(
                            INodeNo(parent),
                            entry.next_offset,
                            name,
                            &shared.entry_ttl,
                            &dir_placeholder(parent),
                            GENERATION,
                        )
                    }
                    (_, Some(attr)) => {
                        let Ok(entry_name) = Name::new(entry.name.as_slice()) else {
                            tracing::warn!(dir = ino.0, name = %String::from_utf8_lossy(&entry.name), "readdirplus entry with an invalid name; skipped");
                            continue;
                        };
                        // The kernel may refuse the entry for want of room, and one it refused must leave no node behind, so the node is asked for first and registered once the entry is in; the table stays locked between the two, or another request could be given the number meanwhile.
                        let (id, full) = {
                            let mut nodes = shared.nodes.lock();
                            let id = nodes.id_for(attr.into());
                            let full = reply.add(
                                INodeNo(id),
                                entry.next_offset,
                                name,
                                &shared.entry_ttl,
                                &file_attr(id, attr),
                                GENERATION,
                            );
                            if !full && nodes.insert_lookup(ino.0, entry_name, attr.into()).is_none() {
                                tracing::warn!(ino = attr.ino, "readdirplus entry that claims to be the root; not registered");
                            }
                            (id, full)
                        };
                        if !full {
                            shared.xattr_remember(id, attr);
                            shared.attr_reported(id, attr);
                        }
                        full
                    }
                    (_, None) => {
                        tracing::warn!(dir = ino.0, name = %String::from_utf8_lossy(&entry.name), "readdirplus entry without attributes; skipped");
                        continue;
                    }
                };
                if full {
                    let mut rest = VecDeque::from([(cookie, entry)]);
                    rest.extend(entries);
                    shared.stash(fh.0, rest);
                    break;
                }
                added += 1;
            }
            reply.ok();
            Outcome::items(added)
        });
    }

    fn fsyncdir(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let shared = self.shared.clone();
        let key = KeyPerf {
            fh: Some(fh.0),
            ..KeyPerf::of("fsyncdir", req, ino.0)
        };
        self.spawn(key, async move {
            match shared.client.fsync(fh.0, datasync).await {
                Ok(()) => {
                    reply.ok();
                    Outcome::default()
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn releasedir(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _flags: fuser::OpenFlags,
        reply: ReplyEmpty,
    ) {
        let shared = self.shared.clone();
        let key = KeyPerf {
            fh: Some(fh.0),
            ..KeyPerf::of("releasedir", req, ino.0)
        };
        self.spawn(key, async move {
            shared.dirs.lock().remove(&fh.0);
            match shared.client.releasedir(fh.0).await {
                Ok(()) => {
                    reply.ok();
                    Outcome::default()
                }
                Err(e) => {
                    tracing::debug!(fh = fh.0, "releasedir failed: {e}");
                    fail(reply, errno(&e))
                }
            }
        });
    }

    fn statfs(&self, req: &Request, ino: INodeNo, reply: ReplyStatfs) {
        let shared = self.shared.clone();
        self.spawn(KeyPerf::of("statfs", req, ino.0), async move {
            let path = shared
                .nodes
                .lock()
                .path_of(ino.0)
                .unwrap_or_else(Path::root);
            match shared.client.statfs(path).await {
                Ok(s) => {
                    reply.statfs(
                        s.blocks, s.bfree, s.bavail, s.files, s.ffree, s.bsize, s.namelen, s.frsize,
                    );
                    Outcome::default()
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn setxattr(
        &self,
        req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        if position != 0 {
            return reply.error(Errno::EINVAL);
        }
        let shared = self.shared.clone();
        let name = name.as_bytes().to_vec();
        let value = value.to_vec();
        let key = KeyPerf {
            size: Some(value.len() as u64),
            ..KeyPerf::of("setxattr", req, ino.0)
        };
        self.spawn(key, async move {
            let path = match shared.path_of(ino.0) {
                Ok(path) => path,
                Err(e) => return fail(reply, e),
            };
            let outcome = shared.client.setxattr(path, name, value, flags).await;
            shared.xattr_forget(ino.0);
            match outcome {
                Ok(()) => {
                    reply.ok();
                    Outcome::default()
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn getxattr(&self, req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        let shared = self.shared.clone();
        let name = name.as_bytes().to_vec();
        let key = KeyPerf {
            size: Some(size as u64),
            ..KeyPerf::of("getxattr", req, ino.0)
        };
        self.spawn(key, async move {
            if shared.xattr_known_absent(ino.0, &name) {
                return fail(reply, Errno::ENODATA);
            }
            let path = match shared.path_of(ino.0) {
                Ok(path) => path,
                Err(e) => return fail(reply, e),
            };
            match shared.client.getxattr(path, name).await {
                Ok(value) => reply_xattr(reply, size, &value),
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn listxattr(&self, req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let shared = self.shared.clone();
        let key = KeyPerf {
            size: Some(size as u64),
            ..KeyPerf::of("listxattr", req, ino.0)
        };
        self.spawn(key, async move {
            if let Some(list) = shared.xattr_known_list(ino.0) {
                return reply_xattr(reply, size, &list);
            }
            let path = match shared.path_of(ino.0) {
                Ok(path) => path,
                Err(e) => return fail(reply, e),
            };
            match shared.client.listxattr(path).await {
                Ok(list) => reply_xattr(reply, size, &list),
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn removexattr(&self, req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let shared = self.shared.clone();
        let name = name.as_bytes().to_vec();
        self.spawn(KeyPerf::of("removexattr", req, ino.0), async move {
            let path = match shared.path_of(ino.0) {
                Ok(path) => path,
                Err(e) => return fail(reply, e),
            };
            let outcome = shared.client.removexattr(path, name).await;
            shared.xattr_forget(ino.0);
            match outcome {
                Ok(()) => {
                    reply.ok();
                    Outcome::default()
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    fn access(&self, req: &Request, ino: INodeNo, mask: fuser::AccessFlags, reply: ReplyEmpty) {
        let shared = self.shared.clone();
        let mask = mask.bits();
        self.spawn(KeyPerf::of("access", req, ino.0), async move {
            let path = match shared.path_of(ino.0) {
                Ok(path) => path,
                Err(e) => return fail(reply, e),
            };
            match shared.client.access(path, mask).await {
                Ok(()) => {
                    reply.ok();
                    Outcome::default()
                }
                Err(e) => fail(reply, errno(&e)),
            }
        });
    }

    /// No ioctl is carried to the server, and `ENOTTY` is the errno for an ioctl a file does not support. The kernel remembers no such answer, so every probe arrives here.
    #[allow(clippy::too_many_arguments)]
    fn ioctl(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        flags: fuser::IoctlFlags,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
        reply: ReplyIoctl,
    ) {
        tracing::trace!(
            target: TRACE_TARGET,
            unique = req.unique().0,
            fh = fh.0,
            %flags,
            cmd = format_args!("{cmd:#x}"),
            in_len = in_data.len(),
            out_size,
            "ioctl refused"
        );
        self.spawn(KeyPerf::of("ioctl", req, ino.0), async move {
            fail(reply, Errno::ENOTTY)
        });
    }
}

/// The xattr size protocol: a zero `size` asks how big the value is; otherwise the value must fit.
fn reply_xattr(reply: ReplyXattr, size: u32, value: &[u8]) -> Outcome {
    if size == 0 {
        reply.size(value.len() as u32);
        Outcome::default()
    } else if value.len() > size as usize {
        fail(reply, Errno::ERANGE)
    } else {
        reply.data(value);
        Outcome::bytes(value.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jackalopefs_proto::Identity;

    /// The file with inode number `ino` in its `generation`th life, as ext4 would put it in a handle.
    fn identity(ino: u64, generation: u32) -> Identity {
        Identity {
            handle_type: 1,
            handle: [(ino as u32).to_le_bytes(), generation.to_le_bytes()].concat(),
        }
    }

    fn listed(name: &str, ino: u64, generation: u32, foreign: bool) -> DirEntry {
        let t = TimeSpec { sec: 0, nsec: 0 };
        DirEntry {
            next_offset: 1,
            name: name.as_bytes().to_vec(),
            attr: Some(Attr {
                ino,
                size: 0,
                blocks: 0,
                atime: t,
                mtime: t,
                ctime: t,
                kind: FileKind::Regular,
                perm: 0o644,
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: 0,
                blksize: 4096,
                xattr_names: None,
                identity: identity(ino, generation),
                foreign,
            }),
        }
    }

    /// What a lookup of the listed name registers, which is what `stat` then reports.
    fn looked_up(nodes: &mut NodeTable, dir: u64, item: &DirEntry) -> Option<u64> {
        nodes.insert_lookup(
            dir,
            Name::new(item.name.as_slice()).unwrap(),
            item.attr.as_ref().unwrap().into(),
        )
    }

    /// A plain page lists every entry under the number `stat` will report for it, which the entry's own inode number is not whenever the file needs a substitute.
    #[test]
    fn a_plain_page_numbers_an_entry_as_stat_will() {
        let mut nodes = NodeTable::new();
        // Known, by a lookup.
        let known = listed("known", 30, 0, false);
        looked_up(&mut nodes, ROOT, &known);
        // A name the table maps to one file, which now shows another.
        looked_up(&mut nodes, ROOT, &listed("replaced", 40, 0, false));
        // A number another file's node holds: the old life of 20, under another name.
        looked_up(&mut nodes, ROOT, &listed("old", 20, 0, false));
        let cases = [
            ("in another subvolume", listed("snap", 10, 0, true)),
            (
                "a recycled number another node holds",
                listed("new", 20, 1, false),
            ),
            ("known", known),
            (
                "a name now showing another file",
                listed("replaced", 41, 0, false),
            ),
        ];
        for (what, item) in cases {
            let plain = plain_number(&nodes, ROOT, ROOT, &item);
            assert_eq!(plain, looked_up(&mut nodes, ROOT, &item), "{what}");
        }
    }

    #[test]
    fn a_plain_page_numbers_the_dots_and_skips_what_it_cannot_number() {
        let nodes = NodeTable::new();
        let mut dot = listed(".", 99, 0, false);
        dot.attr = None;
        let mut dotdot = listed("..", 98, 0, false);
        dotdot.attr = None;
        assert_eq!(plain_number(&nodes, 7, 3, &dot), Some(7));
        assert_eq!(plain_number(&nodes, 7, 3, &dotdot), Some(3));
        let mut bare = listed("bare", 50, 0, false);
        bare.attr = None;
        assert_eq!(plain_number(&nodes, 7, 3, &bare), None);
    }

    #[test]
    fn only_a_lone_modification_time_value_is_a_time_flush() {
        let time = Some(TimeOrNow::Time(TimeSpec { sec: 1, nsec: 0 }));
        let flush = SetAttr {
            mtime: time,
            ..SetAttr::default()
        };
        assert!(setattr_flushes_times(&flush));
        assert!(
            !setattr_flushes_times(&SetAttr::default()),
            "an observation sets nothing"
        );
        let others = [
            SetAttr {
                mtime: Some(TimeOrNow::Now),
                ..SetAttr::default()
            },
            SetAttr {
                atime: time,
                ..flush
            },
            SetAttr {
                size: Some(0),
                ..flush
            },
            SetAttr {
                mode: Some(0o600),
                ..flush
            },
            SetAttr {
                uid: Some(1),
                ..flush
            },
            SetAttr {
                gid: Some(1),
                ..flush
            },
        ];
        for set in others {
            assert!(!setattr_flushes_times(&set), "{set:?}");
        }
    }

    #[test]
    fn time_conversions_round_trip() {
        for t in [
            TimeSpec { sec: 0, nsec: 0 },
            TimeSpec {
                sec: 1_700_000_000,
                nsec: 123_456_789,
            },
            TimeSpec {
                sec: -1,
                nsec: 500_000_000,
            },
            TimeSpec {
                sec: -86_400,
                nsec: 0,
            },
        ] {
            assert_eq!(timespec(system_time(t)), t, "{t:?}");
        }
    }

    #[test]
    fn cookies_tag_each_entry_with_what_yields_it() {
        let entries = vec![
            DirEntry {
                next_offset: 10,
                name: b"a".to_vec(),
                attr: None,
            },
            DirEntry {
                next_offset: 20,
                name: b"b".to_vec(),
                attr: None,
            },
        ];
        let tagged = tag_with_cookies(entries, 5, |e| e.next_offset);
        assert_eq!(
            tagged.iter().map(|(c, _)| *c).collect::<Vec<_>>(),
            vec![5, 10]
        );
    }

    #[test]
    fn server_flags_read_through_write_handles_and_never_append() {
        use libc::{O_ACCMODE, O_APPEND, O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY};
        assert_eq!(flags_for_server(O_RDONLY), O_RDONLY);
        assert_eq!(flags_for_server(O_RDWR), O_RDWR);
        assert_eq!(
            flags_for_server(O_WRONLY | O_CREAT | O_EXCL | O_TRUNC),
            O_RDWR | O_CREAT | O_EXCL | O_TRUNC
        );
        assert_eq!(flags_for_server(O_RDWR | O_APPEND), O_RDWR);
        assert_eq!(flags_for_server(O_WRONLY | O_APPEND), O_RDWR);
        for flags in [O_RDONLY, O_WRONLY, O_RDWR, O_WRONLY | O_APPEND | O_TRUNC] {
            assert_eq!(
                flags_for_server(flags) & O_ACCMODE,
                if flags & O_ACCMODE == O_RDONLY {
                    O_RDONLY
                } else {
                    O_RDWR
                }
            );
        }
    }
}

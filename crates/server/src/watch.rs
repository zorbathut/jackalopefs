//! Change notification: an inotify watch on each directory clients use, placed before the request that names it runs, so a client caches only what is watched. The watched directories form a tree under the export root, every one's parent watched too, so a rename or removal of any of them is reported on a watched parent. Events are folded into short batches and fanned out to sessions; a session is not told about changes it made itself.
//!
//! This is a latency improvement, not the correctness mechanism: the client's cache TTL is the backstop. inotify misses `mmap` writes and drops events under load; every such gap surfaces as [`EventItem::Overflow`] or is simply covered by the TTL.

use crate::export::{proc_path, Export};
use crate::perf::{Slowpath, EVENT_TARGET, TRACE_TARGET};
use jackalopefs_perf::events::Events;
use jackalopefs_perf::hub::IdsEvent;
use jackalopefs_proto::{shown, Event, EventItem, Name, Path, Request};
use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::eventfd::{EfdFlags, EventFd};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::hash::Hash;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

/// How long raw events accumulate before one batch goes out.
pub const DEBOUNCE_WINDOW: Duration = Duration::from_millis(100);

/// Distinct items one batch may hold before it collapses to an overflow.
const MAX_PENDING: usize = 10_000;

/// Upper bound on how long a recorded change waits for its inotify event before it stops counting as the origin.
const ORIGIN_MEMORY: Duration = Duration::from_secs(1);

/// How long a directory that could not be watched is left alone before a request naming it tries again.
const UNWATCHABLE_RETRY: Duration = Duration::from_secs(60);

/// Most directories one eviction drops: each removal queues an `IN_IGNORED` in the same inotify queue the changes come through, whose default length is 16384.
const EVICT_BATCH: usize = 512;

/// Directories watched at most, besides the export root, when `--watch-limit` is not given: half of `fs.inotify.max_user_watches`, which every process of the server's user shares, and at most this many. A watch pins its directory's inode in kernel memory, so this bounds that at some tens of MiB.
const BUDGET_MAX: usize = 65536;

/// The budget when `fs.inotify.max_user_watches` cannot be read.
const BUDGET_FALLBACK: usize = 8192;

/// How long the budget stays lowered after the system ran out of watches before it.
const LIMITED_HOLD: Duration = Duration::from_secs(600);

/// What a directory's watch reports: changes to its entries, its children's contents and attributes (a directory's watch reports those for every child, subdirectories included), and its own removal or move. Opens, reads and closes are left out, so the server's own work never fills the queue.
const MASK: AddWatchFlags = AddWatchFlags::IN_CREATE
    .union(AddWatchFlags::IN_DELETE)
    .union(AddWatchFlags::IN_MOVED_FROM)
    .union(AddWatchFlags::IN_MOVED_TO)
    .union(AddWatchFlags::IN_MODIFY)
    .union(AddWatchFlags::IN_ATTRIB)
    .union(AddWatchFlags::IN_DELETE_SELF)
    .union(AddWatchFlags::IN_MOVE_SELF)
    .union(AddWatchFlags::IN_ONLYDIR);

/// One debounce window of events. Each item carries the session that caused it (when the server did the work itself) so that session is not told about its own change.
#[derive(Debug, Default)]
pub struct EventBatch {
    pub items: Vec<(EventItem, Option<u64>)>,
}

impl EventBatch {
    /// The wire event for `session_id`, or `None` if nothing in the batch concerns it.
    pub fn for_session(&self, session_id: u64) -> Option<Event> {
        let items: Vec<EventItem> = self
            .items
            .iter()
            .filter(|(_, origin)| *origin != Some(session_id))
            .map(|(item, _)| item.clone())
            .collect();
        if items.is_empty() {
            None
        } else {
            Some(Event { items })
        }
    }
}

/// Records the change log keeps at most; beyond that the oldest is forgotten, which only costs one spurious invalidation.
const CHANGE_LOG_CAPACITY: usize = 4096;

/// Which session most recently changed which path. Keys are the `/`-joined relative path; entry changes are keyed by the entry's own path. A record is consumed by the first matching inotify event, so a later change to the same path by someone else is reported normally.
#[derive(Default)]
pub struct ChangeLog {
    recent: Mutex<ChangeLogInner>,
}

#[derive(Default)]
struct ChangeLogInner {
    by_path: HashMap<OsString, (u64, Instant)>,
    /// Insertion order for O(1) eviction; a re-recorded path keeps its original slot.
    order: VecDeque<OsString>,
}

impl ChangeLog {
    pub fn record(&self, path: &Path, session_id: u64) {
        let key = path.to_os_string();
        let mut inner = self.recent.lock();
        if inner
            .by_path
            .insert(key.clone(), (session_id, Instant::now()))
            .is_none()
        {
            inner.order.push_back(key);
            while inner.order.len() > CHANGE_LOG_CAPACITY {
                if let Some(oldest) = inner.order.pop_front() {
                    inner.by_path.remove(&oldest);
                }
            }
        }
    }

    pub fn record_entry(&self, dir: &Path, name: &Name, session_id: u64) {
        match dir.join(name.clone()) {
            Ok(path) => self.record(&path, session_id),
            Err(e) => tracing::debug!("not recording origin of an overlong path: {e}"),
        }
    }

    /// The session that recorded a change to `key`, consuming the record. The order queue keeps the key until eviction, which is harmless: an evicted key that was already taken is simply absent.
    pub fn take_origin(&self, key: &std::ffi::OsStr) -> Option<u64> {
        let (session, at) = self.recent.lock().by_path.remove(key)?;
        (at.elapsed() < ORIGIN_MEMORY).then_some(session)
    }
}

/// Accumulates one window's worth of items, deduplicated, in arrival order.
#[derive(Default)]
pub struct Pending {
    items: Vec<(EventItem, Option<u64>)>,
    seen: HashSet<EventItem>,
    overflow: bool,
}

impl Pending {
    pub fn fold(&mut self, item: EventItem, origin: Option<u64>) {
        if self.overflow {
            return;
        }
        if matches!(item, EventItem::Overflow) || self.items.len() >= MAX_PENDING {
            self.items.clear();
            self.seen.clear();
            self.overflow = true;
            return;
        }
        if self.seen.insert(item.clone()) {
            self.items.push((item, origin));
        }
    }

    pub fn flush(&mut self) -> Option<EventBatch> {
        if self.overflow {
            self.overflow = false;
            self.items.clear();
            self.seen.clear();
            return Some(EventBatch {
                items: vec![(EventItem::Overflow, None)],
            });
        }
        if self.items.is_empty() {
            return None;
        }
        self.seen.clear();
        Some(EventBatch {
            items: std::mem::take(&mut self.items),
        })
    }
}

fn origin_key(item: &EventItem) -> Option<OsString> {
    match item {
        EventItem::Entry { dir, name } => dir.join(name.clone()).ok().map(|p| p.to_os_string()),
        EventItem::Data { path } => Some(path.to_os_string()),
        // A notice is the server's own doing, never a session's change to suppress.
        EventItem::Overflow | EventItem::Unwatched { .. } => None,
    }
}

/// The items an inotify event in the directory `dir` about its entry `name` stands for: an entry change for a create, removal or rename, a data change for contents or attributes.
fn items_for(dir: &Path, mask: AddWatchFlags, name: &Name) -> Vec<EventItem> {
    let mut items = Vec::new();
    if mask.intersects(
        AddWatchFlags::IN_CREATE
            | AddWatchFlags::IN_DELETE
            | AddWatchFlags::IN_MOVED_FROM
            | AddWatchFlags::IN_MOVED_TO,
    ) {
        items.push(EventItem::Entry {
            dir: dir.clone(),
            name: name.clone(),
        });
    }
    if mask.intersects(AddWatchFlags::IN_MODIFY | AddWatchFlags::IN_ATTRIB) {
        match dir.join(name.clone()) {
            Ok(path) => items.push(EventItem::Data { path }),
            Err(e) => tracing::debug!("a change in {} not reported: {e}", shown(dir)),
        }
    }
    items
}

/// Whether an event changes which directories the table has where, which takes the table's write lock.
fn structural<W>(event: &RawEvent<W>) -> bool {
    event.mask.intersects(
        AddWatchFlags::IN_Q_OVERFLOW
            | AddWatchFlags::IN_IGNORED
            | AddWatchFlags::IN_UNMOUNT
            | AddWatchFlags::IN_DELETE_SELF,
    ) || (event.mask.contains(AddWatchFlags::IN_ISDIR)
        && event.mask.intersects(
            AddWatchFlags::IN_MOVED_FROM | AddWatchFlags::IN_MOVED_TO | AddWatchFlags::IN_DELETE,
        ))
}

/// The directory `path` is in; the root is its own.
pub fn parent_of(path: &Path) -> Path {
    path.split_last()
        .map_or_else(Path::root, |(parent, _)| parent)
}

/// The directories `req` reads or changes by path, which must be watched before it runs: the parent of every path it names (whose watch reports the node's entry, contents and attributes) and the directory a listing opens. Watching a directory watches every directory above it too. A request on an open handle names none: its directory is kept watched by the handle ([`Watches::hold`]).
pub fn dirs_named(req: &Request) -> Vec<Path> {
    match req {
        Request::Lookup { parent, .. }
        | Request::Mknod { parent, .. }
        | Request::Mkdir { parent, .. }
        | Request::Unlink { parent, .. }
        | Request::Rmdir { parent, .. }
        | Request::Symlink { parent, .. }
        | Request::Create { parent, .. } => vec![parent.clone()],
        Request::Rename {
            parent, newparent, ..
        } => vec![parent.clone(), newparent.clone()],
        Request::Link {
            path, newparent, ..
        } => vec![parent_of(path), newparent.clone()],
        Request::Getattr { path, .. } | Request::Setattr { path, .. } => {
            path.iter().map(parent_of).collect()
        }
        Request::Readlink { path }
        | Request::Open { path, .. }
        | Request::Setxattr { path, .. }
        | Request::Getxattr { path, .. }
        | Request::Listxattr { path }
        | Request::Removexattr { path, .. }
        | Request::Access { path, .. } => vec![parent_of(path)],
        Request::Opendir { path, .. } => vec![path.clone()],
        Request::Read { .. }
        | Request::Write { .. }
        | Request::Release { .. }
        | Request::Fsync { .. }
        | Request::Readdir { .. }
        | Request::Releasedir { .. }
        | Request::Statfs { .. }
        | Request::CopyFileRange { .. }
        | Request::Fallocate { .. }
        | Request::Lseek { .. } => Vec::new(),
    }
}

/// What the watch table needs from the system. The table is generic over it so its bookkeeping can be tested with events in any order.
trait Marks {
    type Wd: Copy + Eq + Hash + std::fmt::Debug;
    type Dir;
    /// The directory at `path` under the export root.
    fn open(&self, path: &Path) -> Result<Self::Dir, Errno>;
    /// The directory `name` inside `parent`.
    fn open_child(&self, parent: &Self::Dir, name: &Name) -> Result<Self::Dir, Errno>;
    /// Watch `dir`; a directory already watched gives the descriptor it has.
    fn add(&self, dir: &Self::Dir) -> Result<Self::Wd, Errno>;
    fn rm(&self, wd: Self::Wd);
}

/// The system's: directories resolved as every request path is, and watched through the descriptor that resolved them, so the watch is on exactly that inode.
struct Inotified {
    inotify: Arc<Inotify>,
    export: Arc<Export>,
}

impl Marks for Inotified {
    type Wd = WatchDescriptor;
    type Dir = OwnedFd;

    fn open(&self, path: &Path) -> Result<OwnedFd, Errno> {
        self.export.resolve_dir(path)
    }

    fn open_child(&self, parent: &OwnedFd, name: &Name) -> Result<OwnedFd, Errno> {
        self.export.resolve_dir_in(parent.as_fd(), name)
    }

    fn add(&self, dir: &OwnedFd) -> Result<WatchDescriptor, Errno> {
        self.inotify
            .add_watch(proc_path(dir.as_fd()).as_path(), MASK)
    }

    fn rm(&self, wd: WatchDescriptor) {
        // The kernel has already dropped the watch of a directory that is gone.
        if let Err(e) = self.inotify.rm_watch(wd) {
            tracing::debug!(?wd, "removing a watch: {e}");
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State<W> {
    Watched(W),
    /// Could not be watched; a request naming it tries again from `retry_at`. Nothing below it is watched, since a rename there would go unseen.
    Unwatchable {
        retry_at: Instant,
    },
}

/// One directory in the table, shared with the requests and handles that keep it watched.
struct Mark<W> {
    state: State<W>,
    /// The eviction round in which a request last named this directory or one below it; eviction takes the oldest first. A directory is never older than one below it, since naming one names every directory above it.
    used: AtomicU64,
    /// Requests in flight and handles open in this directory, which keep it watched: a notice that reached the client before a reply would leave the reply cached under a directory nobody watches, and a file held open is what the kernel trusts its own cache for.
    holds: AtomicU32,
}

impl<W> Mark<W> {
    fn new(state: State<W>, round: u64) -> Arc<Mark<W>> {
        Arc::new(Mark {
            state,
            used: AtomicU64::new(round),
            holds: AtomicU32::new(0),
        })
    }

    /// Stored only when it changes, so a busy directory's cache line is not written by every request.
    fn stamp(&self, round: u64) {
        if self.used.load(Ordering::Relaxed) != round {
            self.used.store(round, Ordering::Relaxed);
        }
    }
}

/// Keeps a directory watched while it lives: for a request until its reply is sent, for a handle until it is released.
pub struct Armed<W = WatchDescriptor>(Arc<Mark<W>>);

impl<W> Armed<W> {
    fn hold(mark: &Arc<Mark<W>>) -> Armed<W> {
        mark.holds.fetch_add(1, Ordering::Relaxed);
        Armed(mark.clone())
    }
}

impl<W> Drop for Armed<W> {
    fn drop(&mut self) {
        self.0.holds.fetch_sub(1, Ordering::Relaxed);
    }
}

struct Node<W> {
    mark: Arc<Mark<W>>,
    children: HashMap<Name, Node<W>>,
}

impl<W> Node<W> {
    fn new(state: State<W>, round: u64) -> Node<W> {
        Node {
            mark: Mark::new(state, round),
            children: HashMap::new(),
        }
    }
}

/// What [`Table::touch`] found.
enum Touched<W> {
    /// Nothing more to watch: the deepest watched directory on the path, held (none once the table is dead).
    Done(Option<Armed<W>>),
    /// Part of the path still needs watching, which takes the write lock.
    Missing,
}

/// One inotify event, as the table needs it.
#[derive(Debug)]
struct RawEvent<W> {
    wd: W,
    mask: AddWatchFlags,
    cookie: u32,
    name: Option<OsString>,
}

/// A log line the table decided on, written once its lock is released, so a blocked log output never holds up a request.
enum Note {
    Warn(String),
    Info(String),
    Debug(String),
    /// An event's detail, built because someone looks: logged at `debug` under the event target and delivered to the taps.
    Event(Slowpath, String),
}

/// The watched directories, as a tree from the export root mirroring the export: a directory is watched only below a watched parent, so the move or removal of any watched directory is reported on its parent's watch.
struct Table<M: Marks> {
    marks: M,
    root: Node<M::Wd>,
    by_wd: HashMap<M::Wd, Path>,
    /// Directories watched besides the root.
    watched: usize,
    /// Directories watched at most besides the root.
    budget: usize,
    /// A lower budget while the system has no more watches to give, and until when.
    capped: Option<(usize, Instant)>,
    /// Advanced by every eviction, so what is used after it is newer than everything it passed over.
    round: AtomicU64,
    /// The root's own watch ended: nothing is watched any more.
    dead: bool,
    evicted_logged: bool,
    events: Arc<Events<Slowpath>>,
    notes: Vec<Note>,
}

fn path_of(names: &[Name]) -> Path {
    Path::from_names(names.to_vec()).expect("a prefix of a path is no longer than the path")
}

impl<M: Marks> Table<M> {
    /// Watch the root, which is never dropped and not counted in `budget`.
    fn new(marks: M, budget: usize, events: Arc<Events<Slowpath>>) -> Result<Table<M>, Errno> {
        let wd = marks.add(&marks.open(&Path::root())?)?;
        Ok(Table {
            marks,
            root: Node::new(State::Watched(wd), 0),
            by_wd: HashMap::from([(wd, Path::root())]),
            watched: 0,
            budget,
            capped: None,
            round: AtomicU64::new(0),
            dead: false,
            evicted_logged: false,
            events,
            notes: Vec::new(),
        })
    }

    /// Count one occurrence of `kind`, keeping its detail for after the lock when anyone looks.
    fn event(&mut self, kind: Slowpath, detail: impl FnOnce() -> String) {
        self.events.inc(kind);
        if self.events.traced(kind)
            || tracing::enabled!(target: EVENT_TARGET, tracing::Level::DEBUG)
        {
            self.notes.push(Note::Event(kind, detail()));
        }
    }

    fn debug(&mut self, line: impl FnOnce() -> String) {
        if tracing::enabled!(tracing::Level::DEBUG) {
            self.notes.push(Note::Debug(line()));
        }
    }

    /// The budget in force at `now`: the configured one, or a lower one while the system has run out of watches.
    fn budget_at(&mut self, now: Instant) -> usize {
        match self.capped {
            Some((cap, until)) if now < until => cap,
            Some(_) => {
                self.capped = None;
                self.notes.push(Note::Info(format!(
                    "watching up to {} directories again",
                    self.budget
                )));
                self.budget
            }
            None => self.budget,
        }
    }

    /// Walk the table along `dir` without changing it.
    fn touch(&self, dir: &Path, now: Instant) -> Touched<M::Wd> {
        if self.dead {
            return Touched::Done(None);
        }
        let round = self.round.load(Ordering::Relaxed);
        let mut node = &self.root;
        for name in dir.names() {
            let Some(child) = node.children.get(name) else {
                return Touched::Missing;
            };
            match child.mark.state {
                State::Watched(_) => {
                    child.mark.stamp(round);
                    node = child;
                }
                State::Unwatchable { retry_at } if now < retry_at => break,
                State::Unwatchable { .. } => return Touched::Missing,
            }
        }
        Touched::Done(Some(Armed::hold(&node.mark)))
    }

    /// Watch `dir` and every directory above it, top-down: each is resolved inside its parent once the parent is watched, so a rename of it from then on is reported. Returns the deepest directory on the path that is watched, held. Notices for directories dropped meanwhile go to `out`.
    fn arm(&mut self, dir: &Path, now: Instant, out: &mut Vec<EventItem>) -> Option<Armed<M::Wd>> {
        if let Touched::Done(held) = self.touch(dir, now) {
            return held;
        }
        let names = dir.names();
        let mut depth = 0;
        let mut node = &self.root;
        while let Some(child) = names.get(depth).and_then(|name| node.children.get(name)) {
            if !matches!(child.mark.state, State::Watched(_)) {
                break;
            }
            node = child;
            depth += 1;
        }
        self.extend(names, depth, now, out);
        Some(Armed::hold(&self.deepest_watched(names).mark))
    }

    /// Watch `names[depth..]`, each inside the one before, stopping at the first that cannot be resolved or watched. The directory at `names[..depth]` is checked first: it may have been replaced since its watch was placed, with the event saying so not yet applied.
    fn extend(&mut self, names: &[Name], depth: usize, now: Instant, out: &mut Vec<EventItem>) {
        let prefix = path_of(&names[..depth]);
        let mut dir = match self.marks.open(&prefix) {
            Ok(dir) => dir,
            Err(e) => {
                self.debug(|| format!("not watching under {}: {e}", shown(&prefix)));
                return;
            }
        };
        if depth > 0 && !self.verify(&prefix, &dir, now, out) {
            return;
        }
        for end in depth + 1..=names.len() {
            let path = path_of(&names[..end]);
            let child = match self.marks.open_child(&dir, &names[end - 1]) {
                Ok(child) => child,
                Err(e) => {
                    self.debug(|| format!("not watching {}: {e}", shown(&path)));
                    return;
                }
            };
            if !self.install(&path, &child, now, out) {
                return;
            }
            dir = child;
        }
    }

    /// Whether `dir`, just opened at `path`, is the directory the table watches there. If it is another, what the table had there is dropped and `dir` watched in its place.
    fn verify(
        &mut self,
        path: &Path,
        dir: &M::Dir,
        now: Instant,
        out: &mut Vec<EventItem>,
    ) -> bool {
        let Some(State::Watched(wd)) = self.node(path).map(|node| node.mark.state) else {
            return false;
        };
        match self.marks.add(dir) {
            Ok(found) if found == wd => true,
            Ok(found) => {
                if let Some(stale) = self.detach(path) {
                    self.drop_tree(stale, path.clone(), Some(out));
                }
                self.place(path, found, now, out)
            }
            Err(e) => {
                self.debug(|| format!("cannot check {}: {e}", shown(path)));
                false
            }
        }
    }

    /// Watch `dir`, resolved at `path` inside a directory the table has, and record it there. Returns whether `path` is now watched.
    fn install(
        &mut self,
        path: &Path,
        dir: &M::Dir,
        now: Instant,
        out: &mut Vec<EventItem>,
    ) -> bool {
        let mut added = self.marks.add(dir);
        if added == Err(Errno::ENOSPC) && self.watched > 0 {
            self.limited(path, now);
            self.evict(path, now, out);
            added = self.marks.add(dir);
        }
        match added {
            Ok(wd) => self.place(path, wd, now, out),
            Err(e) => {
                self.event(Slowpath::WatchUnwatchable, || {
                    format!(
                        "cannot watch {}: {e}; served unwatched for a while",
                        shown(path)
                    )
                });
                let round = self.round.load(Ordering::Relaxed);
                let state = State::Unwatchable {
                    retry_at: now + UNWATCHABLE_RETRY,
                };
                self.put(path, Node::new(state, round), out);
                false
            }
        }
    }

    /// Record the watch `wd` at `path`. A descriptor the table already has under another path is that directory, renamed before its move was reported, and it moves to `path` with everything below it; a new one may first make room within the budget.
    fn place(&mut self, path: &Path, wd: M::Wd, now: Instant, out: &mut Vec<EventItem>) -> bool {
        match self.by_wd.get(&wd).cloned() {
            Some(old) if old == *path => true,
            Some(old) => self.reroot(&old, path, out),
            None => {
                if self.watched >= self.budget_at(now) {
                    self.evict(path, now, out);
                }
                self.by_wd.insert(wd, path.clone());
                self.watched += 1;
                let round = self.round.load(Ordering::Relaxed);
                self.put(path, Node::new(State::Watched(wd), round), out);
                true
            }
        }
    }

    /// The system ran out of watches before the budget did, other processes of this user holding the rest: watch no more than now for a while.
    fn limited(&mut self, path: &Path, now: Instant) {
        let watched = self.watched;
        self.event(Slowpath::WatchLimited, || {
            format!(
                "out of inotify watches at {} with {watched} directories watched",
                shown(path)
            )
        });
        self.capped = Some((self.watched, now + LIMITED_HOLD));
        self.notes.push(Note::Warn(format!(
            "inotify watch limit reached at {} with {} directories watched; watching at most that many for the next {} minutes (raise fs.inotify.max_user_watches)",
            shown(path),
            self.watched,
            LIMITED_HOLD.as_secs() / 60
        )));
    }

    /// Make room for one more watch by dropping the directories used longest ago, each announced: a batch, or as many as it takes to get back within the budget. Only directories with nothing watched below them go, so every watched directory's parent stays watched; never the root, one held by a request or handle, or one on `keep`, the path being watched.
    fn evict(&mut self, keep: &Path, now: Instant, out: &mut Vec<EventItem>) {
        let budget = self.budget_at(now);
        let over = (self.watched + 1).saturating_sub(budget);
        let want = over.max((budget / 16).clamp(1, EVICT_BATCH));
        // Whatever is used from here on is newer than everything this round considers.
        self.round.fetch_add(1, Ordering::Relaxed);
        let mut dropped = 0;
        while dropped < want {
            let mut leaves = Vec::new();
            leaves_of(&self.root, &mut Vec::new(), keep.names(), &mut leaves);
            if leaves.is_empty() {
                break;
            }
            let take = (want - dropped).min(leaves.len());
            leaves.select_nth_unstable_by(take - 1, |a, b| {
                (a.0, std::cmp::Reverse(a.1.len()), &a.1).cmp(&(
                    b.0,
                    std::cmp::Reverse(b.1.len()),
                    &b.1,
                ))
            });
            for (_, names) in leaves.into_iter().take(take) {
                let victim = path_of(&names);
                if let Some(node) = self.detach(&victim) {
                    self.event(Slowpath::WatchEvicted, || {
                        format!("{} dropped to stay within the watch limit", shown(&victim))
                    });
                    self.drop_tree(node, victim, Some(out));
                }
            }
            dropped += take;
        }
        if dropped == 0 {
            self.debug(|| {
                format!(
                    "nothing could be dropped to watch {}; watching it beyond the budget",
                    shown(keep)
                )
            });
        } else if !self.evicted_logged {
            self.notes.push(Note::Info(format!(
                "{budget} directories watched, the most allowed (--watch-limit): from now on the ones used longest ago are dropped as others are needed, and clients told to drop what they cached under them"
            )));
            self.evicted_logged = true;
        }
    }

    /// Move the directory at `from`, and everything below it, to `to`. Returns whether it was there to move.
    fn reroot(&mut self, from: &Path, to: &Path, out: &mut Vec<EventItem>) -> bool {
        let Some(mut node) = self.detach(from) else {
            return false;
        };
        self.rekey(&mut node, to, out);
        self.put(to, node, out);
        true
    }

    /// Record `node`, and everything below it, under `path`. A directory below whose new path would be too long is dropped.
    fn rekey(&mut self, node: &mut Node<M::Wd>, path: &Path, out: &mut Vec<EventItem>) {
        if let State::Watched(wd) = node.mark.state {
            self.by_wd.insert(wd, path.clone());
        }
        let names: Vec<Name> = node.children.keys().cloned().collect();
        for name in names {
            match path.join(name.clone()) {
                Ok(child_path) => {
                    let mut child = node.children.remove(&name).expect("listed just now");
                    self.rekey(&mut child, &child_path, out);
                    node.children.insert(name, child);
                }
                Err(_) => {
                    let child = node.children.remove(&name).expect("listed just now");
                    self.drop_tree(child, path.clone(), Some(out));
                }
            }
        }
    }

    /// Record `node` at `path`, whose parent the table has; whatever was there is dropped.
    fn put(&mut self, path: &Path, node: Node<M::Wd>, out: &mut Vec<EventItem>) {
        let Some((parent, name)) = path.split_last() else {
            return;
        };
        let displaced = match self.node_mut(&parent) {
            Some(slot) => slot.children.insert(name.clone(), node),
            None => Some(node),
        };
        if let Some(displaced) = displaced {
            self.drop_tree(displaced, path.clone(), Some(out));
        }
    }

    fn node(&self, path: &Path) -> Option<&Node<M::Wd>> {
        path.names()
            .iter()
            .try_fold(&self.root, |node, name| node.children.get(name))
    }

    fn node_mut(&mut self, path: &Path) -> Option<&mut Node<M::Wd>> {
        path.names()
            .iter()
            .try_fold(&mut self.root, |node, name| node.children.get_mut(name))
    }

    fn deepest_watched(&self, names: &[Name]) -> &Node<M::Wd> {
        let mut node = &self.root;
        for name in names {
            match node.children.get(name) {
                Some(child) if matches!(child.mark.state, State::Watched(_)) => node = child,
                _ => break,
            }
        }
        node
    }

    fn detach(&mut self, path: &Path) -> Option<Node<M::Wd>> {
        let (parent, name) = path.split_last()?;
        self.node_mut(&parent)?.children.remove(name)
    }

    /// Stop watching `node`, at `path`, and everything below it, announcing each watched directory in `out` when given. A directory below whose path would be too long is announced as `path`, which covers it.
    fn drop_tree(&mut self, node: Node<M::Wd>, path: Path, mut out: Option<&mut Vec<EventItem>>) {
        for (name, child) in node.children {
            let child_path = path.join(name).unwrap_or_else(|_| path.clone());
            self.drop_tree(child, child_path, out.as_deref_mut());
        }
        if let State::Watched(wd) = node.mark.state {
            if self.by_wd.remove(&wd).is_some() {
                self.marks.rm(wd);
            }
            self.watched -= 1;
            if let Some(out) = out {
                out.push(EventItem::Unwatched { dir: path });
            }
        }
    }

    /// Whether the directory the table has at `path` is still the one there. A request can watch a directory under its new name before the event that moved it away from the old one is applied, so a structural event is checked against the filesystem before it drops anything.
    fn still_there(&mut self, path: &Path) -> bool {
        let Some(State::Watched(wd)) = self.node(path).map(|node| node.mark.state) else {
            return false;
        };
        let Ok(dir) = self.marks.open(path) else {
            return false;
        };
        self.is(&dir, wd)
    }

    /// Whether `dir` is the directory watched as `wd`. Finding out watches it; a directory the table does not have has that watch taken off again.
    fn is(&mut self, dir: &M::Dir, wd: M::Wd) -> bool {
        match self.marks.add(dir) {
            Ok(found) if found == wd => true,
            Ok(found) => {
                if !self.by_wd.contains_key(&found) {
                    self.marks.rm(found);
                }
                false
            }
            Err(_) => false,
        }
    }

    /// After lost events, which may have moved or replaced any directory: keep each watched directory that is still where the table has it, inside a parent that is, and drop the rest, announced.
    fn recheck(&mut self, out: &mut Vec<EventItem>) {
        let children = std::mem::take(&mut self.root.children);
        match self.marks.open(&Path::root()) {
            Ok(root) => {
                let kept = self.recheck_below(children, &root, &mut Vec::new(), out);
                self.root.children = kept;
            }
            Err(e) => {
                self.notes.push(Note::Warn(format!(
                    "cannot open the export root to check its watches: {e}"
                )));
                for (name, node) in children {
                    self.drop_tree(node, path_of(std::slice::from_ref(&name)), Some(out));
                }
            }
        }
    }

    fn recheck_below(
        &mut self,
        children: HashMap<Name, Node<M::Wd>>,
        parent: &M::Dir,
        names: &mut Vec<Name>,
        out: &mut Vec<EventItem>,
    ) -> HashMap<Name, Node<M::Wd>> {
        let mut kept = HashMap::new();
        for (name, mut node) in children {
            names.push(name.clone());
            let here = match node.mark.state {
                State::Watched(wd) => self
                    .marks
                    .open_child(parent, &name)
                    .ok()
                    .filter(|dir| self.is(dir, wd)),
                State::Unwatchable { .. } => None,
            };
            match here {
                Some(dir) => {
                    node.children =
                        self.recheck_below(std::mem::take(&mut node.children), &dir, names, out);
                    kept.insert(name, node);
                }
                None => self.drop_tree(node, path_of(names), Some(out)),
            }
            names.pop();
        }
        kept
    }

    /// The root's own watch ended (the export was removed or unmounted): nothing is watched from here on. The watches still placed go with the inotify instance.
    fn die(&mut self, why: AddWatchFlags) {
        self.notes.push(Note::Warn(format!(
            "the export root's own watch ended ({why:?}); change notification is off until a restart"
        )));
        self.root.children.clear();
        self.by_wd.clear();
        self.watched = 0;
        self.dead = true;
    }

    /// What a non-structural event reports, into `out`.
    fn report(&self, event: &RawEvent<M::Wd>, out: &mut Vec<EventItem>) -> Option<(Path, Name)> {
        let dir = self.by_wd.get(&event.wd)?;
        let Some(name) = &event.name else {
            // A directory's own change, which its parent reports, except for the root's.
            if dir.is_root()
                && event
                    .mask
                    .intersects(AddWatchFlags::IN_MODIFY | AddWatchFlags::IN_ATTRIB)
            {
                out.push(EventItem::Data { path: dir.clone() });
            }
            return None;
        };
        let name = match Name::try_from(name.as_os_str()) {
            Ok(name) => name,
            Err(e) => {
                tracing::debug!("a change in {} not reported: {e}", shown(dir));
                return None;
            }
        };
        out.extend(items_for(dir, event.mask, &name));
        Some((dir.clone(), name))
    }

    /// Apply one read's worth of events, in order, putting what they report in `out`. A directory moved within the export keeps its watches under its new name when both halves of the move are in the batch; one moved out, or whose other half is not there, is dropped and announced.
    fn apply(&mut self, events: Vec<RawEvent<M::Wd>>, out: &mut Vec<EventItem>) {
        let mut moving: HashMap<u32, (Path, Node<M::Wd>)> = HashMap::new();
        for event in events {
            if self.dead {
                break;
            }
            if event.mask.contains(AddWatchFlags::IN_Q_OVERFLOW) {
                self.event(Slowpath::InotifyOverflow, || {
                    "the inotify queue overflowed; the watched directories are checked against the filesystem".into()
                });
                self.notes.push(Note::Warn(
                    "the inotify queue overflowed; clients will be told to rescan".into(),
                ));
                for (_, (path, node)) in moving.drain() {
                    self.drop_tree(node, path, Some(out));
                }
                out.push(EventItem::Overflow);
                self.recheck(out);
                continue;
            }
            let Some(dir) = self.by_wd.get(&event.wd).cloned() else {
                continue;
            };
            if event.mask.intersects(
                AddWatchFlags::IN_IGNORED
                    | AddWatchFlags::IN_UNMOUNT
                    | AddWatchFlags::IN_DELETE_SELF,
            ) {
                if dir.is_root() {
                    self.die(event.mask);
                    out.push(EventItem::Overflow);
                } else if event.mask.contains(AddWatchFlags::IN_IGNORED) {
                    // The directory is gone; its parent reported that.
                    if let Some(node) = self.detach(&dir) {
                        self.drop_tree(node, dir, None);
                    }
                }
                continue;
            }
            // A move of a watched directory is acted on from its parent's events; one of the root changes no path below it.
            if event.mask.contains(AddWatchFlags::IN_MOVE_SELF) {
                continue;
            }
            let Some((dir, name)) = self.report(&event, out) else {
                continue;
            };
            if !event.mask.contains(AddWatchFlags::IN_ISDIR) {
                continue;
            }
            let Ok(path) = dir.join(name) else {
                continue;
            };
            if event.mask.contains(AddWatchFlags::IN_MOVED_FROM) {
                if !self.still_there(&path) {
                    if let Some(node) = self.detach(&path) {
                        moving.insert(event.cookie, (path, node));
                    }
                }
            } else if event.mask.contains(AddWatchFlags::IN_MOVED_TO) {
                let arrived = moving.remove(&event.cookie);
                if self.still_there(&path) {
                    if let Some((from, node)) = arrived {
                        self.drop_tree(node, from, Some(out));
                    }
                } else {
                    if let Some(old) = self.detach(&path) {
                        self.drop_tree(old, path.clone(), Some(out));
                    }
                    if let Some((_, mut node)) = arrived {
                        self.rekey(&mut node, &path, out);
                        self.put(&path, node, out);
                    }
                }
            } else if event.mask.contains(AddWatchFlags::IN_DELETE) && !self.still_there(&path) {
                if let Some(node) = self.detach(&path) {
                    self.drop_tree(node, path, Some(out));
                }
            }
        }
        for (_, (path, node)) in moving {
            self.drop_tree(node, path, Some(out));
        }
    }
}

/// Every directory below `node` (at `names`) that eviction may take, with when it was last used: watched, with nothing watched below it, not held, and not on `keep`.
fn leaves_of<W>(
    node: &Node<W>,
    names: &mut Vec<Name>,
    keep: &[Name],
    leaves: &mut Vec<(u64, Vec<Name>)>,
) {
    for (name, child) in &node.children {
        if !matches!(child.mark.state, State::Watched(_)) {
            continue;
        }
        names.push(name.clone());
        let watched_below = child
            .children
            .values()
            .any(|c| matches!(c.mark.state, State::Watched(_)));
        if watched_below {
            leaves_of(child, names, keep, leaves);
        } else if child.mark.holds.load(Ordering::Relaxed) == 0 && !keep.starts_with(names) {
            leaves.push((child.mark.used.load(Ordering::Relaxed), names.clone()));
        }
        names.pop();
    }
}

/// The budget for a `fs.inotify.max_user_watches` read as `sysctl`.
fn budget_from(sysctl: std::io::Result<String>) -> usize {
    match sysctl.map(|text| text.trim().parse::<usize>()) {
        Ok(Ok(limit)) => (limit / 2).clamp(1, BUDGET_MAX),
        Ok(Err(e)) => {
            tracing::warn!("fs.inotify.max_user_watches does not parse ({e}); watching at most {BUDGET_FALLBACK} directories");
            BUDGET_FALLBACK
        }
        Err(e) => {
            tracing::warn!("cannot read fs.inotify.max_user_watches ({e}); watching at most {BUDGET_FALLBACK} directories");
            BUDGET_FALLBACK
        }
    }
}

/// How many directories to watch at most, besides the export root, when `--watch-limit` does not say.
pub fn default_budget() -> usize {
    budget_from(std::fs::read_to_string(
        "/proc/sys/fs/inotify/max_user_watches",
    ))
}

fn write_notes(notes: Vec<Note>, events: &Events<Slowpath>) {
    for note in notes {
        match note {
            Note::Warn(line) => tracing::warn!("{line}"),
            Note::Info(line) => tracing::info!("{line}"),
            Note::Debug(line) => tracing::debug!("{line}"),
            Note::Event(kind, detail) => {
                tracing::debug!(target: EVENT_TARGET, event = kind.name(), "{detail}");
                events.deliver(kind, &IdsEvent::default(), &detail);
            }
        }
    }
}

/// The watch table, shared by every request and the event thread.
pub struct Watches {
    inner: Option<Inner>,
}

struct Inner {
    table: RwLock<Table<Inotified>>,
    pending: Mutex<Pending>,
    inotify: Arc<Inotify>,
    slowpaths: Arc<Events<Slowpath>>,
}

impl Watches {
    /// A table that watches nothing, for a server without change notification.
    pub fn disabled() -> Arc<Watches> {
        Arc::new(Watches { inner: None })
    }

    /// Watch every directory `req` names ([`dirs_named`]) before it runs. The guards keep them watched until they are dropped, which is to be after the reply is sent.
    pub fn arm_request(&self, req: &Request) -> Vec<Armed> {
        if self.inner.is_none() {
            return Vec::new();
        }
        dirs_named(req)
            .iter()
            .filter_map(|dir| self.arm(dir))
            .collect()
    }

    /// Keep `dir` watched for as long as a handle opened there lives: the kernel trusts what it caches for a file held open, so changes to it must keep coming. The request that opened it has just watched `dir`, so this finds it watched.
    pub fn hold(&self, dir: &Path) -> Option<Arc<Armed>> {
        self.arm(dir).map(Arc::new)
    }

    /// Log how many directories are watched; what the table did is in the events line.
    pub fn report(&self) {
        let Some(inner) = &self.inner else {
            tracing::info!(target: TRACE_TARGET, "perf watches: change notification is off");
            return;
        };
        let (watched, budget) = {
            let table = inner.table.read();
            let budget = match table.capped {
                Some((cap, until)) if Instant::now() < until => cap,
                _ => table.budget,
            };
            (table.watched, budget)
        };
        tracing::info!(target: TRACE_TARGET, "perf watches watched={watched} limit={budget}");
    }

    /// Directories watched besides the export root.
    pub fn watched(&self) -> usize {
        self.inner
            .as_ref()
            .map_or(0, |inner| inner.table.read().watched)
    }

    /// Watch `dir` and every directory above it. `None` when nothing on the path is watched, as on a table that watches nothing.
    pub fn arm(&self, dir: &Path) -> Option<Armed> {
        let inner = self.inner.as_ref()?;
        let now = Instant::now();
        if let Touched::Done(held) = inner.table.read().touch(dir, now) {
            return held;
        }
        let (held, notes) = {
            let mut table = inner.table.write();
            let mut out = Vec::new();
            let held = table.arm(dir, now, &mut out);
            // Folded while the table is still held, so notices keep their order with the events applied under it.
            let mut pending = inner.pending.lock();
            for item in out {
                pending.fold(item, None);
            }
            (held, std::mem::take(&mut table.notes))
        };
        write_notes(notes, &inner.slowpaths);
        held
    }
}

/// Events read at most before they are applied, so a storm still lets batches go out.
const READS_PER_APPLY: usize = 64;

fn read_events(inotify: &Inotify) -> Vec<RawEvent<WatchDescriptor>> {
    let mut events = Vec::new();
    for _ in 0..READS_PER_APPLY {
        match inotify.read_events() {
            Ok(read) => events.extend(read.into_iter().map(|e| RawEvent {
                wd: e.wd,
                mask: e.mask,
                cookie: e.cookie,
                name: e.name,
            })),
            Err(Errno::EAGAIN) => break,
            Err(Errno::EINTR) => {}
            Err(e) => {
                tracing::warn!("reading inotify events: {e}");
                break;
            }
        }
    }
    events
}

/// Read events as they come, apply them to the table, and send what they report every [`DEBOUNCE_WINDOW`], until `stop` is signalled.
fn run_events(
    watches: &Watches,
    stop: &EventFd,
    changes: &ChangeLog,
    events: &broadcast::Sender<Arc<EventBatch>>,
) {
    let inner = watches
        .inner
        .as_ref()
        .expect("an event thread runs only for a table that watches");
    let flush = || {
        let batch = inner.pending.lock().flush();
        if let Some(batch) = batch {
            if events.send(Arc::new(batch)).is_err() {
                tracing::trace!("change batch dropped: no sessions");
            }
        }
    };
    let mut flush_at = Instant::now() + DEBOUNCE_WINDOW;
    loop {
        let wait = PollTimeout::try_from(flush_at.saturating_duration_since(Instant::now()))
            .unwrap_or(PollTimeout::ZERO);
        let mut fds = [
            PollFd::new(inner.inotify.as_fd(), PollFlags::POLLIN),
            PollFd::new(stop.as_fd(), PollFlags::POLLIN),
        ];
        match poll(&mut fds, wait) {
            Ok(_) | Err(Errno::EINTR) => {}
            Err(e) => {
                tracing::error!(
                    "waiting for inotify events: {e}; change notification is off until a restart"
                );
                let notes = {
                    let mut table = inner.table.write();
                    table.die(AddWatchFlags::empty());
                    fold_events(&inner.pending, changes, vec![EventItem::Overflow]);
                    std::mem::take(&mut table.notes)
                };
                write_notes(notes, &inner.slowpaths);
                flush();
                return;
            }
        }
        let ready = |fd: &PollFd<'_>| fd.revents().is_some_and(|r| !r.is_empty());
        if ready(&fds[1]) {
            return;
        }
        if ready(&fds[0]) {
            let raw = read_events(&inner.inotify);
            let mut out = Vec::new();
            if raw.iter().any(structural) {
                let notes = {
                    let mut table = inner.table.write();
                    table.apply(raw, &mut out);
                    fold_events(&inner.pending, changes, out);
                    std::mem::take(&mut table.notes)
                };
                write_notes(notes, &inner.slowpaths);
            } else {
                let table = inner.table.read();
                for event in &raw {
                    table.report(event, &mut out);
                }
                fold_events(&inner.pending, changes, out);
            }
        }
        if Instant::now() >= flush_at {
            flush_at = Instant::now() + DEBOUNCE_WINDOW;
            flush();
        }
    }
}

fn fold_events(pending: &Mutex<Pending>, changes: &ChangeLog, items: Vec<EventItem>) {
    let mut pending = pending.lock();
    for item in items {
        let origin = origin_key(&item).and_then(|key| changes.take_origin(&key));
        pending.fold(item, origin);
    }
}

/// Keeps change notification running: dropping it stops the event thread. The inotify instance closes with the last [`Watches`].
pub struct WatcherHandle {
    stop: Arc<EventFd>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for WatcherHandle {
    fn drop(&mut self) {
        if let Err(e) = self.stop.write(1) {
            tracing::warn!("cannot stop the watch event thread: {e}");
            return;
        }
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                tracing::error!("the watch event thread panicked");
            }
        }
    }
}

/// Start change notification for `export`, which logs show as `shown_root`, counting its events in `slowpaths`. The root is watched at once and every other directory as requests name it ([`Watches::arm_request`]), `budget` of them at most. Without inotify, or when the root cannot be watched, the table watches nothing (logged) and clients fall back to their cache TTLs.
pub fn spawn(
    export: Arc<Export>,
    shown_root: &std::path::Path,
    budget: usize,
    slowpaths: Arc<Events<Slowpath>>,
    changes: Arc<ChangeLog>,
    events: broadcast::Sender<Arc<EventBatch>>,
) -> (Arc<Watches>, Option<WatcherHandle>) {
    let disabled = |why: String| {
        tracing::error!("{why}; change notification disabled");
        (Watches::disabled(), None)
    };
    let inotify = match Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC) {
        Ok(inotify) => Arc::new(inotify),
        Err(e) => return disabled(format!("cannot create an inotify instance: {e}")),
    };
    let table = match Table::new(
        Inotified {
            inotify: inotify.clone(),
            export,
        },
        budget,
        slowpaths.clone(),
    ) {
        Ok(table) => table,
        Err(e) => return disabled(format!("cannot watch {}: {e}", shown_root.display())),
    };
    let stop = match EventFd::from_flags(EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK) {
        Ok(stop) => Arc::new(stop),
        Err(e) => return disabled(format!("cannot create the watch thread's stop signal: {e}")),
    };
    let watches = Arc::new(Watches {
        inner: Some(Inner {
            table: RwLock::new(table),
            pending: Mutex::new(Pending::default()),
            inotify,
            slowpaths,
        }),
    });
    let spawned = std::thread::Builder::new()
        .name("watch-events".into())
        .spawn({
            let watches = watches.clone();
            let stop = stop.clone();
            move || run_events(&watches, &stop, &changes, &events)
        });
    match spawned {
        Ok(thread) => {
            tracing::info!(
                "watching directories under {} as clients use them, at most {budget}",
                shown_root.display()
            );
            (
                watches,
                Some(WatcherHandle {
                    stop,
                    thread: Some(thread),
                }),
            )
        }
        Err(e) => disabled(format!("cannot start the watch event thread: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn name(s: &str) -> Name {
        Name::new(s.as_bytes()).unwrap()
    }

    fn path(s: &str) -> Path {
        if s.is_empty() {
            Path::root()
        } else {
            Path::from_names(s.split('/').map(name).collect()).unwrap()
        }
    }

    fn entry(dir: &str, n: &str) -> EventItem {
        EventItem::Entry {
            dir: path(dir),
            name: name(n),
        }
    }

    fn unwatched(dir: &str) -> EventItem {
        EventItem::Unwatched { dir: path(dir) }
    }

    #[test]
    fn pending_dedups_and_orders() {
        let mut pending = Pending::default();
        pending.fold(entry("", "a"), Some(1));
        pending.fold(entry("", "b"), None);
        pending.fold(entry("", "a"), Some(1));
        let batch = pending.flush().unwrap();
        assert_eq!(batch.items.len(), 2);
        assert_eq!(batch.items[0].1, Some(1));
        assert!(pending.flush().is_none());
        assert_eq!(batch.for_session(1).unwrap().items, vec![entry("", "b")]);
        assert_eq!(batch.for_session(2).unwrap().items.len(), 2);
    }

    #[test]
    fn pending_collapses_to_overflow() {
        let mut pending = Pending::default();
        pending.fold(entry("", "a"), None);
        pending.fold(EventItem::Overflow, None);
        pending.fold(entry("", "b"), None);
        let batch = pending.flush().unwrap();
        assert_eq!(batch.items, vec![(EventItem::Overflow, None)]);
        assert!(pending.flush().is_none(), "overflow resets the accumulator");

        let mut pending = Pending::default();
        for i in 0..=MAX_PENDING {
            pending.fold(entry("", &format!("f{i}")), None);
        }
        assert_eq!(
            pending.flush().unwrap().items,
            vec![(EventItem::Overflow, None)]
        );
    }

    #[test]
    fn change_log_records_are_consumed_once() {
        let log = ChangeLog::default();
        let p = Path::from_names(vec![name("d"), name("f")]).unwrap();
        assert_eq!(log.take_origin(&p.to_os_string()), None);
        log.record(&p, 7);
        assert_eq!(log.take_origin(&p.to_os_string()), Some(7));
        assert_eq!(
            log.take_origin(&p.to_os_string()),
            None,
            "a second event for the same path is someone else's"
        );
        log.record_entry(&Path::from_names(vec![name("d")]).unwrap(), &name("g"), 8);
        assert_eq!(log.take_origin(std::ffi::OsStr::new("d/g")), Some(8));
    }

    #[test]
    fn change_log_is_bounded() {
        let log = ChangeLog::default();
        for i in 0..(CHANGE_LOG_CAPACITY + 10) {
            log.record(&Path::from_names(vec![name(&format!("f{i}"))]).unwrap(), 1);
        }
        let inner = log.recent.lock();
        assert_eq!(inner.by_path.len(), CHANGE_LOG_CAPACITY);
        assert_eq!(inner.order.len(), CHANGE_LOG_CAPACITY);
        assert!(
            !inner.by_path.contains_key(std::ffi::OsStr::new("f0")),
            "the oldest record was evicted"
        );
        assert!(inner.by_path.contains_key(std::ffi::OsStr::new("f10")));
    }

    #[test]
    fn a_notice_is_never_taken_for_a_sessions_own_change() {
        assert_eq!(origin_key(&unwatched("d")), None);
        assert_eq!(origin_key(&entry("d", "f")), Some("d/f".into()));
    }

    #[test]
    fn events_map_to_items() {
        let dir = path("d");
        assert_eq!(
            items_for(&dir, AddWatchFlags::IN_CREATE, &name("n")),
            vec![entry("d", "n")]
        );
        for mask in [
            AddWatchFlags::IN_DELETE,
            AddWatchFlags::IN_MOVED_FROM,
            AddWatchFlags::IN_MOVED_TO | AddWatchFlags::IN_ISDIR,
        ] {
            assert_eq!(
                items_for(&dir, mask, &name("n")),
                vec![entry("d", "n")],
                "{mask:?}"
            );
        }
        for mask in [AddWatchFlags::IN_MODIFY, AddWatchFlags::IN_ATTRIB] {
            assert_eq!(
                items_for(&dir, mask, &name("n")),
                vec![EventItem::Data { path: path("d/n") }],
                "{mask:?}"
            );
        }
    }

    #[test]
    fn requests_name_the_directories_they_watch() {
        let named = |req: Request| dirs_named(&req);
        assert_eq!(
            named(Request::Lookup {
                parent: path("a/b"),
                name: name("x")
            }),
            vec![path("a/b")]
        );
        assert_eq!(
            named(Request::Rename {
                parent: path("a"),
                name: name("x"),
                newparent: path("b"),
                newname: name("y"),
                flags: 0
            }),
            vec![path("a"), path("b")]
        );
        assert_eq!(
            named(Request::Link {
                path: path("a/f"),
                newparent: path("b"),
                newname: name("g")
            }),
            vec![path("a"), path("b")]
        );
        assert_eq!(
            named(Request::Getattr {
                path: Some(path("a/f")),
                fh: None
            }),
            vec![path("a")]
        );
        assert_eq!(
            named(Request::Getattr {
                path: Some(Path::root()),
                fh: None
            }),
            vec![Path::root()],
            "the root is its own"
        );
        assert!(
            named(Request::Getattr {
                path: None,
                fh: Some(1)
            })
            .is_empty(),
            "an unlinked open file is in no directory"
        );
        assert_eq!(
            named(Request::Opendir {
                fh: 3,
                path: path("a/d")
            }),
            vec![path("a/d")],
            "a listing watches the directory listed"
        );
        for req in [
            Request::Read {
                fh: 1,
                offset: 0,
                size: 1,
            },
            Request::Readdir {
                fh: 2,
                offset: 0,
                max_bytes: 4096,
            },
            Request::Release { fh: 1 },
            Request::Statfs { path: path("a") },
        ] {
            assert!(named(req.clone()).is_empty(), "{req:?}");
        }
    }

    /// A directory tree in memory, watched the way inotify watches: one descriptor per watched directory, the same one for a second `add`, and none once the directory is removed. Inode 1 is the root. The `*_reporting` changes return the events inotify would queue for them.
    #[derive(Default)]
    struct Fake {
        state: Mutex<FakeState>,
    }

    #[derive(Default)]
    struct FakeState {
        dirs: HashMap<u64, HashMap<Name, u64>>,
        next_ino: u64,
        watches: HashMap<u64, u32>,
        next_wd: u32,
        next_cookie: u32,
        refused: HashMap<u64, Errno>,
        calls: Vec<String>,
    }

    impl FakeState {
        fn ino_of(&self, p: &Path) -> Option<u64> {
            p.names()
                .iter()
                .try_fold(1, |ino, name| self.dirs.get(&ino)?.get(name).copied())
        }

        /// Where `ino` is now, for the call log.
        fn shown(&self, ino: u64) -> String {
            if ino == 1 {
                return "/".into();
            }
            for (parent, children) in &self.dirs {
                for (name, child) in children {
                    if *child == ino {
                        let above = self.shown(*parent);
                        return if above == "/" {
                            name.to_string()
                        } else {
                            format!("{above}/{name}")
                        };
                    }
                }
            }
            format!("#{ino}")
        }

        fn event(
            &self,
            ino: u64,
            mask: AddWatchFlags,
            cookie: u32,
            name: Option<&Name>,
        ) -> Option<RawEvent<u32>> {
            Some(RawEvent {
                wd: *self.watches.get(&ino)?,
                mask,
                cookie,
                name: name.map(|n| n.as_os_str().to_os_string()),
            })
        }
    }

    impl Fake {
        fn new(dirs: &[&str]) -> Fake {
            let fake = Fake::default();
            {
                let mut state = fake.state.lock();
                state.dirs.insert(1, HashMap::new());
                state.next_ino = 2;
            }
            for dir in dirs {
                fake.mkdir(dir);
            }
            fake
        }

        fn mkdir(&self, p: &str) {
            let mut state = self.state.lock();
            let mut ino = 1;
            for name in path(p).names() {
                ino = match state.dirs[&ino].get(name) {
                    Some(child) => *child,
                    None => {
                        let child = state.next_ino;
                        state.next_ino += 1;
                        state.dirs.insert(child, HashMap::new());
                        state
                            .dirs
                            .get_mut(&ino)
                            .unwrap()
                            .insert(name.clone(), child);
                        child
                    }
                };
            }
        }

        /// Take `p` out of its parent; with `to`, put it there instead, replacing what was there.
        fn mv(&self, p: &str, to: Option<&str>) {
            self.mv_reporting(&path(p), to.map(path).as_ref());
        }

        /// As [`Fake::mv`], `to` naming no directory yet.
        fn mv_reporting(&self, from: &Path, to: Option<&Path>) -> Vec<RawEvent<u32>> {
            let mut state = self.state.lock();
            let (parent, last) = from.split_last().unwrap();
            let parent = state.ino_of(&parent).unwrap();
            let ino = state.dirs.get_mut(&parent).unwrap().remove(last).unwrap();
            state.next_cookie += 1;
            let cookie = state.next_cookie;
            let mut events = Vec::new();
            events.extend(state.event(
                parent,
                AddWatchFlags::IN_MOVED_FROM | DIR,
                cookie,
                Some(last),
            ));
            if let Some(to) = to {
                let (dest, name) = to.split_last().unwrap();
                let dest = state.ino_of(&dest).unwrap();
                state.dirs.get_mut(&dest).unwrap().insert(name.clone(), ino);
                events.extend(state.event(
                    dest,
                    AddWatchFlags::IN_MOVED_TO | DIR,
                    cookie,
                    Some(name),
                ));
            }
            events.extend(state.event(ino, AddWatchFlags::IN_MOVE_SELF, 0, None));
            events
        }

        /// Remove the empty directory `p`.
        fn rmdir_reporting(&self, p: &Path) -> Vec<RawEvent<u32>> {
            let mut state = self.state.lock();
            let (parent, last) = p.split_last().unwrap();
            let parent = state.ino_of(&parent).unwrap();
            let ino = state.dirs.get_mut(&parent).unwrap().remove(last).unwrap();
            let mut events = Vec::new();
            events.extend(state.event(parent, AddWatchFlags::IN_DELETE | DIR, 0, Some(last)));
            events.extend(state.event(ino, AddWatchFlags::IN_DELETE_SELF, 0, None));
            events.extend(state.event(ino, AddWatchFlags::IN_IGNORED, 0, None));
            state.watches.remove(&ino);
            events
        }

        fn mkdir_reporting(&self, p: &Path) -> Vec<RawEvent<u32>> {
            let (parent, last) = p.split_last().unwrap();
            self.mkdir(&p.to_os_string().to_string_lossy());
            let state = self.state.lock();
            let parent = state.ino_of(&parent).unwrap();
            state
                .event(parent, AddWatchFlags::IN_CREATE | DIR, 0, Some(last))
                .into_iter()
                .collect()
        }

        fn refuse(&self, p: &str, errno: Errno) {
            let mut state = self.state.lock();
            let ino = state.ino_of(&path(p)).unwrap();
            state.refused.insert(ino, errno);
        }

        fn wd_of(&self, p: &str) -> u32 {
            let state = self.state.lock();
            state.watches[&state.ino_of(&path(p)).unwrap()]
        }

        fn calls(&self) -> Vec<String> {
            std::mem::take(&mut self.state.lock().calls)
        }
    }

    impl Marks for Fake {
        type Wd = u32;
        type Dir = u64;

        fn open(&self, p: &Path) -> Result<u64, Errno> {
            let mut state = self.state.lock();
            state.calls.push(format!("open {}", shown(p)));
            state.ino_of(p).ok_or(Errno::ENOENT)
        }

        fn open_child(&self, parent: &u64, name: &Name) -> Result<u64, Errno> {
            let mut state = self.state.lock();
            state.calls.push(format!("open_child {name}"));
            state.dirs[parent].get(name).copied().ok_or(Errno::ENOENT)
        }

        fn add(&self, dir: &u64) -> Result<u32, Errno> {
            let mut state = self.state.lock();
            let shown = state.shown(*dir);
            state.calls.push(format!("add {shown}"));
            if let Some(errno) = state.refused.get(dir) {
                return Err(*errno);
            }
            if let Some(wd) = state.watches.get(dir) {
                return Ok(*wd);
            }
            state.next_wd += 1;
            let wd = state.next_wd;
            state.watches.insert(*dir, wd);
            Ok(wd)
        }

        fn rm(&self, wd: u32) {
            let mut state = self.state.lock();
            state.calls.push(format!("rm {wd}"));
            state.watches.retain(|_, w| *w != wd);
        }
    }

    fn table(dirs: &[&str]) -> Table<Fake> {
        table_within(dirs, 64)
    }

    fn table_within(dirs: &[&str], budget: usize) -> Table<Fake> {
        let hub = Arc::new(jackalopefs_perf::hub::Hub::default());
        let table = Table::new(Fake::new(dirs), budget, Events::new(&hub)).unwrap();
        table.marks.calls();
        table
    }

    fn watched(table: &Table<Fake>) -> BTreeSet<String> {
        table
            .by_wd
            .values()
            .filter(|p| !p.is_root())
            .map(|p| p.to_os_string().to_string_lossy().into_owned())
            .collect()
    }

    fn set(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|p| p.to_string()).collect()
    }

    /// Watch `p` as a request that has already been answered does.
    fn arm(table: &mut Table<Fake>, p: &str) -> Vec<EventItem> {
        let mut out = Vec::new();
        table.arm(&path(p), Instant::now(), &mut out);
        out
    }

    fn event(wd: u32, mask: AddWatchFlags, cookie: u32, name: Option<&str>) -> RawEvent<u32> {
        RawEvent {
            wd,
            mask,
            cookie,
            name: name.map(OsString::from),
        }
    }

    fn apply(table: &mut Table<Fake>, events: Vec<RawEvent<u32>>) -> Vec<EventItem> {
        let mut out = Vec::new();
        table.apply(events, &mut out);
        out
    }

    const ROOT_WD: u32 = 1;
    const DIR: AddWatchFlags = AddWatchFlags::IN_ISDIR;

    #[test]
    fn a_deep_path_is_watched_top_down_each_directory_inside_its_watched_parent() {
        let mut t = table(&["a/b/c"]);
        assert!(arm(&mut t, "a/b/c").is_empty());
        assert_eq!(watched(&t), set(&["a", "a/b", "a/b/c"]));
        assert_eq!(t.watched, 3);
        assert_eq!(
            t.marks.calls(),
            [
                "open /",
                "open_child a",
                "add a",
                "open_child b",
                "add a/b",
                "open_child c",
                "add a/b/c"
            ],
            "each directory is resolved only once the one above it is watched"
        );
    }

    #[test]
    fn a_watched_path_needs_no_system_call() {
        let mut t = table(&["a/b/c"]);
        arm(&mut t, "a/b");
        t.marks.calls();
        let now = Instant::now();
        assert!(matches!(t.touch(&path("a/b"), now), Touched::Done(Some(_))));
        assert!(matches!(t.touch(&path("a"), now), Touched::Done(Some(_))));
        assert!(matches!(t.touch(&path("a/b/c"), now), Touched::Missing));
        assert!(t.marks.calls().is_empty());
    }

    #[test]
    fn a_request_holds_the_directory_it_is_in_until_it_is_done() {
        let mut t = table(&["a/b"]);
        let first = t
            .arm(&path("a/b"), Instant::now(), &mut Vec::new())
            .unwrap();
        let Touched::Done(Some(second)) = t.touch(&path("a/b"), Instant::now()) else {
            panic!("a/b is watched");
        };
        assert!(Arc::ptr_eq(&first.0, &second.0));
        assert_eq!(first.0.holds.load(Ordering::Relaxed), 2);
        drop(second);
        drop(first);
        assert_eq!(
            t.node(&path("a/b"))
                .unwrap()
                .mark
                .holds
                .load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn a_directory_moved_within_the_export_keeps_its_watches_under_its_new_name() {
        let mut t = table(&["a/b/c"]);
        arm(&mut t, "a/b/c");
        let c = t.marks.wd_of("a/b/c");
        let events = t.marks.mv_reporting(&path("a/b"), Some(&path("x")));
        t.marks.calls();
        let out = apply(&mut t, events);
        assert_eq!(out, vec![entry("a", "b"), entry("", "x")]);
        assert_eq!(watched(&t), set(&["a", "x", "x/c"]));
        assert_eq!(t.by_wd[&c], path("x/c"));
        assert!(
            !t.marks.calls().iter().any(|c| c.starts_with("rm")),
            "the watches stay on"
        );
    }

    #[test]
    fn a_directory_watched_under_its_new_name_before_its_move_is_applied_keeps_its_watch() {
        let mut t = table(&["a/b/c"]);
        arm(&mut t, "a/b/c");
        let events = t.marks.mv_reporting(&path("a/b"), Some(&path("x")));
        assert!(arm(&mut t, "x").is_empty(), "nothing was dropped");
        assert_eq!(watched(&t), set(&["a", "x", "x/c"]));
        let out = apply(&mut t, events);
        assert_eq!(out, vec![entry("a", "b"), entry("", "x")]);
        assert_eq!(watched(&t), set(&["a", "x", "x/c"]));
        assert!(!t.marks.calls().iter().any(|c| c.starts_with("rm")));
    }

    #[test]
    fn a_directory_replaced_before_its_move_is_applied_is_caught_by_a_request_below_it() {
        let mut t = table(&["a"]);
        arm(&mut t, "a");
        let old = t.marks.wd_of("a");
        let mut events = t.marks.mv_reporting(&path("a"), Some(&path("a.old")));
        events.extend(t.marks.mkdir_reporting(&path("a")));
        t.marks.mkdir("a/b");
        assert_eq!(
            arm(&mut t, "a/b"),
            vec![unwatched("a")],
            "what the table had at a went with the old directory"
        );
        assert_eq!(watched(&t), set(&["a", "a/b"]));
        assert_eq!(t.by_wd.get(&t.marks.wd_of("a")), Some(&path("a")));
        assert!(!t.by_wd.contains_key(&old));
        apply(&mut t, events);
        assert_eq!(watched(&t), set(&["a", "a/b"]));
        assert_eq!(t.by_wd.get(&t.marks.wd_of("a/b")), Some(&path("a/b")));
    }

    #[test]
    fn a_directory_moved_out_of_sight_is_dropped_and_announced() {
        let mut t = table(&["a/b/c"]);
        arm(&mut t, "a/b/c");
        let events = t.marks.mv_reporting(&path("a/b"), None);
        let out = apply(&mut t, events);
        assert_eq!(
            out.into_iter().collect::<HashSet<_>>(),
            HashSet::from([entry("a", "b"), unwatched("a/b"), unwatched("a/b/c")])
        );
        assert_eq!(watched(&t), set(&["a"]));
        assert_eq!(t.watched, 1);
    }

    #[test]
    fn a_directory_renamed_over_or_removed_is_dropped_without_waiting_for_its_watch_to_end() {
        let mut t = table(&["d/old/sub", "d/gone", "e"]);
        arm(&mut t, "d/old/sub");
        arm(&mut t, "d/gone");
        let d = t.marks.wd_of("d");
        t.marks.mv("e", Some("d/old"));
        t.marks.mv("d/gone", None);
        let out = apply(
            &mut t,
            vec![
                event(ROOT_WD, AddWatchFlags::IN_MOVED_FROM | DIR, 9, Some("e")),
                event(d, AddWatchFlags::IN_MOVED_TO | DIR, 9, Some("old")),
                event(d, AddWatchFlags::IN_DELETE | DIR, 0, Some("gone")),
            ],
        );
        for item in [
            unwatched("d/old"),
            unwatched("d/old/sub"),
            unwatched("d/gone"),
        ] {
            assert!(out.contains(&item), "{item:?} in {out:?}");
        }
        assert_eq!(watched(&t), set(&["d"]));
        assert_eq!(
            t.marks.state.lock().watches.len(),
            2,
            "the root and d; the check of what is at d/old took its watch off again"
        );
    }

    #[test]
    fn a_directory_replaced_before_its_removal_is_applied_is_dropped_and_then_watched_afresh() {
        let mut t = table(&["d/sub"]);
        arm(&mut t, "d/sub");
        let old = t.marks.wd_of("d/sub");
        let mut events = t.marks.rmdir_reporting(&path("d/sub"));
        events.extend(t.marks.mkdir_reporting(&path("d/sub")));
        let out = apply(&mut t, events);
        assert_eq!(
            out,
            vec![entry("d", "sub"), unwatched("d/sub"), entry("d", "sub")]
        );
        assert_eq!(watched(&t), set(&["d"]));
        assert_eq!(
            t.marks.state.lock().watches.len(),
            2,
            "the check of what is at d/sub took its watch off again"
        );
        arm(&mut t, "d/sub");
        assert_ne!(t.marks.wd_of("d/sub"), old);
        assert_eq!(watched(&t), set(&["d", "d/sub"]));
    }

    #[test]
    fn an_overflow_keeps_what_is_still_where_the_table_has_it() {
        let mut t = table(&["a/b", "c/d"]);
        arm(&mut t, "a/b");
        arm(&mut t, "c/d");
        let (c, d) = (t.marks.wd_of("c"), t.marks.wd_of("c/d"));
        t.marks.mv("c", Some("x"));
        t.marks.calls();
        let out = apply(
            &mut t,
            vec![event(u32::MAX, AddWatchFlags::IN_Q_OVERFLOW, 0, None)],
        );
        assert_eq!(
            out,
            vec![EventItem::Overflow, unwatched("c/d"), unwatched("c")]
        );
        assert_eq!(watched(&t), set(&["a", "a/b"]));
        let removed: HashSet<String> = t
            .marks
            .calls()
            .into_iter()
            .filter(|c| c.starts_with("rm"))
            .collect();
        assert_eq!(
            removed,
            HashSet::from([format!("rm {c}"), format!("rm {d}")]),
            "only the moved directories' watches came off"
        );
    }

    #[test]
    fn a_directory_that_cannot_be_watched_is_left_alone_until_its_retry() {
        let mut t = table(&["a/b/c"]);
        t.marks.refuse("a/b", Errno::EACCES);
        let now = Instant::now();
        let held = t.arm(&path("a/b/c"), now, &mut Vec::new()).unwrap();
        assert!(
            Arc::ptr_eq(&held.0, &t.node(&path("a")).unwrap().mark),
            "a is the deepest watched"
        );
        assert_eq!(watched(&t), set(&["a"]));
        assert_eq!(t.watched, 1);
        assert!(
            !t.marks.calls().contains(&"open_child c".to_string()),
            "nothing below it is tried"
        );
        assert!(matches!(
            t.touch(&path("a/b/c"), now + Duration::from_secs(1)),
            Touched::Done(Some(_))
        ));
        let later = now + UNWATCHABLE_RETRY + Duration::from_secs(1);
        assert!(matches!(t.touch(&path("a/b/c"), later), Touched::Missing));
        t.marks.state.lock().refused.clear();
        t.arm(&path("a/b/c"), later, &mut Vec::new());
        assert_eq!(watched(&t), set(&["a", "a/b", "a/b/c"]));
    }

    #[test]
    fn a_directory_gone_on_its_own_is_dropped_quietly_and_the_roots_end_disables_everything() {
        let mut t = table(&["a/b"]);
        arm(&mut t, "a/b");
        let b = t.marks.wd_of("a/b");
        assert!(apply(&mut t, vec![event(b, AddWatchFlags::IN_IGNORED, 0, None)]).is_empty());
        assert_eq!(watched(&t), set(&["a"]));
        assert!(
            apply(
                &mut t,
                vec![event(ROOT_WD, AddWatchFlags::IN_MOVE_SELF, 0, None)]
            )
            .is_empty(),
            "the export root moving changes no path below it"
        );
        assert_eq!(watched(&t), set(&["a"]));
        assert_eq!(
            apply(
                &mut t,
                vec![event(ROOT_WD, AddWatchFlags::IN_IGNORED, 0, None)]
            ),
            vec![EventItem::Overflow]
        );
        assert!(matches!(
            t.touch(&path("a"), Instant::now()),
            Touched::Done(None)
        ));
        assert!(t.arm(&path("a"), Instant::now(), &mut Vec::new()).is_none());
    }

    #[test]
    fn the_roots_own_attributes_are_reported_and_a_subdirectorys_are_left_to_its_parent() {
        let mut t = table(&["a"]);
        arm(&mut t, "a");
        let a = t.marks.wd_of("a");
        let out = apply(
            &mut t,
            vec![
                event(ROOT_WD, AddWatchFlags::IN_ATTRIB, 0, None),
                event(a, AddWatchFlags::IN_ATTRIB, 0, None),
            ],
        );
        assert_eq!(out, vec![EventItem::Data { path: Path::root() }]);
    }

    #[test]
    fn the_directory_used_longest_ago_goes_first() {
        let mut t = table_within(&["a", "b", "c", "d", "e"], 3);
        arm(&mut t, "a");
        arm(&mut t, "b");
        arm(&mut t, "c");
        assert_eq!(
            arm(&mut t, "d"),
            vec![unwatched("a")],
            "a, b and c tie, and a comes first"
        );
        drop(t.touch(&path("b"), Instant::now()));
        assert_eq!(
            arm(&mut t, "e"),
            vec![unwatched("c")],
            "b was used again since the last drop, c was not"
        );
        assert_eq!(watched(&t), set(&["b", "d", "e"]));
        assert_eq!(
            t.marks.state.lock().watches.len(),
            4,
            "the watches dropped came off"
        );
    }

    #[test]
    fn a_directory_goes_only_once_nothing_below_it_is_watched() {
        let mut t = table_within(&["a/b", "c", "d"], 3);
        arm(&mut t, "a/b");
        arm(&mut t, "c");
        assert_eq!(
            arm(&mut t, "d"),
            vec![unwatched("a/b")],
            "the deepest of a tie goes first"
        );
        assert_eq!(
            arm(&mut t, "a/b"),
            vec![unwatched("c")],
            "a is on the way to a/b"
        );
        assert_eq!(watched(&t), set(&["a", "a/b", "d"]));
    }

    #[test]
    fn a_held_directory_is_kept_beyond_the_budget() {
        let mut t = table_within(&["a/b", "c"], 1);
        let held = t.arm(&path("c"), Instant::now(), &mut Vec::new()).unwrap();
        assert!(arm(&mut t, "a").is_empty(), "c is held");
        assert_eq!(watched(&t), set(&["a", "c"]));
        drop(held);
        assert_eq!(arm(&mut t, "a/b"), vec![unwatched("c")]);
        assert_eq!(watched(&t), set(&["a", "a/b"]));
    }

    #[test]
    fn running_out_of_watches_first_lowers_the_budget_for_a_while() {
        let mut t = table_within(&["a", "b", "c"], 64);
        arm(&mut t, "a");
        arm(&mut t, "b");
        t.marks.refuse("c", Errno::ENOSPC);
        let now = Instant::now();
        let mut out = Vec::new();
        t.arm(&path("c"), now, &mut out);
        assert_eq!(out, vec![unwatched("a")], "one directory made room");
        assert!(
            !watched(&t).contains("c"),
            "still refused, so left unwatched"
        );
        assert_eq!(t.budget_at(now), 2);
        assert_eq!(t.budget_at(now + LIMITED_HOLD), 64);
        assert!(t.notes.iter().any(|n| matches!(n, Note::Warn(_))));
        assert!(t.notes.iter().any(|n| matches!(n, Note::Info(_))));
    }

    #[test]
    fn the_budget_is_half_the_systems_limit_within_bounds() {
        assert_eq!(budget_from(Ok("524288\n".into())), BUDGET_MAX);
        assert_eq!(budget_from(Ok("8192".into())), 4096);
        assert_eq!(budget_from(Ok("1".into())), 1);
        assert_eq!(budget_from(Ok("lots".into())), BUDGET_FALLBACK);
        assert_eq!(
            budget_from(Err(std::io::ErrorKind::NotFound.into())),
            BUDGET_FALLBACK
        );
    }

    /// Requests, handles, moves, removals and creations in a pseudo-random order, with the events for the changes applied some steps later, as the event thread may: the table never watches a directory whose parent it does not, never holds a watch the system has not or the other way round, keeps to the budget but for what is held, and once every event is applied has each directory where the filesystem has it.
    #[test]
    fn the_table_keeps_its_shape_whatever_the_order() {
        let names = ["a", "b", "x"];
        let mut candidates = vec![Path::root()];
        for depth in 1..=3 {
            let mut next = Vec::new();
            for p in candidates.iter().filter(|p| p.names().len() == depth - 1) {
                for n in names {
                    next.push(p.join(name(n)).unwrap());
                }
            }
            candidates.extend(next);
        }
        candidates.remove(0);
        let mut t = table_within(&["a/a/a", "a/b", "b/a", "b/b/x"], 4);
        let mut seed: u64 = 0x9e3779b97f4a7c15;
        let mut next = |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        let mut held = Vec::new();
        let mut queued = Vec::new();
        let exists = |t: &Table<Fake>, p: &Path| t.marks.state.lock().ino_of(p).is_some();
        for step in 0..5000 {
            let p = candidates[next(candidates.len())].clone();
            match next(100) {
                0..=29 => {
                    let before = t.watched;
                    if let Some(h) = t.arm(&p, Instant::now(), &mut Vec::new()) {
                        held.push(h);
                    }
                    let installed = t.watched > before;
                    // Right after a directory was watched: a held directory stays, and so does every directory above it, and so does the path just watched.
                    let mut kept = HashSet::new();
                    for q in t.by_wd.values() {
                        if t.node(q)
                            .is_some_and(|n| n.mark.holds.load(Ordering::Relaxed) > 0)
                        {
                            for depth in 1..=q.names().len() {
                                kept.insert(path_of(&q.names()[..depth]));
                            }
                        }
                    }
                    assert!(
                        !installed || t.watched <= t.budget.max(kept.len()) + p.names().len(),
                        "step {step}: {} watched, budget {}, {} kept",
                        t.watched,
                        t.budget,
                        kept.len()
                    );
                }
                30..=39 => {
                    if let Touched::Done(Some(h)) = t.touch(&p, Instant::now()) {
                        held.push(h);
                    }
                }
                40..=69 => {
                    if !held.is_empty() {
                        held.swap_remove(next(held.len()));
                    }
                }
                70..=77 => {
                    let to = candidates[next(candidates.len())].clone();
                    let to_parent = parent_of(&to);
                    if exists(&t, &p)
                        && !exists(&t, &to)
                        && exists(&t, &to_parent)
                        && !to.names().starts_with(p.names())
                    {
                        queued.extend(t.marks.mv_reporting(&p, Some(&to)));
                    }
                }
                78..=81 => {
                    if exists(&t, &p) {
                        let empty = {
                            let state = t.marks.state.lock();
                            state
                                .ino_of(&p)
                                .is_some_and(|ino| state.dirs[&ino].is_empty())
                        };
                        if empty {
                            queued.extend(t.marks.rmdir_reporting(&p));
                        }
                    }
                }
                82..=87 => {
                    if !exists(&t, &p) && exists(&t, &parent_of(&p)) {
                        queued.extend(t.marks.mkdir_reporting(&p));
                    }
                }
                88..=98 => {
                    apply(&mut t, std::mem::take(&mut queued));
                    for (wd, q) in &t.by_wd {
                        let state = t.marks.state.lock();
                        let ino = state.ino_of(q);
                        assert!(
                            ino.is_some_and(|ino| state.watches.get(&ino) == Some(wd)),
                            "step {step}: {} is not where the table has it",
                            shown(q)
                        );
                    }
                }
                _ => {
                    // The kernel lost what it had queued.
                    queued.clear();
                    let out = apply(
                        &mut t,
                        vec![event(u32::MAX, AddWatchFlags::IN_Q_OVERFLOW, 0, None)],
                    );
                    assert_eq!(out.first(), Some(&EventItem::Overflow));
                }
            }
            for q in t.by_wd.values() {
                assert!(
                    q.is_root() || t.by_wd.values().any(|r| *r == parent_of(q)),
                    "step {step}: {} watched without its parent",
                    shown(q)
                );
            }
            assert_eq!(t.by_wd.len(), t.watched + 1, "step {step}");
            let state = t.marks.state.lock();
            for wd in state.watches.values() {
                assert!(
                    t.by_wd.contains_key(wd),
                    "step {step}: watch {wd} placed and forgotten"
                );
            }
        }
        assert!(t.events.count(Slowpath::WatchEvicted) > 100);
        assert!(t.events.count(Slowpath::InotifyOverflow) > 10);
    }

    /// Write a file in the root and collect items until its own arrives. The kernel queues events in order, so anything an earlier change was going to produce has come by then.
    async fn until_sentinel(
        rx: &mut broadcast::Receiver<Arc<EventBatch>>,
        root: &std::path::Path,
        n: usize,
    ) -> Vec<EventItem> {
        let sentinel = format!("sentinel-{n}");
        std::fs::write(root.join(&sentinel), b"").unwrap();
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let batch = tokio::time::timeout(left, rx.recv())
                .await
                .expect("the sentinel's event did not come")
                .unwrap();
            for (item, _) in batch.items.iter() {
                if *item == entry("", &sentinel) {
                    return seen;
                }
                seen.push(item.clone());
            }
        }
    }

    fn export_in(dir: &std::path::Path) -> Arc<Export> {
        Arc::new(Export::open(dir).unwrap())
    }

    #[tokio::test]
    async fn a_directory_is_reported_once_a_request_names_it() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("d")).unwrap();
        let (events, mut rx) = broadcast::channel(256);
        let (watches, _handle) = spawn(
            export_in(&root),
            &root,
            64,
            Events::new(&Arc::new(jackalopefs_perf::hub::Hub::default())),
            Arc::new(ChangeLog::default()),
            events,
        );
        std::fs::write(root.join("d/early"), b"").unwrap();
        let seen = until_sentinel(&mut rx, &root, 0).await;
        assert!(
            !seen
                .iter()
                .any(|item| matches!(item, EventItem::Entry { dir, .. } if *dir == path("d"))),
            "d is not watched until a request names it: {seen:?}"
        );
        assert!(watches.arm(&path("d")).is_some());
        std::fs::write(root.join("d/late"), b"").unwrap();
        let seen = until_sentinel(&mut rx, &root, 1).await;
        assert!(seen.contains(&entry("d", "late")), "{seen:?}");
    }

    #[tokio::test]
    async fn a_watched_directory_renamed_on_the_export_is_reported_under_its_new_name() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        let (events, mut rx) = broadcast::channel(256);
        let (watches, _handle) = spawn(
            export_in(&root),
            &root,
            64,
            Events::new(&Arc::new(jackalopefs_perf::hub::Hub::default())),
            Arc::new(ChangeLog::default()),
            events,
        );
        assert!(watches.arm(&path("a/b")).is_some());
        std::fs::rename(root.join("a/b"), root.join("x")).unwrap();
        std::fs::write(root.join("x/f"), b"").unwrap();
        let seen = until_sentinel(&mut rx, &root, 0).await;
        assert!(seen.contains(&entry("a", "b")), "{seen:?}");
        assert!(seen.contains(&entry("", "x")), "{seen:?}");
        assert!(seen.contains(&entry("x", "f")), "{seen:?}");
        assert!(
            !seen
                .iter()
                .any(|item| matches!(item, EventItem::Unwatched { .. })),
            "{seen:?}"
        );
    }

    #[tokio::test]
    async fn dropping_the_handle_stops_the_event_thread() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let (events, _rx) = broadcast::channel(256);
        let (watches, handle) = spawn(
            export_in(&root),
            &root,
            64,
            Events::new(&Arc::new(jackalopefs_perf::hub::Hub::default())),
            Arc::new(ChangeLog::default()),
            events,
        );
        assert_eq!(
            Arc::strong_count(&watches),
            2,
            "the event thread holds the table"
        );
        drop(handle);
        assert_eq!(Arc::strong_count(&watches), 1, "the thread has ended");
    }
}

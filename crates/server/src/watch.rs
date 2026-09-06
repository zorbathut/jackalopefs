//! Change notification: one inotify watch per directory under the export, placed by a walker thread that skips what it cannot list, folded into short batches and fanned out to sessions. A session is not told about changes it made itself. Each directory's watch also reports that directory's own deletion or move, which its parent's watch reports too; the batch folds the duplicate.
//!
//! This is a latency improvement, not the correctness mechanism: the client's cache TTL is the backstop. inotify misses `mmap` writes, has watch limits, and drops events under load; every such gap surfaces as [`EventItem::Overflow`] or is simply covered by the TTL.

use jackalopefs_proto::{Event, EventItem, Name, Path};
use notify::event::{CreateKind, ModifyKind, RenameMode};
use notify::{EventKind, RecursiveMode, Watcher};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};

/// How long raw events accumulate before one batch goes out.
pub const DEBOUNCE_WINDOW: Duration = Duration::from_millis(100);

/// Distinct items one batch may hold before it collapses to an overflow.
const MAX_PENDING: usize = 10_000;

/// Raw events buffered between the inotify thread and the debouncer.
const RAW_QUEUE: usize = 4096;

/// Upper bound on how long a recorded change waits for its inotify event before it stops counting as the origin.
const ORIGIN_MEMORY: Duration = Duration::from_secs(1);

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

/// Relative `Path` for an absolute path under `root`; `None` (logged) if it is outside, has a component that isn't a valid name, or is too long. Such a change goes unreported and the client's TTL covers it.
pub fn relative_path(root: &std::path::Path, abs: &std::path::Path) -> Option<Path> {
    let Ok(rel) = abs.strip_prefix(root) else {
        tracing::debug!(path = %abs.display(), "event outside the export root ignored");
        return None;
    };
    let mut names = Vec::new();
    for component in rel.components() {
        match component {
            std::path::Component::Normal(part) => match Name::try_from(part) {
                Ok(name) => names.push(name),
                Err(e) => {
                    tracing::debug!(path = %abs.display(), "event path has an unrepresentable component ({e}); not reported");
                    return None;
                }
            },
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    match Path::from_names(names) {
        Ok(path) => Some(path),
        Err(e) => {
            tracing::debug!(path = %abs.display(), "event path not reported: {e}");
            None
        }
    }
}

/// Translate one inotify event into items. Renames and creates/removes are entry changes on the parent; content and attribute changes are data changes on the node; a rescan request is an overflow.
pub fn items_for(root: &std::path::Path, event: &notify::Event) -> Vec<EventItem> {
    if event.need_rescan() {
        return vec![EventItem::Overflow];
    }
    let entry = |abs: &PathBuf| -> Option<EventItem> {
        let path = relative_path(root, abs)?;
        let (dir, name) = path.split_last()?;
        Some(EventItem::Entry {
            dir,
            name: name.clone(),
        })
    };
    let data = |abs: &PathBuf| -> Option<EventItem> {
        Some(EventItem::Data {
            path: relative_path(root, abs)?,
        })
    };
    let mapper: &dyn Fn(&PathBuf) -> Option<EventItem> = match &event.kind {
        EventKind::Create(_) | EventKind::Remove(_) => &entry,
        EventKind::Modify(ModifyKind::Name(
            RenameMode::From
            | RenameMode::To
            | RenameMode::Both
            | RenameMode::Any
            | RenameMode::Other,
        )) => &entry,
        EventKind::Modify(_) | EventKind::Any | EventKind::Other => &data,
        EventKind::Access(_) => return Vec::new(),
    };
    event.paths.iter().filter_map(mapper).collect()
}

fn origin_key(item: &EventItem) -> Option<OsString> {
    match item {
        EventItem::Entry { dir, name } => dir.join(name.clone()).ok().map(|p| p.to_os_string()),
        EventItem::Data { path } => Some(path.to_os_string()),
        EventItem::Overflow => None,
    }
}

/// Directories this event brought into the tree: creates the kernel flagged as directories, and rename destinations that are directories right now (a rename is reported for files too, and the stat here keeps them off the walker's queue). Each needs its own walk, since nothing under a non-recursive watch is watched automatically. `RenameMode::Both` is not consulted: notify emits `To` for every `MOVED_TO` and adds `Both` alongside it only when it paired the cookie, so `To` alone is complete.
fn arrivals(event: &notify::Event) -> Vec<PathBuf> {
    match event.kind {
        EventKind::Create(CreateKind::Folder) => event.paths.clone(),
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => event
            .paths
            .iter()
            .filter(|path| std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir()))
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

#[derive(Debug, Default)]
struct WalkOutcome {
    watched: usize,
    skipped: usize,
    /// The directory at which the inotify watch limit was hit; the walk stopped there and the rest of the tree is unwatched.
    limit_hit: Option<PathBuf>,
}

/// The failure behind a watch error, without the path notify appends to its own message.
fn io_cause(err: notify::Error) -> std::io::Error {
    match err.kind {
        notify::ErrorKind::Io(e) => e,
        notify::ErrorKind::PathNotFound => std::io::ErrorKind::NotFound.into(),
        other => std::io::Error::other(format!("{other:?}")),
    }
}

/// Report a directory the walk is leaving out. An unreadable or vanished directory is routine on an export (snapshot directories, private home directories); anything else deserves attention.
fn log_skip(dir: &std::path::Path, err: &std::io::Error) {
    if matches!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
    ) {
        tracing::debug!("not watching {}: {err}", dir.display());
    } else {
        tracing::warn!("not watching {}: {err}", dir.display());
    }
}

/// Watch `top` and every directory below it, one non-recursive watch each. A directory below `top` that cannot be watched or listed is skipped: the server cannot list it for clients either, and its parent's watch still reports the entry itself. `top` itself failing is the error. Hitting the inotify watch limit ends the walk, keeping the watches placed so far; so does `stopping`. Symlinks are not followed; the server never resolves through them.
///
/// Each directory is watched before it is listed, so a subdirectory created meanwhile is found either by the listing or by the fresh watch's own create event (watching a path twice is harmless).
fn watch_tree(
    watcher: &mut notify::RecommendedWatcher,
    top: &std::path::Path,
    stopping: &AtomicBool,
) -> Result<WalkOutcome, std::io::Error> {
    let mut outcome = WalkOutcome::default();
    let mut stack = vec![top.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if stopping.load(Ordering::Relaxed) {
            break;
        }
        if let Err(e) = watcher.watch(&dir, RecursiveMode::NonRecursive) {
            if matches!(e.kind, notify::ErrorKind::MaxFilesWatch) {
                outcome.limit_hit = Some(dir);
                break;
            }
            let e = io_cause(e);
            if dir == top {
                return Err(e);
            }
            log_skip(&dir, &e);
            outcome.skipped += 1;
            continue;
        }
        outcome.watched += 1;
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) => {
                log_skip(&dir, &e);
                outcome.skipped += 1;
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    tracing::warn!("listing {}: {e}", dir.display());
                    continue;
                }
            };
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => stack.push(entry.path()),
                Ok(_) => {}
                Err(e) => tracing::debug!("not examining {}: {e}", entry.path().display()),
            }
        }
    }
    Ok(outcome)
}

/// A request to the walker thread.
enum Walk {
    /// Watch this directory and everything under it.
    Tree(PathBuf),
    Stop,
}

/// Owns the watcher: walks the root first, then every directory the event handler reports as new, until told to stop. Adding a watch is a round trip through notify's event loop, so this runs on its own thread rather than holding up event handling or the server's startup.
fn walker(
    mut watcher: notify::RecommendedWatcher,
    root: PathBuf,
    walks: std::sync::mpsc::Receiver<Walk>,
    stopping: Arc<AtomicBool>,
) {
    let mut limit_logged = false;
    let mut batch = vec![root.clone()];
    loop {
        // Take everything queued so far and collapse it: a root walk (a rescan after the kernel dropped events) covers every other request, and a burst of rescans is one walk, not a walk per overflow.
        for request in walks.try_iter() {
            match request {
                Walk::Tree(dir) => batch.push(dir),
                Walk::Stop => return,
            }
        }
        if batch.contains(&root) {
            batch = vec![root.clone()];
        } else {
            batch.sort();
            batch.dedup();
        }
        for dir in batch.drain(..) {
            if stopping.load(Ordering::Relaxed) {
                return;
            }
            walk_and_report(&mut watcher, &root, &dir, &stopping, &mut limit_logged);
        }
        match walks.recv() {
            Ok(Walk::Tree(dir)) => batch.push(dir),
            Ok(Walk::Stop) | Err(_) => return,
        }
    }
}

/// One walk and its log lines: a root walk at info, any other at debug, a root that cannot be watched at all as the error it is.
fn walk_and_report(
    watcher: &mut notify::RecommendedWatcher,
    root: &std::path::Path,
    dir: &std::path::Path,
    stopping: &AtomicBool,
    limit_logged: &mut bool,
) {
    let outcome = match watch_tree(watcher, dir, stopping) {
        // A walk cut short by shutdown has no census worth reporting.
        Ok(_) if stopping.load(Ordering::Relaxed) => return,
        Ok(outcome) => outcome,
        Err(e) if dir == root => {
            tracing::error!(
                "cannot watch {}: {e}; change notification disabled",
                root.display()
            );
            return;
        }
        Err(e) => {
            log_skip(dir, &e);
            return;
        }
    };
    if dir == root {
        tracing::info!(
            "watching {} directories under {} ({} skipped)",
            outcome.watched,
            root.display(),
            outcome.skipped
        );
    } else {
        tracing::debug!(
            "watching {} directories under {} ({} skipped)",
            outcome.watched,
            dir.display(),
            outcome.skipped
        );
    }
    if let Some(at) = outcome.limit_hit {
        if *limit_logged {
            tracing::debug!("inotify watch limit reached at {}", at.display());
        } else {
            tracing::error!("inotify watch limit reached at {}; directories beyond it stay unwatched (raise fs.inotify.max_user_watches and restart)", at.display());
            *limit_logged = true;
        }
    }
}

/// Keeps change notification alive. Dropping it stops the walker thread, which drops the inotify watcher, and aborts the debounce task.
pub struct WatcherHandle {
    walks: std::sync::mpsc::Sender<Walk>,
    stopping: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for WatcherHandle {
    fn drop(&mut self) {
        // The flag ends a walk in progress; the message wakes the walker if it is idle. Dropping this sender would not: the event handler holds one too, inside the watcher the walker owns.
        self.stopping.store(true, Ordering::Relaxed);
        if self.walks.send(Walk::Stop).is_err() {
            tracing::debug!("watch walker had already stopped");
        }
        self.task.abort();
    }
}

/// Start watching `export_dir` and everything under it. Returns `None` (after logging) when no watcher can be created, in which case clients fall back to their cache TTLs; a root that cannot be watched is logged by the walker to the same effect. Watches are placed by a background walk, so the first changes after startup may arrive on a large export before its watch does; the TTL covers those too.
pub fn spawn(
    export_dir: &std::path::Path,
    changes: Arc<ChangeLog>,
    events: broadcast::Sender<Arc<EventBatch>>,
) -> Option<WatcherHandle> {
    let root = match export_dir.canonicalize() {
        Ok(root) => root,
        Err(e) => {
            tracing::error!(
                "cannot canonicalize {}: {e}; change notification disabled",
                export_dir.display()
            );
            return None;
        }
    };
    let (raw_tx, raw_rx) = mpsc::channel::<notify::Event>(RAW_QUEUE);
    let (walk_tx, walk_rx) = std::sync::mpsc::channel::<Walk>();
    let stopping = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let dropped_by_handler = dropped.clone();
    let handler = {
        let root = root.clone();
        let walks = walk_tx.clone();
        // Watches for new directories are requested from here rather than from the debounce task so that a full raw queue can only ever lose client notifications, never watches. The handler cannot add them itself: a watch request waits on the event loop that is running the handler.
        let request = move |dir: PathBuf| {
            if walks.send(Walk::Tree(dir)).is_err() {
                tracing::debug!("watch walker has stopped; new directories go unwatched");
            }
        };
        move |result: notify::Result<notify::Event>| match result {
            Ok(event) => {
                // Opens, which the server itself generates in bulk, produce nothing downstream.
                if matches!(event.kind, EventKind::Access(_)) {
                    return;
                }
                // The kernel dropped events, possibly directory creations: re-walk everything.
                if event.need_rescan() {
                    request(root.clone());
                }
                for dir in arrivals(&event) {
                    request(dir);
                }
                if raw_tx.try_send(event).is_err() {
                    dropped_by_handler.store(true, Ordering::Relaxed);
                }
            }
            Err(e) => {
                tracing::warn!("inotify error: {e}");
                dropped_by_handler.store(true, Ordering::Relaxed);
            }
        }
    };
    let watcher = match notify::recommended_watcher(handler) {
        Ok(watcher) => watcher,
        Err(e) => {
            tracing::error!(
                "cannot create a filesystem watcher: {e}; change notification disabled"
            );
            return None;
        }
    };
    let spawned = std::thread::Builder::new()
        .name("watch-walker".into())
        .spawn({
            let root = root.clone();
            let stopping = stopping.clone();
            move || walker(watcher, root, walk_rx, stopping)
        });
    if let Err(e) = spawned {
        tracing::error!("cannot start the watch walker thread: {e}; change notification disabled");
        return None;
    }
    let task = tokio::spawn(debounce(root, raw_rx, dropped, changes, events));
    Some(WatcherHandle {
        walks: walk_tx,
        stopping,
        task,
    })
}

async fn debounce(
    root: PathBuf,
    mut raw: mpsc::Receiver<notify::Event>,
    dropped: Arc<AtomicBool>,
    changes: Arc<ChangeLog>,
    events: broadcast::Sender<Arc<EventBatch>>,
) {
    let mut pending = Pending::default();
    let mut tick = tokio::time::interval(DEBOUNCE_WINDOW);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            received = raw.recv() => {
                let Some(event) = received else { break };
                for item in items_for(&root, &event) {
                    let origin = origin_key(&item).and_then(|key| changes.take_origin(&key));
                    pending.fold(item, origin);
                }
            }
            _ = tick.tick() => {
                if dropped.swap(false, Ordering::Relaxed) {
                    tracing::warn!("raw inotify queue overflowed; clients will be told to rescan");
                    pending.fold(EventItem::Overflow, None);
                }
                if let Some(batch) = pending.flush() {
                    if events.send(Arc::new(batch)).is_err() {
                        tracing::trace!("change batch dropped: no sessions");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        Name::new(s.as_bytes()).unwrap()
    }

    fn entry(dir: &str, n: &str) -> EventItem {
        let dir = if dir.is_empty() {
            Path::root()
        } else {
            Path::from_names(dir.split('/').map(name).collect()).unwrap()
        };
        EventItem::Entry { dir, name: name(n) }
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
    fn notify_events_map_to_items() {
        let root = std::path::Path::new("/export");
        let ev = |kind: EventKind, paths: &[&str]| notify::Event {
            kind,
            paths: paths.iter().map(PathBuf::from).collect(),
            attrs: Default::default(),
        };
        assert_eq!(
            items_for(
                root,
                &ev(
                    EventKind::Create(notify::event::CreateKind::File),
                    &["/export/d/new"]
                )
            ),
            vec![entry("d", "new")]
        );
        assert_eq!(
            items_for(
                root,
                &ev(
                    EventKind::Remove(notify::event::RemoveKind::Any),
                    &["/export/gone"]
                )
            ),
            vec![entry("", "gone")]
        );
        assert_eq!(
            items_for(
                root,
                &ev(
                    EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
                    &["/export/a", "/export/d/b"]
                )
            ),
            vec![entry("", "a"), entry("d", "b")]
        );
        assert_eq!(
            items_for(
                root,
                &ev(
                    EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Any)),
                    &["/export/f"]
                )
            ),
            vec![EventItem::Data {
                path: Path::from_names(vec![name("f")]).unwrap()
            }]
        );
        assert!(items_for(
            root,
            &ev(
                EventKind::Access(notify::event::AccessKind::Any),
                &["/export/f"]
            )
        )
        .is_empty());
        assert!(
            items_for(
                root,
                &ev(
                    EventKind::Create(notify::event::CreateKind::File),
                    &["/elsewhere/x"]
                )
            )
            .is_empty(),
            "paths outside the root are ignored"
        );
        assert!(
            items_for(
                root,
                &ev(
                    EventKind::Create(notify::event::CreateKind::File),
                    &["/export"]
                )
            )
            .is_empty(),
            "the root itself has no parent entry"
        );
        let mut rescan = ev(EventKind::Other, &[]);
        rescan.attrs.set_flag(notify::event::Flag::Rescan);
        assert_eq!(items_for(root, &rescan), vec![EventItem::Overflow]);
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
    fn arrivals_are_directory_creates_and_rename_destinations() {
        let ev = |kind: EventKind, paths: &[&std::path::Path]| notify::Event {
            kind,
            paths: paths.iter().map(PathBuf::from).collect(),
            attrs: Default::default(),
        };
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        let file = tmp.path().join("f");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(&file, b"x").unwrap();
        let gone = tmp.path().join("gone");
        assert_eq!(
            arrivals(&ev(EventKind::Create(CreateKind::Folder), &[&gone])),
            std::slice::from_ref(&gone),
            "the kernel said directory; no stat needed"
        );
        assert_eq!(
            arrivals(&ev(
                EventKind::Modify(ModifyKind::Name(RenameMode::To)),
                &[&dir, &file, &gone]
            )),
            std::slice::from_ref(&dir),
            "only rename destinations that are directories"
        );
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Any)),
            EventKind::Remove(notify::event::RemoveKind::Folder),
        ] {
            assert!(
                arrivals(&ev(kind, &[&dir])).is_empty(),
                "{kind:?} brings no directory into the tree"
            );
        }
    }

    /// Restores a directory's mode on drop, so a failed assertion does not leave a tempdir that cannot be removed.
    struct ModeGuard(PathBuf);

    impl Drop for ModeGuard {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            // Not unwrapped: a panic here during an assertion failure's unwind would abort the whole test binary.
            if let Err(e) =
                std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755))
            {
                eprintln!("cannot restore the mode of {}: {e}", self.0.display());
            }
        }
    }

    #[test]
    fn watch_tree_skips_unlistable_directories() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let top = tmp.path().canonicalize().unwrap();
        std::fs::create_dir_all(top.join("a/b")).unwrap();
        let c = top.join("c");
        std::fs::create_dir(&c).unwrap();
        std::fs::set_permissions(&c, std::fs::Permissions::from_mode(0o000)).unwrap();
        let _restore = ModeGuard(c.clone());
        if std::fs::read_dir(&c).is_ok() {
            eprintln!("mode bits are not enforced for this user; nothing to test");
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher =
            notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
                // The receiver is gone once the test has what it needs.
                let _ = tx.send(result);
            })
            .unwrap();
        let outcome = watch_tree(&mut watcher, &top, &AtomicBool::new(false)).unwrap();
        assert_eq!(outcome.watched, 3, "top, a and a/b");
        assert_eq!(outcome.skipped, 1, "c");
        assert!(outcome.limit_hit.is_none());
        let err = watch_tree(&mut watcher, &c, &AtomicBool::new(false)).unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "the top itself failing is the error"
        );
        let file = top.join("a/b/f");
        std::fs::write(&file, b"x").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let event = rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("no create event for a/b/f before the deadline")
                .unwrap();
            if matches!(event.kind, EventKind::Create(_)) && event.paths.contains(&file) {
                break;
            }
        }
    }

    /// Create files under `dir` until a batch reports an entry there, failing after 5 s. The walk that watches a new directory runs on its own thread, so the first files may land before the watch does.
    async fn wait_until_watched(
        events: &mut broadcast::Receiver<Arc<EventBatch>>,
        root: &std::path::Path,
        dir: &str,
    ) {
        let target = if dir.is_empty() {
            Path::root()
        } else {
            Path::from_names(dir.split('/').map(name).collect()).unwrap()
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        for i in 0.. {
            assert!(
                Instant::now() < deadline,
                "no entry event under {dir} before the deadline"
            );
            std::fs::write(root.join(dir).join(format!("f{i}")), b"x").unwrap();
            while let Ok(batch) =
                tokio::time::timeout(Duration::from_millis(50), events.recv()).await
            {
                let batch = batch.unwrap();
                if batch
                    .items
                    .iter()
                    .any(|(item, _)| matches!(item, EventItem::Entry { dir, .. } if *dir == target))
                {
                    return;
                }
            }
        }
    }

    #[tokio::test]
    async fn new_directories_are_watched() {
        let tmp = tempfile::tempdir().unwrap();
        let export = tmp.path().join("export");
        let staging = tmp.path().join("staging");
        std::fs::create_dir(&export).unwrap();
        std::fs::create_dir(&staging).unwrap();
        let export = export.canonicalize().unwrap();
        let (events, mut rx) = broadcast::channel(256);
        let _watcher = spawn(&export, Arc::new(ChangeLog::default()), events).expect("watcher");
        // Until the root walk has listed the (empty) root, a directory created there would be found by that listing rather than by its own create event, which is the path under test. An event from the root takes at least one debounce window to arrive, by which time the listing is long done.
        wait_until_watched(&mut rx, &export, "").await;

        std::fs::create_dir(export.join("d")).unwrap();
        wait_until_watched(&mut rx, &export, "d").await;

        std::fs::create_dir_all(staging.join("e/sub")).unwrap();
        std::fs::rename(staging.join("e"), export.join("e")).unwrap();
        wait_until_watched(&mut rx, &export, "e/sub").await;
    }

    #[tokio::test]
    async fn reads_do_not_fill_the_change_queue() {
        let tmp = tempfile::tempdir().unwrap();
        let export = tmp.path().canonicalize().unwrap();
        let file = export.join("f");
        std::fs::write(&file, b"x").unwrap();
        let (events, mut rx) = broadcast::channel(256);
        let _watcher = spawn(&export, Arc::new(ChangeLog::default()), events).expect("watcher");
        wait_until_watched(&mut rx, &export, "").await;
        // Well over RAW_QUEUE opens while the debounce task cannot run (this runtime is single-threaded and we are not awaiting).
        for _ in 0..(RAW_QUEUE * 5) {
            std::fs::read(&file).unwrap();
        }
        // Whatever those opens produced is in the next window; a write afterwards proves the pipeline is still live and marks the end.
        std::fs::write(&file, b"y").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                Instant::now() < deadline,
                "no batch for the write before the deadline"
            );
            let Ok(batch) = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await else {
                continue;
            };
            let batch = batch.unwrap();
            assert!(
                !batch
                    .items
                    .iter()
                    .any(|(item, _)| matches!(item, EventItem::Overflow)),
                "reads must not overflow the queue"
            );
            if batch.items.iter().any(
                |(item, _)| matches!(item, EventItem::Data { path } if path.to_os_string() == "f"),
            ) {
                break;
            }
        }
    }
}

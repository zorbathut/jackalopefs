//! Change notification: inotify on the export root, folded into short batches and fanned out to sessions. A session is not told about changes it made itself.
//!
//! This is a latency improvement, not the correctness mechanism: the client's cache TTL is the backstop. inotify misses `mmap` writes, has watch limits, and drops events under load; every such gap surfaces as [`EventItem::Overflow`] or is simply covered by the TTL.

use jackalopefs_proto::{Event, EventItem, Name, Path};
use notify::event::{ModifyKind, RenameMode};
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

/// Keeps the inotify watcher alive; dropping it stops notifications.
pub struct WatcherHandle {
    _watcher: notify::RecommendedWatcher,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for WatcherHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Start watching `export_dir` recursively. Returns `None` (after logging) when watching is impossible, in which case clients fall back to their cache TTLs.
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
    let dropped = Arc::new(AtomicBool::new(false));
    let dropped_by_handler = dropped.clone();
    let handler = move |result: notify::Result<notify::Event>| match result {
        Ok(event) => {
            if raw_tx.try_send(event).is_err() {
                dropped_by_handler.store(true, Ordering::Relaxed);
            }
        }
        Err(e) => {
            tracing::warn!("inotify error: {e}");
            dropped_by_handler.store(true, Ordering::Relaxed);
        }
    };
    let mut watcher = match notify::recommended_watcher(handler) {
        Ok(watcher) => watcher,
        Err(e) => {
            tracing::error!(
                "cannot create a filesystem watcher: {e}; change notification disabled"
            );
            return None;
        }
    };
    if let Err(e) = watcher.watch(&root, RecursiveMode::Recursive) {
        tracing::error!("cannot watch {}: {e}; change notification disabled (check fs.inotify.max_user_watches)", root.display());
        return None;
    }
    tracing::info!("watching {} for changes", root.display());
    let task = tokio::spawn(debounce(root, raw_rx, dropped, changes, events));
    Some(WatcherHandle {
        _watcher: watcher,
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
}

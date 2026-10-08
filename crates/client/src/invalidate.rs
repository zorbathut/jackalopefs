//! Turns server events (and reconnects) into kernel cache invalidations. The `Notifier` calls are blocking writes to `/dev/fuse` that can wait on kernel directory locks, so they run on their own thread, fed by a bounded queue; a full queue collapses into one bounded sweep rather than blocking the event reader.

use crate::conn::ConnState;
use crate::fuse::{NotifierWork, Shared};
use fuser::{INodeNo, Notifier};
use jackalopefs_proto::{Event, EventItem, FileKind, Name};
use std::collections::HashSet;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, watch};

/// Pending notifier calls; beyond this, events collapse into a sweep.
const QUEUE: usize = 4096;

/// Directory entries a sweep will invalidate at most; the TTL covers the rest.
pub const SWEEP_LIMIT: usize = 4096;

pub enum Work {
    Entry(u64, Name),
    Inode(u64),
    /// A handle parked at the end of this directory's listing must ask the server again.
    DirGrew(u64),
    Sweep,
}

pub struct Invalidator {
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Invalidator {
    pub fn start(
        shared: Arc<Shared>,
        events: mpsc::Receiver<Event>,
        state: watch::Receiver<ConnState>,
        notifier: Notifier,
    ) -> Invalidator {
        let (tx, rx) = sync_channel(QUEUE);
        shared.invalidations_set(tx.clone());
        let thread_shared = shared.clone();
        let thread = std::thread::Builder::new()
            .name("jackalopefs-inval".into())
            .spawn(move || notifier_loop(rx, notifier, thread_shared))
            .expect("spawn notifier thread");
        let task = tokio::spawn(translate(shared.clone(), events, state, tx));
        Invalidator {
            shared,
            task,
            thread: Some(thread),
        }
    }

    /// Stop translating and wait for the notifier thread to drain; dropping does the same.
    pub fn stop(self) {
        drop(self);
    }
}

impl Drop for Invalidator {
    fn drop(&mut self) {
        // The notifier thread's receive loop ends when every sender is gone: the translator's with the task, and the FUSE layer's here.
        self.shared.invalidations_clear();
        self.task.abort();
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                tracing::error!("notifier thread panicked");
            }
        }
    }
}

/// Map wire events onto known nodes. Unknown paths need no invalidation: nothing is cached for them.
async fn translate(
    shared: Arc<Shared>,
    mut events: mpsc::Receiver<Event>,
    mut state: watch::Receiver<ConnState>,
    tx: SyncSender<Work>,
) {
    let mut sweep_pending = false;
    let mut last_generation = 0;
    loop {
        let mut work = Vec::new();
        tokio::select! {
            received = events.recv() => {
                let Some(event) = received else { break };
                // Taken before the node table, never inside it.
                let open: HashSet<u64> = if event.items.iter().any(|i| matches!(i, EventItem::Unwatched { .. })) {
                    shared.client.handles().open_nodeids().into_iter().collect()
                } else {
                    HashSet::new()
                };
                let nodes = shared.nodes.lock();
                for item in event.items {
                    match item {
                        EventItem::Entry { dir, name } => {
                            if let Some(parent) = nodes.resolve_path(&dir) {
                                work.push(Work::Entry(parent, name));
                            }
                        }
                        EventItem::Data { path } => {
                            if let Some(ino) = nodes.resolve_path(&path) {
                                work.push(Work::Inode(ino));
                                // The kernel keeps its own size and mtime for a regular file it holds, so the file is also taken away from it by name: an unopened file is then evicted and looked up afresh.
                                if let Some(node) = nodes.get(ino).filter(|n| n.kind == FileKind::Regular) {
                                    for (parent, name) in &node.aliases {
                                        work.push(Work::Entry(*parent, name.clone()));
                                    }
                                }
                            }
                        }
                        EventItem::Overflow => work.push(Work::Sweep),
                        // Dropping the directory's own dentry prunes every unused dentry beneath it, and their inodes with them; a file held open there keeps its inode, so its attributes and pages are dropped by name.
                        EventItem::Unwatched { dir } => {
                            if let Some((ino, node)) = nodes.resolve_path(&dir).and_then(|ino| Some((ino, nodes.get(ino)?))) {
                                for (parent, name) in &node.aliases {
                                    work.push(Work::Entry(*parent, name.clone()));
                                }
                                work.push(Work::DirGrew(ino));
                                for child in node.children.values().filter(|c| open.contains(c)) {
                                    work.push(Work::Inode(*child));
                                }
                            }
                        }
                    }
                }
            }
            changed = state.changed() => {
                if changed.is_err() {
                    break;
                }
                let generation = match &*state.borrow_and_update() {
                    ConnState::Connected(att) => att.generation,
                    _ => continue,
                };
                if generation > 1 && generation != last_generation {
                    tracing::info!(generation, "reconnected; invalidating cached state");
                    work.push(Work::Sweep);
                }
                last_generation = generation;
            }
        }
        if sweep_pending {
            match tx.try_send(Work::Sweep) {
                Ok(()) => sweep_pending = false,
                Err(TrySendError::Full(_)) => continue,
                Err(TrySendError::Disconnected(_)) => break,
            }
        }
        for item in work {
            match tx.try_send(item) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    tracing::warn!("invalidation queue full; collapsing to a sweep");
                    sweep_pending = true;
                    break;
                }
                Err(TrySendError::Disconnected(_)) => return,
            }
        }
    }
}

fn notifier_loop(rx: Receiver<Work>, notifier: Notifier, shared: Arc<Shared>) {
    while let Ok(work) = rx.recv() {
        match work {
            Work::Entry(parent, name) => {
                shared.dir_grew(parent);
                inval_entry(&notifier, &shared, parent, &name)
            }
            Work::Inode(ino) => {
                shared.xattr_forget(ino);
                inval_inode(&notifier, &shared, ino)
            }
            Work::DirGrew(ino) => shared.dir_grew(ino),
            Work::Sweep => {
                shared.xattr_clear();
                shared.dirs_grew_all();
                sweep(&notifier, &shared)
            }
        }
    }
}

/// Make one notifier call, marked as in progress for the watchdog while it lasts.
fn notifying<T>(shared: &Shared, kind: &'static str, ino: u64, call: impl FnOnce() -> T) -> T {
    *shared.notifier_busy.lock() = Some(NotifierWork {
        kind,
        ino,
        since: Instant::now(),
    });
    let out = call();
    *shared.notifier_busy.lock() = None;
    out
}

fn inval_entry(notifier: &Notifier, shared: &Shared, parent: u64, name: &Name) {
    match notifying(shared, "inval_entry", parent, || {
        notifier.inval_entry(INodeNo(parent), name.as_os_str())
    }) {
        Ok(()) => tracing::trace!(parent, %name, "inval_entry"),
        Err(e) => tracing::debug!(parent, %name, "inval_entry: {e}"),
    }
}

/// Drop the kernel's attributes for `ino`, and its pages unless this client is writing the file: invalidating pages first writes the dirty ones back, which would park this thread on the network for as long as that takes, and the kernel's copy of a file we are writing is the authority anyway.
fn inval_inode(notifier: &Notifier, shared: &Shared, ino: u64) {
    let pages = !shared.client.handles().has_writer(ino);
    let offset = if pages { 0 } else { -1 };
    match notifying(shared, "inval_inode", ino, || {
        notifier.inval_inode(INodeNo(ino), offset, 0)
    }) {
        Ok(()) => tracing::trace!(ino, pages, "inval_inode"),
        Err(e) => tracing::debug!(ino, pages, "inval_inode: {e}"),
    }
}

/// Everything might have changed: drop cached data for every open file and up to [`SWEEP_LIMIT`] directory entries. The snapshot is taken under the lock; the notifier calls are made without it.
fn sweep(notifier: &Notifier, shared: &Shared) {
    let open = shared.client.handles().open_nodeids();
    let (entries, files) = {
        let nodes = shared.nodes.lock();
        let entries = nodes.entries(SWEEP_LIMIT);
        let files: Vec<u64> = entries
            .iter()
            .filter(|(_, _, child)| {
                nodes
                    .get(*child)
                    .is_some_and(|n| n.kind == FileKind::Regular)
            })
            .map(|(_, _, child)| *child)
            .collect();
        (entries, files)
    };
    tracing::info!(
        open = open.len(),
        entries = entries.len(),
        "sweeping kernel cache"
    );
    for ino in open.into_iter().chain(files) {
        inval_inode(notifier, shared, ino);
    }
    for (parent, name, _) in entries {
        inval_entry(notifier, shared, parent, &name);
    }
}

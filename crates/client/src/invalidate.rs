//! Turns server events (and reconnects) into kernel cache invalidations. The `Notifier` calls are blocking writes to `/dev/fuse` that can wait on kernel directory locks, so they run on their own thread, fed by a bounded queue; a full queue collapses into one bounded sweep rather than blocking the event reader.

use crate::conn::ConnState;
use crate::fuse::Shared;
use fuser::{INodeNo, Notifier};
use jackalopefs_proto::{Event, EventItem, FileKind, Name};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

/// Pending notifier calls; beyond this, events collapse into a sweep.
const QUEUE: usize = 4096;

/// Directory entries a sweep will invalidate at most; the TTL covers the rest.
pub const SWEEP_LIMIT: usize = 4096;

pub enum Work {
    Entry(u64, Name),
    Inode(u64),
    Sweep,
}

pub struct Invalidator {
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
        let thread_shared = shared.clone();
        let thread = std::thread::Builder::new()
            .name("jackalopefs-inval".into())
            .spawn(move || notifier_loop(rx, notifier, thread_shared))
            .expect("spawn notifier thread");
        let task = tokio::spawn(translate(shared, events, state, tx));
        Invalidator {
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
        // Aborting the translator drops the queue's sender, which ends the notifier thread's receive loop.
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
                            }
                        }
                        EventItem::Overflow => work.push(Work::Sweep),
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
            Work::Entry(parent, name) => inval_entry(&notifier, parent, &name),
            Work::Inode(ino) => {
                shared.xattr_forget(ino);
                inval_inode(&notifier, ino)
            }
            Work::Sweep => {
                shared.xattr_clear();
                sweep(&notifier, &shared)
            }
        }
    }
}

fn inval_entry(notifier: &Notifier, parent: u64, name: &Name) {
    match notifier.inval_entry(INodeNo(parent), name.as_os_str()) {
        Ok(()) => tracing::trace!(parent, %name, "inval_entry"),
        Err(e) => tracing::debug!(parent, %name, "inval_entry: {e}"),
    }
}

fn inval_inode(notifier: &Notifier, ino: u64) {
    match notifier.inval_inode(INodeNo(ino), 0, 0) {
        Ok(()) => tracing::trace!(ino, "inval_inode"),
        Err(e) => tracing::debug!(ino, "inval_inode: {e}"),
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
        inval_inode(notifier, ino);
    }
    for (parent, name, _) in entries {
        inval_entry(notifier, parent, &name);
    }
}

//! Per-session table of open files and directories, keyed by the client-chosen handle id.

use crate::watch::Armed;
use jackalopefs_proto::control::HandlesTotals;
use jackalopefs_proto::Path;
use nix::errno::Errno;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// Files are shared freely because every access that depends on a position carries its own offset (`pread`/`pwrite`); an `lseek` for data or a hole moves the descriptor's position, which nothing reads. A directory's read position is shared state and so carries its own lock.
#[derive(Clone)]
pub enum Handle {
    /// `path` is where the file was opened; it identifies the client's own writes for echo suppression and may go stale after a rename, which only costs a spurious invalidation.
    File {
        file: Arc<File>,
        path: Path,
        /// Keeps the directory it was opened in watched while it is open.
        watch: Option<Arc<Armed>>,
    },
    /// `watch` keeps the directory itself watched while it is open.
    Dir {
        dir: Arc<Mutex<OwnedFd>>,
        watch: Option<Arc<Armed>>,
    },
}

/// The most handles a session holds before it is reported, however many file descriptors the server has. The share a server applies is derived from its file descriptor limit at startup ([`per_session`]).
pub const SHARE_MAX: usize = 16384;

/// File descriptors kept out of the handle pool for the server's own use: the endpoint, epoll, inotify and logs, and up to three transient fds for each of tokio's 512 default blocking threads. A limit too small to spare that many keeps half for the server.
const RESERVED_FDS: u64 = 2048;

/// The handles every session together may hold under an open-file limit of `limit`: what is left after [`RESERVED_FDS`].
pub fn pool_capacity(limit: u64) -> usize {
    usize::try_from(limit - RESERVED_FDS.min(limit / 2)).unwrap_or(usize::MAX)
}

/// One session's share of the pool under an open-file limit of `limit`: the pool shared evenly among every session that can hold handles at once ([`MAX_CONNECTIONS`](crate::MAX_CONNECTIONS) attached plus [`MAX_DETACHED_SESSIONS`](crate::session::MAX_DETACHED_SESSIONS) waiting out their grace), at most [`SHARE_MAX`]. A session past its share is reported, not refused; it draws on the rest of the pool. Zero means the limit leaves no room for client handles at all.
pub fn per_session(limit: u64) -> usize {
    let sessions = crate::MAX_CONNECTIONS + crate::session::MAX_DETACHED_SESSIONS;
    (pool_capacity(limit) / sessions).min(SHARE_MAX)
}

/// The handles every session holds, against what the server can spare for them.
pub struct HandlePool {
    capacity: usize,
    used: AtomicUsize,
}

impl HandlePool {
    pub fn new(capacity: usize) -> HandlePool {
        HandlePool {
            capacity,
            used: AtomicUsize::new(0),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    /// Takes a slot, unless every one is taken.
    fn take(&self) -> bool {
        self.used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                (used < self.capacity).then_some(used + 1)
            })
            .is_ok()
    }

    fn give(&self, slots: usize) {
        self.used.fetch_sub(slots, Ordering::Relaxed);
    }
}

/// A slot of the pool held for one open until its handle is inserted; given back if it never is.
pub struct Slot<'a> {
    handles: &'a Handles,
    fh: u64,
    /// Whether this took a slot of its own, which the handle keeps or the drop gives back.
    taken: bool,
}

impl Slot<'_> {
    /// Register `handle` under the slot's `fh`; an existing entry (a retried open whose reply was lost) is replaced and closed. The answer is the number of handles held when that just crossed a report threshold (the share, then each doubling), for the dispatcher to log with the rest of the session's state.
    pub fn insert(mut self, handle: Handle) -> Option<u64> {
        let handles = self.handles;
        let mut map = handles.map.lock();
        handles.count(&handle).fetch_add(1, Ordering::Relaxed);
        match (map.insert(self.fh, handle), self.taken) {
            (Some(old), taken) => {
                handles.count(&old).fetch_sub(1, Ordering::Relaxed);
                tracing::debug!(fh = self.fh, "replaced an existing handle");
                if taken {
                    handles.pool.give(1);
                }
            }
            // The entry this relied on was released meanwhile: the handle takes a slot even past a full pool, by the one a racing release just gave back.
            (None, false) => {
                handles.pool.used.fetch_add(1, Ordering::Relaxed);
            }
            (None, true) => {}
        }
        self.taken = false;
        let held = map.len() as u64;
        let mut reported = handles.reported.load(Ordering::Relaxed);
        let due = jackalopefs_perf::doubling_due(held, handles.share.max(1) as u64, &mut reported);
        handles.reported.store(reported, Ordering::Relaxed);
        due.then_some(held)
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        if self.taken {
            self.handles.pool.give(1);
        }
    }
}

/// Every slot of the [`HandlePool`] is taken; the answer is `EMFILE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorPoolFull;

/// One session's handles, each holding a slot of the server's pool until it is removed or the table dropped.
pub struct Handles {
    map: Mutex<HashMap<u64, Handle>>,
    /// The handles past which the session is reported.
    share: usize,
    pool: Arc<HandlePool>,
    /// The report threshold last crossed ([`jackalopefs_perf::stall::doubling_due`] from the share), 0 once the session is back under half its share; changed under `map`'s lock.
    reported: AtomicU64,
    /// The handles in `map` of each kind, changed under its lock.
    files: AtomicU64,
    dirs: AtomicU64,
}

impl Handle {
    fn is_dir(&self) -> bool {
        matches!(self, Handle::Dir { .. })
    }
}

impl Handles {
    pub fn new(share: usize, pool: Arc<HandlePool>) -> Handles {
        Handles {
            map: Mutex::new(HashMap::new()),
            share,
            pool,
            reported: AtomicU64::new(0),
            files: AtomicU64::new(0),
            dirs: AtomicU64::new(0),
        }
    }

    pub fn share(&self) -> usize {
        self.share
    }

    pub fn pool(&self) -> &HandlePool {
        &self.pool
    }

    fn count(&self, handle: &Handle) -> &AtomicU64 {
        if handle.is_dir() {
            &self.dirs
        } else {
            &self.files
        }
    }

    /// The handles open, by kind.
    pub fn totals(&self) -> HandlesTotals {
        HandlesTotals {
            files: self.files.load(Ordering::Relaxed),
            dirs: self.dirs.load(Ordering::Relaxed),
        }
    }

    /// A slot of the pool for an open under `fh`, taken before anything is opened so that a refusal has changed nothing; a retried open of an `fh` already held (its reply was lost) keeps that one's slot and needs none. Past the session's share too.
    pub fn reserve(&self, fh: u64) -> Result<Slot<'_>, ErrorPoolFull> {
        let held = self.map.lock().contains_key(&fh);
        if !held && !self.pool.take() {
            return Err(ErrorPoolFull);
        }
        Ok(Slot {
            handles: self,
            fh,
            taken: !held,
        })
    }

    /// [`Handles::reserve`] and [`Slot::insert`] at once.
    #[cfg(test)]
    pub fn insert(&self, fh: u64, handle: Handle) -> Result<Option<u64>, ErrorPoolFull> {
        Ok(self.reserve(fh)?.insert(handle))
    }

    pub fn file(&self, fh: u64) -> Result<Arc<File>, Errno> {
        self.file_and_path(fh).map(|(file, _)| file)
    }

    pub fn file_and_path(&self, fh: u64) -> Result<(Arc<File>, Path), Errno> {
        match self.map.lock().get(&fh) {
            Some(Handle::File { file, path, .. }) => Ok((file.clone(), path.clone())),
            _ => Err(Errno::EBADF),
        }
    }

    pub fn dir(&self, fh: u64) -> Result<Arc<Mutex<OwnedFd>>, Errno> {
        match self.map.lock().get(&fh) {
            Some(Handle::Dir { dir, .. }) => Ok(dir.clone()),
            _ => Err(Errno::EBADF),
        }
    }

    pub fn get(&self, fh: u64) -> Result<Handle, Errno> {
        self.map.lock().get(&fh).cloned().ok_or(Errno::EBADF)
    }

    pub fn remove(&self, fh: u64) -> Option<Handle> {
        let mut map = self.map.lock();
        let handle = map.remove(&fh)?;
        self.pool.give(1);
        self.count(&handle).fetch_sub(1, Ordering::Relaxed);
        // Back under half its share, a session is reported afresh when it next crosses it; a session hovering at its share is not.
        if 2 * map.len() < self.share {
            self.reported.store(0, Ordering::Relaxed);
        }
        Some(handle)
    }

    pub fn len(&self) -> usize {
        self.map.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for Handles {
    fn drop(&mut self) {
        self.pool.give(self.map.get_mut().len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_handle() -> Handle {
        Handle::File {
            file: Arc::new(File::open("/dev/null").unwrap()),
            path: Path::root(),
            watch: None,
        }
    }

    #[test]
    fn sessions_draw_on_one_pool_past_their_share() {
        let pool = Arc::new(HandlePool::new(3));
        let a = Handles::new(1, pool.clone());
        let b = Handles::new(1, pool.clone());
        assert!(a.insert(1, file_handle()).is_ok());
        assert!(a.insert(2, file_handle()).is_ok(), "past the share");
        assert!(b.insert(1, file_handle()).is_ok());
        assert_eq!(pool.used(), 3);
        assert_eq!(a.insert(3, file_handle()), Err(ErrorPoolFull));
        assert_eq!(b.insert(2, file_handle()), Err(ErrorPoolFull));
        assert!(
            a.insert(1, file_handle()).is_ok(),
            "replacing takes no slot"
        );
        assert_eq!(pool.used(), 3);
        let slot = a.reserve(1).unwrap();
        drop(slot);
        assert_eq!(pool.used(), 3, "a retried open's slot is the handle's");
        assert_eq!(a.reserve(9).err(), Some(ErrorPoolFull));
        assert!(a.remove(2).is_some());
        assert!(a.remove(2).is_none());
        assert_eq!(pool.used(), 2);
        let unused = b.reserve(2).unwrap();
        assert_eq!(pool.used(), 3);
        drop(unused);
        assert_eq!(pool.used(), 2, "a slot never filled goes back");
        assert!(b.insert(2, file_handle()).is_ok());
        drop(b);
        assert_eq!(pool.used(), 1, "a dropped table gives back its slots");
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn the_pool_counts_every_slot_under_concurrent_use() {
        let pool = Arc::new(HandlePool::new(64));
        let tables: Vec<Arc<Handles>> = (0..4)
            .map(|_| Arc::new(Handles::new(4, pool.clone())))
            .collect();
        let threads: Vec<_> = tables
            .iter()
            .cloned()
            .map(|table| {
                std::thread::spawn(move || {
                    for i in 0..2000u64 {
                        let fh = i % 40;
                        if i % 3 == 0 {
                            table.remove(fh);
                        } else {
                            // A full pool is part of what is exercised.
                            match table.insert(fh, file_handle()) {
                                Ok(_) | Err(ErrorPoolFull) => {}
                            }
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(pool.used(), tables.iter().map(|t| t.len()).sum::<usize>());
        assert!(pool.used() <= pool.capacity());
        drop(tables);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn a_session_is_reported_at_its_share_and_each_doubling_and_afresh_once_well_under() {
        let handles = Handles::new(4, Arc::new(HandlePool::new(100)));
        let mut due = Vec::new();
        for fh in 1..=20 {
            if let Some(held) = handles.insert(fh, file_handle()).unwrap() {
                due.push(held);
            }
        }
        assert_eq!(due, [4, 8, 16]);
        for fh in 3..=20 {
            handles.remove(fh);
        }
        assert_eq!(handles.len(), 2);
        assert_eq!(
            handles.insert(30, file_handle()).unwrap(),
            None,
            "still at half its share"
        );
        handles.remove(30);
        handles.remove(2);
        assert_eq!(handles.len(), 1, "under half its share");
        let again: Vec<u64> = (40..43)
            .filter_map(|fh| handles.insert(fh, file_handle()).unwrap())
            .collect();
        assert_eq!(again, [4]);
        // Hovering at the share, opening and closing one, reports nothing more.
        for _ in 0..5 {
            handles.remove(42);
            assert_eq!(handles.insert(42, file_handle()).unwrap(), None);
        }
    }

    #[test]
    fn totals_count_each_kind_through_replacement_and_removal() {
        let handles = Handles::new(8, Arc::new(HandlePool::new(8)));
        let dir_handle = || Handle::Dir {
            dir: Arc::new(Mutex::new(OwnedFd::from(File::open("/").unwrap()))),
            watch: None,
        };
        handles.insert(1, file_handle()).unwrap();
        handles.insert(2, dir_handle()).unwrap();
        handles.insert(3, dir_handle()).unwrap();
        assert_eq!(handles.totals(), HandlesTotals { files: 1, dirs: 2 });
        handles.insert(1, dir_handle()).unwrap();
        assert_eq!(handles.totals(), HandlesTotals { files: 0, dirs: 3 });
        handles.remove(2);
        assert!(handles.remove(2).is_none());
        assert_eq!(handles.totals(), HandlesTotals { files: 0, dirs: 2 });
    }

    #[test]
    fn per_session_leaves_the_reserve_and_shares_the_rest() {
        let sessions = (crate::MAX_CONNECTIONS + crate::session::MAX_DETACHED_SESSIONS) as u64;
        assert_eq!(per_session(0), 0);
        assert_eq!(
            per_session(sessions),
            0,
            "half of a tiny limit is the reserve"
        );
        assert_eq!(per_session(2 * sessions), 1);
        assert_eq!(per_session(1024), (512 / sessions) as usize);
        assert_eq!(
            per_session(524288),
            ((524288 - RESERVED_FDS) / sessions) as usize
        );
        assert!(per_session(524288) < SHARE_MAX);
        assert_eq!(per_session(u64::MAX), SHARE_MAX);
        assert_eq!(pool_capacity(524288), 524288 - RESERVED_FDS as usize);
        assert_eq!(pool_capacity(1024), 512);
        assert!(
            per_session(524288) * sessions as usize <= pool_capacity(524288),
            "the shares fit the pool"
        );
    }
}

//! Per-session table of open files and directories, keyed by the client-chosen handle id.

use crate::watch::Armed;
use jackalopefs_proto::control::HandlesTotals;
use jackalopefs_proto::NoticeHandles;
use jackalopefs_proto::Path;
use nix::errno::Errno;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::watch;

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

/// What an open under some id goes on with: a slot for the handle it is about to open, or the handle already under the id.
pub enum Reserved<'a> {
    Slot(Slot<'a>),
    /// The open is a resend whose original ran and kept this handle: M1 has the original finish before its resend begins, and the client never reuses an id, so nothing else can be under it. The resend answers from it and opens nothing again.
    Held(Handle),
}

/// A slot of the pool held for one open until its handle is inserted; given back if it never is.
pub struct Slot<'a> {
    handles: &'a Handles,
    fh: u64,
    /// Whether the slot is still this open's own, which the handle takes over once inserted.
    taken: bool,
}

impl Slot<'_> {
    /// Register `handle` under the slot's `fh`. The answer is the number of handles held when that just crossed a report threshold (the share, then each doubling), for the dispatcher to log with the rest of the session's state. Refused, and `handle` closed, when the client released `fh` while it was being opened, whether or not anything was open under it then; and when another open of the same id got there first, which a client keeping to the protocol never sends.
    pub fn insert(mut self, handle: Handle) -> Result<Option<u64>, ErrorReserve> {
        let handles = self.handles;
        let mut map = handles.map.lock();
        if handles.released.lock().contains(self.fh) {
            tracing::debug!(
                fh = self.fh,
                "the client released this id while it was being opened; closing what was opened"
            );
            return Err(ErrorReserve::Released);
        }
        if map.contains_key(&self.fh) {
            tracing::error!(
                fh = self.fh,
                "two opens under one id ran at once; the second's handle is closed"
            );
            return Err(ErrorReserve::Duplicate);
        }
        handles.count(&handle).fetch_add(1, Ordering::Relaxed);
        map.insert(self.fh, handle);
        self.taken = false;
        let held = map.len() as u64;
        let mut reported = handles.reported.load(Ordering::Relaxed);
        let due = jackalopefs_perf::doubling_due(held, handles.share.max(1) as u64, &mut reported);
        handles.reported.store(reported, Ordering::Relaxed);
        if !due {
            return Ok(None);
        }
        handles.notice.send_replace(Some(NoticeHandles {
            held,
            share: handles.share as u64,
        }));
        Ok(Some(held))
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        if self.taken {
            self.handles.pool.give(1);
        }
    }
}

/// Why an open under some id was refused before it kept anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorReserve {
    /// Every slot of the [`HandlePool`] is taken; the answer is `EMFILE`.
    PoolFull,
    /// The client released the id before the open could keep it: an open it gave up on, and released in case it had landed; the answer is `EBADF`, which nobody reads.
    Released,
    /// Another open under the id kept its handle while this one ran; the answer is `EBADF`.
    Duplicate,
}

/// Released ids a session remembers, the most recent ones. An open under one older than that is an open the client gave up on long ago; it would keep its descriptor until the session ends.
const RELEASED_KEPT: usize = 1024;

/// The ids a session's client has released, the latest [`RELEASED_KEPT`] of them.
#[derive(Default)]
struct Released {
    order: VecDeque<u64>,
    set: std::collections::HashSet<u64>,
}

impl Released {
    fn contains(&self, fh: u64) -> bool {
        self.set.contains(&fh)
    }

    fn record(&mut self, fh: u64) {
        if !self.set.insert(fh) {
            return;
        }
        if self.order.len() == RELEASED_KEPT {
            let oldest = self.order.pop_front().expect("the list is full");
            self.set.remove(&oldest);
        }
        self.order.push_back(fh);
    }
}

/// One session's handles, each holding a slot of the server's pool until it is removed or the table dropped.
pub struct Handles {
    map: Mutex<HashMap<u64, Handle>>,
    /// The handles past which the session is reported.
    share: usize,
    pool: Arc<HandlePool>,
    /// The report threshold last crossed ([`jackalopefs_perf::stall::doubling_due`] from the share), 0 once the session is back under half its share; changed under `map`'s lock.
    reported: AtomicU64,
    /// Locked only under `map`'s lock.
    released: Mutex<Released>,
    /// The handles in `map` of each kind, changed under its lock.
    files: AtomicU64,
    dirs: AtomicU64,
    /// What the session's client is asked to report: set at each threshold crossed, and cleared once it has been written to the session's connection or the session is back under half its share.
    notice: watch::Sender<Option<NoticeHandles>>,
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
            released: Mutex::new(Released::default()),
            files: AtomicU64::new(0),
            dirs: AtomicU64::new(0),
            notice: watch::Sender::new(None),
        }
    }

    /// The notice for the session's client, which its connection's event stream sends and then clears.
    pub fn notice(&self) -> watch::Sender<Option<NoticeHandles>> {
        self.notice.clone()
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

    /// A slot of the pool for an open under `fh`, taken before anything is opened so that a refusal has changed nothing; past the session's share too. A resend of an open whose original kept its handle gets that handle instead ([`Reserved::Held`]). An `fh` the client has already released is refused: the open is one it gave up on, and must not create or truncate anything now.
    pub fn reserve(&self, fh: u64) -> Result<Reserved<'_>, ErrorReserve> {
        {
            let map = self.map.lock();
            if self.released.lock().contains(fh) {
                tracing::debug!(fh, "an open under an id the client has released is refused");
                return Err(ErrorReserve::Released);
            }
            if let Some(handle) = map.get(&fh) {
                return Ok(Reserved::Held(handle.clone()));
            }
        }
        if !self.pool.take() {
            return Err(ErrorReserve::PoolFull);
        }
        Ok(Reserved::Slot(Slot {
            handles: self,
            fh,
            taken: true,
        }))
    }

    /// [`Handles::reserve`] and [`Slot::insert`] at once.
    #[cfg(test)]
    pub fn insert(&self, fh: u64, handle: Handle) -> Result<Option<u64>, ErrorReserve> {
        self.slot(fh)?.insert(handle)
    }

    /// [`Handles::reserve`] of an id not held.
    #[cfg(test)]
    pub fn slot(&self, fh: u64) -> Result<Slot<'_>, ErrorReserve> {
        match self.reserve(fh)? {
            Reserved::Slot(slot) => Ok(slot),
            Reserved::Held(_) => panic!("{fh} is held"),
        }
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

    /// Close the handle under `fh`, and remember the id: the client never opens one again once it has released it, so an open under it still on its way (one it gave up on, or a retry of one whose original has just been released) is refused.
    pub fn remove(&self, fh: u64) -> Option<Handle> {
        let mut map = self.map.lock();
        self.released.lock().record(fh);
        let handle = map.remove(&fh)?;
        self.pool.give(1);
        self.count(&handle).fetch_sub(1, Ordering::Relaxed);
        // Back under half its share, a session is reported afresh when it next crosses it; a session hovering at its share is not.
        if 2 * map.len() < self.share {
            self.reported.store(0, Ordering::Relaxed);
            self.notice
                .send_if_modified(|notice| notice.take().is_some());
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
    fn an_open_after_its_own_release_keeps_nothing() {
        let pool = Arc::new(HandlePool::new(8));
        let handles = Handles::new(8, pool.clone());
        assert!(handles.remove(5).is_none(), "nothing was open under it");
        assert_eq!(handles.reserve(5).err(), Some(ErrorReserve::Released));
        let slot = handles.slot(6).unwrap();
        assert!(
            handles.remove(6).is_none(),
            "released while it was being opened"
        );
        let opened = file_handle();
        let Handle::File { file, .. } = &opened else {
            unreachable!()
        };
        let file = file.clone();
        assert_eq!(slot.insert(opened), Err(ErrorReserve::Released));
        assert_eq!(Arc::strong_count(&file), 1, "what was opened is closed");
        assert_eq!(pool.used(), 0, "its slot went back");
        assert!(
            handles.insert(7, file_handle()).is_ok(),
            "other ids open as before"
        );
        assert_eq!(handles.len(), 1);
    }

    #[test]
    fn a_resent_open_gets_the_handle_its_original_kept() {
        let pool = Arc::new(HandlePool::new(8));
        let handles = Handles::new(8, pool.clone());
        let kept = file_handle();
        let Handle::File { file, .. } = &kept else {
            unreachable!()
        };
        let file = file.clone();
        handles.insert(3, kept).unwrap();
        let Ok(Reserved::Held(Handle::File { file: held, .. })) = handles.reserve(3) else {
            panic!("the original's handle is not offered to its resend");
        };
        assert!(
            Arc::ptr_eq(&held, &file),
            "the very descriptor the original kept"
        );
        assert_eq!(pool.used(), 1, "the resend takes no slot");
        assert_eq!(handles.len(), 1);
    }

    #[test]
    fn a_retry_of_an_open_already_released_keeps_nothing() {
        let pool = Arc::new(HandlePool::new(8));
        let handles = Handles::new(8, pool.clone());
        handles.insert(3, file_handle()).unwrap();
        assert!(
            handles.remove(3).is_some(),
            "the original landed and was released"
        );
        assert_eq!(handles.reserve(3).err(), Some(ErrorReserve::Released));
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn a_second_open_landing_under_a_held_id_is_closed() {
        let pool = Arc::new(HandlePool::new(8));
        let handles = Handles::new(8, pool.clone());
        let first = handles.slot(3).unwrap();
        let second = handles.slot(3).unwrap();
        assert!(first.insert(file_handle()).is_ok());
        let opened = file_handle();
        let Handle::File { file, .. } = &opened else {
            unreachable!()
        };
        let file = file.clone();
        assert_eq!(second.insert(opened), Err(ErrorReserve::Duplicate));
        assert_eq!(
            Arc::strong_count(&file),
            1,
            "what the second opened is closed"
        );
        assert_eq!(handles.len(), 1);
        assert_eq!(pool.used(), 1, "its slot went back");
    }

    #[test]
    fn only_the_most_recent_releases_are_remembered() {
        let handles = Handles::new(8, Arc::new(HandlePool::new(8)));
        for fh in 0..=RELEASED_KEPT as u64 {
            assert!(handles.remove(fh).is_none());
        }
        assert!(
            handles.reserve(0).is_ok(),
            "the oldest release is forgotten"
        );
        assert_eq!(handles.reserve(1).err(), Some(ErrorReserve::Released));
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
        assert_eq!(a.insert(3, file_handle()), Err(ErrorReserve::PoolFull));
        assert_eq!(b.insert(2, file_handle()), Err(ErrorReserve::PoolFull));
        assert!(
            matches!(a.reserve(1), Ok(Reserved::Held(_))),
            "a held id takes no slot"
        );
        assert_eq!(pool.used(), 3);
        assert_eq!(a.reserve(9).err(), Some(ErrorReserve::PoolFull));
        assert!(a.remove(2).is_some());
        assert!(a.remove(2).is_none());
        assert_eq!(pool.used(), 2);
        let unused = b.slot(2).unwrap();
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
                            // A full pool is part of what is exercised; an id released is refused from then on, as a client's would be, and one held is answered from its handle.
                            match table.reserve(fh) {
                                Ok(Reserved::Slot(slot)) => match slot.insert(file_handle()) {
                                    Ok(_)
                                    | Err(ErrorReserve::Released | ErrorReserve::Duplicate) => {}
                                    Err(ErrorReserve::PoolFull) => {
                                        unreachable!("a slot is in hand")
                                    }
                                },
                                Ok(Reserved::Held(_))
                                | Err(ErrorReserve::PoolFull | ErrorReserve::Released) => {}
                                Err(ErrorReserve::Duplicate) => {
                                    unreachable!("reserve finds no duplicate")
                                }
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
        let notices = handles.notice().subscribe();
        assert_eq!(
            *notices.borrow(),
            Some(NoticeHandles { held: 16, share: 4 }),
            "the last crossing waits for the client"
        );
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
        assert_eq!(*notices.borrow(), None, "nothing left to report");
        let again: Vec<u64> = (40..43)
            .filter_map(|fh| handles.insert(fh, file_handle()).unwrap())
            .collect();
        assert_eq!(again, [4]);
        // Hovering at the share, closing one and opening another, reports nothing more.
        for fh in 42..47 {
            handles.remove(fh);
            assert_eq!(handles.insert(fh + 1, file_handle()).unwrap(), None);
        }
    }

    #[test]
    fn totals_count_each_kind_through_removal() {
        let handles = Handles::new(8, Arc::new(HandlePool::new(8)));
        let dir_handle = || Handle::Dir {
            dir: Arc::new(Mutex::new(OwnedFd::from(File::open("/").unwrap()))),
            watch: None,
        };
        handles.insert(1, file_handle()).unwrap();
        handles.insert(2, dir_handle()).unwrap();
        handles.insert(3, dir_handle()).unwrap();
        assert_eq!(handles.totals(), HandlesTotals { files: 1, dirs: 2 });
        handles.remove(2);
        assert!(handles.remove(2).is_none());
        assert_eq!(handles.totals(), HandlesTotals { files: 1, dirs: 1 });
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

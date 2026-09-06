//! Client-side table of open handles. The client chooses handle ids and never reuses one, so when an open's outcome is unknown (timeout, lost connection) the client can simply ask the server to release that id: releasing an id the server never opened is harmless, and releasing one it did closes the fd the client would otherwise never learn about.

use jackalopefs_proto::{Path, Request, Response};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleKind {
    File,
    Dir,
}

#[derive(Debug)]
pub struct HandleRec {
    pub nodeid: u64,
    pub path: Path,
    pub flags: i32,
    pub kind: HandleKind,
    /// Set when a reopen after a lost session found a different inode (or nothing) at the path; every later use fails with `ESTALE`.
    dead: AtomicBool,
}

impl HandleRec {
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }

    fn mark_dead(&self) {
        self.dead.store(true, Ordering::Relaxed);
    }

    /// The request that reopens this handle after the server lost it: creation flags are dropped, the id is reused.
    pub fn reopen_request(&self, fh: u64) -> Request {
        match self.kind {
            HandleKind::File => Request::Open {
                fh,
                path: self.path.clone(),
                flags: self.flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC),
            },
            HandleKind::Dir => Request::Opendir {
                fh,
                path: self.path.clone(),
            },
        }
    }
}

#[derive(Default)]
pub struct HandleTable {
    next: AtomicU64,
    map: Mutex<HashMap<u64, Arc<HandleRec>>>,
}

impl HandleTable {
    /// A fresh id; ids are never reused within a client's lifetime.
    pub fn alloc(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn insert(
        &self,
        fh: u64,
        nodeid: u64,
        path: Path,
        flags: i32,
        kind: HandleKind,
    ) -> Arc<HandleRec> {
        let rec = Arc::new(HandleRec {
            nodeid,
            path,
            flags,
            kind,
            dead: AtomicBool::new(false),
        });
        if self.map.lock().insert(fh, rec.clone()).is_some() {
            tracing::error!(fh, "handle id reused; this is a bug");
        }
        rec
    }

    pub fn get(&self, fh: u64) -> Option<Arc<HandleRec>> {
        self.map.lock().get(&fh).cloned()
    }

    pub fn remove(&self, fh: u64) -> Option<Arc<HandleRec>> {
        self.map.lock().remove(&fh)
    }

    pub fn len(&self) -> usize {
        self.map.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Any live handle on `nodeid`, for an operation that arrives without one after the node's last name is gone (`fstat`, `fchmod` and the like on an unlinked file).
    pub fn any_live_for(&self, nodeid: u64) -> Option<u64> {
        self.map
            .lock()
            .iter()
            .find(|(_, r)| r.nodeid == nodeid && !r.is_dead())
            .map(|(fh, _)| *fh)
    }

    /// Node ids of every live handle, for post-reconnect invalidation.
    pub fn open_nodeids(&self) -> Vec<u64> {
        self.map
            .lock()
            .values()
            .filter(|r| !r.is_dead())
            .map(|r| r.nodeid)
            .collect()
    }

    /// Everything that needs reopening when the server did not resume our session.
    pub fn live(&self) -> Vec<(u64, Arc<HandleRec>)> {
        self.map
            .lock()
            .iter()
            .filter(|(_, r)| !r.is_dead())
            .map(|(fh, r)| (*fh, r.clone()))
            .collect()
    }

    /// Judge a reopen reply: the same inode keeps the handle alive, anything else kills it.
    pub fn apply_reopen(
        &self,
        fh: u64,
        rec: &HandleRec,
        outcome: Result<Response, crate::client::Error>,
    ) {
        match outcome {
            Ok(Response::Opened { attr }) if attr.ino == rec.nodeid => {}
            Ok(Response::Opened { attr }) => {
                tracing::warn!(fh, path = ?rec.path, "path now names a different inode ({} was {}); handle is stale", attr.ino, rec.nodeid);
                rec.mark_dead();
            }
            Ok(other) => {
                tracing::warn!(fh, path = ?rec.path, "unexpected reply to reopen: {other:?}; handle is stale");
                rec.mark_dead();
            }
            Err(e) => {
                tracing::warn!(fh, path = ?rec.path, "reopen failed: {e}; handle is stale");
                rec.mark_dead();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jackalopefs_proto::{Attr, FileKind, TimeSpec};

    fn attr(ino: u64) -> Attr {
        let t = TimeSpec { sec: 0, nsec: 0 };
        Attr {
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
        }
    }

    #[test]
    fn reopen_verifies_identity() {
        let table = HandleTable::default();
        let fh = table.alloc();
        let rec = table.insert(
            fh,
            42,
            Path::root(),
            libc::O_RDWR | libc::O_TRUNC | libc::O_CREAT,
            HandleKind::File,
        );
        assert!(
            matches!(rec.reopen_request(fh), Request::Open { flags, .. } if flags == libc::O_RDWR)
        );
        table.apply_reopen(fh, &rec, Ok(Response::Opened { attr: attr(42) }));
        assert!(!rec.is_dead());
        table.apply_reopen(fh, &rec, Ok(Response::Opened { attr: attr(43) }));
        assert!(rec.is_dead());
        assert!(table.open_nodeids().is_empty());
        assert!(table.live().is_empty());
        assert!(table.alloc() > fh);
    }

    #[test]
    fn any_live_handle_for_a_node() {
        let table = HandleTable::default();
        let a = table.alloc();
        let rec_a = table.insert(a, 42, Path::root(), libc::O_RDONLY, HandleKind::File);
        let b = table.alloc();
        table.insert(b, 43, Path::root(), libc::O_RDONLY, HandleKind::File);
        assert_eq!(table.any_live_for(42), Some(a));
        assert_eq!(table.any_live_for(43), Some(b));
        assert_eq!(table.any_live_for(44), None);
        table.apply_reopen(a, &rec_a, Ok(Response::Opened { attr: attr(99) }));
        assert!(rec_a.is_dead());
        assert_eq!(table.any_live_for(42), None);
    }
}

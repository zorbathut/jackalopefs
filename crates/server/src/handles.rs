//! Per-session table of open files and directories, keyed by the client-chosen handle id.

use jackalopefs_proto::Path;
use nix::errno::Errno;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::sync::Arc;

/// Files are shared freely because every access is positional (`pread`/`pwrite`); a directory's read position is shared state and so carries its own lock.
#[derive(Clone)]
pub enum Handle {
    /// `path` is where the file was opened; it identifies the client's own writes for echo suppression and may go stale after a rename, which only costs a spurious invalidation.
    File {
        file: Arc<File>,
        path: Path,
    },
    Dir(Arc<Mutex<OwnedFd>>),
}

/// Most open handles one session may hold, however many file descriptors the server has; a client's own kernel keeps honest clients far below this, so hitting it means a leak or an attack, and the answer is `EMFILE`. The cap a server applies is derived from its file descriptor limit at startup ([`per_session`]).
pub const MAX_HANDLES: usize = 16384;

/// File descriptors kept out of the handle caps for the server's own use: the endpoint, epoll, inotify and logs, and up to three transient fds for each of tokio's 512 default blocking threads. A limit too small to spare that many keeps half for the server.
const RESERVED_FDS: u64 = 2048;

/// Open handles one session may hold under an open-file limit of `limit`: what is left after [`RESERVED_FDS`], shared evenly among every session that can hold handles at once ([`MAX_CONNECTIONS`](crate::MAX_CONNECTIONS) attached plus [`MAX_DETACHED_SESSIONS`](crate::session::MAX_DETACHED_SESSIONS) waiting out their grace), at most [`MAX_HANDLES`]. Zero means the limit leaves no room for client handles at all.
pub fn per_session(limit: u64) -> usize {
    let reserved = RESERVED_FDS.min(limit / 2);
    let sessions = (crate::MAX_CONNECTIONS + crate::session::MAX_DETACHED_SESSIONS) as u64;
    let share = (limit - reserved) / sessions;
    usize::try_from(share)
        .unwrap_or(usize::MAX)
        .min(MAX_HANDLES)
}

pub struct Handles {
    map: Mutex<HashMap<u64, Handle>>,
    max: usize,
}

impl Handles {
    pub fn new(max: usize) -> Handles {
        Handles {
            map: Mutex::new(HashMap::new()),
            max,
        }
    }

    pub fn max(&self) -> usize {
        self.max
    }

    /// Register `handle` under `fh`; an existing entry (a retried open whose reply was lost) is replaced and closed.
    pub fn insert(&self, fh: u64, handle: Handle) -> Result<(), Errno> {
        let mut map = self.map.lock();
        if map.len() >= self.max && !map.contains_key(&fh) {
            tracing::warn!(fh, limit = self.max, "session holds too many open handles");
            return Err(Errno::EMFILE);
        }
        if map.insert(fh, handle).is_some() {
            tracing::debug!(fh, "replaced an existing handle");
        }
        Ok(())
    }

    pub fn file(&self, fh: u64) -> Result<Arc<File>, Errno> {
        self.file_and_path(fh).map(|(file, _)| file)
    }

    pub fn file_and_path(&self, fh: u64) -> Result<(Arc<File>, Path), Errno> {
        match self.map.lock().get(&fh) {
            Some(Handle::File { file, path }) => Ok((file.clone(), path.clone())),
            _ => Err(Errno::EBADF),
        }
    }

    pub fn dir(&self, fh: u64) -> Result<Arc<Mutex<OwnedFd>>, Errno> {
        match self.map.lock().get(&fh) {
            Some(Handle::Dir(dir)) => Ok(dir.clone()),
            _ => Err(Errno::EBADF),
        }
    }

    pub fn get(&self, fh: u64) -> Result<Handle, Errno> {
        self.map.lock().get(&fh).cloned().ok_or(Errno::EBADF)
    }

    pub fn remove(&self, fh: u64) -> Option<Handle> {
        self.map.lock().remove(&fh)
    }

    pub fn len(&self) -> usize {
        self.map.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_capped() {
        let handles = Handles::new(2);
        let file = Arc::new(File::open("/dev/null").unwrap());
        let handle = || Handle::File {
            file: file.clone(),
            path: Path::root(),
        };
        handles.insert(1, handle()).unwrap();
        handles.insert(2, handle()).unwrap();
        assert_eq!(handles.insert(3, handle()), Err(Errno::EMFILE));
        assert_eq!(handles.len(), 2);
        handles.insert(1, handle()).unwrap();
        assert!(handles.remove(2).is_some());
        handles.insert(3, handle()).unwrap();
        assert_eq!(handles.len(), 2);
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
        assert!(per_session(524288) < MAX_HANDLES);
        assert_eq!(per_session(u64::MAX), MAX_HANDLES);
    }
}

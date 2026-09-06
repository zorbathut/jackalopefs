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

/// Open handles one session may hold; a client's own kernel keeps honest clients far below this, so hitting it means a leak or an attack, and the answer is `EMFILE`.
pub const MAX_HANDLES: usize = 16384;

#[derive(Default)]
pub struct Handles {
    map: Mutex<HashMap<u64, Handle>>,
}

impl Handles {
    /// Register `handle` under `fh`; an existing entry (a retried open whose reply was lost) is replaced and closed.
    pub fn insert(&self, fh: u64, handle: Handle) -> Result<(), Errno> {
        let mut map = self.map.lock();
        if map.len() >= MAX_HANDLES && !map.contains_key(&fh) {
            tracing::warn!(
                fh,
                limit = MAX_HANDLES,
                "session holds too many open handles"
            );
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

//! The FUSE backend: every kernel request is copied out of the session thread and answered from a tokio task, so the session thread never waits on the network.

use crate::client::{Client, Error};
use crate::inodes::{NodeTable, ROOT};
use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, InitFlags,
    KernelConfig, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request,
};
use jackalopefs_proto::{
    Attr, DirEntry, DirEntryPlus, FileKind, Name, Path, SetAttr, TimeOrNow, TimeSpec, MAX_IO,
};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Bytes of directory entries fetched from the server per request; the kernel asks for far less at a time, and the rest is served from the handle's buffer.
const READDIR_FETCH: u32 = 256 * 1024;

/// Concurrent background requests (readahead, writeback of mmap'd pages) the kernel may keep in flight.
const MAX_BACKGROUND: u16 = 64;

/// State shared between the session thread and the request tasks.
pub struct Shared {
    pub client: Arc<Client>,
    pub nodes: Mutex<NodeTable>,
    dirs: Mutex<HashMap<u64, DirBuffer>>,
    pub entry_ttl: Duration,
    pub attr_ttl: Duration,
}

/// Entries fetched from the server but not yet handed to the kernel, each tagged with the cookie that yields it.
#[derive(Default)]
struct DirBuffer {
    plain: VecDeque<(u64, DirEntry)>,
    plus: VecDeque<(u64, DirEntryPlus)>,
}

pub struct Backend {
    shared: Arc<Shared>,
    runtime: tokio::runtime::Handle,
}

impl Backend {
    pub fn new(
        client: Arc<Client>,
        entry_ttl: Duration,
        attr_ttl: Duration,
        runtime: tokio::runtime::Handle,
    ) -> (Backend, Arc<Shared>) {
        let shared = Arc::new(Shared {
            client,
            nodes: Mutex::new(NodeTable::new()),
            dirs: Mutex::new(HashMap::new()),
            entry_ttl,
            attr_ttl,
        });
        (
            Backend {
                shared: shared.clone(),
                runtime,
            },
            shared,
        )
    }

    fn spawn<F: std::future::Future<Output = ()> + Send + 'static>(&self, f: F) {
        self.runtime.spawn(f);
    }
}

fn errno(e: &Error) -> Errno {
    Errno::from_i32(e.errno())
}

fn system_time(t: TimeSpec) -> SystemTime {
    let base = if t.sec >= 0 {
        UNIX_EPOCH + Duration::from_secs(t.sec as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(t.sec.unsigned_abs())
    };
    base + Duration::from_nanos(t.nsec as u64)
}

fn timespec(t: SystemTime) -> TimeSpec {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => TimeSpec {
            sec: d.as_secs() as i64,
            nsec: d.subsec_nanos(),
        },
        Err(before) => {
            let d = before.duration();
            if d.subsec_nanos() == 0 {
                TimeSpec {
                    sec: -(d.as_secs() as i64),
                    nsec: 0,
                }
            } else {
                TimeSpec {
                    sec: -(d.as_secs() as i64) - 1,
                    nsec: 1_000_000_000 - d.subsec_nanos(),
                }
            }
        }
    }
}

fn time_or_now(t: fuser::TimeOrNow) -> TimeOrNow {
    match t {
        fuser::TimeOrNow::SpecificTime(t) => TimeOrNow::Time(timespec(t)),
        fuser::TimeOrNow::Now => TimeOrNow::Now,
    }
}

fn file_type(kind: FileKind) -> FileType {
    match kind {
        FileKind::Regular => FileType::RegularFile,
        FileKind::Directory => FileType::Directory,
        FileKind::Symlink => FileType::Symlink,
        FileKind::Fifo => FileType::NamedPipe,
        FileKind::Socket => FileType::Socket,
        FileKind::CharDevice => FileType::CharDevice,
        FileKind::BlockDevice => FileType::BlockDevice,
    }
}

fn file_attr(attr: &Attr) -> FileAttr {
    FileAttr {
        ino: INodeNo(attr.ino),
        size: attr.size,
        blocks: attr.blocks,
        atime: system_time(attr.atime),
        mtime: system_time(attr.mtime),
        ctime: system_time(attr.ctime),
        crtime: system_time(attr.ctime),
        kind: file_type(attr.kind),
        perm: attr.perm,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: attr.rdev as u32,
        blksize: attr.blksize,
        flags: 0,
    }
}

/// Attributes for `.`/`..` in a readdirplus reply; the kernel ignores everything but the inode number for those two names.
fn dir_placeholder(ino: u64) -> FileAttr {
    FileAttr {
        ino: INodeNo(ino),
        size: 0,
        blocks: 0,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::Directory,
        perm: 0o755,
        nlink: 2,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

fn name_of(os: &OsStr) -> Result<Name, Errno> {
    Name::try_from(os).map_err(|e| match e {
        jackalopefs_proto::ErrorName::TooLong => Errno::ENAMETOOLONG,
        _ => Errno::EINVAL,
    })
}

impl Shared {
    fn path_of(&self, ino: u64) -> Result<Path, Errno> {
        self.nodes.lock().path_of(ino).ok_or(Errno::ESTALE)
    }

    /// The path and handle for an operation that may carry a handle. An unlinked-but-open file has no path, and then a handle is all the server gets: the one the kernel sent, or any handle still open on the inode, because `fstat` and the `f*` attribute calls (`fchmod`, `fchown`, `futimens`) arrive without one. Any live handle serves: attributes are read and set through the descriptor whatever it was opened for, and a size change always carries the kernel's own handle.
    fn path_for_handle_op(
        &self,
        ino: u64,
        fh: Option<u64>,
    ) -> Result<(Option<Path>, Option<u64>), Errno> {
        if let Some(path) = self.nodes.lock().path_of(ino) {
            return Ok((Some(path), fh));
        }
        match fh.or_else(|| self.client.handles().any_live_for(ino)) {
            Some(fh) => Ok((None, Some(fh))),
            None => Err(Errno::ESTALE),
        }
    }

    fn parent_of(&self, ino: u64) -> u64 {
        self.nodes
            .lock()
            .get(ino)
            .and_then(|n| n.aliases.last().map(|(p, _)| *p))
            .unwrap_or(ROOT)
    }

    /// Register a successful entry reply and return the generation to send.
    fn register(&self, parent: u64, name: Name, attr: &Attr) -> Result<Generation, Errno> {
        self.nodes
            .lock()
            .insert_lookup(parent, name, attr.ino, attr.kind)
            .map(Generation)
            .ok_or(Errno::EIO)
    }

    /// Serve one page of entries for `fh` starting at `offset`, from the buffer when it continues where the kernel left off and from the server otherwise. A handle without a buffer has been released.
    async fn dir_page(&self, fh: u64, offset: u64) -> Result<Vec<(u64, DirEntry)>, Error> {
        {
            let mut dirs = self.dirs.lock();
            let buffer = dirs.get_mut(&fh).ok_or(Error::Remote(libc::EBADF))?;
            if buffer
                .plain
                .front()
                .is_some_and(|(cookie, _)| *cookie == offset)
            {
                return Ok(buffer.plain.drain(..).collect());
            }
            buffer.plain.clear();
        }
        let entries = self.client.readdir(fh, offset, READDIR_FETCH).await?;
        Ok(tag_with_cookies(entries, offset, |e| e.next_offset))
    }

    async fn dir_page_plus(&self, fh: u64, offset: u64) -> Result<Vec<(u64, DirEntryPlus)>, Error> {
        {
            let mut dirs = self.dirs.lock();
            let buffer = dirs.get_mut(&fh).ok_or(Error::Remote(libc::EBADF))?;
            if buffer
                .plus
                .front()
                .is_some_and(|(cookie, _)| *cookie == offset)
            {
                return Ok(buffer.plus.drain(..).collect());
            }
            buffer.plus.clear();
        }
        let entries = self.client.readdirplus(fh, offset, READDIR_FETCH).await?;
        Ok(tag_with_cookies(entries, offset, |e| e.entry.next_offset))
    }

    fn stash_plain(&self, fh: u64, rest: Vec<(u64, DirEntry)>) {
        if let Some(buffer) = self.dirs.lock().get_mut(&fh) {
            buffer.plain = rest.into_iter().collect();
        }
    }

    fn stash_plus(&self, fh: u64, rest: Vec<(u64, DirEntryPlus)>) {
        if let Some(buffer) = self.dirs.lock().get_mut(&fh) {
            buffer.plus = rest.into_iter().collect();
        }
    }
}

/// Pair each entry with the cookie that yields it: the request offset for the first, the previous entry's `next_offset` after that.
fn tag_with_cookies<T>(entries: Vec<T>, first: u64, next: impl Fn(&T) -> u64) -> Vec<(u64, T)> {
    let mut cookie = first;
    entries
        .into_iter()
        .map(|e| {
            let tagged = (cookie, e);
            cookie = next(&tagged.1);
            tagged
        })
        .collect()
}

impl Filesystem for Backend {
    /// Each setter answers with the previous value when it accepts and the ceiling when it refuses, so what is logged is the value asked for or the ceiling it hit. The kernel proposes its own readahead (the mount's `bdi` setting, 128 KiB by default) and lets the daemon only lower it, so the readahead cap is the usual outcome and it bounds every read the kernel will ever issue; the effective values are read from sysfs after mounting.
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        let max_write = config
            .set_max_write(MAX_IO as u32)
            .map_or_else(|limit| limit, |_| MAX_IO as u32);
        let max_readahead = config
            .set_max_readahead(MAX_IO as u32)
            .map_or_else(|limit| limit, |_| MAX_IO as u32);
        let max_background = config
            .set_max_background(MAX_BACKGROUND)
            .map_or_else(|limit| limit, |_| MAX_BACKGROUND);
        let wanted = InitFlags::FUSE_ATOMIC_O_TRUNC
            | InitFlags::FUSE_ASYNC_READ
            | InitFlags::FUSE_PARALLEL_DIROPS
            | InitFlags::FUSE_AUTO_INVAL_DATA
            | InitFlags::FUSE_DO_READDIRPLUS
            | InitFlags::FUSE_READDIRPLUS_AUTO;
        let supported = wanted & config.capabilities();
        let missing = wanted - supported;
        if !missing.is_empty() {
            tracing::warn!(
                ?missing,
                "kernel does not offer some wanted FUSE capabilities"
            );
        }
        if let Err(rejected) = config.add_capabilities(supported) {
            tracing::debug!(?rejected, "kernel rejected capabilities it advertised");
        }
        tracing::info!(
            max_write,
            max_readahead,
            max_background,
            capabilities = ?supported,
            "FUSE parameters: asked for {MAX_IO} bytes of write and readahead and {MAX_BACKGROUND} background requests"
        );
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let shared = self.shared.clone();
        let name = match name_of(name) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        self.spawn(async move {
            let path = match shared.path_of(parent.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.lookup(path, name.clone()).await {
                Ok(attr) => match shared.register(parent.0, name, &attr) {
                    Ok(generation) => reply.entry_with_ttls(
                        &shared.attr_ttl,
                        &shared.entry_ttl,
                        &file_attr(&attr),
                        generation,
                    ),
                    Err(e) => reply.error(e),
                },
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.shared.nodes.lock().forget(ino.0, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        let shared = self.shared.clone();
        let fh = fh.map(|f| f.0);
        self.spawn(async move {
            let (path, fh) = match shared.path_for_handle_op(ino.0, fh) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.getattr(path, fh).await {
                Ok(attr) => reply.attr(&shared.attr_ttl, &file_attr(&attr)),
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        // ctime cannot be set on Linux and the remaining fields are macOS-only; they are dropped on purpose.
        let shared = self.shared.clone();
        let fh = fh.map(|f| f.0);
        let set = SetAttr {
            mode,
            uid,
            gid,
            size,
            atime: atime.map(time_or_now),
            mtime: mtime.map(time_or_now),
        };
        self.spawn(async move {
            let (path, fh) = match shared.path_for_handle_op(ino.0, fh) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.setattr(path, fh, set).await {
                Ok(attr) => reply.attr(&shared.attr_ttl, &file_attr(&attr)),
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let shared = self.shared.clone();
        self.spawn(async move {
            let path = match shared.path_of(ino.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.readlink(path).await {
                Ok(target) => reply.data(&target),
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        let shared = self.shared.clone();
        let name = match name_of(name) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        self.spawn(async move {
            let path = match shared.path_of(parent.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared
                .client
                .mknod(path, name.clone(), mode, rdev as u64)
                .await
            {
                Ok(attr) => match shared.register(parent.0, name, &attr) {
                    Ok(generation) => reply.entry_with_ttls(
                        &shared.attr_ttl,
                        &shared.entry_ttl,
                        &file_attr(&attr),
                        generation,
                    ),
                    Err(e) => reply.error(e),
                },
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let shared = self.shared.clone();
        let name = match name_of(name) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        self.spawn(async move {
            let path = match shared.path_of(parent.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.mkdir(path, name.clone(), mode).await {
                Ok(attr) => match shared.register(parent.0, name, &attr) {
                    Ok(generation) => reply.entry_with_ttls(
                        &shared.attr_ttl,
                        &shared.entry_ttl,
                        &file_attr(&attr),
                        generation,
                    ),
                    Err(e) => reply.error(e),
                },
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let shared = self.shared.clone();
        let name = match name_of(name) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        self.spawn(async move {
            let path = match shared.path_of(parent.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.unlink(path, name.clone()).await {
                Ok(()) => {
                    shared.nodes.lock().unlink(parent.0, &name);
                    reply.ok()
                }
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let shared = self.shared.clone();
        let name = match name_of(name) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        self.spawn(async move {
            let path = match shared.path_of(parent.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.rmdir(path, name.clone()).await {
                Ok(()) => {
                    shared.nodes.lock().unlink(parent.0, &name);
                    reply.ok()
                }
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &std::path::Path,
        reply: ReplyEntry,
    ) {
        let shared = self.shared.clone();
        let name = match name_of(link_name) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        let target = target.as_os_str().as_bytes().to_vec();
        self.spawn(async move {
            let path = match shared.path_of(parent.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.symlink(path, name.clone(), target).await {
                Ok(attr) => match shared.register(parent.0, name, &attr) {
                    Ok(generation) => reply.entry_with_ttls(
                        &shared.attr_ttl,
                        &shared.entry_ttl,
                        &file_attr(&attr),
                        generation,
                    ),
                    Err(e) => reply.error(e),
                },
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: fuser::RenameFlags,
        reply: ReplyEmpty,
    ) {
        let shared = self.shared.clone();
        let (name, newname) = match (name_of(name), name_of(newname)) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => return reply.error(e),
        };
        let exchange = flags.contains(fuser::RenameFlags::RENAME_EXCHANGE);
        let flags = flags.bits();
        self.spawn(async move {
            let (path, newpath) = match (shared.path_of(parent.0), shared.path_of(newparent.0)) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => return reply.error(e),
            };
            match shared
                .client
                .rename(path, name.clone(), newpath, newname.clone(), flags)
                .await
            {
                Ok(()) => {
                    let mut nodes = shared.nodes.lock();
                    if exchange {
                        nodes.exchange(parent.0, &name, newparent.0, &newname);
                    } else {
                        nodes.rename(parent.0, &name, newparent.0, newname);
                    }
                    drop(nodes);
                    reply.ok()
                }
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn link(
        &self,
        _req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let shared = self.shared.clone();
        let newname = match name_of(newname) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        self.spawn(async move {
            let (path, newpath) = match (shared.path_of(ino.0), shared.path_of(newparent.0)) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => return reply.error(e),
            };
            match shared.client.link(path, newpath, newname.clone()).await {
                Ok(attr) => match shared.register(newparent.0, newname, &attr) {
                    Ok(generation) => reply.entry_with_ttls(
                        &shared.attr_ttl,
                        &shared.entry_ttl,
                        &file_attr(&attr),
                        generation,
                    ),
                    Err(e) => reply.error(e),
                },
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: fuser::OpenFlags, reply: ReplyOpen) {
        let shared = self.shared.clone();
        let flags = flags.0;
        self.spawn(async move {
            let path = match shared.path_of(ino.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.open(ino.0, path, flags).await {
                Ok((fh, _)) => reply.opened(FileHandle(fh), FopenFlags::empty()),
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let shared = self.shared.clone();
        let name = match name_of(name) {
            Ok(name) => name,
            Err(e) => return reply.error(e),
        };
        self.spawn(async move {
            let path = match shared.path_of(parent.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.create(path, name.clone(), mode, flags).await {
                Ok((fh, attr)) => match shared.register(parent.0, name, &attr) {
                    Ok(generation) => reply.created(
                        &shared.entry_ttl.min(shared.attr_ttl),
                        &file_attr(&attr),
                        generation,
                        FileHandle(fh),
                        FopenFlags::empty(),
                    ),
                    Err(e) => reply.error(e),
                },
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let shared = self.shared.clone();
        self.spawn(async move {
            match shared.client.read(fh.0, offset, size).await {
                Ok(data) => reply.data(&data),
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        let shared = self.shared.clone();
        let data = data.to_vec();
        self.spawn(async move {
            match shared.client.write(fh.0, offset, data).await {
                Ok(n) => reply.written(n),
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    /// Nothing is buffered on the client, so a `close(2)` has nothing to flush.
    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let shared = self.shared.clone();
        self.spawn(async move {
            match shared.client.release(fh.0).await {
                Ok(()) => reply.ok(),
                Err(e) => {
                    tracing::debug!(fh = fh.0, "release failed: {e}");
                    reply.error(errno(&e))
                }
            }
        });
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let shared = self.shared.clone();
        self.spawn(async move {
            match shared.client.fsync(fh.0, datasync).await {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: fuser::OpenFlags, reply: ReplyOpen) {
        let shared = self.shared.clone();
        self.spawn(async move {
            let path = match shared.path_of(ino.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.opendir(ino.0, path).await {
                Ok((fh, _)) => {
                    shared.dirs.lock().insert(fh, DirBuffer::default());
                    reply.opened(FileHandle(fh), FopenFlags::empty())
                }
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let shared = self.shared.clone();
        self.spawn(async move {
            let mut entries = match shared.dir_page(fh.0, offset).await {
                Ok(entries) => entries.into_iter(),
                Err(e) => return reply.error(errno(&e)),
            };
            for (cookie, entry) in entries.by_ref() {
                let entry_ino = match entry.name.as_slice() {
                    b"." => ino.0,
                    b".." => shared.parent_of(ino.0),
                    _ => entry.ino,
                };
                if reply.add(
                    INodeNo(entry_ino),
                    entry.next_offset,
                    file_type(entry.kind),
                    OsStr::from_bytes(&entry.name),
                ) {
                    let mut rest = vec![(cookie, entry)];
                    rest.extend(entries);
                    shared.stash_plain(fh.0, rest);
                    break;
                }
            }
            reply.ok();
        });
    }

    fn readdirplus(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let shared = self.shared.clone();
        self.spawn(async move {
            let mut entries = match shared.dir_page_plus(fh.0, offset).await {
                Ok(entries) => entries.into_iter(),
                Err(e) => return reply.error(errno(&e)),
            };
            for (cookie, item) in entries.by_ref() {
                let entry = &item.entry;
                let name = OsStr::from_bytes(&entry.name);
                let full = match (entry.name.as_slice(), &item.attr) {
                    (b".", _) => reply.add(
                        INodeNo(ino.0),
                        entry.next_offset,
                        name,
                        &shared.entry_ttl,
                        &dir_placeholder(ino.0),
                        Generation(0),
                    ),
                    (b"..", _) => {
                        let parent = shared.parent_of(ino.0);
                        reply.add(
                            INodeNo(parent),
                            entry.next_offset,
                            name,
                            &shared.entry_ttl,
                            &dir_placeholder(parent),
                            Generation(0),
                        )
                    }
                    (_, Some(attr)) => {
                        let Ok(entry_name) = Name::new(entry.name.as_slice()) else {
                            continue;
                        };
                        let generation = shared.nodes.lock().generation_for_lookup(attr.ino);
                        let full = reply.add(
                            INodeNo(attr.ino),
                            entry.next_offset,
                            name,
                            &shared.entry_ttl,
                            &file_attr(attr),
                            Generation(generation),
                        );
                        if !full && shared.register(ino.0, entry_name, attr).is_err() {
                            tracing::warn!(
                                ino = attr.ino,
                                "readdirplus entry could not be registered"
                            );
                        }
                        full
                    }
                    (_, None) => continue,
                };
                if full {
                    let mut rest = vec![(cookie, item)];
                    rest.extend(entries);
                    shared.stash_plus(fh.0, rest);
                    break;
                }
            }
            reply.ok();
        });
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let shared = self.shared.clone();
        self.spawn(async move {
            match shared.client.fsync(fh.0, datasync).await {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: fuser::OpenFlags,
        reply: ReplyEmpty,
    ) {
        let shared = self.shared.clone();
        self.spawn(async move {
            shared.dirs.lock().remove(&fh.0);
            match shared.client.releasedir(fh.0).await {
                Ok(()) => reply.ok(),
                Err(e) => {
                    tracing::debug!(fh = fh.0, "releasedir failed: {e}");
                    reply.error(errno(&e))
                }
            }
        });
    }

    fn statfs(&self, _req: &Request, ino: INodeNo, reply: ReplyStatfs) {
        let shared = self.shared.clone();
        self.spawn(async move {
            let path = shared
                .nodes
                .lock()
                .path_of(ino.0)
                .unwrap_or_else(Path::root);
            match shared.client.statfs(path).await {
                Ok(s) => reply.statfs(
                    s.blocks, s.bfree, s.bavail, s.files, s.ffree, s.bsize, s.namelen, s.frsize,
                ),
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn setxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        if position != 0 {
            return reply.error(Errno::EINVAL);
        }
        let shared = self.shared.clone();
        let name = name.as_bytes().to_vec();
        let value = value.to_vec();
        self.spawn(async move {
            let path = match shared.path_of(ino.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.setxattr(path, name, value, flags).await {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        let shared = self.shared.clone();
        let name = name.as_bytes().to_vec();
        self.spawn(async move {
            let path = match shared.path_of(ino.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.getxattr(path, name).await {
                Ok(value) => reply_xattr(reply, size, &value),
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let shared = self.shared.clone();
        self.spawn(async move {
            let path = match shared.path_of(ino.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.listxattr(path).await {
                Ok(list) => reply_xattr(reply, size, &list),
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn removexattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let shared = self.shared.clone();
        let name = name.as_bytes().to_vec();
        self.spawn(async move {
            let path = match shared.path_of(ino.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.removexattr(path, name).await {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(errno(&e)),
            }
        });
    }

    fn access(&self, _req: &Request, ino: INodeNo, mask: fuser::AccessFlags, reply: ReplyEmpty) {
        let shared = self.shared.clone();
        let mask = mask.bits();
        self.spawn(async move {
            let path = match shared.path_of(ino.0) {
                Ok(path) => path,
                Err(e) => return reply.error(e),
            };
            match shared.client.access(path, mask).await {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(errno(&e)),
            }
        });
    }
}

/// The xattr size protocol: a zero `size` asks how big the value is; otherwise the value must fit.
fn reply_xattr(reply: ReplyXattr, size: u32, value: &[u8]) {
    if size == 0 {
        reply.size(value.len() as u32);
    } else if value.len() > size as usize {
        reply.error(Errno::ERANGE);
    } else {
        reply.data(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_conversions_round_trip() {
        for t in [
            TimeSpec { sec: 0, nsec: 0 },
            TimeSpec {
                sec: 1_700_000_000,
                nsec: 123_456_789,
            },
            TimeSpec {
                sec: -1,
                nsec: 500_000_000,
            },
            TimeSpec {
                sec: -86_400,
                nsec: 0,
            },
        ] {
            assert_eq!(timespec(system_time(t)), t, "{t:?}");
        }
    }

    #[test]
    fn cookies_tag_each_entry_with_what_yields_it() {
        let entries = vec![
            DirEntry {
                ino: 1,
                next_offset: 10,
                kind: FileKind::Regular,
                name: b"a".to_vec(),
            },
            DirEntry {
                ino: 2,
                next_offset: 20,
                kind: FileKind::Regular,
                name: b"b".to_vec(),
            },
        ];
        let tagged = tag_with_cookies(entries, 5, |e| e.next_offset);
        assert_eq!(
            tagged.iter().map(|(c, _)| *c).collect::<Vec<_>>(),
            vec![5, 10]
        );
    }
}

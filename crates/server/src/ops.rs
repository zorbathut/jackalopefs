//! One synchronous function per request, run on the blocking pool. Every path goes through [`Export`]; every open file goes through [`Handles`].

use crate::dirents::read_dir_fd;
use crate::export::{kind_from_mode, proc_path, Export};
use crate::handles::{Handle, Handles};
use crate::ids::IdMap;
use crate::watch::{parent_of, ChangeLog, Watches};
use jackalopefs_proto::owners::reads_posix_acl;
use jackalopefs_proto::{
    Attr, Name, Path, Request, Response, SetAttr, Statfs, TimeOrNow, Whence, MAX_FALLOCATE, MAX_IO,
    NAME_MAX,
};
use nix::errno::Errno;
use nix::fcntl::{fallocate, renameat2, AtFlags, FallocateFlags, OFlag, RenameFlags, AT_FDCWD};
use nix::sys::stat::{
    fchmod, fstatat, futimens, mkdirat, mknodat, utimensat, Mode, SFlag, UtimensatFlags,
};
use nix::sys::time::TimeSpec;
use nix::unistd::{
    faccessat, fchown, fchownat, fdatasync, fsync, ftruncate, linkat, lseek, symlinkat, unlinkat,
    AccessFlags, Gid, Uid, UnlinkatFlags,
};
use parking_lot::Mutex;
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::sync::Arc;

/// Open flags accepted from a client. `openat2` rejects unknown bits with `EINVAL`, and some (`O_DIRECT`) belong to the client kernel's side of the mount, so anything else is dropped. Creation flags are accepted only from `Create`.
const OPEN_FLAGS_ALLOWED: i32 = libc::O_ACCMODE
    | libc::O_APPEND
    | libc::O_TRUNC
    | libc::O_SYNC
    | libc::O_DSYNC
    | libc::O_NOATIME
    | libc::O_NONBLOCK
    | libc::O_NOFOLLOW
    | libc::O_CLOEXEC
    | libc::O_DIRECTORY
    | libc::O_LARGEFILE
    | libc::O_NOCTTY;

/// The `fallocate` modes the protocol carries: the ones the FUSE kernel forwards.
const FALLOCATE_MODES_ALLOWED: FallocateFlags = FallocateFlags::FALLOC_FL_KEEP_SIZE
    .union(FallocateFlags::FALLOC_FL_PUNCH_HOLE)
    .union(FallocateFlags::FALLOC_FL_ZERO_RANGE);

/// Most bytes one `CopyFileRange` copies; the client asks again for the rest. Nothing notices a request its client abandoned, so this bounds how long a copy holds a blocking thread and how long it goes on writing to a file whose caller has moved on. A power of two, so a copy that starts block-aligned stays so, as a reflink needs.
const MAX_COPY: u64 = 64 << 20;
const _: () = assert!(MAX_COPY <= u32::MAX as u64, "the copied reply is a u32");

pub struct Ops {
    pub export: Arc<Export>,
    pub handles: Arc<Handles>,
    pub session_id: u64,
    pub changes: Arc<ChangeLog>,
    /// What a handle holds watched while it is open.
    pub watches: Arc<Watches>,
    pub ids: IdMap,
}

/// Run one request; every failure becomes an errno for the client. The owner policy (`--ids`) is checked before anything is touched and applied to what goes back. Running out of file descriptors, whether the session's cap or the process's limit, is logged with what this session holds, since the handles of every session share that limit.
pub fn dispatch(ops: &Ops, req: Request) -> Response {
    let op = req.op_name();
    if let Err(errno) = ops.ids.admit(&req) {
        return Response::Err(errno as i32);
    }
    let posix_acl_read = reads_posix_acl(&req);
    match ops.run(req) {
        Ok(mut resp) => {
            ops.ids.reply(posix_acl_read, &mut resp);
            resp
        }
        Err(errno @ (Errno::EMFILE | Errno::ENFILE)) => {
            let open_handles = ops.handles.len();
            if open_handles >= ops.handles.max() {
                tracing::warn!(
                    op,
                    session = ops.session_id,
                    open_handles,
                    limit = ops.handles.max(),
                    "session holds too many open handles"
                );
            } else {
                tracing::warn!(
                    op,
                    session = ops.session_id,
                    open_handles,
                    "out of file descriptors: {errno}"
                );
            }
            Response::Err(errno as i32)
        }
        Err(errno) => Response::Err(errno as i32),
    }
}

fn io_errno(e: std::io::Error) -> Errno {
    e.raw_os_error().map(Errno::from_raw).unwrap_or(Errno::EIO)
}

const CREATE_FLAGS_ALLOWED: i32 = OPEN_FLAGS_ALLOWED | libc::O_CREAT | libc::O_EXCL;

fn open_flags(flags: i32, creating: bool) -> OFlag {
    let allowed = if creating {
        CREATE_FLAGS_ALLOWED
    } else {
        OPEN_FLAGS_ALLOWED
    };
    let unknown = flags & !allowed;
    if unknown != 0 {
        tracing::debug!(
            unknown = format!("{unknown:#x}"),
            "dropping open flags the server does not pass through"
        );
    }
    OFlag::from_bits_truncate(flags & allowed)
}

/// Only regular files and directories are served through handles. The FUSE kernel handles FIFOs, sockets and devices itself and never asks to open one, so such a request is not from an honest client, and a FIFO would be a way to park a server thread.
fn servable(kind: jackalopefs_proto::FileKind) -> Result<(), Errno> {
    match kind {
        jackalopefs_proto::FileKind::Regular | jackalopefs_proto::FileKind::Directory => Ok(()),
        _ => Err(Errno::EOPNOTSUPP),
    }
}

/// The handle's fd, or the `O_PATH` node for a path-addressed request; the two need different syscall forms.
enum Target {
    Fd(OwnedFd),
    Node(OwnedFd),
}

fn cstring(bytes: &[u8]) -> Result<CString, Errno> {
    CString::new(bytes).map_err(|_| Errno::EINVAL)
}

fn timespec(t: Option<TimeOrNow>) -> TimeSpec {
    match t {
        None => TimeSpec::UTIME_OMIT,
        Some(TimeOrNow::Now) => TimeSpec::UTIME_NOW,
        Some(TimeOrNow::Time(t)) => TimeSpec::new(t.sec, t.nsec as i64),
    }
}

fn stat_fd<F: AsFd>(fd: &F) -> Result<nix::sys::stat::FileStat, Errno> {
    fstatat(
        fd,
        "",
        AtFlags::AT_EMPTY_PATH | AtFlags::AT_SYMLINK_NOFOLLOW,
    )
}

impl Ops {
    fn attr_of<F: AsFd>(&self, fd: &F) -> Result<Attr, Errno> {
        self.export.attr_of(fd.as_fd())
    }

    fn attr_in<F: AsFd>(&self, dir: &F, name: &Name) -> Result<Attr, Errno> {
        self.export.attr_in(dir.as_fd(), name)
    }

    fn run(&self, req: Request) -> Result<Response, Errno> {
        match req {
            Request::Lookup { parent, name } => {
                let dir = self.export.resolve_dir(&parent)?;
                Ok(Response::Entry(self.attr_in(&dir, &name)?))
            }
            Request::Getattr { path, fh } => {
                let attr = match fh.map(|fh| self.handles.get(fh)).transpose()? {
                    Some(Handle::File { file, .. }) => self.attr_of(&file)?,
                    Some(Handle::Dir { dir, .. }) => self.attr_of(&*dir.lock())?,
                    None => {
                        self.attr_of(&self.export.resolve(path.as_ref().ok_or(Errno::EINVAL)?)?)?
                    }
                };
                Ok(Response::Attr(attr))
            }
            Request::Setattr { path, fh, set } => self.setattr(path.as_ref(), fh, set),
            Request::Readlink { path } => {
                let fd = self.export.resolve(&path)?;
                let target = nix::fcntl::readlinkat(&fd, "")?;
                Ok(Response::Readlink(target.as_bytes().to_vec()))
            }
            Request::Mknod {
                parent,
                name,
                mode,
                rdev,
            } => {
                // Device nodes need CAP_MKNOD, which an unprivileged server never has; say so up front.
                if !matches!(
                    mode & libc::S_IFMT,
                    libc::S_IFREG | libc::S_IFIFO | libc::S_IFSOCK
                ) {
                    return Err(Errno::EPERM);
                }
                let dir = self.export.resolve_dir(&parent)?;
                self.changes.record_entry(&parent, &name, self.session_id);
                mknodat(
                    &dir,
                    name.as_os_str(),
                    SFlag::from_bits_truncate(mode & libc::S_IFMT),
                    Mode::from_bits_truncate(mode & 0o7777),
                    rdev,
                )?;
                Ok(Response::Entry(self.attr_in(&dir, &name)?))
            }
            Request::Mkdir { parent, name, mode } => {
                let dir = self.export.resolve_dir(&parent)?;
                self.changes.record_entry(&parent, &name, self.session_id);
                mkdirat(
                    &dir,
                    name.as_os_str(),
                    Mode::from_bits_truncate(mode & 0o7777),
                )?;
                Ok(Response::Entry(self.attr_in(&dir, &name)?))
            }
            Request::Unlink { parent, name } => {
                let dir = self.export.resolve_dir(&parent)?;
                self.changes.record_entry(&parent, &name, self.session_id);
                unlinkat(&dir, name.as_os_str(), UnlinkatFlags::NoRemoveDir)?;
                Ok(Response::Ok)
            }
            Request::Rmdir { parent, name } => {
                let dir = self.export.resolve_dir(&parent)?;
                self.changes.record_entry(&parent, &name, self.session_id);
                unlinkat(&dir, name.as_os_str(), UnlinkatFlags::RemoveDir)?;
                Ok(Response::Ok)
            }
            Request::Symlink {
                parent,
                name,
                target,
            } => {
                let dir = self.export.resolve_dir(&parent)?;
                self.changes.record_entry(&parent, &name, self.session_id);
                symlinkat(OsStr::from_bytes(&target), &dir, name.as_os_str())?;
                Ok(Response::Entry(self.attr_in(&dir, &name)?))
            }
            Request::Rename {
                parent,
                name,
                newparent,
                newname,
                flags,
            } => {
                let flags = RenameFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
                if flags.contains(RenameFlags::RENAME_WHITEOUT) {
                    return Err(Errno::EINVAL);
                }
                let old_dir = self.export.resolve_dir(&parent)?;
                let new_dir = self.export.resolve_dir(&newparent)?;
                self.changes.record_entry(&parent, &name, self.session_id);
                self.changes
                    .record_entry(&newparent, &newname, self.session_id);
                renameat2(
                    &old_dir,
                    name.as_os_str(),
                    &new_dir,
                    newname.as_os_str(),
                    flags,
                )?;
                Ok(Response::Ok)
            }
            Request::Link {
                path,
                newparent,
                newname,
            } => {
                let (old_dir, old_name) = self.export.resolve_parent(&path)?;
                let new_dir = self.export.resolve_dir(&newparent)?;
                self.changes
                    .record_entry(&newparent, &newname, self.session_id);
                linkat(
                    &old_dir,
                    old_name.as_os_str(),
                    &new_dir,
                    newname.as_os_str(),
                    AtFlags::empty(),
                )?;
                Ok(Response::Entry(self.attr_in(&new_dir, &newname)?))
            }
            Request::Open { fh, path, flags } => {
                let flags = open_flags(flags, false);
                if flags.contains(OFlag::O_TRUNC) {
                    self.changes.record(&path, self.session_id);
                }
                let fd = self.export.open_node(&path, flags)?;
                let attr = self.attr_of(&fd)?;
                servable(attr.kind)?;
                let watch = self.watches.hold(&parent_of(&path));
                self.handles.insert(
                    fh,
                    Handle::File {
                        file: Arc::new(File::from(fd)),
                        path,
                        watch,
                    },
                )?;
                Ok(Response::Opened { attr })
            }
            Request::Create {
                fh,
                parent,
                name,
                mode,
                flags,
            } => {
                self.changes.record_entry(&parent, &name, self.session_id);
                let fd = self.export.open_in(
                    &parent,
                    &name,
                    open_flags(flags, true) | OFlag::O_CREAT,
                    Mode::from_bits_truncate(mode & 0o7777),
                )?;
                let attr = self.attr_of(&fd)?;
                servable(attr.kind)?;
                let watch = self.watches.hold(&parent);
                let path = parent.join(name).map_err(|_| Errno::ENAMETOOLONG)?;
                self.handles.insert(
                    fh,
                    Handle::File {
                        file: Arc::new(File::from(fd)),
                        path,
                        watch,
                    },
                )?;
                Ok(Response::Opened { attr })
            }
            Request::Read { fh, offset, size } => {
                let file = self.handles.file(fh)?;
                let size = (size as usize).min(MAX_IO);
                let mut buf = vec![0u8; size];
                let mut filled = 0;
                while filled < size {
                    match file.read_at(&mut buf[filled..], offset + filled as u64) {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(io_errno(e)),
                    }
                }
                buf.truncate(filled);
                Ok(Response::Read(buf))
            }
            Request::Write { fh, offset, data } => {
                if data.len() > MAX_IO {
                    return Err(Errno::EINVAL);
                }
                let (file, path) = self.handles.file_and_path(fh)?;
                self.changes.record(&path, self.session_id);
                file.write_all_at(&data, offset).map_err(io_errno)?;
                Ok(Response::Written(data.len() as u32))
            }
            Request::CopyFileRange {
                fh_in,
                offset_in,
                fh_out,
                offset_out,
                len,
            } => {
                let src = self.handles.file(fh_in)?;
                let (dst, path) = self.handles.file_and_path(fh_out)?;
                let mut offset_in = i64::try_from(offset_in).map_err(|_| Errno::EINVAL)?;
                let mut offset_out = i64::try_from(offset_out).map_err(|_| Errno::EINVAL)?;
                self.changes.record(&path, self.session_id);
                let copied = loop {
                    // SAFETY: the `Arc`s keep both fds open across the call, whatever is released meanwhile, and both offsets point at live locals. Explicit offsets keep the call positional: a null one would move the file position that every request on the handle shares.
                    let copied = unsafe {
                        libc::copy_file_range(
                            src.as_raw_fd(),
                            &mut offset_in,
                            dst.as_raw_fd(),
                            &mut offset_out,
                            len.min(MAX_COPY) as usize,
                            0,
                        )
                    };
                    if copied >= 0 {
                        break copied;
                    }
                    match Errno::last() {
                        Errno::EINTR => continue,
                        errno => return Err(errno),
                    }
                };
                Ok(Response::Copied(
                    u32::try_from(copied).expect("a copy is clamped to MAX_COPY"),
                ))
            }
            Request::Fallocate {
                fh,
                offset,
                len,
                mode,
            } => {
                if len > MAX_FALLOCATE {
                    return Err(Errno::EINVAL);
                }
                // A mode outside the protocol's is refused, never trimmed: a punch without its punch bit is an allocation.
                let mode = FallocateFlags::from_bits(mode)
                    .filter(|mode| FALLOCATE_MODES_ALLOWED.contains(*mode))
                    .ok_or(Errno::EOPNOTSUPP)?;
                let (file, path) = self.handles.file_and_path(fh)?;
                let offset = i64::try_from(offset).map_err(|_| Errno::EINVAL)?;
                let len = i64::try_from(len).map_err(|_| Errno::EINVAL)?;
                self.changes.record(&path, self.session_id);
                loop {
                    match fallocate(&*file, mode, offset, len) {
                        Err(Errno::EINTR) => continue,
                        done => break done?,
                    }
                }
                Ok(Response::Ok)
            }
            Request::Lseek { fh, offset, whence } => {
                let file = self.handles.file(fh)?;
                let offset = i64::try_from(offset).map_err(|_| Errno::EINVAL)?;
                let whence = match whence {
                    Whence::Data => nix::unistd::Whence::SeekData,
                    Whence::Hole => nix::unistd::Whence::SeekHole,
                };
                // There is no positional seek, so this moves the position of a descriptor every request on the handle shares; nothing reads it.
                let found = lseek(&*file, offset, whence)?;
                Ok(Response::Seeked(
                    u64::try_from(found).expect("lseek returns no negative offset"),
                ))
            }
            Request::Release { fh } | Request::Releasedir { fh } => {
                if self.handles.remove(fh).is_none() {
                    tracing::debug!(fh, "release of an unknown handle");
                }
                Ok(Response::Ok)
            }
            Request::Fsync { fh, datasync } => {
                match self.handles.get(fh)? {
                    Handle::File { file, .. } => sync(&*file, datasync)?,
                    Handle::Dir { dir, .. } => sync(&*dir.lock(), datasync)?,
                }
                Ok(Response::Ok)
            }
            Request::Opendir { fh, path } => {
                let fd = self
                    .export
                    .open_node(&path, OFlag::O_RDONLY | OFlag::O_DIRECTORY)?;
                let attr = self.attr_of(&fd)?;
                servable(attr.kind)?;
                self.handles.insert(
                    fh,
                    Handle::Dir {
                        dir: Arc::new(Mutex::new(fd)),
                        watch: self.watches.hold(&path),
                    },
                )?;
                Ok(Response::Opened { attr })
            }
            Request::Readdir {
                fh,
                offset,
                max_bytes,
            } => {
                let dir = self.handles.dir(fh)?;
                let guard = dir.lock();
                let listing = read_dir_fd(
                    &self.export,
                    &*guard,
                    offset,
                    (max_bytes as usize).min(MAX_IO),
                )?;
                Ok(Response::Readdir {
                    entries: listing.entries,
                    end: listing.end,
                })
            }
            Request::Statfs { path } => {
                let fd = self.export.resolve(&path)?;
                Ok(Response::Statfs(statfs(&fd)?))
            }
            Request::Setxattr {
                path,
                name,
                value,
                flags,
            } => {
                self.changes.record(&path, self.session_id);
                let fd = self.export.resolve(&path)?;
                let cpath = cstring(proc_path(fd.as_fd()).as_os_str().as_bytes())?;
                let cname = cstring(&name)?;
                // SAFETY: all pointers are valid for the lengths given and the strings are NUL-terminated.
                let rc = unsafe {
                    libc::setxattr(
                        cpath.as_ptr(),
                        cname.as_ptr(),
                        value.as_ptr() as *const libc::c_void,
                        value.len(),
                        flags,
                    )
                };
                if rc != 0 {
                    return Err(Errno::last());
                }
                Ok(Response::Ok)
            }
            Request::Getxattr { path, name } => {
                let fd = self.export.resolve(&path)?;
                let cpath = cstring(proc_path(fd.as_fd()).as_os_str().as_bytes())?;
                let cname = cstring(&name)?;
                let value = xattr_read(|buf, len| unsafe {
                    libc::getxattr(cpath.as_ptr(), cname.as_ptr(), buf, len)
                })?;
                Ok(Response::Xattr(value))
            }
            Request::Listxattr { path } => {
                let fd = self.export.resolve(&path)?;
                let cpath = cstring(proc_path(fd.as_fd()).as_os_str().as_bytes())?;
                let list = xattr_read(|buf, len| unsafe {
                    libc::listxattr(cpath.as_ptr(), buf as *mut libc::c_char, len)
                })?;
                Ok(Response::Xattr(list))
            }
            Request::Removexattr { path, name } => {
                self.changes.record(&path, self.session_id);
                let fd = self.export.resolve(&path)?;
                let cpath = cstring(proc_path(fd.as_fd()).as_os_str().as_bytes())?;
                let cname = cstring(&name)?;
                // SAFETY: both strings are valid NUL-terminated C strings.
                let rc = unsafe { libc::removexattr(cpath.as_ptr(), cname.as_ptr()) };
                if rc != 0 {
                    return Err(Errno::last());
                }
                Ok(Response::Ok)
            }
            Request::Access { path, mask } => {
                let fd = self.export.resolve(&path)?;
                let mode = AccessFlags::from_bits(mask).ok_or(Errno::EINVAL)?;
                faccessat(
                    AT_FDCWD,
                    proc_path(fd.as_fd()).as_os_str(),
                    mode,
                    AtFlags::AT_EACCESS,
                )?;
                Ok(Response::Ok)
            }
        }
    }

    /// Apply the requested changes in an order that leaves the final mode as the client asked for it (a chown clears setuid/setgid, so it goes before chmod), then return the resulting attributes. A handle, when given, must be known; an unlinked-but-open file has no path, so the handle is all there is.
    fn setattr(
        &self,
        path: Option<&Path>,
        fh: Option<u64>,
        set: SetAttr,
    ) -> Result<Response, Errno> {
        let handle = fh.map(|fh| self.handles.get(fh)).transpose()?;
        let origin = match &handle {
            Some(Handle::File { path, .. }) => Some(path),
            _ => path,
        };
        if let Some(origin) = origin {
            self.changes.record(origin, self.session_id);
        }
        let target = match handle {
            Some(Handle::File { file, .. }) => {
                Target::Fd(file.as_fd().try_clone_to_owned().map_err(io_errno)?)
            }
            Some(Handle::Dir { dir, .. }) => {
                Target::Fd(dir.lock().as_fd().try_clone_to_owned().map_err(io_errno)?)
            }
            None => Target::Node(self.export.resolve(path.ok_or(Errno::EINVAL)?)?),
        };

        if set.uid.is_some() || set.gid.is_some() {
            let uid = set.uid.map(Uid::from_raw);
            let gid = set.gid.map(Gid::from_raw);
            match &target {
                Target::Fd(fd) => fchown(fd, uid, gid)?,
                Target::Node(node) => fchownat(
                    node,
                    "",
                    uid,
                    gid,
                    AtFlags::AT_EMPTY_PATH | AtFlags::AT_SYMLINK_NOFOLLOW,
                )?,
            }
        }
        if let Some(mode) = set.mode {
            let mode = Mode::from_bits_truncate(mode & 0o7777);
            match &target {
                Target::Fd(fd) => fchmod(fd, mode)?,
                Target::Node(node) => {
                    if kind_from_mode(stat_fd(node)?.st_mode)
                        == Some(jackalopefs_proto::FileKind::Symlink)
                    {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    let cpath = cstring(proc_path(node.as_fd()).as_os_str().as_bytes())?;
                    chmod(&cpath, mode)?;
                }
            }
        }
        if let Some(size) = set.size {
            match &target {
                Target::Fd(fd) => ftruncate(fd, size as i64)?,
                Target::Node(node) => {
                    servable(kind_from_mode(stat_fd(node)?.st_mode).ok_or(Errno::EIO)?)?;
                    let file = self
                        .export
                        .open_node(path.ok_or(Errno::EINVAL)?, OFlag::O_WRONLY)?;
                    ftruncate(&file, size as i64)?;
                }
            }
        }
        if set.atime.is_some() || set.mtime.is_some() {
            let atime = timespec(set.atime);
            let mtime = timespec(set.mtime);
            match &target {
                Target::Fd(fd) => futimens(fd, &atime, &mtime)?,
                Target::Node(_) => match path.ok_or(Errno::EINVAL)?.split_last() {
                    Some((parent, name)) => utimensat(
                        &self.export.resolve_dir(&parent)?,
                        name.as_os_str(),
                        &atime,
                        &mtime,
                        UtimensatFlags::NoFollowSymlink,
                    )?,
                    None => utimensat(
                        self.export.root(),
                        ".",
                        &atime,
                        &mtime,
                        UtimensatFlags::NoFollowSymlink,
                    )?,
                },
            }
        }
        let attr = match &target {
            Target::Fd(fd) => self.attr_of(fd)?,
            Target::Node(node) => self.attr_of(node)?,
        };
        Ok(Response::Attr(attr))
    }
}

fn chmod(path: &CStr, mode: Mode) -> Result<(), Errno> {
    // SAFETY: `path` is a valid NUL-terminated string.
    let rc = unsafe { libc::chmod(path.as_ptr(), mode.bits()) };
    if rc != 0 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}

fn sync<F: AsFd>(fd: &F, datasync: bool) -> Result<(), Errno> {
    if datasync {
        fdatasync(fd)
    } else {
        fsync(fd)
    }
}

/// Query-then-fetch for the variable-length xattr calls, retrying the handful of times a concurrent change can make the value grow between the two calls.
fn xattr_read(
    mut call: impl FnMut(*mut libc::c_void, usize) -> libc::ssize_t,
) -> Result<Vec<u8>, Errno> {
    for _ in 0..4 {
        let needed = call(std::ptr::null_mut(), 0);
        if needed < 0 {
            return Err(Errno::last());
        }
        let mut buf = vec![0u8; needed as usize];
        let got = call(buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        if got >= 0 {
            buf.truncate(got as usize);
            return Ok(buf);
        }
        let errno = Errno::last();
        if errno != Errno::ERANGE {
            return Err(errno);
        }
    }
    Err(Errno::ERANGE)
}

fn statfs<F: AsFd>(fd: &F) -> Result<Statfs, Errno> {
    // SAFETY: `statfs64` is plain data and the kernel fills it completely on success.
    let mut st: libc::statfs64 = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatfs64(fd.as_fd().as_raw_fd(), &mut st) };
    if rc != 0 {
        return Err(Errno::last());
    }
    Ok(Statfs {
        blocks: st.f_blocks,
        bfree: st.f_bfree,
        bavail: st.f_bavail,
        files: st.f_files,
        ffree: st.f_ffree,
        bsize: st.f_bsize as u32,
        // pathconf(_PC_NAME_MAX) is answered from this, and the protocol refuses names longer than NAME_MAX whatever the export allows.
        namelen: (st.f_namelen as u32).min(NAME_MAX as u32),
        frsize: st.f_frsize as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::ModeIds;
    use jackalopefs_proto::owners::NOBODY;
    use jackalopefs_proto::FileKind;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn fixture() -> (tempfile::TempDir, Ops) {
        nix::sys::stat::umask(Mode::empty());
        let dir = tempfile::tempdir().unwrap();
        let export = Arc::new(Export::open(dir.path()).unwrap());
        (
            dir,
            Ops {
                export,
                handles: Arc::new(Handles::new(crate::handles::MAX_HANDLES)),
                session_id: 1,
                changes: Arc::new(ChangeLog::default()),
                watches: Watches::disabled(),
                ids: IdMap::of_process(ModeIds::Direct).unwrap(),
            },
        )
    }

    fn name(s: &str) -> Name {
        Name::new(s.as_bytes()).unwrap()
    }

    fn path(s: &str) -> Path {
        if s.is_empty() {
            return Path::root();
        }
        Path::from_names(s.split('/').map(name).collect()).unwrap()
    }

    fn expect_attr(resp: Response) -> Attr {
        match resp {
            Response::Entry(a) | Response::Attr(a) | Response::Opened { attr: a } => a,
            other => panic!("expected an attr, got {other:?}"),
        }
    }

    #[test]
    fn create_write_read_release() {
        let (dir, ops) = fixture();
        let created = expect_attr(dispatch(
            &ops,
            Request::Create {
                fh: 1,
                parent: Path::root(),
                name: name("f"),
                mode: 0o100640,
                flags: libc::O_RDWR,
            },
        ));
        assert_eq!(created.kind, FileKind::Regular);
        assert_eq!(
            created.perm, 0o640,
            "server umask must not apply on top of the client's"
        );
        assert_eq!(
            dispatch(
                &ops,
                Request::Write {
                    fh: 1,
                    offset: 0,
                    data: b"hello world".to_vec()
                }
            ),
            Response::Written(11)
        );
        assert_eq!(
            dispatch(
                &ops,
                Request::Read {
                    fh: 1,
                    offset: 6,
                    size: 100
                }
            ),
            Response::Read(b"world".to_vec())
        );
        assert_eq!(fs::read(dir.path().join("f")).unwrap(), b"hello world");
        assert_eq!(dispatch(&ops, Request::Release { fh: 1 }), Response::Ok);
        assert!(ops.handles.is_empty());
        assert_eq!(
            dispatch(
                &ops,
                Request::Read {
                    fh: 1,
                    offset: 0,
                    size: 1
                }
            ),
            Response::Err(Errno::EBADF as i32)
        );
        assert_eq!(
            dispatch(&ops, Request::Release { fh: 1 }),
            Response::Ok,
            "releasing an unknown handle is harmless"
        );
    }

    fn open(ops: &Ops, fh: u64, file: &str, flags: i32) {
        expect_attr(dispatch(
            ops,
            Request::Open {
                fh,
                path: path(file),
                flags,
            },
        ));
    }

    fn copy(
        ops: &Ops,
        fh_in: u64,
        offset_in: u64,
        fh_out: u64,
        offset_out: u64,
        len: u64,
    ) -> Response {
        dispatch(
            ops,
            Request::CopyFileRange {
                fh_in,
                offset_in,
                fh_out,
                offset_out,
                len,
            },
        )
    }

    #[test]
    fn copy_file_range_copies_between_handles() {
        let (dir, ops) = fixture();
        fs::write(dir.path().join("src"), b"0123456789").unwrap();
        fs::write(dir.path().join("dst"), b"abcdefghijklmnop").unwrap();
        open(&ops, 1, "src", libc::O_RDONLY);
        open(&ops, 2, "dst", libc::O_RDWR);
        assert_eq!(copy(&ops, 1, 2, 2, 4, 5), Response::Copied(5));
        assert_eq!(
            fs::read(dir.path().join("dst")).unwrap(),
            b"abcd23456jklmnop"
        );
        assert_eq!(
            dispatch(
                &ops,
                Request::Read {
                    fh: 2,
                    offset: 4,
                    size: 5
                }
            ),
            Response::Read(b"23456".to_vec())
        );
        // The handles are shared and every access positional, so a copy must leave their file positions alone.
        let src = ops.handles.file(1).unwrap();
        assert_eq!(
            nix::unistd::lseek(&*src, 0, nix::unistd::Whence::SeekCur),
            Ok(0)
        );
    }

    #[test]
    fn copy_file_range_is_short_at_the_end_of_the_source() {
        let (dir, ops) = fixture();
        fs::write(dir.path().join("src"), b"0123456789").unwrap();
        fs::write(dir.path().join("dst"), b"").unwrap();
        open(&ops, 1, "src", libc::O_RDONLY);
        open(&ops, 2, "dst", libc::O_RDWR);
        assert_eq!(copy(&ops, 1, 6, 2, 0, 100), Response::Copied(4));
        assert_eq!(copy(&ops, 1, 10, 2, 4, 100), Response::Copied(0));
        assert_eq!(
            copy(&ops, 1, 0, 2, 0, u64::MAX),
            Response::Copied(10),
            "a length no file has is clamped, not refused"
        );
        assert_eq!(fs::read(dir.path().join("dst")).unwrap(), b"0123456789");
    }

    #[test]
    fn copy_file_range_refusals() {
        let (dir, ops) = fixture();
        fs::write(dir.path().join("src"), b"0123456789").unwrap();
        fs::write(dir.path().join("dst"), b"").unwrap();
        open(&ops, 1, "src", libc::O_RDONLY);
        open(&ops, 2, "dst", libc::O_RDWR);
        open(&ops, 3, "dst", libc::O_RDONLY);
        dispatch(
            &ops,
            Request::Opendir {
                fh: 4,
                path: Path::root(),
            },
        );
        let refused = |errno: Errno| Response::Err(errno as i32);
        assert_eq!(
            copy(&ops, 1, 0, 3, 0, 5),
            refused(Errno::EBADF),
            "read-only destination"
        );
        assert_eq!(
            copy(&ops, 9, 0, 2, 0, 5),
            refused(Errno::EBADF),
            "unknown source"
        );
        assert_eq!(
            copy(&ops, 1, 0, 9, 0, 5),
            refused(Errno::EBADF),
            "unknown destination"
        );
        assert_eq!(
            copy(&ops, 4, 0, 2, 0, 5),
            refused(Errno::EBADF),
            "directory source"
        );
        assert_eq!(
            copy(&ops, 1, u64::MAX, 2, 0, 5),
            refused(Errno::EINVAL),
            "source offset past off_t"
        );
        assert_eq!(
            copy(&ops, 1, 0, 2, u64::MAX, 5),
            refused(Errno::EINVAL),
            "destination offset past off_t"
        );
        fs::write(dir.path().join("same"), b"0123456789").unwrap();
        open(&ops, 5, "same", libc::O_RDWR);
        assert_eq!(
            copy(&ops, 5, 0, 5, 2, 5),
            refused(Errno::EINVAL),
            "overlapping ranges of one file"
        );
        assert_eq!(fs::read(dir.path().join("dst")).unwrap(), b"");
    }

    fn fallocate(ops: &Ops, fh: u64, offset: u64, len: u64, mode: i32) -> Response {
        dispatch(
            ops,
            Request::Fallocate {
                fh,
                offset,
                len,
                mode,
            },
        )
    }

    /// What a filesystem does with each mode is its own business (tmpfs has no zero-range, and they all count blocks differently), so the server's answer is held against the same call made directly on a twin file beside it.
    #[test]
    fn fallocate_does_what_the_syscall_does() {
        use nix::fcntl::FallocateFlags;
        let (dir, ops) = fixture();
        let content: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8 + 1).collect();
        let modes = [
            (FallocateFlags::empty(), 100_000, 400_000),
            (FallocateFlags::FALLOC_FL_KEEP_SIZE, 100_000, 400_000),
            (
                FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_KEEP_SIZE,
                65_536,
                65_536,
            ),
            (FallocateFlags::FALLOC_FL_ZERO_RANGE, 65_536, 300_000),
            (
                FallocateFlags::FALLOC_FL_ZERO_RANGE | FallocateFlags::FALLOC_FL_KEEP_SIZE,
                65_536,
                300_000,
            ),
        ];
        for (i, (mode, offset, len)) in modes.into_iter().enumerate() {
            let (served, control) = (format!("served{i}"), format!("control{i}"));
            fs::write(dir.path().join(&served), &content).unwrap();
            fs::write(dir.path().join(&control), &content).unwrap();
            let fh = 10 + i as u64;
            open(&ops, fh, &served, libc::O_RDWR);
            let twin = fs::OpenOptions::new()
                .write(true)
                .open(dir.path().join(&control))
                .unwrap();
            let expected = match nix::fcntl::fallocate(&twin, mode, offset, len) {
                Ok(()) => Response::Ok,
                // Zero-range is the one a filesystem tests run on may lack (tmpfs does); without the others this test would compare refusals.
                Err(errno) => {
                    assert!(
                        mode.contains(FallocateFlags::FALLOC_FL_ZERO_RANGE),
                        "{mode:?} is {errno} here"
                    );
                    Response::Err(errno as i32)
                }
            };
            assert_eq!(
                fallocate(&ops, fh, offset as u64, len as u64, mode.bits()),
                expected,
                "{mode:?}"
            );
            assert_eq!(
                fs::read(dir.path().join(&served)).unwrap(),
                fs::read(dir.path().join(&control)).unwrap(),
                "{mode:?}"
            );
            assert_eq!(
                fs::metadata(dir.path().join(&served)).unwrap().blocks(),
                fs::metadata(dir.path().join(&control)).unwrap().blocks(),
                "{mode:?}"
            );
        }
    }

    fn seek(ops: &Ops, fh: u64, offset: u64, whence: Whence) -> Response {
        dispatch(ops, Request::Lseek { fh, offset, whence })
    }

    /// Where a filesystem draws the line between data and hole is its own business, so the server's answer is held against the same `lseek` on the export's file.
    #[test]
    fn lseek_finds_what_the_syscall_finds() {
        let (dir, ops) = fixture();
        let file = fs::File::create(dir.path().join("sparse")).unwrap();
        file.write_all_at(b"data", 1 << 20).unwrap();
        file.write_all_at(b"more", 3 << 20).unwrap();
        file.set_len(4 << 20).unwrap();
        open(&ops, 1, "sparse", libc::O_RDONLY);
        let control = fs::File::open(dir.path().join("sparse")).unwrap();
        for offset in [0, 1 << 20, (1 << 20) + 2, 2 << 20, 3 << 20, (4 << 20) - 1] {
            for (whence, local) in [
                (Whence::Data, nix::unistd::Whence::SeekData),
                (Whence::Hole, nix::unistd::Whence::SeekHole),
            ] {
                let expected = match nix::unistd::lseek(&control, offset, local) {
                    Ok(found) => Response::Seeked(found as u64),
                    Err(errno) => Response::Err(errno as i32),
                };
                assert_eq!(
                    seek(&ops, 1, offset as u64, whence),
                    expected,
                    "{whence:?} from {offset}"
                );
            }
        }
        let refused = |errno: Errno| Response::Err(errno as i32);
        assert_eq!(
            seek(&ops, 1, 4 << 20, Whence::Data),
            refused(Errno::ENXIO),
            "at the end"
        );
        assert_eq!(
            seek(&ops, 1, 4 << 20, Whence::Hole),
            refused(Errno::ENXIO),
            "at the end"
        );
        assert_eq!(
            seek(&ops, 1, u64::MAX, Whence::Data),
            refused(Errno::EINVAL),
            "past off_t"
        );
        assert_eq!(
            seek(&ops, 9, 0, Whence::Data),
            refused(Errno::EBADF),
            "unknown handle"
        );
        dispatch(
            &ops,
            Request::Opendir {
                fh: 2,
                path: Path::root(),
            },
        );
        assert_eq!(
            seek(&ops, 2, 0, Whence::Data),
            refused(Errno::EBADF),
            "directory handle"
        );
        // A seek moves the descriptor's position, which nothing reads: a read still starts where it says.
        assert_eq!(
            dispatch(
                &ops,
                Request::Read {
                    fh: 1,
                    offset: 1 << 20,
                    size: 4
                }
            ),
            Response::Read(b"data".to_vec())
        );
    }

    #[test]
    fn fallocate_refusals() {
        let (dir, ops) = fixture();
        fs::write(dir.path().join("f"), b"0123456789").unwrap();
        open(&ops, 1, "f", libc::O_RDWR);
        open(&ops, 2, "f", libc::O_RDONLY);
        dispatch(
            &ops,
            Request::Opendir {
                fh: 3,
                path: Path::root(),
            },
        );
        let refused = |errno: Errno| Response::Err(errno as i32);
        assert_eq!(
            fallocate(&ops, 1, 0, 5, libc::FALLOC_FL_COLLAPSE_RANGE),
            refused(Errno::EOPNOTSUPP),
            "a mode the protocol does not carry"
        );
        assert_eq!(
            fallocate(&ops, 1, 0, 5, 1 << 20),
            refused(Errno::EOPNOTSUPP),
            "a mode nobody knows"
        );
        assert_eq!(
            fallocate(&ops, 1, 0, MAX_FALLOCATE + 1, 0),
            refused(Errno::EINVAL),
            "longer than one request may be"
        );
        assert_eq!(
            fallocate(&ops, 1, u64::MAX, 5, 0),
            refused(Errno::EINVAL),
            "offset past off_t"
        );
        assert_eq!(
            fallocate(&ops, 2, 0, 5, 0),
            refused(Errno::EBADF),
            "read-only handle"
        );
        assert_eq!(
            fallocate(&ops, 3, 0, 5, 0),
            refused(Errno::EBADF),
            "directory handle"
        );
        assert_eq!(
            fallocate(&ops, 9, 0, 5, 0),
            refused(Errno::EBADF),
            "unknown handle"
        );
        assert_eq!(fs::read(dir.path().join("f")).unwrap(), b"0123456789");
    }

    #[test]
    fn append_handle_ignores_offset() {
        let (dir, ops) = fixture();
        fs::write(dir.path().join("log"), b"start-").unwrap();
        dispatch(
            &ops,
            Request::Open {
                fh: 5,
                path: path("log"),
                flags: libc::O_WRONLY | libc::O_APPEND,
            },
        );
        dispatch(
            &ops,
            Request::Write {
                fh: 5,
                offset: 0,
                data: b"end".to_vec(),
            },
        );
        assert_eq!(fs::read(dir.path().join("log")).unwrap(), b"start-end");
    }

    #[test]
    fn directory_ops_and_lookup() {
        let (dir, ops) = fixture();
        let made = expect_attr(dispatch(
            &ops,
            Request::Mkdir {
                parent: Path::root(),
                name: name("d"),
                mode: 0o777,
            },
        ));
        assert_eq!(made.perm, 0o777);
        assert_eq!(
            fs::metadata(dir.path().join("d"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o777
        );
        let looked = expect_attr(dispatch(
            &ops,
            Request::Lookup {
                parent: Path::root(),
                name: name("d"),
            },
        ));
        assert_eq!(looked.ino, made.ino);
        assert_eq!(
            dispatch(
                &ops,
                Request::Lookup {
                    parent: Path::root(),
                    name: name("nope")
                }
            ),
            Response::Err(Errno::ENOENT as i32)
        );
        assert_eq!(
            dispatch(
                &ops,
                Request::Rmdir {
                    parent: Path::root(),
                    name: name("d")
                }
            ),
            Response::Ok
        );
        assert!(!dir.path().join("d").exists());
    }

    #[test]
    fn symlink_link_rename_unlink() {
        let (dir, ops) = fixture();
        fs::write(dir.path().join("a"), b"A").unwrap();
        let linked = expect_attr(dispatch(
            &ops,
            Request::Symlink {
                parent: Path::root(),
                name: name("s"),
                target: b"a".to_vec(),
            },
        ));
        assert_eq!(linked.kind, FileKind::Symlink);
        assert_eq!(
            dispatch(&ops, Request::Readlink { path: path("s") }),
            Response::Readlink(b"a".to_vec())
        );

        let hard = expect_attr(dispatch(
            &ops,
            Request::Link {
                path: path("a"),
                newparent: Path::root(),
                newname: name("b"),
            },
        ));
        assert_eq!(hard.nlink, 2);
        assert_eq!(hard.ino, fs::metadata(dir.path().join("a")).unwrap().ino());

        assert_eq!(
            dispatch(
                &ops,
                Request::Rename {
                    parent: Path::root(),
                    name: name("b"),
                    newparent: Path::root(),
                    newname: name("a"),
                    flags: libc::RENAME_NOREPLACE
                }
            ),
            Response::Err(Errno::EEXIST as i32)
        );
        assert_eq!(
            dispatch(
                &ops,
                Request::Rename {
                    parent: Path::root(),
                    name: name("b"),
                    newparent: Path::root(),
                    newname: name("c"),
                    flags: 0
                }
            ),
            Response::Ok
        );
        assert!(dir.path().join("c").exists() && !dir.path().join("b").exists());
        assert_eq!(
            dispatch(
                &ops,
                Request::Rename {
                    parent: Path::root(),
                    name: name("c"),
                    newparent: Path::root(),
                    newname: name("a"),
                    flags: libc::RENAME_WHITEOUT
                }
            ),
            Response::Err(Errno::EINVAL as i32)
        );
        assert_eq!(
            dispatch(
                &ops,
                Request::Unlink {
                    parent: Path::root(),
                    name: name("c")
                }
            ),
            Response::Ok
        );
        assert_eq!(
            dispatch(
                &ops,
                Request::Unlink {
                    parent: Path::root(),
                    name: name("s")
                }
            ),
            Response::Ok
        );
        assert_eq!(
            dispatch(
                &ops,
                Request::Link {
                    path: Path::root(),
                    newparent: Path::root(),
                    newname: name("x")
                }
            ),
            Response::Err(Errno::EPERM as i32)
        );
    }

    #[test]
    fn setattr_by_path_and_by_handle() {
        let (dir, ops) = fixture();
        fs::write(dir.path().join("f"), b"0123456789").unwrap();
        let attr = expect_attr(dispatch(
            &ops,
            Request::Setattr {
                path: Some(path("f")),
                fh: None,
                set: SetAttr {
                    mode: Some(0o600),
                    size: Some(4),
                    mtime: Some(TimeOrNow::Time(jackalopefs_proto::TimeSpec {
                        sec: 1_000_000,
                        nsec: 5,
                    })),
                    ..SetAttr::default()
                },
            },
        ));
        assert_eq!(attr.perm, 0o600);
        assert_eq!(attr.size, 4);
        assert_eq!(
            attr.mtime,
            jackalopefs_proto::TimeSpec {
                sec: 1_000_000,
                nsec: 5
            }
        );

        dispatch(
            &ops,
            Request::Open {
                fh: 9,
                path: path("f"),
                flags: libc::O_RDWR,
            },
        );
        fs::remove_file(dir.path().join("f")).unwrap();
        let after = expect_attr(dispatch(
            &ops,
            Request::Setattr {
                path: None,
                fh: Some(9),
                set: SetAttr {
                    size: Some(0),
                    ..SetAttr::default()
                },
            },
        ));
        assert_eq!(
            after.size, 0,
            "an unlinked open file is still reachable through its handle"
        );
        assert_eq!(
            dispatch(
                &ops,
                Request::Getattr {
                    path: None,
                    fh: Some(9)
                }
            ),
            Response::Attr(after)
        );
        assert_eq!(
            dispatch(
                &ops,
                Request::Setattr {
                    path: None,
                    fh: Some(77),
                    set: SetAttr {
                        mode: Some(0o600),
                        ..SetAttr::default()
                    }
                }
            ),
            Response::Err(Errno::EBADF as i32),
            "an unknown handle never falls back to a path"
        );
        assert_eq!(
            dispatch(
                &ops,
                Request::Getattr {
                    path: None,
                    fh: None
                }
            ),
            Response::Err(Errno::EINVAL as i32)
        );
        dispatch(
            &ops,
            Request::Opendir {
                fh: 10,
                path: Path::root(),
            },
        );
        let dir_touched = expect_attr(dispatch(
            &ops,
            Request::Setattr {
                path: None,
                fh: Some(10),
                set: SetAttr {
                    mtime: Some(TimeOrNow::Time(jackalopefs_proto::TimeSpec {
                        sec: 9,
                        nsec: 0,
                    })),
                    ..SetAttr::default()
                },
            },
        ));
        assert_eq!(
            dir_touched.mtime.sec, 9,
            "directory handles work for setattr too"
        );
        assert_eq!(
            dispatch(
                &ops,
                Request::Getattr {
                    path: Some(path("f")),
                    fh: None
                }
            ),
            Response::Err(Errno::ENOENT as i32)
        );

        std::os::unix::fs::symlink("f", dir.path().join("l")).unwrap();
        assert_eq!(
            dispatch(
                &ops,
                Request::Setattr {
                    path: Some(path("l")),
                    fh: None,
                    set: SetAttr {
                        mode: Some(0o600),
                        ..SetAttr::default()
                    }
                }
            ),
            Response::Err(Errno::EOPNOTSUPP as i32)
        );
        let touched = expect_attr(dispatch(
            &ops,
            Request::Setattr {
                path: Some(path("l")),
                fh: None,
                set: SetAttr {
                    atime: Some(TimeOrNow::Now),
                    mtime: Some(TimeOrNow::Time(jackalopefs_proto::TimeSpec {
                        sec: 7,
                        nsec: 0,
                    })),
                    ..SetAttr::default()
                },
            },
        ));
        assert_eq!(touched.kind, FileKind::Symlink);
        assert_eq!(
            touched.mtime.sec, 7,
            "times are set on the symlink itself, not its target"
        );
    }

    #[test]
    fn readdir_and_opendir() {
        let (dir, ops) = fixture();
        fs::write(dir.path().join("x"), b"").unwrap();
        let attr = expect_attr(dispatch(
            &ops,
            Request::Opendir {
                fh: 2,
                path: Path::root(),
            },
        ));
        let root_ino = fs::metadata(dir.path()).unwrap().ino();
        assert_eq!(attr.ino, root_ino);
        match dispatch(
            &ops,
            Request::Readdir {
                fh: 2,
                offset: 0,
                max_bytes: 1 << 20,
            },
        ) {
            Response::Readdir { entries, end } => {
                assert!(end, "a one-page listing ends");
                let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
                assert!(
                    names.contains(&b".".as_slice())
                        && names.contains(&b"..".as_slice())
                        && names.contains(&b"x".as_slice())
                );
                // The dots go without attributes; the client numbers them itself.
                assert!(entries
                    .iter()
                    .all(|e| e.attr.is_none() == e.is_dot_or_dotdot()));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(dispatch(&ops, Request::Releasedir { fh: 2 }), Response::Ok);
        assert_eq!(
            dispatch(
                &ops,
                Request::Opendir {
                    fh: 3,
                    path: path("x")
                }
            ),
            Response::Err(Errno::ENOTDIR as i32)
        );
    }

    #[test]
    fn xattr_statfs_access() {
        let (dir, ops) = fixture();
        fs::write(dir.path().join("f"), b"").unwrap();
        let set = dispatch(
            &ops,
            Request::Setxattr {
                path: path("f"),
                name: b"user.k".to_vec(),
                value: b"v".to_vec(),
                flags: 0,
            },
        );
        if set == Response::Err(Errno::EOPNOTSUPP as i32) {
            eprintln!("skipping xattr assertions: filesystem does not support user xattrs");
        } else {
            assert_eq!(set, Response::Ok);
            // The attributes carry the names, from every reply shape that has them.
            let by_path = expect_attr(dispatch(
                &ops,
                Request::Getattr {
                    path: Some(path("f")),
                    fh: None,
                },
            ));
            assert_eq!(by_path.xattr_names, Some(vec![b"user.k".to_vec()]));
            let by_lookup = expect_attr(dispatch(
                &ops,
                Request::Lookup {
                    parent: Path::root(),
                    name: name("f"),
                },
            ));
            assert_eq!(by_lookup.xattr_names, Some(vec![b"user.k".to_vec()]));
            fs::write(dir.path().join("plain"), b"").unwrap();
            let plain = expect_attr(dispatch(
                &ops,
                Request::Lookup {
                    parent: Path::root(),
                    name: name("plain"),
                },
            ));
            assert_eq!(
                plain.xattr_names,
                Some(Vec::new()),
                "no names is a statement, not an unknown"
            );
            assert_eq!(
                dispatch(
                    &ops,
                    Request::Getxattr {
                        path: path("f"),
                        name: b"user.k".to_vec()
                    }
                ),
                Response::Xattr(b"v".to_vec())
            );
            assert_eq!(
                dispatch(&ops, Request::Listxattr { path: path("f") }),
                Response::Xattr(b"user.k\0".to_vec())
            );
            assert_eq!(
                dispatch(
                    &ops,
                    Request::Removexattr {
                        path: path("f"),
                        name: b"user.k".to_vec()
                    }
                ),
                Response::Ok
            );
            assert_eq!(
                dispatch(
                    &ops,
                    Request::Getxattr {
                        path: path("f"),
                        name: b"user.k".to_vec()
                    }
                ),
                Response::Err(Errno::ENODATA as i32)
            );
        }
        match dispatch(&ops, Request::Statfs { path: Path::root() }) {
            Response::Statfs(s) => assert!(
                s.blocks > 0 && s.bsize > 0 && s.namelen > 0 && s.namelen <= NAME_MAX as u32
            ),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            dispatch(
                &ops,
                Request::Access {
                    path: path("f"),
                    mask: libc::R_OK
                }
            ),
            Response::Ok
        );
        assert_eq!(
            dispatch(
                &ops,
                Request::Access {
                    path: path("f"),
                    mask: libc::X_OK
                }
            ),
            Response::Err(Errno::EACCES as i32)
        );
    }

    #[test]
    fn open_flag_allow_list() {
        assert_eq!(
            open_flags(libc::O_RDWR | libc::O_DIRECT | libc::O_APPEND, false),
            OFlag::O_RDWR | OFlag::O_APPEND
        );
        assert_eq!(
            open_flags(libc::O_WRONLY | libc::O_TRUNC, false),
            OFlag::O_WRONLY | OFlag::O_TRUNC
        );
        assert_eq!(
            open_flags(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, false),
            OFlag::O_WRONLY,
            "plain opens cannot create"
        );
        assert_eq!(
            open_flags(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, true),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL
        );
    }

    #[test]
    fn special_files_cannot_park_a_thread_or_be_served() {
        let (dir, ops) = fixture();
        let made = expect_attr(dispatch(
            &ops,
            Request::Mknod {
                parent: Path::root(),
                name: name("fifo"),
                mode: libc::S_IFIFO | 0o644,
                rdev: 0,
            },
        ));
        assert_eq!(made.kind, FileKind::Fifo);
        let started = std::time::Instant::now();
        assert_eq!(
            dispatch(
                &ops,
                Request::Open {
                    fh: 1,
                    path: path("fifo"),
                    flags: libc::O_RDONLY
                }
            ),
            Response::Err(Errno::EOPNOTSUPP as i32)
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "opening a FIFO must not block"
        );
        assert!(ops.handles.is_empty());
        assert_eq!(
            dispatch(
                &ops,
                Request::Setattr {
                    path: Some(path("fifo")),
                    fh: None,
                    set: SetAttr {
                        size: Some(0),
                        ..SetAttr::default()
                    }
                }
            ),
            Response::Err(Errno::EOPNOTSUPP as i32)
        );
        assert_eq!(
            dispatch(
                &ops,
                Request::Mknod {
                    parent: Path::root(),
                    name: name("dev"),
                    mode: libc::S_IFCHR | 0o644,
                    rdev: 0
                }
            ),
            Response::Err(Errno::EPERM as i32)
        );
        assert!(!dir.path().join("dev").exists());
    }

    #[test]
    fn a_session_past_its_handle_cap_cannot_open() {
        let (dir, mut ops) = fixture();
        ops.handles = Arc::new(Handles::new(1));
        fs::write(dir.path().join("f"), b"").unwrap();
        let open = |fh| Request::Open {
            fh,
            path: path("f"),
            flags: libc::O_RDONLY,
        };
        assert!(matches!(dispatch(&ops, open(1)), Response::Opened { .. }));
        assert_eq!(dispatch(&ops, open(2)), Response::Err(Errno::EMFILE as i32));
        assert!(
            matches!(dispatch(&ops, open(1)), Response::Opened { .. }),
            "replacing an existing id is still allowed"
        );
        assert_eq!(dispatch(&ops, Request::Release { fh: 1 }), Response::Ok);
        assert!(matches!(dispatch(&ops, open(2)), Response::Opened { .. }));
    }

    fn flattening(ops: Ops) -> Ops {
        Ops {
            ids: IdMap::of_process(ModeIds::Flatten).unwrap(),
            ..ops
        }
    }

    /// A valid access ACL granting `rw-` to the owner, the owning group, others, and the named user `uid`.
    fn acl_naming(uid: u32) -> Vec<u8> {
        let mut blob = 2u32.to_le_bytes().to_vec();
        for (tag, id) in [
            (0x01u16, u32::MAX),
            (0x02, uid),
            (0x04, u32::MAX),
            (0x10, u32::MAX),
            (0x20, u32::MAX),
        ] {
            blob.extend(tag.to_le_bytes());
            blob.extend(6u16.to_le_bytes());
            blob.extend(id.to_le_bytes());
        }
        blob
    }

    fn set_acl(name: &str, value: Vec<u8>) -> Request {
        Request::Setxattr {
            path: path(name),
            name: b"system.posix_acl_access".to_vec(),
            value,
            flags: 0,
        }
    }

    fn get_acl(name: &str) -> Request {
        Request::Getxattr {
            path: path(name),
            name: b"system.posix_acl_access".to_vec(),
        }
    }

    /// An owner may name any uid in an ACL, so the kernel alone would allow this; refusing it is the server's own policy.
    #[test]
    fn flatten_refuses_an_acl_naming_another_user_that_the_kernel_would_allow() {
        let (dir, ops) = fixture();
        fs::write(dir.path().join("f"), b"").unwrap();
        let direct = dispatch(&ops, set_acl("f", acl_naming(4242)));
        if direct == Response::Err(Errno::EOPNOTSUPP as i32) {
            eprintln!("skipping: filesystem does not support POSIX ACLs");
            return;
        }
        assert_eq!(direct, Response::Ok);
        assert_eq!(
            dispatch(&ops, get_acl("f")),
            Response::Xattr(acl_naming(4242))
        );

        let ops = flattening(ops);
        assert_eq!(
            dispatch(&ops, get_acl("f")),
            Response::Xattr(acl_naming(NOBODY))
        );
        fs::write(dir.path().join("g"), b"").unwrap();
        assert_eq!(
            dispatch(&ops, set_acl("g", acl_naming(4243))),
            Response::Err(Errno::EPERM as i32)
        );
        assert_eq!(
            dispatch(&ops, set_acl("g", acl_naming(NOBODY))),
            Response::Err(Errno::EPERM as i32)
        );
        let own = nix::unistd::geteuid().as_raw();
        assert_eq!(dispatch(&ops, set_acl("g", acl_naming(own))), Response::Ok);
        assert_eq!(
            dispatch(&ops, get_acl("g")),
            Response::Xattr(acl_naming(own))
        );
    }

    /// A refused chown is refused whole: the chmod that came with it is not applied either. The group is one the user is in besides their own, which the kernel would let them give the file, so the refusal is the server's.
    #[test]
    fn flatten_refuses_a_chown_before_changing_anything() {
        let egid = nix::unistd::getegid();
        let Some(other) = nix::unistd::getgroups()
            .unwrap()
            .into_iter()
            .find(|g| *g != egid)
        else {
            eprintln!("skipping: the user is in no group besides their own");
            return;
        };
        let (dir, ops) = fixture();
        let file = dir.path().join("f");
        fs::write(&file, b"").unwrap();
        let chgrp = |gid: u32| Request::Setattr {
            path: Some(path("f")),
            fh: None,
            set: SetAttr {
                mode: Some(0o600),
                gid: Some(gid),
                ..SetAttr::default()
            },
        };
        let refresh = |mode| fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();

        refresh(0o644);
        let attr = expect_attr(dispatch(&ops, chgrp(other.as_raw())));
        assert_eq!(
            (attr.gid, attr.perm & 0o7777),
            (other.as_raw(), 0o600),
            "direct applies what the kernel allows"
        );

        let ops = flattening(ops);
        refresh(0o644);
        assert_eq!(
            dispatch(&ops, chgrp(other.as_raw())),
            Response::Err(Errno::EPERM as i32)
        );
        assert_eq!(
            fs::metadata(&file).unwrap().mode() & 0o7777,
            0o644,
            "nothing of a refused setattr is applied"
        );
        let attr = expect_attr(dispatch(&ops, chgrp(egid.as_raw())));
        assert_eq!((attr.gid, attr.perm & 0o7777), (egid.as_raw(), 0o600));
    }
}

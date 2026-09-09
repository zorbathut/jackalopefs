//! One synchronous function per request, run on the blocking pool. Every path goes through [`Export`]; every open file goes through [`Handles`].

use crate::dirents::{read_dir_fd, Entries};
use crate::export::{kind_from_mode, proc_path, Export};
use crate::handles::{Handle, Handles};
use crate::watch::ChangeLog;
use jackalopefs_proto::{
    Attr, Name, Path, Request, Response, SetAttr, Statfs, TimeOrNow, MAX_IO, NAME_MAX,
};
use nix::errno::Errno;
use nix::fcntl::{renameat2, AtFlags, OFlag, RenameFlags, AT_FDCWD};
use nix::sys::stat::{
    fchmod, fstatat, futimens, mkdirat, mknodat, utimensat, Mode, SFlag, UtimensatFlags,
};
use nix::sys::time::TimeSpec;
use nix::unistd::{
    faccessat, fchown, fchownat, fdatasync, fsync, ftruncate, linkat, symlinkat, unlinkat,
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

pub struct Ops {
    pub export: Arc<Export>,
    pub handles: Arc<Handles>,
    pub session_id: u64,
    pub changes: Arc<ChangeLog>,
}

/// Run one request; every failure becomes an errno for the client. Running out of file descriptors, whether the session's cap or the process's limit, is logged with what this session holds, since the handles of every session share that limit.
pub fn dispatch(ops: &Ops, req: Request) -> Response {
    let op = req.op_name();
    match ops.run(req) {
        Ok(resp) => resp,
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
                    Some(Handle::Dir(dir)) => self.attr_of(&*dir.lock())?,
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
                self.handles.insert(
                    fh,
                    Handle::File {
                        file: Arc::new(File::from(fd)),
                        path,
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
                let path = parent.join(name).map_err(|_| Errno::ENAMETOOLONG)?;
                self.handles.insert(
                    fh,
                    Handle::File {
                        file: Arc::new(File::from(fd)),
                        path,
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
            Request::Release { fh } | Request::Releasedir { fh } => {
                if self.handles.remove(fh).is_none() {
                    tracing::debug!(fh, "release of an unknown handle");
                }
                Ok(Response::Ok)
            }
            Request::Fsync { fh, datasync } => {
                match self.handles.get(fh)? {
                    Handle::File { file, .. } => sync(&*file, datasync)?,
                    Handle::Dir(dir) => sync(&*dir.lock(), datasync)?,
                }
                Ok(Response::Ok)
            }
            Request::Opendir { fh, path } => {
                let fd = self
                    .export
                    .open_node(&path, OFlag::O_RDONLY | OFlag::O_DIRECTORY)?;
                let attr = self.attr_of(&fd)?;
                servable(attr.kind)?;
                self.handles
                    .insert(fh, Handle::Dir(Arc::new(Mutex::new(fd))))?;
                Ok(Response::Opened { attr })
            }
            Request::Readdir {
                fh,
                offset,
                max_bytes,
                plus,
            } => {
                let dir = self.handles.dir(fh)?;
                let guard = dir.lock();
                let listing = read_dir_fd(
                    &self.export,
                    &*guard,
                    offset,
                    (max_bytes as usize).min(MAX_IO),
                    plus,
                )?;
                let end = listing.end;
                Ok(match listing.entries {
                    Entries::Plain(entries) => Response::Readdir { entries, end },
                    Entries::Plus(entries) => Response::ReaddirPlus { entries, end },
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
            Some(Handle::Dir(dir)) => {
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
        assert_eq!(attr.ino, crate::export::ROOT_NODEID);
        match dispatch(
            &ops,
            Request::Readdir {
                fh: 2,
                offset: 0,
                max_bytes: 1 << 20,
                plus: false,
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
                assert_eq!(
                    entries
                        .iter()
                        .find(|e| e.name.as_slice() == b".")
                        .unwrap()
                        .ino,
                    crate::export::ROOT_NODEID
                );
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
}

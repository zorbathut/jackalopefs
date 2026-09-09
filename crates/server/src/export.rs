//! The exported directory and the only way client paths are turned into file descriptors.
//!
//! Every resolution goes through `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`, so a symlink, a `..`, or a mount point inside the export can never lead outside it, and no multi-component client path ever reaches any other syscall: the `*at` family and `llistxattr` through `/proc/self/fd/N/name` only ever see a single validated [`Name`] under an fd resolved that way. The resulting fd pins the inode, so later operations on it are free of lookup races.

use anyhow::Context;
use jackalopefs_proto::{Attr, FileKind, Name, Path, TimeSpec};
use nix::errno::Errno;
use nix::fcntl::{openat2, AtFlags, OFlag, OpenHow, ResolveFlag};
use nix::sys::stat::{fstat, fstatat, FileStat, Mode};
use std::ffi::OsStr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// The nodeid the client uses for the export root, by FUSE convention.
pub const ROOT_NODEID: u64 = 1;

const RESOLVE: ResolveFlag = ResolveFlag::RESOLVE_BENEATH
    .union(ResolveFlag::RESOLVE_NO_SYMLINKS)
    .union(ResolveFlag::RESOLVE_NO_MAGICLINKS)
    .union(ResolveFlag::RESOLVE_NO_XDEV);

pub struct Export {
    root: OwnedFd,
    root_ino: u64,
}

impl Export {
    /// Open `dir` as the export root and verify `openat2` works here (Linux 5.6+, not blocked by seccomp) and that `statx` reports mount roots (Linux 5.8+), which directory listings rely on.
    pub fn open(dir: &std::path::Path) -> anyhow::Result<Export> {
        let root = nix::fcntl::open(
            dir,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening export root {}", dir.display()))?;
        let root_ino = fstat(&root).context("stat of export root")?.st_ino;
        let export = Export { root, root_ino };
        export.resolve(&Path::root()).map_err(|e| anyhow::anyhow!("openat2 probe failed ({e}); jackalopefs needs Linux 5.6+ and an environment that permits openat2"))?;
        let st =
            statx(export.root.as_fd(), c"", libc::AT_EMPTY_PATH).context("statx of export root")?;
        if st.stx_attributes_mask & libc::STATX_ATTR_MOUNT_ROOT as u64 == 0 {
            anyhow::bail!("statx does not report mount roots; jackalopefs needs Linux 5.8+");
        }
        Ok(export)
    }

    pub fn root(&self) -> BorrowedFd<'_> {
        self.root.as_fd()
    }

    /// The nodeid a client uses for a server inode number: the export root is [`ROOT_NODEID`]; any other inode numbered 1 would collide with it and is refused.
    pub fn map_ino(&self, ino: u64) -> Result<u64, Errno> {
        if ino == self.root_ino {
            Ok(ROOT_NODEID)
        } else if ino == ROOT_NODEID {
            tracing::warn!(
                "inode number 1 inside the export collides with the root nodeid; refusing it"
            );
            Err(Errno::EIO)
        } else {
            Ok(ino)
        }
    }

    fn openat2_root(&self, path: &Path, flags: OFlag, mode: Mode) -> Result<OwnedFd, Errno> {
        let joined = path.to_os_string();
        let rel: &OsStr = if joined.is_empty() {
            OsStr::new(".")
        } else {
            &joined
        };
        openat2(
            &self.root,
            rel,
            OpenHow::new()
                .flags(flags | OFlag::O_CLOEXEC)
                .mode(mode)
                .resolve(RESOLVE),
        )
    }

    /// `O_PATH` fd for the node itself (a symlink is returned as itself, never followed).
    pub fn resolve(&self, path: &Path) -> Result<OwnedFd, Errno> {
        self.openat2_root(path, OFlag::O_PATH | OFlag::O_NOFOLLOW, Mode::empty())
    }

    /// `O_PATH` fd for a directory node.
    pub fn resolve_dir(&self, path: &Path) -> Result<OwnedFd, Errno> {
        self.openat2_root(
            path,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
    }

    /// The parent directory's fd and the final component, for `*at` calls; the root has no parent (`EPERM`, as for unlinking `/`).
    pub fn resolve_parent<'p>(&self, path: &'p Path) -> Result<(OwnedFd, &'p Name), Errno> {
        let (parent, name) = path.split_last().ok_or(Errno::EPERM)?;
        Ok((self.resolve_dir(&parent)?, name))
    }

    /// A real (non-`O_PATH`) open of an existing node with the client's flags. Always non-blocking: a FIFO in the export must never park a server thread, and every read and write here is positional anyway.
    pub fn open_node(&self, path: &Path, flags: OFlag) -> Result<OwnedFd, Errno> {
        self.openat2_root(
            path,
            flags | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
    }

    /// A real open of `name` inside `parent`, possibly creating it; used for `create`.
    pub fn open_in(
        &self,
        parent: &Path,
        name: &Name,
        flags: OFlag,
        mode: Mode,
    ) -> Result<OwnedFd, Errno> {
        let dir = self.resolve_dir(parent)?;
        openat2(
            &dir,
            name.as_os_str(),
            OpenHow::new()
                .flags(flags | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC)
                .mode(mode)
                .resolve(RESOLVE),
        )
    }

    /// Convert a `stat` result, mapping the inode number for the client.
    /// The attributes of a pinned node, xattr names included.
    pub fn attr_of(&self, fd: BorrowedFd<'_>) -> Result<Attr, Errno> {
        let st = fstatat(
            fd,
            "",
            AtFlags::AT_EMPTY_PATH | AtFlags::AT_SYMLINK_NOFOLLOW,
        )?;
        let mut attr = self.attr_from_stat(&st)?;
        attr.xattr_names = xattr_names(fd);
        Ok(attr)
    }

    /// The attributes of `dir/name`, the single component resolved under the same rules as every path (no symlink is followed, so a symlink describes itself and never a target; a mount point is refused with `EXDEV`).
    pub fn attr_in(&self, dir: BorrowedFd<'_>, name: &Name) -> Result<Attr, Errno> {
        let node = openat2(
            dir,
            name.as_os_str(),
            OpenHow::new()
                .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(RESOLVE),
        )?;
        self.attr_of(node.as_fd())
    }

    /// The attributes of `dir/name` for a directory listing, `name` being one entry `getdents64` just returned for `dir`: a `statx` on the directory's fd, so describing a page opens nothing. A symlink describes itself. An entry that is the root of a mount is refused with `EXDEV`, as `RESOLVE_NO_XDEV` refuses it in [`Export::attr_in`]. The stat and the xattr name listing resolve `name` separately, so an entry replaced between them is described from both; each sees only this one component under `dir`, so nothing escapes the export.
    pub fn attr_entry(&self, dir: BorrowedFd<'_>, name: &Name) -> Result<Attr, Errno> {
        let cname = std::ffi::CString::new(name.as_bytes()).expect("a name has no NUL");
        let st = statx(dir, &cname, libc::AT_SYMLINK_NOFOLLOW)?;
        if st.stx_attributes & libc::STATX_ATTR_MOUNT_ROOT as u64 != 0 {
            return Err(Errno::EXDEV);
        }
        let stamp = |t: libc::statx_timestamp| TimeSpec {
            sec: t.tv_sec,
            nsec: t.tv_nsec,
        };
        Ok(Attr {
            ino: self.map_ino(st.stx_ino)?,
            size: st.stx_size,
            blocks: st.stx_blocks,
            atime: stamp(st.stx_atime),
            mtime: stamp(st.stx_mtime),
            ctime: stamp(st.stx_ctime),
            kind: kind_from_mode(st.stx_mode as libc::mode_t).ok_or(Errno::EIO)?,
            perm: st.stx_mode & 0o7777,
            nlink: st.stx_nlink,
            uid: st.stx_uid,
            gid: st.stx_gid,
            rdev: libc::makedev(st.stx_rdev_major, st.stx_rdev_minor),
            blksize: st.stx_blksize,
            xattr_names: xattr_names_at(dir, name),
        })
    }

    pub fn attr_from_stat(&self, st: &FileStat) -> Result<Attr, Errno> {
        Ok(Attr {
            ino: self.map_ino(st.st_ino)?,
            size: st.st_size as u64,
            blocks: st.st_blocks as u64,
            atime: TimeSpec {
                sec: st.st_atime,
                nsec: st.st_atime_nsec as u32,
            },
            mtime: TimeSpec {
                sec: st.st_mtime,
                nsec: st.st_mtime_nsec as u32,
            },
            ctime: TimeSpec {
                sec: st.st_ctime,
                nsec: st.st_ctime_nsec as u32,
            },
            kind: kind_from_mode(st.st_mode).ok_or(Errno::EIO)?,
            perm: (st.st_mode & 0o7777) as u16,
            nlink: st.st_nlink as u32,
            uid: st.st_uid,
            gid: st.st_gid,
            rdev: st.st_rdev,
            blksize: st.st_blksize as u32,
            xattr_names: None,
        })
    }
}

/// `statx` of `path` under `dir` with the basic stats, the form `fstatat` has no way to ask for the mount-root attribute in.
fn statx(
    dir: BorrowedFd<'_>,
    path: &std::ffi::CStr,
    flags: libc::c_int,
) -> Result<libc::statx, Errno> {
    let mut st = std::mem::MaybeUninit::<libc::statx>::uninit();
    // SAFETY: the path is NUL-terminated and the buffer is a whole `statx`, which the kernel fills on success.
    let rc = unsafe {
        libc::statx(
            dir.as_raw_fd(),
            path.as_ptr(),
            flags | libc::AT_STATX_SYNC_AS_STAT,
            libc::STATX_BASIC_STATS,
            st.as_mut_ptr(),
        )
    };
    if rc < 0 {
        return Err(Errno::last());
    }
    // SAFETY: the kernel filled the buffer.
    Ok(unsafe { st.assume_init() })
}

/// Most names a node may carry in an `Attr`; beyond this the client asks. Bounds the readdirplus page and the memory a name list can take.
const XATTR_NAMES_MAX: usize = 1024;

/// The node's extended attribute names for its `Attr`, through the pinned fd's `/proc` path (which follows the magic link to the node itself; `llistxattr` would describe the link). `None` when the client has to ask instead: more than [`XATTR_NAMES_MAX`] bytes of names, or a filesystem without xattr support, whose errno a `getxattr` must return rather than the ENODATA an empty list would imply.
pub(crate) fn xattr_names(fd: BorrowedFd<'_>) -> Option<Vec<Vec<u8>>> {
    let path = std::ffi::CString::new(proc_path(fd).as_os_str().as_bytes())
        .expect("a /proc/self/fd path has no NUL");
    xattr_names_by_path(&path, libc::listxattr)
}

/// The names of the entry `name` of `dir`, through the directory fd's `/proc` path: the magic link is an intermediate component, so it resolves, and the entry is the last one, which `llistxattr` does not follow, so a symlink describes itself.
pub(crate) fn xattr_names_at(dir: BorrowedFd<'_>, name: &Name) -> Option<Vec<Vec<u8>>> {
    let path = std::ffi::CString::new(proc_path(dir).join(name.as_os_str()).as_os_str().as_bytes())
        .expect("a name has no NUL");
    xattr_names_by_path(&path, libc::llistxattr)
}

fn xattr_names_by_path(
    path: &std::ffi::CStr,
    list: unsafe extern "C" fn(
        *const libc::c_char,
        *mut libc::c_char,
        libc::size_t,
    ) -> libc::ssize_t,
) -> Option<Vec<Vec<u8>>> {
    let mut buf = [0u8; XATTR_NAMES_MAX];
    // SAFETY: the path is NUL-terminated and the buffer is valid for its length.
    let got = unsafe {
        list(
            path.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if got < 0 {
        let errno = Errno::last();
        let path = path.to_string_lossy();
        match errno {
            Errno::ERANGE => tracing::debug!(
                %path,
                "more than {XATTR_NAMES_MAX} bytes of xattr names; the client will ask"
            ),
            Errno::EOPNOTSUPP => tracing::debug!(
                %path,
                "no xattr support on this node; the client will ask"
            ),
            _ => tracing::warn!(%path, "listxattr for the attributes: {errno}"),
        }
        return None;
    }
    Some(
        buf[..got as usize]
            .split(|b| *b == 0)
            .filter(|name| !name.is_empty())
            .map(|name| name.to_vec())
            .collect(),
    )
}

/// File type from `st_mode`; `None` for a type Linux doesn't have a name for.
pub fn kind_from_mode(mode: libc::mode_t) -> Option<FileKind> {
    Some(match mode & libc::S_IFMT {
        libc::S_IFREG => FileKind::Regular,
        libc::S_IFDIR => FileKind::Directory,
        libc::S_IFLNK => FileKind::Symlink,
        libc::S_IFIFO => FileKind::Fifo,
        libc::S_IFSOCK => FileKind::Socket,
        libc::S_IFCHR => FileKind::CharDevice,
        libc::S_IFBLK => FileKind::BlockDevice,
        _ => return None,
    })
}

/// `/proc/self/fd/N`: re-enters an `O_PATH` fd for the few syscalls that have no `*at`/`AT_EMPTY_PATH` form (chmod, xattrs, access). The magic link jumps straight to the pinned inode, so this is as safe as the fd itself.
pub fn proc_path(fd: BorrowedFd<'_>) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::AtFlags;
    use nix::sys::stat::fstatat;
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt};

    fn path(s: &str) -> Path {
        Path::from_names(
            s.split('/')
                .map(|n| Name::new(n.as_bytes()).unwrap())
                .collect(),
        )
        .unwrap()
    }

    fn fixture() -> (tempfile::TempDir, Export) {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("sub/deep")).unwrap();
        fs::write(dir.path().join("sub/deep/file"), b"x").unwrap();
        symlink("/etc", dir.path().join("escape")).unwrap();
        symlink("sub", dir.path().join("inner")).unwrap();
        let export = Export::open(dir.path()).unwrap();
        (dir, export)
    }

    #[test]
    fn resolves_nested_nodes_and_root() {
        let (dir, export) = fixture();
        let fd = export.resolve(&path("sub/deep/file")).unwrap();
        let st = fstatat(
            &fd,
            "",
            AtFlags::AT_EMPTY_PATH | AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
        assert_eq!(
            st.st_ino,
            fs::metadata(dir.path().join("sub/deep/file"))
                .unwrap()
                .ino()
        );
        let root = export.resolve(&Path::root()).unwrap();
        let attr = export.attr_from_stat(&fstat(&root).unwrap()).unwrap();
        assert_eq!(attr.ino, ROOT_NODEID);
        assert_eq!(attr.kind, FileKind::Directory);
    }

    #[test]
    fn symlinks_are_never_followed() {
        let (_dir, export) = fixture();
        assert!(
            export.resolve(&path("escape/passwd")).is_err(),
            "absolute symlink must not escape"
        );
        assert!(
            export.resolve(&path("inner/deep/file")).is_err(),
            "relative symlink in the middle of a path must not be followed"
        );
        let link = export.resolve(&path("escape")).unwrap();
        let st = fstatat(
            &link,
            "",
            AtFlags::AT_EMPTY_PATH | AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
        assert_eq!(
            kind_from_mode(st.st_mode),
            Some(FileKind::Symlink),
            "the symlink itself is addressable"
        );
        assert!(
            export.open_node(&path("escape"), OFlag::O_RDONLY).is_err(),
            "a real open of a symlink is refused rather than followed"
        );
    }

    #[test]
    fn parent_resolution() {
        let (_dir, export) = fixture();
        let target = path("sub/deep/file");
        let (parent, name) = export.resolve_parent(&target).unwrap();
        assert_eq!(name.as_bytes(), b"file");
        assert!(fstatat(&parent, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW).is_ok());
        assert_eq!(
            export.resolve_parent(&Path::root()).unwrap_err(),
            Errno::EPERM
        );
        assert_eq!(export.resolve_dir(&target).unwrap_err(), Errno::ENOTDIR);
        assert_eq!(export.resolve(&path("missing")).unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn open_in_creates_and_refuses_symlink_targets() {
        let (dir, export) = fixture();
        let created = export
            .open_in(
                &path("sub"),
                &Name::new(b"new").unwrap(),
                OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
                Mode::from_bits_truncate(0o640),
            )
            .unwrap();
        drop(created);
        assert!(dir.path().join("sub/new").exists());
        assert!(export
            .open_in(
                &Path::root(),
                &Name::new(b"escape").unwrap(),
                OFlag::O_WRONLY,
                Mode::empty()
            )
            .is_err());
    }

    #[test]
    fn opening_a_fifo_never_blocks() {
        let (dir, export) = fixture();
        nix::unistd::mkfifo(&dir.path().join("fifo"), Mode::from_bits_truncate(0o644)).unwrap();
        let started = std::time::Instant::now();
        let fd = export.open_node(&path("fifo"), OFlag::O_RDONLY);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(
            fd.is_ok(),
            "a non-blocking read open of a FIFO succeeds immediately"
        );
    }

    #[test]
    fn proc_path_reenters_the_inode() {
        let (dir, export) = fixture();
        let fd = export.resolve(&path("sub/deep/file")).unwrap();
        assert_eq!(fs::read(proc_path(fd.as_fd())).unwrap(), b"x");
        assert_eq!(fs::read(dir.path().join("sub/deep/file")).unwrap(), b"x");
    }

    #[test]
    fn xattr_names_of_a_node() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, b"").unwrap();
        let target = std::ffi::CString::new(file.as_os_str().as_bytes()).unwrap();
        let set = |name: &str| unsafe {
            libc::setxattr(
                target.as_ptr(),
                std::ffi::CString::new(name).unwrap().as_ptr(),
                b"v".as_ptr() as *const libc::c_void,
                1,
                0,
            )
        };
        if set("user.k") != 0 {
            eprintln!("skipping: filesystem does not support user xattrs");
            return;
        }
        let fd = nix::fcntl::open(&file, OFlag::O_PATH, Mode::empty()).unwrap();
        assert_eq!(xattr_names(fd.as_fd()), Some(vec![b"user.k".to_vec()]));
        // A symlink to the file has names of its own (none), never the target's.
        let link = dir.path().join("l");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let link_fd =
            nix::fcntl::open(&link, OFlag::O_PATH | OFlag::O_NOFOLLOW, Mode::empty()).unwrap();
        assert_eq!(xattr_names(link_fd.as_fd()), Some(Vec::new()));
        // More names than fit the cap are left for the client to ask about.
        for i in 0..8 {
            assert_eq!(set(&format!("user.{}{i}", "n".repeat(200))), 0);
        }
        assert_eq!(xattr_names(fd.as_fd()), None);
    }
}

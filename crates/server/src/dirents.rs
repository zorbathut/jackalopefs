//! Directory reading with real `getdents64` cookies, so a client `readdir(offset)` is a genuine `seekdir` and stays correct while the directory changes underneath it.

use crate::export::Export;
use jackalopefs_proto::{DirEntry, Name};
use nix::errno::Errno;
use nix::unistd::{lseek, Whence};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

/// What the server takes from a `linux_dirent64` record: the name and its cookie. The record's inode number and type are not used; an entry is described by its attributes, and the number a file goes by on the mount is the client's to give.
#[derive(Debug, PartialEq, Eq)]
pub struct RawDirent {
    /// Cookie for the entry *after* this one.
    pub off: u64,
    pub name: Vec<u8>,
}

const HEADER_LEN: usize = 8 + 8 + 2 + 1;

/// Parse a buffer filled by `getdents64`. A malformed record ends parsing; the kernel never produces one, so nothing is lost.
pub fn parse(buf: &[u8]) -> Vec<RawDirent> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + HEADER_LEN <= buf.len() {
        let rec = &buf[pos..];
        let off = u64::from_ne_bytes(rec[8..16].try_into().unwrap());
        let reclen = u16::from_ne_bytes(rec[16..18].try_into().unwrap()) as usize;
        if reclen < HEADER_LEN || pos + reclen > buf.len() {
            tracing::error!(pos, reclen, "malformed dirent record from the kernel");
            break;
        }
        let name_area = &rec[HEADER_LEN..reclen];
        let name_len = name_area
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_area.len());
        out.push(RawDirent {
            off,
            name: name_area[..name_len].to_vec(),
        });
        pos += reclen;
    }
    out
}

fn getdents64(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Result<usize, Errno> {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`, which outlives the call.
    let n = unsafe {
        libc::syscall(
            libc::SYS_getdents64,
            fd.as_raw_fd(),
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    if n < 0 {
        Err(Errno::last())
    } else {
        Ok(n as usize)
    }
}

/// One page of a directory. `end` says the directory ended with the last entry returned, which stays true across the entries this page skipped after it (a vanished entry, a mount point): a seek to that entry's cookie re-reads and re-skips them and finds nothing.
pub struct Listing {
    pub entries: Vec<DirEntry>,
    pub end: bool,
}

/// Log a failure to describe `name`. `Ok` means the listing goes on without the entry: it vanished between `getdents64` and its stat, it is a mount point (not exported), or the server cannot describe it (no search permission on the directory, an I/O error), in which case a lookup of it would fail the same way. `Err` ends the listing: the server ran out of a resource, and a page missing the entries it could not afford would read as a shorter directory.
fn entry_failure(name: &[u8], e: Errno) -> Result<(), Errno> {
    let name = String::from_utf8_lossy(name);
    match e {
        Errno::ENOENT | Errno::ESTALE => {
            tracing::debug!(%name, "skipping entry that vanished during readdir: {e}");
            Ok(())
        }
        Errno::EXDEV => {
            tracing::debug!(%name, "skipping a mount point, which is not exported");
            Ok(())
        }
        Errno::EMFILE | Errno::ENFILE | Errno::ENOMEM => {
            tracing::warn!(%name, "readdir failed describing entry: {e}");
            Err(e)
        }
        _ => {
            tracing::warn!(%name, "skipping entry that cannot be described: {e}");
            Ok(())
        }
    }
}

/// Read entries starting at cookie `offset` until roughly `max_bytes` of them are collected or the directory ends. Every entry except `.`/`..` carries its attributes, described from the directory's own fd so a page costs no file descriptors. An entry that vanished or cannot be described is skipped, as is a mount point; a resource failure ends the listing with its errno ([`entry_failure`]).
pub fn read_dir(
    export: &Export,
    dir: BorrowedFd<'_>,
    offset: u64,
    max_bytes: usize,
) -> Result<Listing, Errno> {
    lseek(dir, offset as i64, Whence::SeekSet)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut entries = Vec::new();
    let mut used = 0;
    let mut end = false;
    'outer: loop {
        let n = getdents64(dir, &mut buf)?;
        if n == 0 {
            end = true;
            break;
        }
        for raw in parse(&buf[..n]) {
            let name = raw.name;
            // The dots go without attributes; the client numbers them after its own nodes for the two directories.
            let attr = if name == b"." || name == b".." {
                None
            } else {
                let Ok(component) = Name::new(name.as_slice()) else {
                    tracing::warn!(name = %String::from_utf8_lossy(&name), "skipping entry whose name the protocol cannot carry");
                    continue;
                };
                match export.attr_entry(dir, &component) {
                    Ok(attr) => Some(attr),
                    Err(e) => {
                        entry_failure(&name, e)?;
                        continue;
                    }
                }
            };
            // `max_bytes` is clamped to `MAX_IO`, half of `MAX_FRAME`, so a budget that overshoots by one entry still fits a frame.
            used += jackalopefs_proto::dir_entry_bytes(name.len(), attr.as_ref());
            entries.push(DirEntry {
                next_offset: raw.off,
                name,
                attr,
            });
            if used >= max_bytes {
                break 'outer;
            }
        }
    }
    Ok(Listing { entries, end })
}

/// Convenience for callers holding an `OwnedFd`.
pub fn read_dir_fd<F: AsFd>(
    export: &Export,
    dir: &F,
    offset: u64,
    max_bytes: usize,
) -> Result<Listing, Errno> {
    read_dir(export, dir.as_fd(), offset, max_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::OFlag;
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    fn record(ino: u64, off: u64, d_type: u8, name: &[u8]) -> Vec<u8> {
        let reclen = (HEADER_LEN + name.len() + 1).div_ceil(8) * 8;
        let mut rec = Vec::with_capacity(reclen);
        rec.extend_from_slice(&ino.to_ne_bytes());
        rec.extend_from_slice(&off.to_ne_bytes());
        rec.extend_from_slice(&(reclen as u16).to_ne_bytes());
        rec.push(d_type);
        rec.extend_from_slice(name);
        rec.resize(reclen, 0);
        rec
    }

    #[test]
    fn parses_hand_built_records() {
        let mut buf = record(10, 100, libc::DT_REG, b"a");
        buf.extend(record(11, 200, libc::DT_DIR, b"longer-name"));
        buf.extend(record(12, 300, libc::DT_UNKNOWN, b"\xff\xfe"));
        let parsed = parse(&buf);
        assert_eq!(
            parsed,
            vec![
                RawDirent {
                    off: 100,
                    name: b"a".to_vec()
                },
                RawDirent {
                    off: 200,
                    name: b"longer-name".to_vec()
                },
                RawDirent {
                    off: 300,
                    name: b"\xff\xfe".to_vec()
                },
            ]
        );
        assert!(
            parse(&buf[..buf.len() - 1]).len() < 3,
            "a truncated final record is dropped, not misparsed"
        );
    }

    fn names(listing: &Listing) -> Vec<Vec<u8>> {
        listing.entries.iter().map(|e| e.name.to_vec()).collect()
    }

    fn last_offset(listing: &Listing) -> Option<u64> {
        listing.entries.last().map(|e| e.next_offset)
    }

    /// `read_dir` fills up to `max_bytes` using `dir_entry_bytes`; the reply for a full `MAX_IO` budget must still fit in a frame, in one segment.
    #[test]
    fn a_full_page_of_entries_fits_in_a_frame() {
        use jackalopefs_proto::{encode, Attr, FileKind, Response, TimeSpec, MAX_FRAME, MAX_IO};
        let t = TimeSpec { sec: 0, nsec: 0 };
        let attr = Attr {
            ino: 1,
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
            // The most names the server sends for one node, in the shape that costs the most words: many one-byte names, each with its own pointer word.
            xattr_names: Some(vec![vec![b'x']; 512]),
            // And the longest handle the kernel makes.
            identity: jackalopefs_proto::Identity {
                handle_type: 1,
                handle: vec![0; jackalopefs_proto::HANDLE_MAX],
            },
            foreign: false,
        };
        let mut described = Vec::new();
        let mut used = 0;
        while used < MAX_IO {
            described.push(DirEntry {
                next_offset: 1,
                name: b"a".to_vec(),
                attr: Some(attr.clone()),
            });
            used += jackalopefs_proto::dir_entry_bytes(1, Some(&attr));
        }
        let frame = encode(&Response::Readdir {
            entries: described,
            end: false,
        })
        .unwrap();
        assert!(frame.len() - 4 <= MAX_FRAME, "{} bytes", frame.len());
        // A full page also fits the encoder's first-segment estimate: the segment table's count is zero, so no canonicalizing copy was needed.
        assert_eq!(
            &frame[4..8],
            &[0, 0, 0, 0],
            "a full page spilled into a second segment"
        );
    }

    #[test]
    fn reads_a_real_directory_in_pages() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..200 {
            fs::write(dir.path().join(format!("file-{i:03}")), b"").unwrap();
        }
        fs::create_dir(dir.path().join("subdir")).unwrap();
        let export = Export::open(dir.path()).unwrap();
        let fd = export
            .open_node(
                &jackalopefs_proto::Path::root(),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            )
            .unwrap();

        let all = read_dir_fd(&export, &fd, 0, usize::MAX).unwrap();
        let all_names: BTreeSet<Vec<u8>> = names(&all).into_iter().collect();
        assert_eq!(all_names.len(), 203);
        assert!(all.end, "an unbudgeted read reaches the end");
        assert!(all_names.contains(b".".as_slice()) && all_names.contains(b"..".as_slice()));

        let mut paged = Vec::new();
        let mut offset = 0;
        let mut ended = false;
        loop {
            let page = read_dir_fd(&export, &fd, offset, 1000).unwrap();
            let page_names = names(&page);
            if page_names.is_empty() {
                break;
            }
            // Which page says `end` depends on whether the budget ran out exactly at the last entry, so only this direction is asserted.
            assert!(!ended, "no page follows one that said the directory ended");
            ended = page.end;
            for e in &page.entries {
                assert_eq!(e.attr.is_none(), e.is_dot_or_dotdot());
                if e.name.as_slice() == b"subdir" {
                    assert_eq!(
                        e.attr.as_ref().unwrap().kind,
                        jackalopefs_proto::FileKind::Directory
                    );
                }
            }
            paged.extend(page_names);
            offset = last_offset(&page).unwrap();
        }
        assert_eq!(paged.len(), 203, "paging yields every entry exactly once");
        assert_eq!(paged.into_iter().collect::<BTreeSet<_>>(), all_names);
    }

    /// An entry the server has no search permission to stat is left out of a listing, which a lookup of it would refuse the same way.
    #[test]
    fn an_entry_that_cannot_be_described_is_left_out() {
        if nix::unistd::geteuid().is_root() {
            eprintln!("skipping: root bypasses directory permissions");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("file"), b"").unwrap();
        let export = Export::open(dir.path()).unwrap();
        let fd = export
            .open_node(
                &jackalopefs_proto::Path::from_names(vec![Name::new(b"sub".as_slice()).unwrap()])
                    .unwrap(),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            )
            .unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o644)).unwrap();
        let listing = read_dir_fd(&export, &fd, 0, usize::MAX);
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).unwrap();
        let listing = listing.unwrap();
        assert_eq!(names(&listing), vec![b".".to_vec(), b"..".to_vec()]);
        assert!(listing.end);
    }

    /// The regression test for a server whose descriptors a client's open files have used up: a listing is described without opening anything, so it still comes back. The check runs in a child process (this same test, re-executed with the marker set), since exhausting the descriptors of the test process would fail every other test running beside it.
    #[test]
    fn a_listing_needs_no_file_descriptors() {
        const MARKER: &str = "JACKALOPEFS_TEST_FD_EXHAUSTED_CHILD";
        if std::env::var_os(MARKER).is_none() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "dirents::tests::a_listing_needs_no_file_descriptors",
                    "--nocapture",
                ])
                .env(MARKER, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success() && stdout.contains("1 passed"),
                "child run failed:\n{stdout}{}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        for i in 0..50 {
            fs::write(dir.path().join(format!("file-{i}")), b"").unwrap();
        }
        let export = Export::open(dir.path()).unwrap();
        let fd = export
            .open_node(
                &jackalopefs_proto::Path::root(),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            )
            .unwrap();
        let (_, hard) =
            nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE).unwrap();
        nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE, 64, hard)
            .unwrap();
        let mut hoard = Vec::new();
        loop {
            match fs::File::open("/dev/null") {
                Ok(f) => hoard.push(f),
                Err(e) if e.raw_os_error() == Some(libc::EMFILE) => break,
                Err(e) => panic!("hoarding descriptors: {e}"),
            }
        }
        assert!(
            fs::File::open("/dev/null").is_err(),
            "no descriptor is left"
        );
        let listing = read_dir_fd(&export, &fd, 0, usize::MAX);
        drop(hoard);
        let listing = listing.expect("a listing opens nothing");
        assert_eq!(names(&listing).len(), 52);
        assert!(listing
            .entries
            .iter()
            .all(|e| e.attr.is_some() || e.is_dot_or_dotdot()));
    }

    /// A mount point inside the export is left out of a listing, as the resolver refuses to cross into it.
    #[test]
    fn a_mount_point_is_left_out() {
        if !fs::read_to_string("/proc/self/mounts")
            .unwrap()
            .lines()
            .any(|line| line.split(' ').nth(1) == Some("/proc"))
        {
            eprintln!("skipping: /proc is not a mount point here");
            return;
        }
        let export = Export::open(std::path::Path::new("/")).unwrap();
        let fd = export
            .open_node(
                &jackalopefs_proto::Path::root(),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            )
            .unwrap();
        let listed = names(&read_dir_fd(&export, &fd, 0, usize::MAX).unwrap());
        assert!(!listed.contains(&b"proc".to_vec()), "{listed:?}");
        assert!(listed.contains(&b"etc".to_vec()), "{listed:?}");
    }

    /// A listed entry is described from the directory's fd alone: a symlink describes itself, and a file's xattr names come along.
    #[test]
    fn describes_entries_from_the_directory_fd() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        fs::write(&file, b"x").unwrap();
        std::os::unix::fs::symlink("file", dir.path().join("link")).unwrap();
        let target = std::ffi::CString::new(file.as_os_str().as_bytes()).unwrap();
        // SAFETY: both strings are NUL-terminated and the value pointer is valid for its length.
        let set = unsafe {
            libc::setxattr(
                target.as_ptr(),
                c"user.k".as_ptr(),
                b"v".as_ptr() as *const libc::c_void,
                1,
                0,
            )
        };
        let xattrs = set == 0;
        if !xattrs {
            eprintln!("skipping the xattr half: filesystem does not support user xattrs");
        }
        let export = Export::open(dir.path()).unwrap();
        let fd = export
            .open_node(
                &jackalopefs_proto::Path::root(),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            )
            .unwrap();
        let listing = read_dir_fd(&export, &fd, 0, usize::MAX).unwrap();
        let attr = |name: &[u8]| {
            listing
                .entries
                .iter()
                .find(|e| e.name.as_slice() == name)
                .unwrap_or_else(|| panic!("{} listed", String::from_utf8_lossy(name)))
                .attr
                .clone()
                .unwrap()
        };
        assert_eq!(attr(b"link").kind, jackalopefs_proto::FileKind::Symlink);
        assert_eq!(attr(b"file").kind, jackalopefs_proto::FileKind::Regular);
        assert_eq!(attr(b"file").size, 1);
        if xattrs {
            assert_eq!(attr(b"file").xattr_names, Some(vec![b"user.k".to_vec()]));
            assert_eq!(
                attr(b"link").xattr_names,
                Some(vec![]),
                "the link's own names, not the target's"
            );
        }
    }
}

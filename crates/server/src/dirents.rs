//! Directory reading with real `getdents64` cookies, so a client `readdir(offset)` is a genuine `seekdir` and stays correct while the directory changes underneath it.

use crate::export::{kind_from_mode, Export};
use jackalopefs_proto::{DirEntry, DirEntryPlus, FileKind};
use nix::errno::Errno;
use nix::fcntl::AtFlags;
use nix::sys::stat::{fstat, fstatat};
use nix::unistd::{lseek, Whence};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

/// One `linux_dirent64` record.
#[derive(Debug, PartialEq, Eq)]
pub struct RawDirent {
    pub ino: u64,
    /// Cookie for the entry *after* this one.
    pub off: u64,
    pub d_type: u8,
    pub name: Vec<u8>,
}

const HEADER_LEN: usize = 8 + 8 + 2 + 1;

/// Parse a buffer filled by `getdents64`. A malformed record ends parsing; the kernel never produces one, so nothing is lost.
pub fn parse(buf: &[u8]) -> Vec<RawDirent> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + HEADER_LEN <= buf.len() {
        let rec = &buf[pos..];
        let ino = u64::from_ne_bytes(rec[0..8].try_into().unwrap());
        let off = u64::from_ne_bytes(rec[8..16].try_into().unwrap());
        let reclen = u16::from_ne_bytes(rec[16..18].try_into().unwrap()) as usize;
        let d_type = rec[18];
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
            ino,
            off,
            d_type,
            name: name_area[..name_len].to_vec(),
        });
        pos += reclen;
    }
    out
}

fn kind_from_dtype(d_type: u8) -> Option<FileKind> {
    Some(match d_type {
        libc::DT_REG => FileKind::Regular,
        libc::DT_DIR => FileKind::Directory,
        libc::DT_LNK => FileKind::Symlink,
        libc::DT_FIFO => FileKind::Fifo,
        libc::DT_SOCK => FileKind::Socket,
        libc::DT_CHR => FileKind::CharDevice,
        libc::DT_BLK => FileKind::BlockDevice,
        _ => return None,
    })
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

/// Wire cost per entry, used to honour `max_bytes`. `max_bytes` is clamped to `MAX_IO`, half of `MAX_FRAME`, so even a budget that under-counted by two would still fit a frame.
fn entry_cost(name_len: usize, plus: bool) -> usize {
    jackalopefs_proto::dir_entry_bytes(name_len, plus)
}

pub enum Listing {
    Plain(Vec<DirEntry>),
    Plus(Vec<DirEntryPlus>),
}

/// Read entries starting at cookie `offset` until roughly `max_bytes` of them are collected or the directory ends. With `plus`, every entry except `.`/`..` carries its attributes; an entry whose stat fails (it is being removed) is skipped.
pub fn read_dir(
    export: &Export,
    dir: BorrowedFd<'_>,
    offset: u64,
    max_bytes: usize,
    plus: bool,
) -> Result<Listing, Errno> {
    lseek(dir, offset as i64, Whence::SeekSet)?;
    let self_ino = export.map_ino(fstat(dir)?.st_ino)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut plain = Vec::new();
    let mut with_attr = Vec::new();
    let mut used = 0;
    'outer: loop {
        let n = getdents64(dir, &mut buf)?;
        if n == 0 {
            break;
        }
        for raw in parse(&buf[..n]) {
            let name = raw.name;
            let is_dot = name == b"." || name == b"..";
            let stat = || fstatat(dir, name.as_slice(), AtFlags::AT_SYMLINK_NOFOLLOW);
            let kind = match kind_from_dtype(raw.d_type) {
                Some(kind) => kind,
                None => match stat() {
                    Ok(st) => match kind_from_mode(st.st_mode) {
                        Some(kind) => kind,
                        None => continue,
                    },
                    Err(e) => {
                        tracing::debug!(name = %String::from_utf8_lossy(&name), "skipping entry with unknown type: {e}");
                        continue;
                    }
                },
            };
            let ino = if name == b"." {
                self_ino
            } else if name == b".." {
                // The root's parent lies outside the export; a subdirectory's parent maps like any node, and the client overrides both anyway.
                if self_ino == crate::export::ROOT_NODEID {
                    self_ino
                } else {
                    export.map_ino(raw.ino).unwrap_or(self_ino)
                }
            } else {
                match export.map_ino(raw.ino) {
                    Ok(ino) => ino,
                    Err(_) => continue,
                }
            };
            let attr = if plus && !is_dot {
                match stat().and_then(|st| export.attr_from_stat(&st)) {
                    Ok(attr) => Some(attr),
                    Err(e) => {
                        tracing::debug!(name = %String::from_utf8_lossy(&name), "skipping entry that vanished during readdirplus: {e}");
                        continue;
                    }
                }
            } else {
                None
            };
            used += entry_cost(name.len(), plus);
            let entry = DirEntry {
                ino,
                next_offset: raw.off,
                kind,
                name,
            };
            if plus {
                with_attr.push(DirEntryPlus { entry, attr });
            } else {
                plain.push(entry);
            }
            if used >= max_bytes {
                break 'outer;
            }
        }
    }
    Ok(if plus {
        Listing::Plus(with_attr)
    } else {
        Listing::Plain(plain)
    })
}

/// Convenience for callers holding an `OwnedFd`.
pub fn read_dir_fd<F: AsFd>(
    export: &Export,
    dir: &F,
    offset: u64,
    max_bytes: usize,
    plus: bool,
) -> Result<Listing, Errno> {
    read_dir(export, dir.as_fd(), offset, max_bytes, plus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::OFlag;
    use std::collections::BTreeSet;
    use std::fs;

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
                    ino: 10,
                    off: 100,
                    d_type: libc::DT_REG,
                    name: b"a".to_vec()
                },
                RawDirent {
                    ino: 11,
                    off: 200,
                    d_type: libc::DT_DIR,
                    name: b"longer-name".to_vec()
                },
                RawDirent {
                    ino: 12,
                    off: 300,
                    d_type: libc::DT_UNKNOWN,
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
        match listing {
            Listing::Plain(v) => v.iter().map(|e| e.name.to_vec()).collect(),
            Listing::Plus(v) => v.iter().map(|e| e.entry.name.to_vec()).collect(),
        }
    }

    fn last_offset(listing: &Listing) -> Option<u64> {
        match listing {
            Listing::Plain(v) => v.last().map(|e| e.next_offset),
            Listing::Plus(v) => v.last().map(|e| e.entry.next_offset),
        }
    }

    /// `read_dir` fills up to `max_bytes` using `entry_cost`; the reply for a full `MAX_IO` budget must still fit in a frame.
    #[test]
    fn a_full_page_of_entries_fits_in_a_frame() {
        use jackalopefs_proto::{
            encode, Attr, DirEntryPlus, Response, TimeSpec, MAX_FRAME, MAX_IO,
        };
        let entry = || DirEntry {
            ino: 1,
            next_offset: 1,
            kind: FileKind::Regular,
            name: b"a".to_vec(),
        };
        let mut plain = Vec::new();
        let mut used = 0;
        while used < MAX_IO {
            plain.push(entry());
            used += entry_cost(1, false);
        }
        let frame = encode(&Response::Readdir(plain)).unwrap();
        assert!(frame.len() - 4 <= MAX_FRAME, "{} bytes", frame.len());

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
        };
        let mut plus = Vec::new();
        let mut used = 0;
        while used < MAX_IO {
            plus.push(DirEntryPlus {
                entry: entry(),
                attr: Some(attr),
            });
            used += entry_cost(1, true);
        }
        let frame = encode(&Response::ReaddirPlus(plus)).unwrap();
        assert!(frame.len() - 4 <= MAX_FRAME, "{} bytes", frame.len());
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

        let all = read_dir_fd(&export, &fd, 0, usize::MAX, false).unwrap();
        let all_names: BTreeSet<Vec<u8>> = names(&all).into_iter().collect();
        assert_eq!(all_names.len(), 203);
        assert!(all_names.contains(b".".as_slice()) && all_names.contains(b"..".as_slice()));

        let mut paged = Vec::new();
        let mut offset = 0;
        loop {
            let page = read_dir_fd(&export, &fd, offset, 1000, true).unwrap();
            let page_names = names(&page);
            if page_names.is_empty() {
                break;
            }
            if let Listing::Plus(entries) = &page {
                for e in entries {
                    assert_eq!(e.attr.is_none(), e.entry.is_dot_or_dotdot());
                    if e.entry.name.as_slice() == b"subdir" {
                        assert_eq!(e.attr.unwrap().kind, FileKind::Directory);
                    }
                }
            }
            paged.extend(page_names);
            offset = last_offset(&page).unwrap();
        }
        assert_eq!(paged.len(), 203, "paging yields every entry exactly once");
        assert_eq!(paged.into_iter().collect::<BTreeSet<_>>(), all_names);
    }
}

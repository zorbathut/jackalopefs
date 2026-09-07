//! Filesystem value types shared by requests, replies and events.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

/// Longest single path component, matching Linux `NAME_MAX`.
pub const NAME_MAX: usize = 255;

/// Longest joined path in bytes, matching Linux `PATH_MAX`; a server resolves the whole path in one `openat2`, so this is a hard limit on tree depth.
pub const PATH_MAX: usize = 4096;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ErrorName {
    #[error("empty name")]
    Empty,
    #[error("name longer than {NAME_MAX} bytes")]
    TooLong,
    #[error("name contains '/' or NUL")]
    BadByte,
    #[error("name is '.' or '..'")]
    Dot,
}

/// One validated path component: non-empty, at most [`NAME_MAX`] bytes, no `/` or NUL, and not `.` or `..`.
///
/// The decoder builds names only through [`Name::new`], so a `Name` that came off the wire is as trustworthy as one built locally.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(Vec<u8>);

impl Name {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, ErrorName> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(ErrorName::Empty);
        }
        if bytes.len() > NAME_MAX {
            return Err(ErrorName::TooLong);
        }
        if bytes.iter().any(|&b| b == b'/' || b == 0) {
            return Err(ErrorName::BadByte);
        }
        if bytes == b"." || bytes == b".." {
            return Err(ErrorName::Dot);
        }
        Ok(Name(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_os_str(&self) -> &OsStr {
        OsStr::from_bytes(&self.0)
    }
}

impl TryFrom<&OsStr> for Name {
    type Error = ErrorName;

    fn try_from(s: &OsStr) -> Result<Self, ErrorName> {
        Name::new(s.as_bytes())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(&self.0))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.0))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("path longer than {PATH_MAX} bytes")]
pub struct ErrorPathTooLong;

/// A path relative to the export root as a sequence of [`Name`]s; the root itself is the empty path.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Path(Vec<Name>);

impl Path {
    pub fn root() -> Self {
        Path(Vec::new())
    }

    pub fn from_names(names: Vec<Name>) -> Result<Self, ErrorPathTooLong> {
        let path = Path(names);
        if path.byte_len() > PATH_MAX {
            return Err(ErrorPathTooLong);
        }
        Ok(path)
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn names(&self) -> &[Name] {
        &self.0
    }

    pub fn join(&self, name: Name) -> Result<Path, ErrorPathTooLong> {
        let mut names = self.0.clone();
        names.push(name);
        Path::from_names(names)
    }

    /// Parent path and final component, or `None` for the root.
    pub fn split_last(&self) -> Option<(Path, &Name)> {
        let (last, parent) = self.0.split_last()?;
        Some((Path(parent.to_vec()), last))
    }

    /// Length of the `/`-joined form; zero for the root.
    pub fn byte_len(&self) -> usize {
        let names: usize = self.0.iter().map(|n| n.as_bytes().len()).sum();
        names + self.0.len().saturating_sub(1)
    }

    /// `/`-joined form with no leading slash; empty for the root.
    pub fn to_os_string(&self) -> OsString {
        let mut out = Vec::with_capacity(self.byte_len());
        for (i, name) in self.0.iter().enumerate() {
            if i > 0 {
                out.push(b'/');
            }
            out.extend_from_slice(name.as_bytes());
        }
        OsString::from_vec(out)
    }
}

impl fmt::Debug for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_os_string().to_string_lossy())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    Fifo,
    Socket,
    CharDevice,
    BlockDevice,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TimeSpec {
    pub sec: i64,
    pub nsec: u32,
}

/// A `stat` result. `ino` is the server's real inode number; the client uses it directly as the FUSE nodeid.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Attr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: TimeSpec,
    pub mtime: TimeSpec,
    pub ctime: TimeSpec,
    pub kind: FileKind,
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub blksize: u32,
    /// The node's extended attribute names when the server looked: an empty list means it has none, which a client may answer `getxattr` and `listxattr` from; `None` means the client must ask.
    pub xattr_names: Option<Vec<Vec<u8>>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Statfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
}

/// One `getdents64` record. `name` is raw because `.` and `..` travel with their real `d_off` cookies; `next_offset` is the cookie to request the entries after this one.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DirEntry {
    pub ino: u64,
    pub next_offset: u64,
    pub kind: FileKind,
    pub name: Vec<u8>,
}

impl DirEntry {
    pub fn is_dot_or_dotdot(&self) -> bool {
        self.name.as_slice() == b"." || self.name.as_slice() == b".."
    }
}

/// A readdirplus record; `attr` is `None` only for `.` and `..`, which the kernel never links.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DirEntryPlus {
    pub entry: DirEntry,
    pub attr: Option<Attr>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimeOrNow {
    Time(TimeSpec),
    Now,
}

/// The settable subset of attributes; every field is independent and `None` means leave alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SetAttr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<TimeOrNow>,
    pub mtime: Option<TimeOrNow>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validation() {
        assert!(Name::new(b"file.txt").is_ok());
        assert!(Name::new(vec![b'x'; NAME_MAX]).is_ok());
        assert!(Name::new(b"\xff\xfe").is_ok(), "non-UTF-8 is a valid name");
        assert_eq!(Name::new(b""), Err(ErrorName::Empty));
        assert_eq!(Name::new(vec![b'x'; NAME_MAX + 1]), Err(ErrorName::TooLong));
        assert_eq!(Name::new(b"a/b"), Err(ErrorName::BadByte));
        assert_eq!(Name::new(b"a\0b"), Err(ErrorName::BadByte));
        assert_eq!(Name::new(b"."), Err(ErrorName::Dot));
        assert_eq!(Name::new(b".."), Err(ErrorName::Dot));
        assert!(Name::new(b"...").is_ok());
    }

    #[test]
    fn path_join_split_and_render() {
        let root = Path::root();
        assert!(root.is_root());
        assert_eq!(root.to_os_string(), "");
        assert!(root.split_last().is_none());

        let a = root.join(Name::new(b"a").unwrap()).unwrap();
        let ab = a.join(Name::new(b"b").unwrap()).unwrap();
        assert_eq!(ab.to_os_string(), "a/b");
        assert_eq!(ab.byte_len(), 3);
        let (parent, last) = ab.split_last().unwrap();
        assert_eq!(parent, a);
        assert_eq!(last.as_bytes(), b"b");
    }

    #[test]
    fn path_length_limit() {
        let name = Name::new(vec![b'x'; NAME_MAX]).unwrap();
        let sixteen: Vec<Name> = std::iter::repeat_n(name.clone(), 16).collect();
        assert!(Path::from_names(sixteen.clone()).is_ok());
        let seventeen: Vec<Name> = std::iter::repeat_n(name, 17).collect();
        assert_eq!(Path::from_names(seventeen), Err(ErrorPathTooLong));
        let sixteen_path = Path::from_names(sixteen).unwrap();
        assert_eq!(
            sixteen_path.join(Name::new(b"y").unwrap()).is_err(),
            sixteen_path.byte_len() + 2 > PATH_MAX
        );
    }
}

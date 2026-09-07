//! Messages: the control-stream handshake, per-request bidi stream payloads, and the server-to-client event stream.

use crate::types::*;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Auth {
    Anonymous,
    /// Compared as bytes on the server; never interpreted as text.
    Token(Vec<u8>),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Resume {
    pub session_id: u64,
    pub token: [u8; 16],
}

/// First message on the control stream, client to server.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Hello {
    /// [`crate::PROTO_REVISION`] of the sender's build.
    pub revision: u64,
    pub auth: Auth,
    /// Present when reconnecting: asks the server to reattach the previous session's open handles.
    pub resume: Option<Resume>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HelloReply {
    Ack {
        session_id: u64,
        resume_token: [u8; 16],
        /// True when `Hello::resume` named a live session and its handles are still open.
        resumed: bool,
    },
    Reject {
        reason: String,
    },
    /// The server speaks another revision of the protocol; it closes the connection once this has been read.
    RevisionMismatch {
        revision: u64,
    },
}

/// One request per bidi stream. Paths are relative to the export root; `fh` values are chosen by the client.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Request {
    Lookup {
        parent: Path,
        name: Name,
    },
    /// `path` is `None` only when `fh` is given and the file has no path any more (unlinked while open).
    Getattr {
        path: Option<Path>,
        fh: Option<u64>,
    },
    Setattr {
        path: Option<Path>,
        fh: Option<u64>,
        set: SetAttr,
    },
    Readlink {
        path: Path,
    },
    Mknod {
        parent: Path,
        name: Name,
        mode: u32,
        rdev: u64,
    },
    Mkdir {
        parent: Path,
        name: Name,
        mode: u32,
    },
    Unlink {
        parent: Path,
        name: Name,
    },
    Rmdir {
        parent: Path,
        name: Name,
    },
    Symlink {
        parent: Path,
        name: Name,
        target: Vec<u8>,
    },
    Rename {
        parent: Path,
        name: Name,
        newparent: Path,
        newname: Name,
        flags: u32,
    },
    Link {
        path: Path,
        newparent: Path,
        newname: Name,
    },
    Open {
        fh: u64,
        path: Path,
        flags: i32,
    },
    Create {
        fh: u64,
        parent: Path,
        name: Name,
        mode: u32,
        flags: i32,
    },
    Read {
        fh: u64,
        offset: u64,
        size: u32,
    },
    Write {
        fh: u64,
        offset: u64,
        data: Vec<u8>,
    },
    Release {
        fh: u64,
    },
    Fsync {
        fh: u64,
        datasync: bool,
    },
    Opendir {
        fh: u64,
        path: Path,
    },
    Readdir {
        fh: u64,
        offset: u64,
        max_bytes: u32,
        plus: bool,
    },
    Releasedir {
        fh: u64,
    },
    Statfs {
        path: Path,
    },
    Setxattr {
        path: Path,
        name: Vec<u8>,
        value: Vec<u8>,
        flags: i32,
    },
    Getxattr {
        path: Path,
        name: Vec<u8>,
    },
    Listxattr {
        path: Path,
    },
    Removexattr {
        path: Path,
        name: Vec<u8>,
    },
    Access {
        path: Path,
        mask: i32,
    },
}

impl Request {
    /// The handle this request operates on, if any.
    pub fn fh(&self) -> Option<u64> {
        match self {
            Request::Getattr { fh, .. } | Request::Setattr { fh, .. } => *fh,
            Request::Open { fh, .. }
            | Request::Create { fh, .. }
            | Request::Read { fh, .. }
            | Request::Write { fh, .. }
            | Request::Release { fh }
            | Request::Fsync { fh, .. }
            | Request::Opendir { fh, .. }
            | Request::Readdir { fh, .. }
            | Request::Releasedir { fh } => Some(*fh),
            _ => None,
        }
    }

    /// The handle, offset and size (or byte count) this request names, for logs.
    pub fn perf_fields(&self) -> (Option<u64>, Option<u64>, Option<u64>) {
        match self {
            Request::Read { fh, offset, size } => (Some(*fh), Some(*offset), Some(*size as u64)),
            Request::Write { fh, offset, data } => {
                (Some(*fh), Some(*offset), Some(data.len() as u64))
            }
            Request::Readdir {
                fh,
                offset,
                max_bytes,
                ..
            } => (Some(*fh), Some(*offset), Some(*max_bytes as u64)),
            other => (other.fh(), None, None),
        }
    }

    /// Short operation name for logs.
    pub fn op_name(&self) -> &'static str {
        match self {
            Request::Lookup { .. } => "lookup",
            Request::Getattr { .. } => "getattr",
            Request::Setattr { .. } => "setattr",
            Request::Readlink { .. } => "readlink",
            Request::Mknod { .. } => "mknod",
            Request::Mkdir { .. } => "mkdir",
            Request::Unlink { .. } => "unlink",
            Request::Rmdir { .. } => "rmdir",
            Request::Symlink { .. } => "symlink",
            Request::Rename { .. } => "rename",
            Request::Link { .. } => "link",
            Request::Open { .. } => "open",
            Request::Create { .. } => "create",
            Request::Read { .. } => "read",
            Request::Write { .. } => "write",
            Request::Release { .. } => "release",
            Request::Fsync { .. } => "fsync",
            Request::Opendir { .. } => "opendir",
            Request::Readdir { plus: false, .. } => "readdir",
            Request::Readdir { plus: true, .. } => "readdirplus",
            Request::Releasedir { .. } => "releasedir",
            Request::Statfs { .. } => "statfs",
            Request::Setxattr { .. } => "setxattr",
            Request::Getxattr { .. } => "getxattr",
            Request::Listxattr { .. } => "listxattr",
            Request::Removexattr { .. } => "removexattr",
            Request::Access { .. } => "access",
        }
    }
}

/// Reply to a [`Request`]; `Err` carries a Linux errno.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Response {
    Err(i32),
    /// lookup, mknod, mkdir, symlink, link
    Entry(Attr),
    /// getattr, setattr
    Attr(Attr),
    Readlink(Vec<u8>),
    /// unlink, rmdir, rename, release, fsync, releasedir, setxattr, removexattr, access
    Ok,
    /// open, create, opendir; the attr lets a reconnecting client verify it reopened the same inode
    Opened {
        attr: Attr,
    },
    Read(Vec<u8>),
    Written(u32),
    /// `end`: no entry follows the last one, so the client may answer a read at its `next_offset` itself; meaningless with no entries.
    Readdir {
        entries: Vec<DirEntry>,
        end: bool,
    },
    /// `end` as for `Readdir`.
    ReaddirPlus {
        entries: Vec<DirEntryPlus>,
        end: bool,
    },
    Statfs(Statfs),
    /// getxattr value, or the NUL-separated listxattr names
    Xattr(Vec<u8>),
}

/// One invalidation. `Entry` means the directory entry `dir/name` changed (created, removed, renamed, or its inode replaced); `Data` means the file's contents or attributes changed; `Overflow` means events were dropped and the client should treat everything it caches as suspect.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum EventItem {
    Entry { dir: Path, name: Name },
    Data { path: Path },
    Overflow,
}

/// One debounce window's worth of events, in order, on the server-to-client event stream.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Event {
    pub items: Vec<EventItem>,
}

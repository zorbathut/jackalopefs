//! Conversions between the Rust message types and the generated Cap'n Proto readers and builders. Parsing is the trust boundary: every name, path and token is validated here, and anything the schema version on the other side knows but this one doesn't is a decode error rather than a guess.

use crate::jackalopefs_capnp as schema;
use crate::msg::{Auth, Event, EventItem, Hello, HelloReply, Request, Response, Resume};
use crate::types::{
    Attr, DirEntry, DirEntryPlus, ErrorName, ErrorPathTooLong, FileKind, Name, Path, SetAttr,
    Statfs, TimeOrNow, TimeSpec, PATH_MAX,
};
use capnp::message::{self, HeapAllocator, ReaderSegments};

#[derive(Debug, thiserror::Error)]
pub enum ErrorDecode {
    #[error("{0}")]
    Capnp(#[from] capnp::Error),
    #[error("unknown discriminant or enum value {0}; the peer may speak a newer schema")]
    NotInSchema(u16),
    #[error("invalid name: {0}")]
    Name(#[from] ErrorName),
    #[error("{0}")]
    Path(#[from] ErrorPathTooLong),
    #[error("{0}")]
    Invalid(String),
    /// The frame around the message was malformed (segment table, trailing bytes).
    #[error("{0}")]
    Frame(String),
}

impl From<capnp::NotInSchema> for ErrorDecode {
    fn from(e: capnp::NotInSchema) -> ErrorDecode {
        ErrorDecode::NotInSchema(e.0)
    }
}

/// A top-level message: knows how to fill a fresh builder and how to read itself back.
pub trait Message: Sized {
    fn build(&self, message: &mut message::Builder<HeapAllocator>);
    fn parse<S: ReaderSegments>(message: &message::Reader<S>) -> Result<Self, ErrorDecode>;
    /// Words to reserve for the first segment so the message fits in one; an underestimate costs a copy, never correctness.
    fn size_hint(&self) -> u32;
}

/// Words for a `Data` payload of `len` bytes: the data itself plus its pointer.
fn words_for(len: usize) -> u32 {
    (len.div_ceil(8) + 1) as u32
}

/// `Text` carries a trailing NUL that `Data` does not.
fn words_for_text(len: usize) -> u32 {
    words_for(len + 1)
}

fn words_for_path(path: &Path) -> u32 {
    path.names()
        .iter()
        .map(|n| words_for(n.as_bytes().len()))
        .sum::<u32>()
        + 2
}

/// First-segment reservation every message starts from: the root pointer and root struct take at most eight words; the rest is slack so the per-message estimates can be simple without ever forcing a spill.
const BASE_WORDS: u32 = 32;

/// A path cannot legitimately have more components than this (every component is at least one byte plus a separator), so a list that declares more is rejected before anything is allocated for it.
const MAX_PATH_COMPONENTS: u32 = (PATH_MAX / 2 + 1) as u32;

/// Every element of a struct list occupies at least one word in a genuine message, so a list declaring more elements than the whole message has words is an amplification attempt (a zero-sized element type makes the count otherwise unbounded). Checked before allocating. Changing this rule is a protocol change: edit the schema so the revision moves.
fn checked_len(declared: u32, message_words: usize) -> Result<usize, ErrorDecode> {
    if declared as usize > message_words {
        return Err(ErrorDecode::Invalid(format!(
            "list declares {declared} elements inside a {message_words}-word message"
        )));
    }
    Ok(declared as usize)
}

/// Wire size of one directory entry in a `readdir`/`readdirPlus` reply: four words of `DirEntry` plus the name rounded up to a word; with an `Attr`, sixteen more words (three for `DirEntryPlus`, thirteen for the `Attr`) and, when it carries xattr names, a pointer word per name plus each name rounded up to a word. The server budgets listings with this. Changing it is a protocol change: edit the schema so the revision moves.
pub fn dir_entry_bytes(name_len: usize, plus: bool, xattr_names: Option<&[Vec<u8>]>) -> usize {
    let names = xattr_names.map_or(0, |names| {
        names.iter().map(|n| 8 + n.len().next_multiple_of(8)).sum()
    });
    32 + name_len.next_multiple_of(8) + if plus { 128 + names } else { 0 }
}

/// Words the names an `Attr` carries add to it: a pointer word per name and the name rounded up to a word.
fn words_for_xattr_names(names: Option<&[Vec<u8>]>) -> u32 {
    names.map_or(0, |names| names.iter().map(|n| words_for(n.len())).sum())
}

// ---------- value helpers ----------

fn kind_to_wire(kind: FileKind) -> schema::FileKind {
    match kind {
        FileKind::Regular => schema::FileKind::Regular,
        FileKind::Directory => schema::FileKind::Directory,
        FileKind::Symlink => schema::FileKind::Symlink,
        FileKind::Fifo => schema::FileKind::Fifo,
        FileKind::Socket => schema::FileKind::Socket,
        FileKind::CharDevice => schema::FileKind::CharDevice,
        FileKind::BlockDevice => schema::FileKind::BlockDevice,
    }
}

fn kind_from_wire(kind: schema::FileKind) -> FileKind {
    match kind {
        schema::FileKind::Regular => FileKind::Regular,
        schema::FileKind::Directory => FileKind::Directory,
        schema::FileKind::Symlink => FileKind::Symlink,
        schema::FileKind::Fifo => FileKind::Fifo,
        schema::FileKind::Socket => FileKind::Socket,
        schema::FileKind::CharDevice => FileKind::CharDevice,
        schema::FileKind::BlockDevice => FileKind::BlockDevice,
    }
}

fn build_path(mut list: capnp::data_list::Builder<'_>, path: &Path) {
    for (i, name) in path.names().iter().enumerate() {
        list.set(i as u32, name.as_bytes());
    }
}

fn parse_path(list: capnp::data_list::Reader<'_>) -> Result<Path, ErrorDecode> {
    if list.len() > MAX_PATH_COMPONENTS {
        return Err(ErrorDecode::Path(ErrorPathTooLong));
    }
    let mut names = Vec::with_capacity(list.len() as usize);
    let mut joined = 0usize;
    for item in list.iter() {
        let name = Name::new(item?)?;
        joined += name.as_bytes().len() + 1;
        if joined > PATH_MAX + 1 {
            return Err(ErrorDecode::Path(ErrorPathTooLong));
        }
        names.push(name);
    }
    Ok(Path::from_names(names)?)
}

fn parse_name(bytes: &[u8]) -> Result<Name, ErrorDecode> {
    Ok(Name::new(bytes)?)
}

fn build_attr(mut b: schema::attr::Builder<'_>, attr: &Attr) {
    b.set_ino(attr.ino);
    b.set_size(attr.size);
    b.set_blocks(attr.blocks);
    let mut t = b.reborrow().init_atime();
    t.set_sec(attr.atime.sec);
    t.set_nsec(attr.atime.nsec);
    let mut t = b.reborrow().init_mtime();
    t.set_sec(attr.mtime.sec);
    t.set_nsec(attr.mtime.nsec);
    let mut t = b.reborrow().init_ctime();
    t.set_sec(attr.ctime.sec);
    t.set_nsec(attr.ctime.nsec);
    b.set_kind(kind_to_wire(attr.kind));
    b.set_perm(attr.perm);
    b.set_nlink(attr.nlink);
    b.set_uid(attr.uid);
    b.set_gid(attr.gid);
    b.set_rdev(attr.rdev);
    b.set_blksize(attr.blksize);
    match &attr.xattr_names {
        None => b.init_xattr_names().set_unknown(()),
        Some(names) => {
            let mut list = b.init_xattr_names().init_some(names.len() as u32);
            for (i, name) in names.iter().enumerate() {
                list.set(i as u32, name);
            }
        }
    }
}

fn parse_attr(r: schema::attr::Reader<'_>) -> Result<Attr, ErrorDecode> {
    let atime = r.get_atime();
    let mtime = r.get_mtime();
    let ctime = r.get_ctime();
    Ok(Attr {
        ino: r.get_ino(),
        size: r.get_size(),
        blocks: r.get_blocks(),
        atime: TimeSpec {
            sec: atime.get_sec(),
            nsec: atime.get_nsec(),
        },
        mtime: TimeSpec {
            sec: mtime.get_sec(),
            nsec: mtime.get_nsec(),
        },
        ctime: TimeSpec {
            sec: ctime.get_sec(),
            nsec: ctime.get_nsec(),
        },
        kind: kind_from_wire(r.get_kind()?),
        perm: r.get_perm(),
        nlink: r.get_nlink(),
        uid: r.get_uid(),
        gid: r.get_gid(),
        rdev: r.get_rdev(),
        blksize: r.get_blksize(),
        xattr_names: match r.get_xattr_names().which()? {
            schema::attr::xattr_names::Unknown(()) => None,
            schema::attr::xattr_names::Some(list) => {
                let list = list?;
                let mut names = Vec::with_capacity(list.len() as usize);
                for i in 0..list.len() {
                    names.push(list.get(i)?.to_vec());
                }
                Some(names)
            }
        },
    })
}

fn build_statfs(mut b: schema::statfs::Builder<'_>, s: &Statfs) {
    b.set_blocks(s.blocks);
    b.set_bfree(s.bfree);
    b.set_bavail(s.bavail);
    b.set_files(s.files);
    b.set_ffree(s.ffree);
    b.set_bsize(s.bsize);
    b.set_namelen(s.namelen);
    b.set_frsize(s.frsize);
}

fn parse_statfs(r: schema::statfs::Reader<'_>) -> Statfs {
    Statfs {
        blocks: r.get_blocks(),
        bfree: r.get_bfree(),
        bavail: r.get_bavail(),
        files: r.get_files(),
        ffree: r.get_ffree(),
        bsize: r.get_bsize(),
        namelen: r.get_namelen(),
        frsize: r.get_frsize(),
    }
}

fn build_dir_entry(mut b: schema::dir_entry::Builder<'_>, e: &DirEntry) {
    b.set_ino(e.ino);
    b.set_next_offset(e.next_offset);
    b.set_kind(kind_to_wire(e.kind));
    b.set_name(&e.name);
}

fn parse_dir_entry(r: schema::dir_entry::Reader<'_>) -> Result<DirEntry, ErrorDecode> {
    Ok(DirEntry {
        ino: r.get_ino(),
        next_offset: r.get_next_offset(),
        kind: kind_from_wire(r.get_kind()?),
        name: r.get_name()?.to_vec(),
    })
}

fn build_time_or_now(mut b: schema::time_or_now::Builder<'_>, t: TimeOrNow) {
    match t {
        TimeOrNow::Time(ts) => {
            let mut w = b.init_time();
            w.set_sec(ts.sec);
            w.set_nsec(ts.nsec);
        }
        TimeOrNow::Now => b.set_now(()),
    }
}

fn parse_time_or_now(r: schema::time_or_now::Reader<'_>) -> Result<TimeOrNow, ErrorDecode> {
    Ok(match r.which()? {
        schema::time_or_now::Which::Time(ts) => {
            let ts = ts?;
            TimeOrNow::Time(TimeSpec {
                sec: ts.get_sec(),
                nsec: ts.get_nsec(),
            })
        }
        schema::time_or_now::Which::Now(()) => TimeOrNow::Now,
    })
}

fn build_set_attr(mut b: schema::set_attr::Builder<'_>, s: &SetAttr) {
    match s.mode {
        Some(v) => b.reborrow().get_mode().set_some(v),
        None => b.reborrow().get_mode().set_none(()),
    }
    match s.uid {
        Some(v) => b.reborrow().get_uid().set_some(v),
        None => b.reborrow().get_uid().set_none(()),
    }
    match s.gid {
        Some(v) => b.reborrow().get_gid().set_some(v),
        None => b.reborrow().get_gid().set_none(()),
    }
    match s.size {
        Some(v) => b.reborrow().get_size().set_some(v),
        None => b.reborrow().get_size().set_none(()),
    }
    match s.atime {
        Some(t) => build_time_or_now(b.reborrow().get_atime().init_some(), t),
        None => b.reborrow().get_atime().set_none(()),
    }
    match s.mtime {
        Some(t) => build_time_or_now(b.reborrow().get_mtime().init_some(), t),
        None => b.reborrow().get_mtime().set_none(()),
    }
}

fn parse_set_attr(r: schema::set_attr::Reader<'_>) -> Result<SetAttr, ErrorDecode> {
    use schema::set_attr as sa;
    Ok(SetAttr {
        mode: match r.get_mode().which()? {
            sa::mode::Which::None(()) => None,
            sa::mode::Which::Some(v) => Some(v),
        },
        uid: match r.get_uid().which()? {
            sa::uid::Which::None(()) => None,
            sa::uid::Which::Some(v) => Some(v),
        },
        gid: match r.get_gid().which()? {
            sa::gid::Which::None(()) => None,
            sa::gid::Which::Some(v) => Some(v),
        },
        size: match r.get_size().which()? {
            sa::size::Which::None(()) => None,
            sa::size::Which::Some(v) => Some(v),
        },
        atime: match r.get_atime().which()? {
            sa::atime::Which::None(()) => None,
            sa::atime::Which::Some(t) => Some(parse_time_or_now(t?)?),
        },
        mtime: match r.get_mtime().which()? {
            sa::mtime::Which::None(()) => None,
            sa::mtime::Which::Some(t) => Some(parse_time_or_now(t?)?),
        },
    })
}

// ---------- Hello / HelloReply ----------

impl Message for Hello {
    fn build(&self, message: &mut message::Builder<HeapAllocator>) {
        let mut b = message.init_root::<schema::hello::Builder<'_>>();
        b.set_revision(self.revision);
        match &self.auth {
            Auth::Anonymous => b.reborrow().get_auth().set_anonymous(()),
            Auth::Token(token) => b.reborrow().get_auth().set_token(token),
        }
        match &self.resume {
            None => b.reborrow().get_resume().set_none(()),
            Some(resume) => {
                let mut r = b.reborrow().get_resume().init_some();
                r.set_session_id(resume.session_id);
                r.set_token(&resume.token);
            }
        }
    }

    fn parse<S: ReaderSegments>(message: &message::Reader<S>) -> Result<Self, ErrorDecode> {
        let r = message.get_root::<schema::hello::Reader<'_>>()?;
        let auth = match r.get_auth().which()? {
            schema::hello::auth::Which::Anonymous(()) => Auth::Anonymous,
            schema::hello::auth::Which::Token(t) => Auth::Token(t?.to_vec()),
        };
        let resume = match r.get_resume().which()? {
            schema::hello::resume::Which::None(()) => None,
            schema::hello::resume::Which::Some(res) => {
                let res = res?;
                Some(Resume {
                    session_id: res.get_session_id(),
                    token: resume_token(res.get_token()?)?,
                })
            }
        };
        Ok(Hello {
            revision: r.get_revision(),
            auth,
            resume,
        })
    }

    fn size_hint(&self) -> u32 {
        let token = match &self.auth {
            Auth::Token(t) => words_for(t.len()),
            Auth::Anonymous => 0,
        };
        BASE_WORDS + token + 8
    }
}

fn resume_token(bytes: &[u8]) -> Result<[u8; 16], ErrorDecode> {
    bytes
        .try_into()
        .map_err(|_| ErrorDecode::Invalid(format!("resume token is {} bytes, not 16", bytes.len())))
}

impl Message for HelloReply {
    fn build(&self, message: &mut message::Builder<HeapAllocator>) {
        let b = message.init_root::<schema::hello_reply::Builder<'_>>();
        match self {
            HelloReply::Ack {
                session_id,
                resume_token,
                resumed,
            } => {
                let mut ack = b.init_ack();
                ack.set_session_id(*session_id);
                ack.set_resume_token(resume_token);
                ack.set_resumed(*resumed);
            }
            HelloReply::Reject { reason } => b.init_reject().set_reason(reason.as_str()),
            HelloReply::RevisionMismatch { revision } => {
                b.init_revision_mismatch().set_revision(*revision)
            }
        }
    }

    fn parse<S: ReaderSegments>(message: &message::Reader<S>) -> Result<Self, ErrorDecode> {
        let r = message.get_root::<schema::hello_reply::Reader<'_>>()?;
        Ok(match r.which()? {
            schema::hello_reply::Which::Ack(ack) => HelloReply::Ack {
                session_id: ack.get_session_id(),
                resume_token: resume_token(ack.get_resume_token()?)?,
                resumed: ack.get_resumed(),
            },
            schema::hello_reply::Which::Reject(reject) => {
                let reason = reject
                    .get_reason()?
                    .to_str()
                    .map_err(|e| ErrorDecode::Invalid(format!("reason is not UTF-8: {e}")))?;
                HelloReply::Reject {
                    reason: reason.to_string(),
                }
            }
            schema::hello_reply::Which::RevisionMismatch(m) => HelloReply::RevisionMismatch {
                revision: m.get_revision(),
            },
        })
    }

    fn size_hint(&self) -> u32 {
        BASE_WORDS
            + match self {
                HelloReply::Ack { .. } => 4,
                HelloReply::Reject { reason } => words_for_text(reason.len()),
                HelloReply::RevisionMismatch { .. } => 1,
            }
    }
}

// ---------- Request ----------

impl Message for Request {
    fn build(&self, message: &mut message::Builder<HeapAllocator>) {
        use schema::request as rq;
        let b = message.init_root::<rq::Builder<'_>>();
        match self {
            Request::Lookup { parent, name } => {
                let mut g = b.init_lookup();
                build_path(
                    g.reborrow().init_parent(parent.names().len() as u32),
                    parent,
                );
                g.set_name(name.as_bytes());
            }
            Request::Getattr { path, fh } => {
                let mut g = b.init_getattr();
                match path {
                    Some(p) => {
                        build_path(g.reborrow().get_path().init_some(p.names().len() as u32), p)
                    }
                    None => g.reborrow().get_path().set_none(()),
                }
                match fh {
                    Some(v) => g.reborrow().get_fh().set_some(*v),
                    None => g.reborrow().get_fh().set_none(()),
                }
            }
            Request::Setattr { path, fh, set } => {
                let mut g = b.init_setattr();
                match path {
                    Some(p) => {
                        build_path(g.reborrow().get_path().init_some(p.names().len() as u32), p)
                    }
                    None => g.reborrow().get_path().set_none(()),
                }
                match fh {
                    Some(v) => g.reborrow().get_fh().set_some(*v),
                    None => g.reborrow().get_fh().set_none(()),
                }
                build_set_attr(g.init_set(), set);
            }
            Request::Readlink { path } => {
                let g = b.init_readlink();
                build_path(g.init_path(path.names().len() as u32), path);
            }
            Request::Mknod {
                parent,
                name,
                mode,
                rdev,
            } => {
                let mut g = b.init_mknod();
                build_path(
                    g.reborrow().init_parent(parent.names().len() as u32),
                    parent,
                );
                g.set_name(name.as_bytes());
                g.set_mode(*mode);
                g.set_rdev(*rdev);
            }
            Request::Mkdir { parent, name, mode } => {
                let mut g = b.init_mkdir();
                build_path(
                    g.reborrow().init_parent(parent.names().len() as u32),
                    parent,
                );
                g.set_name(name.as_bytes());
                g.set_mode(*mode);
            }
            Request::Unlink { parent, name } => {
                let mut g = b.init_unlink();
                build_path(
                    g.reborrow().init_parent(parent.names().len() as u32),
                    parent,
                );
                g.set_name(name.as_bytes());
            }
            Request::Rmdir { parent, name } => {
                let mut g = b.init_rmdir();
                build_path(
                    g.reborrow().init_parent(parent.names().len() as u32),
                    parent,
                );
                g.set_name(name.as_bytes());
            }
            Request::Symlink {
                parent,
                name,
                target,
            } => {
                let mut g = b.init_symlink();
                build_path(
                    g.reborrow().init_parent(parent.names().len() as u32),
                    parent,
                );
                g.set_name(name.as_bytes());
                g.set_target(target);
            }
            Request::Rename {
                parent,
                name,
                newparent,
                newname,
                flags,
            } => {
                let mut g = b.init_rename();
                build_path(
                    g.reborrow().init_parent(parent.names().len() as u32),
                    parent,
                );
                g.set_name(name.as_bytes());
                build_path(
                    g.reborrow().init_new_parent(newparent.names().len() as u32),
                    newparent,
                );
                g.set_new_name(newname.as_bytes());
                g.set_flags(*flags);
            }
            Request::Link {
                path,
                newparent,
                newname,
            } => {
                let mut g = b.init_link();
                build_path(g.reborrow().init_path(path.names().len() as u32), path);
                build_path(
                    g.reborrow().init_new_parent(newparent.names().len() as u32),
                    newparent,
                );
                g.set_new_name(newname.as_bytes());
            }
            Request::Open { fh, path, flags } => {
                let mut g = b.init_open();
                g.set_fh(*fh);
                build_path(g.reborrow().init_path(path.names().len() as u32), path);
                g.set_flags(*flags);
            }
            Request::Create {
                fh,
                parent,
                name,
                mode,
                flags,
            } => {
                let mut g = b.init_create();
                g.set_fh(*fh);
                build_path(
                    g.reborrow().init_parent(parent.names().len() as u32),
                    parent,
                );
                g.set_name(name.as_bytes());
                g.set_mode(*mode);
                g.set_flags(*flags);
            }
            Request::Read { fh, offset, size } => {
                let mut g = b.init_read();
                g.set_fh(*fh);
                g.set_offset(*offset);
                g.set_size(*size);
            }
            Request::Write { fh, offset, data } => {
                let mut g = b.init_write();
                g.set_fh(*fh);
                g.set_offset(*offset);
                g.set_data(data);
            }
            Request::Release { fh } => b.init_release().set_fh(*fh),
            Request::Fsync { fh, datasync } => {
                let mut g = b.init_fsync();
                g.set_fh(*fh);
                g.set_datasync(*datasync);
            }
            Request::Opendir { fh, path } => {
                let mut g = b.init_opendir();
                g.set_fh(*fh);
                build_path(g.init_path(path.names().len() as u32), path);
            }
            Request::Readdir {
                fh,
                offset,
                max_bytes,
                plus,
            } => {
                let mut g = b.init_readdir();
                g.set_fh(*fh);
                g.set_offset(*offset);
                g.set_max_bytes(*max_bytes);
                g.set_plus(*plus);
            }
            Request::Releasedir { fh } => b.init_releasedir().set_fh(*fh),
            Request::Statfs { path } => {
                build_path(b.init_statfs().init_path(path.names().len() as u32), path)
            }
            Request::Setxattr {
                path,
                name,
                value,
                flags,
            } => {
                let mut g = b.init_setxattr();
                build_path(g.reborrow().init_path(path.names().len() as u32), path);
                g.set_name(name);
                g.set_value(value);
                g.set_flags(*flags);
            }
            Request::Getxattr { path, name } => {
                let mut g = b.init_getxattr();
                build_path(g.reborrow().init_path(path.names().len() as u32), path);
                g.set_name(name);
            }
            Request::Listxattr { path } => build_path(
                b.init_listxattr().init_path(path.names().len() as u32),
                path,
            ),
            Request::Removexattr { path, name } => {
                let mut g = b.init_removexattr();
                build_path(g.reborrow().init_path(path.names().len() as u32), path);
                g.set_name(name);
            }
            Request::Access { path, mask } => {
                let mut g = b.init_access();
                build_path(g.reborrow().init_path(path.names().len() as u32), path);
                g.set_mask(*mask);
            }
        }
    }

    fn parse<S: ReaderSegments>(message: &message::Reader<S>) -> Result<Self, ErrorDecode> {
        use schema::request as rq;
        let r = message.get_root::<rq::Reader<'_>>()?;
        Ok(match r.which()? {
            rq::Which::Lookup(g) => Request::Lookup {
                parent: parse_path(g.get_parent()?)?,
                name: parse_name(g.get_name()?)?,
            },
            rq::Which::Getattr(g) => Request::Getattr {
                path: match g.get_path().which()? {
                    rq::getattr::path::Which::None(()) => None,
                    rq::getattr::path::Which::Some(p) => Some(parse_path(p?)?),
                },
                fh: match g.get_fh().which()? {
                    rq::getattr::fh::Which::None(()) => None,
                    rq::getattr::fh::Which::Some(v) => Some(v),
                },
            },
            rq::Which::Setattr(g) => Request::Setattr {
                path: match g.get_path().which()? {
                    rq::setattr::path::Which::None(()) => None,
                    rq::setattr::path::Which::Some(p) => Some(parse_path(p?)?),
                },
                fh: match g.get_fh().which()? {
                    rq::setattr::fh::Which::None(()) => None,
                    rq::setattr::fh::Which::Some(v) => Some(v),
                },
                set: parse_set_attr(g.get_set()?)?,
            },
            rq::Which::Readlink(g) => Request::Readlink {
                path: parse_path(g.get_path()?)?,
            },
            rq::Which::Mknod(g) => Request::Mknod {
                parent: parse_path(g.get_parent()?)?,
                name: parse_name(g.get_name()?)?,
                mode: g.get_mode(),
                rdev: g.get_rdev(),
            },
            rq::Which::Mkdir(g) => Request::Mkdir {
                parent: parse_path(g.get_parent()?)?,
                name: parse_name(g.get_name()?)?,
                mode: g.get_mode(),
            },
            rq::Which::Unlink(g) => Request::Unlink {
                parent: parse_path(g.get_parent()?)?,
                name: parse_name(g.get_name()?)?,
            },
            rq::Which::Rmdir(g) => Request::Rmdir {
                parent: parse_path(g.get_parent()?)?,
                name: parse_name(g.get_name()?)?,
            },
            rq::Which::Symlink(g) => Request::Symlink {
                parent: parse_path(g.get_parent()?)?,
                name: parse_name(g.get_name()?)?,
                target: g.get_target()?.to_vec(),
            },
            rq::Which::Rename(g) => Request::Rename {
                parent: parse_path(g.get_parent()?)?,
                name: parse_name(g.get_name()?)?,
                newparent: parse_path(g.get_new_parent()?)?,
                newname: parse_name(g.get_new_name()?)?,
                flags: g.get_flags(),
            },
            rq::Which::Link(g) => Request::Link {
                path: parse_path(g.get_path()?)?,
                newparent: parse_path(g.get_new_parent()?)?,
                newname: parse_name(g.get_new_name()?)?,
            },
            rq::Which::Open(g) => Request::Open {
                fh: g.get_fh(),
                path: parse_path(g.get_path()?)?,
                flags: g.get_flags(),
            },
            rq::Which::Create(g) => Request::Create {
                fh: g.get_fh(),
                parent: parse_path(g.get_parent()?)?,
                name: parse_name(g.get_name()?)?,
                mode: g.get_mode(),
                flags: g.get_flags(),
            },
            rq::Which::Read(g) => Request::Read {
                fh: g.get_fh(),
                offset: g.get_offset(),
                size: g.get_size(),
            },
            rq::Which::Write(g) => Request::Write {
                fh: g.get_fh(),
                offset: g.get_offset(),
                data: g.get_data()?.to_vec(),
            },
            rq::Which::Release(g) => Request::Release { fh: g.get_fh() },
            rq::Which::Fsync(g) => Request::Fsync {
                fh: g.get_fh(),
                datasync: g.get_datasync(),
            },
            rq::Which::Opendir(g) => Request::Opendir {
                fh: g.get_fh(),
                path: parse_path(g.get_path()?)?,
            },
            rq::Which::Readdir(g) => Request::Readdir {
                fh: g.get_fh(),
                offset: g.get_offset(),
                max_bytes: g.get_max_bytes(),
                plus: g.get_plus(),
            },
            rq::Which::Releasedir(g) => Request::Releasedir { fh: g.get_fh() },
            rq::Which::Statfs(g) => Request::Statfs {
                path: parse_path(g.get_path()?)?,
            },
            rq::Which::Setxattr(g) => Request::Setxattr {
                path: parse_path(g.get_path()?)?,
                name: g.get_name()?.to_vec(),
                value: g.get_value()?.to_vec(),
                flags: g.get_flags(),
            },
            rq::Which::Getxattr(g) => Request::Getxattr {
                path: parse_path(g.get_path()?)?,
                name: g.get_name()?.to_vec(),
            },
            rq::Which::Listxattr(g) => Request::Listxattr {
                path: parse_path(g.get_path()?)?,
            },
            rq::Which::Removexattr(g) => Request::Removexattr {
                path: parse_path(g.get_path()?)?,
                name: g.get_name()?.to_vec(),
            },
            rq::Which::Access(g) => Request::Access {
                path: parse_path(g.get_path()?)?,
                mask: g.get_mask(),
            },
        })
    }

    fn size_hint(&self) -> u32 {
        let payload = match self {
            Request::Lookup { parent, name }
            | Request::Unlink { parent, name }
            | Request::Rmdir { parent, name }
            | Request::Mkdir { parent, name, .. }
            | Request::Mknod { parent, name, .. }
            | Request::Create { parent, name, .. } => {
                words_for_path(parent) + words_for(name.as_bytes().len())
            }
            Request::Getattr { path, .. } | Request::Setattr { path, .. } => {
                path.as_ref().map_or(0, words_for_path) + 16
            }
            Request::Readlink { path }
            | Request::Open { path, .. }
            | Request::Opendir { path, .. }
            | Request::Statfs { path }
            | Request::Listxattr { path } => words_for_path(path),
            Request::Symlink {
                parent,
                name,
                target,
            } => {
                words_for_path(parent) + words_for(name.as_bytes().len()) + words_for(target.len())
            }
            Request::Rename {
                parent,
                name,
                newparent,
                newname,
                ..
            } => {
                words_for_path(parent)
                    + words_for(name.as_bytes().len())
                    + words_for_path(newparent)
                    + words_for(newname.as_bytes().len())
            }
            Request::Link {
                path,
                newparent,
                newname,
            } => {
                words_for_path(path)
                    + words_for_path(newparent)
                    + words_for(newname.as_bytes().len())
            }
            Request::Write { data, .. } => words_for(data.len()),
            Request::Setxattr {
                path, name, value, ..
            } => words_for_path(path) + words_for(name.len()) + words_for(value.len()),
            Request::Getxattr { path, name } | Request::Removexattr { path, name } => {
                words_for_path(path) + words_for(name.len())
            }
            Request::Access { path, .. } => words_for_path(path),
            Request::Read { .. }
            | Request::Release { .. }
            | Request::Fsync { .. }
            | Request::Readdir { .. }
            | Request::Releasedir { .. } => 0,
        };
        BASE_WORDS + payload
    }
}

// ---------- Response ----------

/// Words per directory entry in a composite list, excluding the name data; a `DirEntryPlus` adds its own three words and a thirteen-word `Attr`, whose names are added per name.
const DIR_ENTRY_WORDS: u32 = 4;
const DIR_ENTRY_PLUS_WORDS: u32 = 20;
/// An `Attr` in a reply, with the reply's own words; a word or two over, on purpose, since an under-estimate costs a canonicalizing copy.
const ATTR_WORDS: u32 = 18;

/// Words per `EventItem` in a composite list, excluding path and name data.
const EVENT_ITEM_WORDS: u32 = 3;

impl Message for Response {
    fn build(&self, message: &mut message::Builder<HeapAllocator>) {
        use schema::response as rs;
        let mut b = message.init_root::<rs::Builder<'_>>();
        match self {
            Response::Err(errno) => b.set_err(*errno),
            Response::Entry(attr) => build_attr(b.init_entry().init_attr(), attr),
            Response::Attr(attr) => build_attr(b.init_attr(), attr),
            Response::Readlink(target) => b.set_readlink(target),
            Response::Ok => b.set_ok(()),
            Response::Opened { attr } => build_attr(b.init_opened().init_attr(), attr),
            Response::Read(data) => b.init_read().set_data(data),
            Response::Written(n) => b.set_written(*n),
            Response::Readdir { entries, end } => {
                let mut g = b.init_readdir();
                g.set_end(*end);
                let mut list = g.init_entries(entries.len() as u32);
                for (i, e) in entries.iter().enumerate() {
                    build_dir_entry(list.reborrow().get(i as u32), e);
                }
            }
            Response::ReaddirPlus { entries, end } => {
                let mut g = b.init_readdir_plus();
                g.set_end(*end);
                let mut list = g.init_entries(entries.len() as u32);
                for (i, e) in entries.iter().enumerate() {
                    let mut item = list.reborrow().get(i as u32);
                    build_dir_entry(item.reborrow().init_entry(), &e.entry);
                    match &e.attr {
                        Some(attr) => build_attr(item.get_attr().init_some(), attr),
                        None => item.get_attr().set_none(()),
                    }
                }
            }
            Response::Statfs(s) => build_statfs(b.init_statfs(), s),
            Response::Xattr(value) => b.set_xattr(value),
        }
    }

    fn parse<S: ReaderSegments>(message: &message::Reader<S>) -> Result<Self, ErrorDecode> {
        use schema::response as rs;
        let r = message.get_root::<rs::Reader<'_>>()?;
        Ok(match r.which()? {
            rs::Which::Err(errno) => Response::Err(errno),
            rs::Which::Entry(g) => Response::Entry(parse_attr(g.get_attr()?)?),
            rs::Which::Attr(attr) => Response::Attr(parse_attr(attr?)?),
            rs::Which::Readlink(target) => Response::Readlink(target?.to_vec()),
            rs::Which::Ok(()) => Response::Ok,
            rs::Which::Opened(g) => Response::Opened {
                attr: parse_attr(g.get_attr()?)?,
            },
            rs::Which::Read(g) => Response::Read(g.get_data()?.to_vec()),
            rs::Which::Written(n) => Response::Written(n),
            rs::Which::Readdir(g) => {
                let list = g.get_entries()?;
                let mut entries =
                    Vec::with_capacity(checked_len(list.len(), message.size_in_words())?);
                for item in list.iter() {
                    entries.push(parse_dir_entry(item)?);
                }
                Response::Readdir {
                    entries,
                    end: g.get_end(),
                }
            }
            rs::Which::ReaddirPlus(g) => {
                let list = g.get_entries()?;
                let mut entries =
                    Vec::with_capacity(checked_len(list.len(), message.size_in_words())?);
                for item in list.iter() {
                    let attr = match item.get_attr().which()? {
                        schema::dir_entry_plus::attr::Which::None(()) => None,
                        schema::dir_entry_plus::attr::Which::Some(attr) => Some(parse_attr(attr?)?),
                    };
                    entries.push(DirEntryPlus {
                        entry: parse_dir_entry(item.get_entry()?)?,
                        attr,
                    });
                }
                Response::ReaddirPlus {
                    entries,
                    end: g.get_end(),
                }
            }
            rs::Which::Statfs(s) => Response::Statfs(parse_statfs(s?)),
            rs::Which::Xattr(value) => Response::Xattr(value?.to_vec()),
        })
    }

    fn size_hint(&self) -> u32 {
        let payload = match self {
            Response::Err(_) | Response::Ok | Response::Written(_) => 0,
            Response::Entry(attr) | Response::Attr(attr) | Response::Opened { attr } => {
                ATTR_WORDS + words_for_xattr_names(attr.xattr_names.as_deref())
            }
            Response::Readlink(b) | Response::Read(b) | Response::Xattr(b) => words_for(b.len()),
            Response::Readdir { entries, .. } => entries
                .iter()
                .map(|e| DIR_ENTRY_WORDS + e.name.len().div_ceil(8) as u32)
                .sum(),
            Response::ReaddirPlus { entries, .. } => entries
                .iter()
                .map(|e| {
                    DIR_ENTRY_PLUS_WORDS
                        + e.entry.name.len().div_ceil(8) as u32
                        + words_for_xattr_names(
                            e.attr.as_ref().and_then(|a| a.xattr_names.as_deref()),
                        )
                })
                .sum(),
            Response::Statfs(_) => 8,
        };
        BASE_WORDS + payload
    }
}

// ---------- Event ----------

impl Message for Event {
    fn build(&self, message: &mut message::Builder<HeapAllocator>) {
        let b = message.init_root::<schema::event::Builder<'_>>();
        let mut list = b.init_items(self.items.len() as u32);
        for (i, item) in self.items.iter().enumerate() {
            let mut w = list.reborrow().get(i as u32);
            match item {
                EventItem::Entry { dir, name } => {
                    let mut g = w.init_entry();
                    build_path(g.reborrow().init_dir(dir.names().len() as u32), dir);
                    g.set_name(name.as_bytes());
                }
                EventItem::Data { path } => {
                    build_path(w.init_data(path.names().len() as u32), path)
                }
                EventItem::Overflow => w.set_overflow(()),
            }
        }
    }

    fn parse<S: ReaderSegments>(message: &message::Reader<S>) -> Result<Self, ErrorDecode> {
        use schema::event_item as ei;
        let r = message.get_root::<schema::event::Reader<'_>>()?;
        let list = r.get_items()?;
        let mut items = Vec::with_capacity(checked_len(list.len(), message.size_in_words())?);
        for item in list.iter() {
            items.push(match item.which()? {
                ei::Which::Entry(g) => EventItem::Entry {
                    dir: parse_path(g.get_dir()?)?,
                    name: parse_name(g.get_name()?)?,
                },
                ei::Which::Data(path) => EventItem::Data {
                    path: parse_path(path?)?,
                },
                ei::Which::Overflow(()) => EventItem::Overflow,
            });
        }
        Ok(Event { items })
    }

    fn size_hint(&self) -> u32 {
        BASE_WORDS
            + self
                .items
                .iter()
                .map(|item| match item {
                    EventItem::Entry { dir, name } => {
                        4 + words_for_path(dir) + words_for(name.as_bytes().len())
                    }
                    EventItem::Data { path } => EVENT_ITEM_WORDS + words_for_path(path),
                    EventItem::Overflow => EVENT_ITEM_WORDS,
                })
                .sum::<u32>()
    }
}

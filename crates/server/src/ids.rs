//! Which owners the server lets through (`--ids`). `direct` sends every owner as the filesystem has it and applies whatever ids a client asks for, subject to this process's privileges. `flatten` lets only this process's own uid and gid cross: every other owner goes out as nobody, and a request naming another id is refused. That is policy the server enforces whatever the client does; a client decides separately how to show what it gets.

use jackalopefs_proto::owners::{self, KindOwner, NOBODY};
use jackalopefs_proto::{Request, Response};
use nix::errno::Errno;

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum ModeIds {
    Direct,
    Flatten,
}

#[derive(Clone, Copy, Debug)]
pub struct IdMap {
    pub mode: ModeIds,
    /// This process's effective ids, which own everything it creates.
    pub uid: u32,
    pub gid: u32,
}

impl IdMap {
    /// The map for this process. Flattening as nobody is refused: every other owner would be indistinguishable from the server's own.
    pub fn of_process(mode: ModeIds) -> Result<IdMap, String> {
        IdMap::new(
            mode,
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        )
    }

    pub fn new(mode: ModeIds, uid: u32, gid: u32) -> Result<IdMap, String> {
        if mode == ModeIds::Flatten && (uid == NOBODY || gid == NOBODY) {
            return Err(format!("--ids flatten cannot run as uid {uid} gid {gid}: every other owner goes out as nobody ({NOBODY}), which would be indistinguishable from this server's own; run as a user and group of its own, or with --ids direct"));
        }
        Ok(IdMap { mode, uid, gid })
    }

    /// Whether `req` may run: under `flatten`, it names no owner but the server's own, and touches no `system.*` attribute but the POSIX ACLs.
    pub fn admit(&self, req: &Request) -> Result<(), Errno> {
        if self.mode == ModeIds::Direct {
            return Ok(());
        }
        match req {
            Request::Setattr { set, .. } => {
                if set.uid.is_some_and(|uid| uid != self.uid)
                    || set.gid.is_some_and(|gid| gid != self.gid)
                {
                    return Err(Errno::EPERM);
                }
                Ok(())
            }
            Request::Setxattr { name, value, .. } if owners::is_posix_acl(name) => {
                // An honest client's kernel encodes every ACL itself; one that does not parse is not from one.
                let mut named = owners::acl_owners(value).ok_or(Errno::EINVAL)?;
                if named.all(|(kind, id)| id == self.own(kind)) {
                    Ok(())
                } else {
                    Err(Errno::EPERM)
                }
            }
            Request::Setxattr { name, .. }
            | Request::Getxattr { name, .. }
            | Request::Removexattr { name, .. } => {
                if name.starts_with(b"system.") && !owners::is_posix_acl(name) {
                    return Err(Errno::EOPNOTSUPP);
                }
                Ok(())
            }
            Request::Lookup { .. }
            | Request::Getattr { .. }
            | Request::Readlink { .. }
            | Request::Mknod { .. }
            | Request::Mkdir { .. }
            | Request::Unlink { .. }
            | Request::Rmdir { .. }
            | Request::Symlink { .. }
            | Request::Rename { .. }
            | Request::Link { .. }
            | Request::Open { .. }
            | Request::Create { .. }
            | Request::Read { .. }
            | Request::Write { .. }
            | Request::Release { .. }
            | Request::Fsync { .. }
            | Request::Opendir { .. }
            | Request::Readdir { .. }
            | Request::Releasedir { .. }
            | Request::Statfs { .. }
            | Request::Listxattr { .. }
            | Request::Access { .. }
            | Request::CopyFileRange { .. }
            | Request::Fallocate { .. }
            | Request::Lseek { .. } => Ok(()),
        }
    }

    /// Rewrite the owners in `resp`; `posix_acl_read` says it answers a read of a POSIX ACL ([`owners::reads_posix_acl`]).
    pub fn reply(&self, posix_acl_read: bool, resp: &mut Response) {
        if self.mode == ModeIds::Flatten {
            owners::map_reply(resp, posix_acl_read, |kind, id| {
                if id == self.own(kind) {
                    id
                } else {
                    NOBODY
                }
            });
        }
    }

    fn own(&self, kind: KindOwner) -> u32 {
        match kind {
            KindOwner::User => self.uid,
            KindOwner::Group => self.gid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jackalopefs_proto::{Attr, FileKind, Identity, Path, SetAttr, TimeSpec};

    const UID: u32 = 1005;
    const GID: u32 = 1000;

    fn flatten() -> IdMap {
        IdMap::new(ModeIds::Flatten, UID, GID).unwrap()
    }

    fn direct() -> IdMap {
        IdMap::new(ModeIds::Direct, UID, GID).unwrap()
    }

    fn attr(uid: u32, gid: u32) -> Attr {
        let t = TimeSpec { sec: 0, nsec: 0 };
        Attr {
            ino: 5,
            size: 0,
            blocks: 0,
            atime: t,
            mtime: t,
            ctime: t,
            kind: FileKind::Regular,
            perm: 0o644,
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            blksize: 4096,
            xattr_names: None,
            identity: Identity {
                handle_type: 1,
                handle: vec![5],
            },
            foreign: false,
        }
    }

    /// The owner an attribute reply owned by `uid`/`gid` goes out with; which replies carry owners is `owners::map_reply`'s, tested there.
    fn mapped(map: &IdMap, uid: u32, gid: u32) -> (u32, u32) {
        let mut resp = Response::Attr(attr(uid, gid));
        map.reply(false, &mut resp);
        match resp {
            Response::Attr(a) => (a.uid, a.gid),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn flatten_sends_only_its_own_owners() {
        assert_eq!(mapped(&flatten(), UID, GID), (UID, GID));
        assert_eq!(mapped(&flatten(), 7, 8), (NOBODY, NOBODY));
        assert_eq!(mapped(&flatten(), UID, 8), (UID, NOBODY));
        assert_eq!(mapped(&flatten(), 0, GID), (NOBODY, GID));
    }

    #[test]
    fn direct_sends_owners_as_they_are() {
        assert_eq!(mapped(&direct(), 7, 8), (7, 8));
    }

    use jackalopefs_proto::owners::{
        ACL_GROUP, ACL_OTHER, ACL_UNDEFINED_ID, ACL_USER, ACL_USER_OBJ,
    };

    fn acl(entries: &[(u16, u32)]) -> Vec<u8> {
        let mut blob = 2u32.to_le_bytes().to_vec();
        for (tag, id) in entries {
            blob.extend(tag.to_le_bytes());
            blob.extend(6u16.to_le_bytes());
            blob.extend(id.to_le_bytes());
        }
        blob
    }

    fn acl_naming(user: u32, group: u32) -> Vec<u8> {
        acl(&[
            (ACL_USER_OBJ, ACL_UNDEFINED_ID),
            (ACL_USER, user),
            (ACL_GROUP, group),
            (ACL_OTHER, ACL_UNDEFINED_ID),
        ])
    }

    #[test]
    fn flatten_sends_only_its_own_acl_entries() {
        let read = |map: &IdMap, value: Vec<u8>| {
            let mut resp = Response::Xattr(value);
            map.reply(true, &mut resp);
            resp
        };
        assert_eq!(
            read(&flatten(), acl_naming(UID, GID)),
            Response::Xattr(acl_naming(UID, GID))
        );
        assert_eq!(
            read(&flatten(), acl_naming(7, 8)),
            Response::Xattr(acl_naming(NOBODY, NOBODY))
        );
        assert_eq!(
            read(&direct(), acl_naming(7, 8)),
            Response::Xattr(acl_naming(7, 8))
        );
        // What does not parse is not an ACL anyone can read an owner from; the server's kernel produced it.
        assert_eq!(
            read(&flatten(), vec![1, 2, 3]),
            Response::Xattr(vec![1, 2, 3])
        );
    }

    fn chown(uid: Option<u32>, gid: Option<u32>) -> Request {
        Request::Setattr {
            path: Some(Path::root()),
            fh: None,
            set: SetAttr {
                mode: Some(0o600),
                uid,
                gid,
                ..SetAttr::default()
            },
        }
    }

    fn setxattr(name: &[u8], value: Vec<u8>) -> Request {
        Request::Setxattr {
            path: Path::root(),
            name: name.to_vec(),
            value,
            flags: 0,
        }
    }

    fn removexattr(name: &[u8]) -> Request {
        Request::Removexattr {
            path: Path::root(),
            name: name.to_vec(),
        }
    }

    fn getxattr(name: &[u8]) -> Request {
        Request::Getxattr {
            path: Path::root(),
            name: name.to_vec(),
        }
    }

    #[test]
    fn flatten_admits_only_its_own_owners() {
        let map = flatten();
        for (uid, gid) in [
            (Some(UID), Some(GID)),
            (Some(UID), None),
            (None, Some(GID)),
            (None, None),
        ] {
            assert_eq!(map.admit(&chown(uid, gid)), Ok(()), "{uid:?} {gid:?}");
        }
        // Nobody included: a chown copied from what the server sent must not overwrite the owner it hid.
        for (uid, gid) in [
            (Some(0), None),
            (None, Some(0)),
            (Some(NOBODY), None),
            (None, Some(NOBODY)),
            (Some(UID), Some(8)),
        ] {
            assert_eq!(
                map.admit(&chown(uid, gid)),
                Err(Errno::EPERM),
                "{uid:?} {gid:?}"
            );
        }
        for name in [&b"system.posix_acl_access"[..], b"system.posix_acl_default"] {
            assert_eq!(map.admit(&setxattr(name, acl_naming(UID, GID))), Ok(()));
            assert_eq!(
                map.admit(&setxattr(
                    name,
                    acl(&[
                        (ACL_USER_OBJ, ACL_UNDEFINED_ID),
                        (ACL_OTHER, ACL_UNDEFINED_ID)
                    ])
                )),
                Ok(())
            );
            for (user, group) in [(7, GID), (UID, 8), (NOBODY, GID), (UID, NOBODY)] {
                assert_eq!(
                    map.admit(&setxattr(name, acl_naming(user, group))),
                    Err(Errno::EPERM),
                    "{user} {group}"
                );
            }
            // An honest client's kernel encodes every ACL itself; one that does not parse is not from one.
            assert_eq!(
                map.admit(&setxattr(name, vec![1, 2, 3])),
                Err(Errno::EINVAL)
            );
            assert_eq!(map.admit(&getxattr(name)), Ok(()));
        }
    }

    /// The rest of `system.*` holds the other ACL formats, whose principals the server cannot map, so it is not touched at all.
    #[test]
    fn flatten_refuses_the_rest_of_system() {
        let map = flatten();
        for name in [
            &b"system.nfs4_acl"[..],
            b"system.richacl",
            b"system.cifs_acl",
            b"system.ntfs_attrib",
        ] {
            assert_eq!(map.admit(&getxattr(name)), Err(Errno::EOPNOTSUPP));
            assert_eq!(
                map.admit(&setxattr(name, vec![0; 8])),
                Err(Errno::EOPNOTSUPP)
            );
            assert_eq!(map.admit(&removexattr(name)), Err(Errno::EOPNOTSUPP));
        }
        for name in [
            &b"user.x"[..],
            b"trusted.x",
            b"security.selinux",
            b"system.posix_acl_access",
        ] {
            assert_eq!(map.admit(&getxattr(name)), Ok(()));
            assert_eq!(map.admit(&removexattr(name)), Ok(()));
        }
        for name in [&b"user.x"[..], b"trusted.x", b"security.selinux"] {
            assert_eq!(map.admit(&setxattr(name, acl_naming(7, 8))), Ok(()));
        }
    }

    #[test]
    fn direct_admits_everything() {
        let map = direct();
        for req in [
            chown(Some(0), Some(0)),
            chown(Some(NOBODY), None),
            setxattr(b"system.posix_acl_access", acl_naming(7, 8)),
            setxattr(b"system.posix_acl_access", vec![1]),
            setxattr(b"system.nfs4_acl", vec![0; 8]),
            getxattr(b"system.nfs4_acl"),
            removexattr(b"system.nfs4_acl"),
        ] {
            assert_eq!(map.admit(&req), Ok(()), "{req:?}");
        }
    }

    #[test]
    fn flatten_cannot_run_as_nobody() {
        assert!(IdMap::new(ModeIds::Flatten, NOBODY, GID).is_err());
        assert!(IdMap::new(ModeIds::Flatten, UID, NOBODY).is_err());
        assert!(IdMap::new(ModeIds::Direct, NOBODY, NOBODY).is_ok());
    }
}

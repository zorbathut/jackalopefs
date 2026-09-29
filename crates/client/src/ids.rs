//! How this mount shows file owners (`--ids`). `direct` shows every owner as the server sends it and sends ids as given. `owned` makes the server's user this mount's user: the uid and gid the server runs as (its `Ack` says which) show as the local user's, and every other owner as nobody, since a number from another machine names nobody here; going out, only the local user's own ids have a server counterpart. This is presentation only: what a client may do is the server's to decide (its own `--ids`). Owners travel in attributes, in `setattr`, and inside POSIX ACLs, which the kernel converts to and from their extended attribute form.

use crate::client::Error;
use jackalopefs_proto::owners::{self, KindOwner, NOBODY};
use jackalopefs_proto::{Request, Response, SetAttr};

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum ModeIds {
    Direct,
    Owned,
}

#[derive(Clone, Copy, Debug)]
pub enum IdMap {
    Direct,
    Owned(Owned),
}

#[derive(Clone, Copy, Debug)]
pub struct Owned {
    pub server_uid: u32,
    pub server_gid: u32,
    pub local_uid: u32,
    pub local_gid: u32,
}

impl IdMap {
    /// The map for a connection in `mode` to a server running as `server_uid`/`server_gid`, from this process's own ids.
    pub fn new(mode: ModeIds, server_uid: u32, server_gid: u32) -> IdMap {
        match mode {
            ModeIds::Direct => IdMap::Direct,
            ModeIds::Owned => IdMap::Owned(Owned {
                server_uid,
                server_gid,
                local_uid: nix::unistd::geteuid().as_raw(),
                local_gid: nix::unistd::getegid().as_raw(),
            }),
        }
    }

    /// What the connection log says about it.
    pub fn describe(&self) -> String {
        match self {
            IdMap::Direct => "direct".to_string(),
            IdMap::Owned(Owned {
                server_uid,
                server_gid,
                local_uid,
                local_gid,
            }) => format!("owned: server {server_uid}:{server_gid} is local {local_uid}:{local_gid}, other owners are nobody"),
        }
    }

    /// Why this map may mislead, if it may: nobody on either side makes nobody's files look like the user's, or the user's like nobody's, and a server running as root makes every root-owned file on it look like the user's.
    pub fn caveat(&self) -> Option<String> {
        let IdMap::Owned(owned) = self else {
            return None;
        };
        if [
            owned.server_uid,
            owned.server_gid,
            owned.local_uid,
            owned.local_gid,
        ]
        .contains(&NOBODY)
        {
            return Some(format!("--ids owned with nobody ({NOBODY}) on one side: files owned by nobody and files owned by the mapped user look alike ({})", self.describe()));
        }
        (owned.server_uid == 0 && owned.local_uid != 0).then(|| format!("--ids owned with a server running as root: every file root owns on the server shows as yours, and a chown to yourself gives the file to root there ({})", self.describe()))
    }

    /// Rewrite every owner in a reply to `req` into local terms.
    pub fn incoming(&self, req: &Request, resp: &mut Response) {
        match self {
            IdMap::Direct => {}
            IdMap::Owned(owned) => owned.incoming(req, resp),
        }
    }

    /// `req` with every owner in server terms, `None` if it carries none; an owner other than the local user's has no counterpart and fails the request before it is sent. An ACL that does not parse goes as it is, for the server to judge.
    pub fn outgoing(&self, req: &Request) -> Result<Option<Request>, Error> {
        match self {
            IdMap::Direct => Ok(None),
            IdMap::Owned(owned) => owned.outgoing(req),
        }
    }
}

impl Owned {
    fn incoming(&self, req: &Request, resp: &mut Response) {
        owners::map_reply(resp, owners::reads_posix_acl(req), |kind, id| {
            self.local(kind, id)
        });
    }

    fn outgoing(&self, req: &Request) -> Result<Option<Request>, Error> {
        match req {
            Request::Setattr { path, fh, set } if set.uid.is_some() || set.gid.is_some() => {
                Ok(Some(Request::Setattr {
                    path: path.clone(),
                    fh: *fh,
                    set: SetAttr {
                        uid: set
                            .uid
                            .map(|id| self.server(KindOwner::User, id))
                            .transpose()?,
                        gid: set
                            .gid
                            .map(|id| self.server(KindOwner::Group, id))
                            .transpose()?,
                        ..*set
                    },
                }))
            }
            Request::Setxattr {
                path,
                name,
                value,
                flags,
            } if owners::is_posix_acl(name) => {
                let Some(mut named) = owners::acl_owners(value) else {
                    return Ok(None);
                };
                if !named.all(|(kind, id)| self.server(kind, id).is_ok()) {
                    return Err(Error::Unmapped);
                }
                let mut value = value.clone();
                owners::acl_map(&mut value, |kind, _| self.pair(kind).0);
                Ok(Some(Request::Setxattr {
                    path: path.clone(),
                    name: name.clone(),
                    value,
                    flags: *flags,
                }))
            }
            _ => Ok(None),
        }
    }

    /// The server's and the local id of `kind`.
    fn pair(&self, kind: KindOwner) -> (u32, u32) {
        match kind {
            KindOwner::User => (self.server_uid, self.local_uid),
            KindOwner::Group => (self.server_gid, self.local_gid),
        }
    }

    fn local(&self, kind: KindOwner, id: u32) -> u32 {
        let (server, local) = self.pair(kind);
        if id == server {
            local
        } else {
            NOBODY
        }
    }

    fn server(&self, kind: KindOwner, id: u32) -> Result<u32, Error> {
        let (server, local) = self.pair(kind);
        if id == local {
            Ok(server)
        } else {
            Err(Error::Unmapped)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jackalopefs_proto::{Attr, FileKind, Identity, Path, SetAttr, TimeSpec};

    const MAP: IdMap = IdMap::Owned(Owned {
        server_uid: 1005,
        server_gid: 1000,
        local_uid: 1000,
        local_gid: 100,
    });

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

    fn owner(attr: &Attr) -> (u32, u32) {
        (attr.uid, attr.gid)
    }

    fn getattr() -> Request {
        Request::Getattr {
            path: Some(Path::root()),
            fh: None,
        }
    }

    fn setattr(uid: Option<u32>, gid: Option<u32>) -> Request {
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

    fn incoming_owner(map: &IdMap, uid: u32, gid: u32) -> (u32, u32) {
        let mut resp = Response::Attr(attr(uid, gid));
        map.incoming(&getattr(), &mut resp);
        match resp {
            Response::Attr(a) => owner(&a),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_server_user_is_the_local_user_and_everyone_else_is_nobody() {
        assert_eq!(incoming_owner(&MAP, 1005, 1000), (1000, 100));
        // The local user's own number on the server is some other account there.
        assert_eq!(incoming_owner(&MAP, 1000, 100), (NOBODY, NOBODY));
        assert_eq!(incoming_owner(&MAP, 0, 0), (NOBODY, NOBODY));
        assert_eq!(incoming_owner(&MAP, NOBODY, NOBODY), (NOBODY, NOBODY));
        // Owner and group map independently.
        assert_eq!(incoming_owner(&MAP, 1005, 7), (1000, NOBODY));
        assert_eq!(incoming_owner(&MAP, 7, 1000), (NOBODY, 100));
    }

    #[test]
    fn a_server_running_as_the_local_user_changes_nothing_for_its_files() {
        let same = IdMap::Owned(Owned {
            server_uid: 1000,
            server_gid: 100,
            local_uid: 1000,
            local_gid: 100,
        });
        assert_eq!(incoming_owner(&same, 1000, 100), (1000, 100));
        assert_eq!(incoming_owner(&same, 0, 0), (NOBODY, NOBODY));
    }

    #[test]
    fn a_chown_to_the_local_user_goes_out_as_the_server_user() {
        let Request::Setattr { set, .. } = MAP
            .outgoing(&setattr(Some(1000), Some(100)))
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            (set.uid, set.gid, set.mode),
            (Some(1005), Some(1000), Some(0o600))
        );
        let Request::Setattr { set, .. } =
            MAP.outgoing(&setattr(None, Some(100))).unwrap().unwrap()
        else {
            panic!()
        };
        assert_eq!((set.uid, set.gid), (None, Some(1000)));
    }

    #[test]
    fn a_chown_to_anyone_else_is_refused_before_it_is_sent() {
        for (uid, gid) in [
            (Some(0), None),
            (None, Some(0)),
            (Some(NOBODY), None),
            (Some(1005), None),
            (Some(1000), Some(7)),
        ] {
            assert!(
                matches!(MAP.outgoing(&setattr(uid, gid)), Err(Error::Unmapped)),
                "{uid:?} {gid:?}"
            );
        }
    }

    #[test]
    fn requests_without_owners_go_out_unchanged() {
        assert!(MAP.outgoing(&setattr(None, None)).unwrap().is_none());
        assert!(MAP.outgoing(&getattr()).unwrap().is_none());
        let other_xattr = Request::Setxattr {
            path: Path::root(),
            name: b"user.acl".to_vec(),
            value: acl(&[(ACL_USER, 7)]),
            flags: 0,
        };
        assert!(MAP.outgoing(&other_xattr).unwrap().is_none());
    }

    #[test]
    fn direct_changes_nothing_either_way() {
        assert_eq!(incoming_owner(&IdMap::Direct, 7, 8), (7, 8));
        assert_eq!(
            incoming_acl_with(&IdMap::Direct, ACL_NAMES[0], full_acl(7, 8)),
            full_acl(7, 8)
        );
        for req in [
            setattr(Some(0), Some(NOBODY)),
            setxattr(ACL_NAMES[0], full_acl(7, 8)),
        ] {
            assert!(IdMap::Direct.outgoing(&req).unwrap().is_none(), "{req:?}");
        }
    }

    #[test]
    fn nobody_on_either_side_is_worth_a_warning() {
        assert!(MAP.caveat().is_none());
        assert!(IdMap::Direct.caveat().is_none());
        let as_nobody = |server_gid, local_uid| {
            IdMap::Owned(Owned {
                server_uid: 1005,
                server_gid,
                local_uid,
                local_gid: 100,
            })
        };
        assert!(as_nobody(NOBODY, 1000).caveat().is_some());
        assert!(as_nobody(1000, NOBODY).caveat().is_some());
    }

    #[test]
    fn a_server_running_as_root_is_worth_a_warning() {
        let server_as = |server_uid, local_uid| {
            IdMap::Owned(Owned {
                server_uid,
                server_gid: 0,
                local_uid,
                local_gid: 0,
            })
            .caveat()
        };
        assert!(server_as(0, 1000).is_some());
        // Root mounting a server that runs as root is root seeing root's files.
        assert!(server_as(0, 0).is_none());
    }

    use jackalopefs_proto::owners::{
        ACL_GROUP, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_UNDEFINED_ID, ACL_USER, ACL_USER_OBJ,
    };

    /// An ACL in the kernel's xattr form, every entry `rw-`.
    fn acl(entries: &[(u16, u32)]) -> Vec<u8> {
        let mut blob = 2u32.to_le_bytes().to_vec();
        for (tag, id) in entries {
            blob.extend(tag.to_le_bytes());
            blob.extend(6u16.to_le_bytes());
            blob.extend(id.to_le_bytes());
        }
        blob
    }

    fn full_acl(user: u32, group: u32) -> Vec<u8> {
        acl(&[
            (ACL_USER_OBJ, ACL_UNDEFINED_ID),
            (ACL_USER, user),
            (ACL_GROUP_OBJ, ACL_UNDEFINED_ID),
            (ACL_GROUP, group),
            (ACL_MASK, ACL_UNDEFINED_ID),
            (ACL_OTHER, ACL_UNDEFINED_ID),
        ])
    }

    const ACL_NAMES: [&[u8]; 2] = [b"system.posix_acl_access", b"system.posix_acl_default"];

    fn incoming_acl(name: &[u8], value: Vec<u8>) -> Vec<u8> {
        incoming_acl_with(&MAP, name, value)
    }

    fn incoming_acl_with(map: &IdMap, name: &[u8], value: Vec<u8>) -> Vec<u8> {
        let mut resp = Response::Xattr(value);
        map.incoming(
            &Request::Getxattr {
                path: Path::root(),
                name: name.to_vec(),
            },
            &mut resp,
        );
        match resp {
            Response::Xattr(v) => v,
            other => panic!("{other:?}"),
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

    #[test]
    fn acl_entries_are_mapped_coming_in() {
        for name in ACL_NAMES {
            assert_eq!(
                incoming_acl(name, full_acl(1005, 1000)),
                full_acl(1000, 100)
            );
            assert_eq!(
                incoming_acl(name, full_acl(1000, 100)),
                full_acl(NOBODY, NOBODY)
            );
        }
        // Any other attribute is a value like any other, whatever it looks like.
        assert_eq!(
            incoming_acl(b"user.x", full_acl(1005, 1000)),
            full_acl(1005, 1000)
        );
    }

    #[test]
    fn acl_entries_are_mapped_going_out() {
        for name in ACL_NAMES {
            let Request::Setxattr { value, .. } = MAP
                .outgoing(&setxattr(name, full_acl(1000, 100)))
                .unwrap()
                .unwrap()
            else {
                panic!()
            };
            assert_eq!(value, full_acl(1005, 1000));
            for (user, group) in [(0, 100), (1000, 0), (NOBODY, 100), (1005, 100)] {
                assert!(
                    matches!(
                        MAP.outgoing(&setxattr(name, full_acl(user, group))),
                        Err(Error::Unmapped)
                    ),
                    "{user} {group}"
                );
            }
            // An ACL naming nobody but the owner, group and others carries no ids to map.
            let minimal = acl(&[
                (ACL_USER_OBJ, ACL_UNDEFINED_ID),
                (ACL_GROUP_OBJ, ACL_UNDEFINED_ID),
                (ACL_OTHER, ACL_UNDEFINED_ID),
            ]);
            let Request::Setxattr { value, .. } = MAP
                .outgoing(&setxattr(name, minimal.clone()))
                .unwrap()
                .unwrap()
            else {
                panic!()
            };
            assert_eq!(value, minimal);
        }
    }

    /// The kernel on the far side judges a malformed ACL; it is passed along as it came.
    #[test]
    fn an_acl_that_does_not_parse_is_left_alone() {
        let mut wrong_version = full_acl(1005, 1000);
        wrong_version[0] = 1;
        let mut ragged = full_acl(1005, 1000);
        ragged.pop();
        for blob in [wrong_version, ragged, vec![2, 0], Vec::new()] {
            for name in ACL_NAMES {
                assert_eq!(incoming_acl(name, blob.clone()), blob);
                let sent = MAP.outgoing(&setxattr(name, blob.clone())).unwrap();
                assert!(sent
                    .is_none_or(|r| matches!(r, Request::Setxattr { value, .. } if value == blob)));
            }
        }
    }
}

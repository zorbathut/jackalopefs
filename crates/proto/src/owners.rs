//! Owners as both ends map them: numeric uids and gids, and the ones inside a POSIX ACL, which reaches a FUSE daemon as an extended attribute in the kernel's xattr form.

use crate::{Attr, Request, Response};

/// The kernel's overflow id, what an id with no mapping shows as in a user namespace too.
pub const NOBODY: u32 = 65534;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KindOwner {
    User,
    Group,
}

const POSIX_ACL_NAMES: [&[u8]; 2] = [b"system.posix_acl_access", b"system.posix_acl_default"];
const ACL_VERSION: u32 = 2;
const ACL_ENTRY: usize = 8;

/// The tags of a POSIX ACL entry (`<linux/posix_acl.h>`); only a named user or group carries an id.
pub const ACL_USER_OBJ: u16 = 0x01;
pub const ACL_USER: u16 = 0x02;
pub const ACL_GROUP_OBJ: u16 = 0x04;
pub const ACL_GROUP: u16 = 0x08;
pub const ACL_MASK: u16 = 0x10;
pub const ACL_OTHER: u16 = 0x20;
/// The id of an entry that has none.
pub const ACL_UNDEFINED_ID: u32 = u32::MAX;

pub fn is_posix_acl(name: &[u8]) -> bool {
    POSIX_ACL_NAMES.contains(&name)
}

/// The entries of a POSIX ACL in the kernel's xattr form (a little-endian version word, then 8-byte entries of tag, permissions and id), or `None` if `value` is not one, by the same test the kernel's `posix_acl_from_xattr` makes.
fn acl_entries_raw(value: &[u8]) -> Option<&[[u8; ACL_ENTRY]]> {
    let (version, entries) = value.split_first_chunk::<4>()?;
    let (entries, ragged) = entries.as_chunks::<ACL_ENTRY>();
    (u32::from_le_bytes(*version) == ACL_VERSION && ragged.is_empty()).then_some(entries)
}

fn owner_of(entry: &[u8; ACL_ENTRY]) -> Option<(KindOwner, u32)> {
    let kind = match u16::from_le_bytes([entry[0], entry[1]]) {
        ACL_USER => KindOwner::User,
        ACL_GROUP => KindOwner::Group,
        _ => return None,
    };
    Some((
        kind,
        u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]),
    ))
}

/// The owner named by every named user and named group entry of a POSIX ACL, or `None` if `value` is not one (see [`acl_entries_raw`]).
pub fn acl_owners(value: &[u8]) -> Option<impl Iterator<Item = (KindOwner, u32)> + '_> {
    Some(acl_entries_raw(value)?.iter().filter_map(owner_of))
}

/// Replace the id of every named user and named group entry of a POSIX ACL with `map`'s; false, with nothing changed, if `value` is not one.
pub fn acl_map(value: &mut [u8], mut map: impl FnMut(KindOwner, u32) -> u32) -> bool {
    if acl_entries_raw(value).is_none() {
        return false;
    }
    let (_, entries) = value.split_at_mut(4);
    for entry in entries.as_chunks_mut::<ACL_ENTRY>().0 {
        if let Some((kind, id)) = owner_of(entry) {
            entry[4..].copy_from_slice(&map(kind, id).to_le_bytes());
        }
    }
    true
}

/// Replace every owner in a reply with `map`'s: the attributes of every reply that has them, and, where `posix_acl_read` says the reply is the value of a POSIX ACL, its named entries. Every variant is named, so one that comes to carry owners cannot slip past either end.
pub fn map_reply(resp: &mut Response, posix_acl_read: bool, map: impl Fn(KindOwner, u32) -> u32) {
    let attr = |attr: &mut Attr| {
        attr.uid = map(KindOwner::User, attr.uid);
        attr.gid = map(KindOwner::Group, attr.gid);
    };
    match resp {
        Response::Entry(a) | Response::Attr(a) | Response::Opened { attr: a } => attr(a),
        Response::Readdir { entries, .. } => entries
            .iter_mut()
            .filter_map(|e| e.attr.as_mut())
            .for_each(attr),
        Response::Xattr(value) => {
            if posix_acl_read {
                acl_map(value, &map);
            }
        }
        Response::Err(_)
        | Response::Readlink(_)
        | Response::Ok
        | Response::Read(_)
        | Response::Written(_)
        | Response::Copied(_)
        | Response::Seeked(_)
        | Response::Statfs(_) => {}
    }
}

/// Whether `req` reads a POSIX ACL, whose reply's owners are then the ACL's.
pub fn reads_posix_acl(req: &Request) -> bool {
    matches!(req, Request::Getxattr { name, .. } if is_posix_acl(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DirEntry, FileKind, Identity, Path, Statfs, TimeSpec};

    /// An ACL in the kernel's xattr form, every entry `rw-`.
    fn acl(entries: &[(u16, u32)]) -> Vec<u8> {
        let mut blob = ACL_VERSION.to_le_bytes().to_vec();
        for (tag, id) in entries {
            blob.extend(tag.to_le_bytes());
            blob.extend(6u16.to_le_bytes());
            blob.extend(id.to_le_bytes());
        }
        blob
    }

    /// Every kind of entry, with `user` and `group` as the named ones.
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

    #[test]
    fn only_named_users_and_groups_are_mapped() {
        let mut value = full_acl(7, 8);
        let mut seen = Vec::new();
        assert_eq!(
            acl_owners(&value).unwrap().collect::<Vec<_>>(),
            vec![(KindOwner::User, 7), (KindOwner::Group, 8)]
        );
        assert!(acl_map(&mut value, |kind, id| {
            seen.push((kind, id));
            id + 100
        }));
        assert_eq!(seen, vec![(KindOwner::User, 7), (KindOwner::Group, 8)]);
        assert_eq!(value, full_acl(107, 108));
    }

    #[test]
    fn a_blob_that_is_not_an_acl_is_left_alone() {
        let mut wrong_version = full_acl(7, 8);
        wrong_version[0] = 1;
        let mut ragged = full_acl(7, 8);
        ragged.pop();
        for blob in [wrong_version, ragged, vec![2, 0], Vec::new()] {
            let mut value = blob.clone();
            assert!(acl_owners(&value).is_none());
            assert!(!acl_map(&mut value, |_, _| 0));
            assert_eq!(value, blob);
        }
        // A header and no entries is an ACL, an empty one.
        assert_eq!(acl_owners(&acl(&[])).unwrap().count(), 0);
    }

    #[test]
    fn the_posix_acl_names() {
        assert!(is_posix_acl(b"system.posix_acl_access"));
        assert!(is_posix_acl(b"system.posix_acl_default"));
        for name in [
            &b"system.nfs4_acl"[..],
            b"user.posix_acl_access",
            b"system.posix_acl",
        ] {
            assert!(!is_posix_acl(name));
        }
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

    fn entry(name: &[u8], attr: Option<Attr>) -> DirEntry {
        DirEntry {
            next_offset: 1,
            name: name.to_vec(),
            attr,
        }
    }

    /// Owners map to themselves plus 100, so every one reached is visible.
    fn plus_100(resp: &mut Response, posix_acl_read: bool) {
        map_reply(resp, posix_acl_read, |_, id| id + 100);
    }

    #[test]
    fn every_owner_in_a_reply_is_mapped() {
        let mut replies = vec![
            Response::Entry(attr(1, 2)),
            Response::Attr(attr(1, 2)),
            Response::Opened { attr: attr(1, 2) },
            Response::Readdir {
                entries: vec![entry(b"a", Some(attr(1, 2))), entry(b"b", None)],
                end: true,
            },
        ];
        for resp in &mut replies {
            plus_100(resp, false);
        }
        assert_eq!(
            replies,
            vec![
                Response::Entry(attr(101, 102)),
                Response::Attr(attr(101, 102)),
                Response::Opened {
                    attr: attr(101, 102)
                },
                Response::Readdir {
                    entries: vec![entry(b"a", Some(attr(101, 102))), entry(b"b", None)],
                    end: true
                },
            ]
        );
        let mut acl_reply = Response::Xattr(full_acl(1, 2));
        plus_100(&mut acl_reply, true);
        assert_eq!(acl_reply, Response::Xattr(full_acl(101, 102)));
    }

    #[test]
    fn replies_without_owners_are_untouched() {
        let unchanged = [
            Response::Err(1),
            Response::Ok,
            Response::Readlink(b"t".to_vec()),
            Response::Read(vec![1]),
            Response::Written(1),
            Response::Copied(1),
            Response::Seeked(1),
            Response::Statfs(Statfs {
                blocks: 1,
                bfree: 1,
                bavail: 1,
                files: 1,
                ffree: 1,
                bsize: 1,
                namelen: 1,
                frsize: 1,
            }),
            // Not the reply to an ACL read: a value like any other, whatever it looks like.
            Response::Xattr(full_acl(1, 2)),
        ];
        for resp in unchanged {
            let mut mapped = resp.clone();
            plus_100(&mut mapped, false);
            assert_eq!(mapped, resp);
        }
    }

    #[test]
    fn only_a_read_of_a_posix_acl_reads_one() {
        let get = |name: &[u8]| Request::Getxattr {
            path: Path::root(),
            name: name.to_vec(),
        };
        assert!(reads_posix_acl(&get(b"system.posix_acl_access")));
        assert!(reads_posix_acl(&get(b"system.posix_acl_default")));
        assert!(!reads_posix_acl(&get(b"user.x")));
        assert!(!reads_posix_acl(&Request::Listxattr { path: Path::root() }));
    }
}

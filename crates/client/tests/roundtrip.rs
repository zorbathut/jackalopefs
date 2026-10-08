mod common;

use common::*;
use jackalopefs_client::ids::{IdMap, ModeIds as ModeIdsClient};
use jackalopefs_client::{
    ConnState, Error, ErrorConnect, ErrorConnectKind, PhaseCall, RequestKernel, ServerTrust,
};
use jackalopefs_proto::owners::NOBODY;
use jackalopefs_proto::{
    Auth, Hello, HelloReply, Path, Request, SetAttr, TimeOrNow, TimeSpec, PROTO_REVISION,
};
use jackalopefs_server::ids::ModeIds as ModeIdsServer;
use std::collections::BTreeSet;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

#[tokio::test]
async fn hello_token_and_fingerprint() {
    let export = tempfile::tempdir().unwrap();
    let server = TestServer::start(export.path(), Some("s3cret".into())).await;

    let anon = jackalopefs_client::Client::connect(server.config(Duration::from_secs(5)))
        .await
        .err()
        .expect("anonymous must be rejected");
    assert!(anon.to_string().contains("token"), "{anon}");
    let wrong = jackalopefs_client::Client::connect(config_for(
        server.addr,
        server.fingerprint,
        Auth::Token("nope".into()),
        Duration::from_secs(5),
    ))
    .await;
    assert!(wrong.is_err());
    let mut bad_fp = server.config(Duration::from_secs(5));
    bad_fp.trust = ServerTrust::Fingerprint([0u8; 32]);
    assert!(jackalopefs_client::Client::connect(bad_fp).await.is_err());

    let client = jackalopefs_client::Client::connect(config_for(
        server.addr,
        server.fingerprint,
        Auth::Token("s3cret".into()),
        Duration::from_secs(5),
    ))
    .await
    .unwrap();
    let root = client.getattr(Some(Path::root()), None).await.unwrap();
    assert_eq!(root.ino, 1);
    let mut insecure = server.config(Duration::from_secs(5));
    insecure.trust = ServerTrust::Insecure;
    insecure.auth = Auth::Token("s3cret".into());
    assert!(jackalopefs_client::Client::connect(insecure).await.is_ok());
    client.shutdown().await;
    server.stop().await;
}

/// Both ends name a connection by the same key, and no two connections share one, so a client's line and the server's about one request join on (connection, stream).
#[tokio::test]
async fn both_ends_name_a_connection_by_the_same_key() {
    let export = tempfile::tempdir().unwrap();
    let server = TestServer::start(export.path(), None).await;
    let key_of = |client: &jackalopefs_client::Client| match &*client.state().borrow() {
        ConnState::Connected(attached) => attached.conn_key.expect("a key"),
        other => panic!("{other:?}"),
    };
    let first = server.client().await;
    let second = server.client().await;
    let server_keys: std::collections::HashSet<u64> = server
        .server
        .connections
        .lock()
        .values()
        .map(|entry| jackalopefs_perf::conn_key(&entry.conn).expect("a key"))
        .collect();
    assert_eq!(
        server_keys,
        std::collections::HashSet::from([key_of(&first), key_of(&second)])
    );
    assert_ne!(key_of(&first), key_of(&second));
    first.shutdown().await;
    second.shutdown().await;
    server.stop().await;
}

#[tokio::test]
async fn file_lifecycle() {
    let export = tempfile::tempdir().unwrap();
    let server = TestServer::start(export.path(), None).await;
    let client = server.client().await;

    let (fh, attr) = client
        .create(Path::root(), name("f"), 0o100640, libc::O_RDWR, |attr| {
            Ok(attr.ino)
        })
        .await
        .unwrap();
    assert_eq!(attr.perm, 0o640);
    assert_eq!(
        client.write(fh, 0, b"hello world".to_vec()).await.unwrap(),
        11
    );
    assert_eq!(client.read(fh, 6, 100).await.unwrap(), b"world");
    let truncated = client
        .setattr(
            None,
            Some(fh),
            SetAttr {
                size: Some(5),
                ..SetAttr::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(truncated.size, 5);
    client.release(fh).await.unwrap();
    assert!(client.handles().is_empty());

    let (fh, _) = client
        .open(path("f"), libc::O_WRONLY | libc::O_APPEND, {
            let meant = attr.ino;
            move |attr| expect_ino(attr, meant)
        })
        .await
        .unwrap();
    client.write(fh, 0, b"!".to_vec()).await.unwrap();
    client.release(fh).await.unwrap();
    assert_eq!(fs::read(export.path().join("f")).unwrap(), b"hello!");

    let looked = client.lookup(Path::root(), name("f")).await.unwrap();
    assert_eq!(looked.ino, attr.ino);
    assert_eq!(looked.size, 6);
    assert_eq!(
        client
            .lookup(Path::root(), name("nope"))
            .await
            .unwrap_err()
            .errno(),
        libc::ENOENT
    );

    let stamped = client
        .setattr(
            Some(path("f")),
            None,
            SetAttr {
                mode: Some(0o600),
                mtime: Some(TimeOrNow::Time(TimeSpec { sec: 1234, nsec: 5 })),
                ..SetAttr::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(stamped.perm, 0o600);
    assert_eq!(stamped.mtime, TimeSpec { sec: 1234, nsec: 5 });

    let dir = client.mkdir(Path::root(), name("d"), 0o777).await.unwrap();
    assert_eq!(dir.perm, 0o777);
    client.rmdir(Path::root(), name("d")).await.unwrap();
    client.unlink(Path::root(), name("f")).await.unwrap();
    assert!(!export.path().join("f").exists());
    client.shutdown().await;
    server.stop().await;
}

#[tokio::test]
async fn copy_file_range_is_done_by_the_server() {
    let export = tempfile::tempdir().unwrap();
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(export.path().join("src"), &data).unwrap();
    let server = TestServer::start(export.path(), None).await;
    let client = server.client().await;

    let src_ino = client.lookup(Path::root(), name("src")).await.unwrap().ino;
    let (src, _) = client
        .open(path("src"), libc::O_RDONLY, move |attr| {
            expect_ino(attr, src_ino)
        })
        .await
        .unwrap();
    let (dst, _) = client
        .create(
            Path::root(),
            name("dst"),
            0o100644,
            libc::O_WRONLY,
            |attr| Ok(attr.ino),
        )
        .await
        .unwrap();
    let mut done = 0u64;
    while done < data.len() as u64 {
        let copied = client
            .copy_file_range(src, done, dst, done, u64::MAX)
            .await
            .unwrap();
        assert!(copied > 0, "no progress at {done}");
        done += copied as u64;
    }
    assert_eq!(
        client
            .copy_file_range(src, done, dst, done, 1)
            .await
            .unwrap(),
        0,
        "nothing is left at the end of the source"
    );
    assert_eq!(fs::read(export.path().join("dst")).unwrap(), data);
    assert_eq!(
        client
            .copy_file_range(dst, 0, src, 0, 1)
            .await
            .unwrap_err()
            .errno(),
        libc::EBADF,
        "a write-only handle cannot be the source"
    );
    client.release(src).await.unwrap();
    client.release(dst).await.unwrap();
    client.shutdown().await;
    server.stop().await;
}

#[tokio::test]
async fn fallocate_is_split_into_requests_the_server_accepts() {
    let export = tempfile::tempdir().unwrap();
    fs::write(export.path().join("f"), vec![7u8; 100_000]).unwrap();
    let server = TestServer::start(export.path(), None).await;
    let client = server.client().await;
    let ino = client.lookup(Path::root(), name("f")).await.unwrap().ino;
    let (fh, _) = client
        .open(path("f"), libc::O_RDWR, move |attr| expect_ino(attr, ino))
        .await
        .unwrap();

    client.fallocate(fh, 0, 300_000, 0).await.unwrap();
    assert_eq!(
        fs::metadata(export.path().join("f")).unwrap().len(),
        300_000
    );

    // Punching far past the end costs a filesystem nothing, so this range can be longer than one request may cover.
    // A report starts a new window, so the count below is this call's alone.
    client.perf().report();
    let punch = libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE;
    let len = 2 * jackalopefs_proto::MAX_FALLOCATE + 1;
    client.fallocate(fh, 4096, len, punch).await.unwrap();
    assert_eq!(client.perf().report().call["fallocate"].row.n, 3);
    let after = fs::read(export.path().join("f")).unwrap();
    assert_eq!(after.len(), 300_000);
    assert!(after[..4096].iter().all(|&b| b == 7));
    assert!(after[4096..].iter().all(|&b| b == 0));

    assert_eq!(
        client
            .fallocate(fh, 0, 1, libc::FALLOC_FL_COLLAPSE_RANGE)
            .await
            .unwrap_err()
            .errno(),
        libc::EOPNOTSUPP
    );
    client.release(fh).await.unwrap();
    client.shutdown().await;
    server.stop().await;
}

#[tokio::test]
async fn lseek_finds_data_and_holes_on_the_server() {
    use jackalopefs_proto::Whence;
    use std::os::unix::fs::FileExt;
    let export = tempfile::tempdir().unwrap();
    let file = fs::File::create(export.path().join("sparse")).unwrap();
    file.write_all_at(b"data", 1 << 20).unwrap();
    file.set_len(2 << 20).unwrap();
    let server = TestServer::start(export.path(), None).await;
    let client = server.client().await;
    let ino = client
        .lookup(Path::root(), name("sparse"))
        .await
        .unwrap()
        .ino;
    let (fh, _) = client
        .open(path("sparse"), libc::O_RDONLY, move |attr| {
            expect_ino(attr, ino)
        })
        .await
        .unwrap();
    let local = |offset: i64, whence| lseek_local(&file, offset, whence);
    for offset in [0u64, 1 << 20, (1 << 20) + 4096] {
        assert_eq!(
            client
                .lseek(fh, offset, Whence::Data)
                .await
                .map_err(|e| e.errno()),
            local(offset as i64, libc::SEEK_DATA),
            "data from {offset}"
        );
        assert_eq!(
            client
                .lseek(fh, offset, Whence::Hole)
                .await
                .map_err(|e| e.errno()),
            local(offset as i64, libc::SEEK_HOLE),
            "hole from {offset}"
        );
    }
    assert_eq!(
        client
            .lseek(fh, 2 << 20, Whence::Data)
            .await
            .unwrap_err()
            .errno(),
        libc::ENXIO
    );
    client.release(fh).await.unwrap();
    client.shutdown().await;
    server.stop().await;
}

/// `lseek(2)` on a local file, as the offset found or the errno.
fn lseek_local(file: &fs::File, offset: i64, whence: i32) -> Result<u64, i32> {
    use std::os::fd::AsRawFd;
    let found = unsafe { libc::lseek(file.as_raw_fd(), offset, whence) };
    if found < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        Ok(found as u64)
    }
}

#[tokio::test]
async fn unlink_while_open_and_stale_open() {
    let export = tempfile::tempdir().unwrap();
    let server = TestServer::start(export.path(), None).await;
    let client = server.client().await;

    let (fh, attr) = client
        .create(Path::root(), name("gone"), 0o100644, libc::O_RDWR, |attr| {
            Ok(attr.ino)
        })
        .await
        .unwrap();
    client.write(fh, 0, b"still here".to_vec()).await.unwrap();
    client.unlink(Path::root(), name("gone")).await.unwrap();
    assert_eq!(client.read(fh, 0, 100).await.unwrap(), b"still here");
    assert_eq!(client.getattr(None, Some(fh)).await.unwrap().ino, attr.ino);
    assert_eq!(
        client
            .getattr(Some(path("gone")), None)
            .await
            .unwrap_err()
            .errno(),
        libc::ENOENT
    );
    client.release(fh).await.unwrap();

    fs::write(export.path().join("other"), b"").unwrap();
    let other_ino = fs::metadata(export.path().join("other")).unwrap().ino();
    let err = client
        .open(path("other"), libc::O_RDONLY, move |attr| {
            expect_ino(attr, other_ino + 1_000_000)
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Stale), "{err}");
    wait_for(Duration::from_secs(5), "orphan release", || {
        (server.server.sessions.get(1).unwrap().handles.is_empty()).then_some(())
    })
    .await;
    client.shutdown().await;
    server.stop().await;
}

#[tokio::test]
async fn directory_listing_in_pages_and_concurrently() {
    let export = tempfile::tempdir().unwrap();
    for i in 0..5000 {
        fs::write(export.path().join(format!("entry-{i:05}")), b"").unwrap();
    }
    let server = TestServer::start(export.path(), None).await;
    let client = server.client().await;

    let (fh, attr) = client
        .opendir(Path::root(), move |attr| expect_ino(attr, 1))
        .await
        .unwrap();
    assert_eq!(attr.ino, 1);
    let mut seen = Vec::new();
    let mut offset = 0;
    let mut pages = 0;
    let mut ended = false;
    loop {
        let (page, end) = client.readdir(fh, offset, 4096).await.unwrap();
        if page.is_empty() {
            break;
        }
        // Which page says `end` depends on whether the budget ran out exactly at the last entry, so only this direction is asserted.
        assert!(!ended, "no page follows one that said the directory ended");
        ended = end;
        pages += 1;
        offset = page.last().unwrap().next_offset;
        for entry in &page {
            assert_eq!(
                entry.attr.is_none(),
                entry.is_dot_or_dotdot(),
                "only the dots come without attributes"
            );
        }
        seen.extend(page.into_iter().map(|e| e.name));
    }
    assert!(pages > 10, "expected many pages, got {pages}");
    assert_eq!(seen.len(), 5002);
    let unique: BTreeSet<_> = seen.iter().cloned().collect();
    assert_eq!(unique.len(), 5002, "no duplicates across pages");
    assert!(unique.contains(b".".as_slice()) && unique.contains(b"..".as_slice()));

    let (a, b) = tokio::join!(
        client.readdir(fh, 0, 1 << 20),
        client.readdir(fh, 0, 1 << 20)
    );
    assert_eq!(a.unwrap().0.len(), 5002);
    assert_eq!(b.unwrap().0.len(), 5002);
    client.releasedir(fh).await.unwrap();
    client.shutdown().await;
    server.stop().await;
}

#[tokio::test]
async fn rename_link_symlink_xattr_statfs_access() {
    let export = tempfile::tempdir().unwrap();
    fs::write(export.path().join("a"), b"A").unwrap();
    fs::write(export.path().join("b"), b"B").unwrap();
    let server = TestServer::start(export.path(), None).await;
    let client = server.client().await;

    assert_eq!(
        client
            .rename(
                Path::root(),
                name("a"),
                Path::root(),
                name("b"),
                libc::RENAME_NOREPLACE
            )
            .await
            .unwrap_err()
            .errno(),
        libc::EEXIST
    );
    client
        .rename(
            Path::root(),
            name("a"),
            Path::root(),
            name("b"),
            libc::RENAME_EXCHANGE,
        )
        .await
        .unwrap();
    assert_eq!(fs::read(export.path().join("a")).unwrap(), b"B");
    assert_eq!(fs::read(export.path().join("b")).unwrap(), b"A");

    let linked = client
        .link(path("a"), Path::root(), name("a2"))
        .await
        .unwrap();
    assert_eq!(linked.nlink, 2);
    assert_eq!(
        linked.ino,
        client.lookup(Path::root(), name("a")).await.unwrap().ino
    );

    let sym = client
        .symlink(Path::root(), name("s"), b"a".to_vec())
        .await
        .unwrap();
    assert_eq!(sym.kind, jackalopefs_proto::FileKind::Symlink);
    assert_eq!(client.readlink(path("s")).await.unwrap(), b"a");

    match client
        .setxattr(path("a"), b"user.k".to_vec(), b"v".to_vec(), 0)
        .await
    {
        Ok(()) => {
            assert_eq!(
                client
                    .getxattr(path("a"), b"user.k".to_vec())
                    .await
                    .unwrap(),
                b"v"
            );
            assert_eq!(client.listxattr(path("a")).await.unwrap(), b"user.k\0");
            let looked = client.lookup(Path::root(), name("a")).await.unwrap();
            assert_eq!(looked.xattr_names, Some(vec![b"user.k".to_vec()]));
            client
                .removexattr(path("a"), b"user.k".to_vec())
                .await
                .unwrap();
            assert_eq!(
                client
                    .getxattr(path("a"), b"user.k".to_vec())
                    .await
                    .unwrap_err()
                    .errno(),
                libc::ENODATA
            );
        }
        Err(e) if e.errno() == libc::EOPNOTSUPP => eprintln!("xattrs unsupported here; skipping"),
        Err(e) => panic!("{e}"),
    }
    let statfs = client.statfs(Path::root()).await.unwrap();
    assert!(statfs.blocks > 0 && statfs.frsize > 0);
    client.access(path("a"), libc::R_OK).await.unwrap();
    assert_eq!(
        client
            .access(path("a"), libc::X_OK)
            .await
            .unwrap_err()
            .errno(),
        libc::EACCES
    );
    client.shutdown().await;
    server.stop().await;
}

#[tokio::test]
async fn timeout_against_a_blackhole_resets_and_releases() {
    let blackhole = Blackhole::start().await;
    let mut cfg = blackhole.config(Duration::from_secs(5));
    cfg.op_timeout = Some(Duration::from_millis(500));
    let client = jackalopefs_client::Client::connect(cfg).await.unwrap();

    let started = Instant::now();
    let err = client.getattr(Some(Path::root()), None).await.unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err}");
    assert_eq!(err.errno(), libc::ETIMEDOUT);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
    wait_for(
        Duration::from_secs(3),
        "the abandoned stream to be stopped",
        || {
            blackhole
                .stops
                .lock()
                .contains(&u64::from(jackalopefs_client::conn::close_code::CANCELLED))
                .then_some(())
        },
    )
    .await;

    let err = client
        .open(Path::root(), libc::O_RDONLY, move |attr| {
            expect_ino(attr, 1)
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err}");
    assert!(
        client.handles().is_empty(),
        "a timed-out open registers no handle"
    );
    let fh = wait_for(Duration::from_secs(3), "orphan release request", || {
        let seen = blackhole.requests.lock();
        let opened = seen.iter().find_map(|r| match r {
            Request::Open { fh, .. } => Some(*fh),
            _ => None,
        })?;
        seen.iter()
            .any(|r| matches!(r, Request::Release { fh } if *fh == opened))
            .then_some(opened)
    })
    .await;
    assert!(fh > 0);
    client.shutdown().await;
}

fn owned_by(uid: u32, gid: u32) -> jackalopefs_proto::Attr {
    let t = TimeSpec { sec: 0, nsec: 0 };
    jackalopefs_proto::Attr {
        ino: 5,
        size: 0,
        blocks: 0,
        atime: t,
        mtime: t,
        ctime: t,
        kind: jackalopefs_proto::FileKind::Regular,
        perm: 0o644,
        nlink: 1,
        uid,
        gid,
        rdev: 0,
        blksize: 4096,
        xattr_names: None,
        identity: jackalopefs_proto::Identity {
            handle_type: 1,
            handle: vec![5],
        },
        foreign: false,
    }
}

fn local_ids() -> (u32, u32) {
    (
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    )
}

/// An ACL in the kernel's xattr form naming one user and one group besides the owner, group and others.
fn acl_naming(uid: u32, gid: u32) -> Vec<u8> {
    let mut blob = 2u32.to_le_bytes().to_vec();
    for (tag, id) in [
        (0x01u16, u32::MAX),
        (0x02, uid),
        (0x04, u32::MAX),
        (0x08, gid),
        (0x10, u32::MAX),
        (0x20, u32::MAX),
    ] {
        blob.extend(tag.to_le_bytes());
        blob.extend(6u16.to_le_bytes());
        blob.extend(id.to_le_bytes());
    }
    blob
}

/// A client that shows the server's user as its own, the mapping these tests are about.
async fn owned_client(hole: &Blackhole) -> jackalopefs_client::Client {
    jackalopefs_client::Client::connect(jackalopefs_client::Config {
        ids: ModeIdsClient::Owned,
        ..hole.config(Duration::from_secs(5))
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn the_server_user_shows_as_the_local_user_and_everyone_else_as_nobody() {
    let (uid, gid) = local_ids();
    for (owner, seen) in [
        ((SERVER_UID, SERVER_GID), (uid, gid)),
        ((uid, gid), (NOBODY, NOBODY)),
        ((0, 0), (NOBODY, NOBODY)),
    ] {
        let hole = Blackhole::start_with(Some(jackalopefs_proto::Response::Attr(owned_by(
            owner.0, owner.1,
        ))))
        .await;
        let client = owned_client(&hole).await;
        let attr = client.getattr(Some(Path::root()), None).await.unwrap();
        assert_eq!((attr.uid, attr.gid), seen, "owner {owner:?}");
        client.shutdown().await;
    }
}

#[tokio::test]
async fn a_chown_to_the_local_user_reaches_the_server_as_its_own_user() {
    let (uid, gid) = local_ids();
    let hole = Blackhole::start_with(Some(jackalopefs_proto::Response::Attr(owned_by(
        SERVER_UID, SERVER_GID,
    ))))
    .await;
    let client = owned_client(&hole).await;
    let chown = |uid, gid| SetAttr {
        uid,
        gid,
        ..SetAttr::default()
    };
    client
        .setattr(Some(Path::root()), None, chown(Some(uid), Some(gid)))
        .await
        .unwrap();
    for (uid, gid) in [
        (Some(0), None),
        (None, Some(0)),
        (Some(SERVER_UID), None),
        (Some(NOBODY), None),
    ] {
        let err = client
            .setattr(Some(Path::root()), None, chown(uid, gid))
            .await
            .unwrap_err();
        assert_eq!(err.errno(), libc::EINVAL, "{uid:?} {gid:?}");
    }
    let sent: Vec<_> = hole
        .requests
        .lock()
        .iter()
        .filter_map(|r| match r {
            Request::Setattr { set, .. } => Some((set.uid, set.gid)),
            _ => None,
        })
        .collect();
    assert_eq!(
        sent,
        vec![(Some(SERVER_UID), Some(SERVER_GID))],
        "only the mappable chown is sent"
    );
    client.shutdown().await;
}

#[tokio::test]
async fn acl_entries_are_mapped_both_ways() {
    let (uid, gid) = local_ids();
    let hole = Blackhole::start_with(Some(jackalopefs_proto::Response::Xattr(acl_naming(
        SERVER_UID, SERVER_GID,
    ))))
    .await;
    let client = owned_client(&hole).await;
    let got = client
        .getxattr(Path::root(), b"system.posix_acl_access".to_vec())
        .await
        .unwrap();
    assert_eq!(got, acl_naming(uid, gid));
    // The canned reply is not what a setxattr expects; what matters is what was sent.
    let err = client
        .setxattr(
            Path::root(),
            b"system.posix_acl_default".to_vec(),
            acl_naming(uid, gid),
            0,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Protocol(_)), "{err}");
    let err = client
        .setxattr(
            Path::root(),
            b"system.posix_acl_access".to_vec(),
            acl_naming(0, gid),
            0,
        )
        .await
        .unwrap_err();
    assert_eq!(err.errno(), libc::EINVAL);
    let sent: Vec<_> = hole
        .requests
        .lock()
        .iter()
        .filter_map(|r| match r {
            Request::Setxattr { value, .. } => Some(value.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(sent, vec![acl_naming(SERVER_UID, SERVER_GID)]);
    client.shutdown().await;
}

async fn client_with(server: &TestServer, ids: ModeIdsClient) -> jackalopefs_client::Client {
    jackalopefs_client::Client::connect(jackalopefs_client::Config {
        ids,
        ..server.config(Duration::from_secs(5))
    })
    .await
    .unwrap()
}

const ACL_ACCESS: &[u8] = b"system.posix_acl_access";

/// The same ACL naming another user, read through a server that passes owners through and one that flattens them, and what an owned client can then do. In-process the server's user is the local user, so the owned mapping is the identity here; the fake server's tests are the ones that show it translating.
#[tokio::test]
async fn a_flattening_server_hides_other_owners_and_an_owned_client_keeps_its_own() {
    let export = tempfile::tempdir().unwrap();
    fs::write(export.path().join("f"), b"").unwrap();
    let (uid, gid) = local_ids();

    let server = TestServer::start_ids(export.path(), ModeIdsServer::Direct).await;
    let client = client_with(&server, ModeIdsClient::Direct).await;
    match client
        .setxattr(path("f"), ACL_ACCESS.to_vec(), acl_naming(4242, 4343), 0)
        .await
    {
        Err(e) if e.errno() == libc::EOPNOTSUPP => {
            eprintln!("skipping: the export's filesystem does not support POSIX ACLs");
            return;
        }
        other => other.unwrap(),
    }
    assert_eq!(
        client
            .getxattr(path("f"), ACL_ACCESS.to_vec())
            .await
            .unwrap(),
        acl_naming(4242, 4343),
        "direct and direct pass owners through"
    );
    client.shutdown().await;
    server.stop().await;

    let server = TestServer::start_ids(export.path(), ModeIdsServer::Flatten).await;
    let client = client_with(&server, ModeIdsClient::Owned).await;
    assert_eq!(
        client
            .getxattr(path("f"), ACL_ACCESS.to_vec())
            .await
            .unwrap(),
        acl_naming(NOBODY, NOBODY)
    );
    let attr = client.getattr(Some(path("f")), None).await.unwrap();
    assert_eq!((attr.uid, attr.gid), (uid, gid));
    // What the user may do still gets through both.
    let chown = SetAttr {
        uid: Some(uid),
        gid: Some(gid),
        ..SetAttr::default()
    };
    client.setattr(Some(path("f")), None, chown).await.unwrap();
    client
        .setxattr(path("f"), ACL_ACCESS.to_vec(), acl_naming(uid, gid), 0)
        .await
        .unwrap();
    assert_eq!(
        client
            .getxattr(path("f"), ACL_ACCESS.to_vec())
            .await
            .unwrap(),
        acl_naming(uid, gid)
    );
    // Anyone else is refused by the client before the server sees it.
    let err = client
        .setxattr(path("f"), ACL_ACCESS.to_vec(), acl_naming(4242, gid), 0)
        .await
        .unwrap_err();
    assert_eq!(err.errno(), libc::EINVAL);
    client.shutdown().await;

    // A direct client asks the flattening server itself, which refuses.
    let client = client_with(&server, ModeIdsClient::Direct).await;
    let err = client
        .setxattr(path("f"), ACL_ACCESS.to_vec(), acl_naming(4242, gid), 0)
        .await
        .unwrap_err();
    assert_eq!(err.errno(), libc::EPERM);
    client.shutdown().await;
    server.stop().await;
}

/// The hello says whom the server runs as, which an owned client maps to its own user.
#[tokio::test]
async fn the_hello_says_whom_the_server_runs_as() {
    let export = tempfile::tempdir().unwrap();
    let server = TestServer::start(export.path(), None).await;
    let client = client_with(&server, ModeIdsClient::Owned).await;
    let (uid, gid) = local_ids();
    match &*client.state().borrow() {
        ConnState::Connected(attached) => match attached.ids {
            IdMap::Owned(owned) => assert_eq!((owned.server_uid, owned.server_gid), (uid, gid)),
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
    client.shutdown().await;
    server.stop().await;
}

/// Owners are mapped against the connection that carries them: a server back as another user is described by its own ids.
#[tokio::test]
async fn a_server_back_as_another_user_is_mapped_by_its_new_ids() {
    let (uid, gid) = local_ids();
    let ack_as = |uid, gid| match Blackhole::ack() {
        HelloReply::Ack {
            session_id,
            resume_token,
            resumed,
            root_ino,
            root_identity,
            ..
        } => HelloReply::Ack {
            session_id,
            resume_token,
            resumed,
            root_ino,
            root_identity,
            uid,
            gid,
        },
        other => panic!("{other:?}"),
    };
    let hole = Blackhole::start_full(
        Some(jackalopefs_proto::Response::Attr(owned_by(5252, 5353))),
        vec![ack_as(SERVER_UID, SERVER_GID), ack_as(5252, 5353)],
    )
    .await;
    let client = owned_client(&hole).await;
    let attr = client.getattr(Some(Path::root()), None).await.unwrap();
    assert_eq!(
        (attr.uid, attr.gid),
        (NOBODY, NOBODY),
        "another user's file to the first server"
    );
    hole.connections.lock()[0].close(0u32.into(), b"restarted");
    let attr = client.getattr(Some(Path::root()), None).await.unwrap();
    assert_eq!(
        (attr.uid, attr.gid),
        (uid, gid),
        "the second server's own file"
    );
    let chown = SetAttr {
        uid: Some(uid),
        ..SetAttr::default()
    };
    client
        .setattr(Some(Path::root()), None, chown)
        .await
        .unwrap();
    let sent: Vec<_> = hole
        .requests
        .lock()
        .iter()
        .filter_map(|r| match r {
            Request::Setattr { set, .. } => Some(set.uid),
            _ => None,
        })
        .collect();
    assert_eq!(sent, vec![Some(5252)]);
    client.shutdown().await;
}

#[tokio::test]
async fn a_nonsense_reply_to_an_open_releases_the_handle() {
    let blackhole = Blackhole::start_with(Some(jackalopefs_proto::Response::Ok)).await;
    let client = jackalopefs_client::Client::connect(blackhole.config(Duration::from_secs(5)))
        .await
        .unwrap();
    let err = client
        .open(Path::root(), libc::O_RDONLY, move |attr| {
            expect_ino(attr, 1)
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Protocol(_)), "{err}");
    assert!(client.handles().is_empty());
    wait_for(
        Duration::from_secs(3),
        "orphan release after a bad reply",
        || {
            let seen = blackhole.requests.lock();
            let opened = seen.iter().find_map(|r| match r {
                Request::Open { fh, .. } => Some(*fh),
                _ => None,
            })?;
            seen.iter()
                .any(|r| matches!(r, Request::Release { fh } if *fh == opened))
                .then_some(())
        },
    )
    .await;
    client.shutdown().await;
}

#[tokio::test]
async fn truncated_request_is_ignored_by_the_server() {
    let export = tempfile::tempdir().unwrap();
    let server = TestServer::start(export.path(), None).await;
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(
        jackalopefs_client::transport::client_config(ServerTrust::Fingerprint(server.fingerprint))
            .unwrap(),
    );
    let conn = endpoint
        .connect(server.addr, "jackalopefs")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    jackalopefs_proto::write_frame(
        &mut send,
        &jackalopefs_proto::Hello {
            revision: PROTO_REVISION,
            auth: Auth::Anonymous,
            resume: None,
        },
    )
    .await
    .unwrap();
    send.finish().unwrap();
    let reply: jackalopefs_proto::HelloReply =
        jackalopefs_proto::read_frame(&mut recv).await.unwrap();
    assert!(matches!(reply, jackalopefs_proto::HelloReply::Ack { .. }));

    let (mut send, _recv) = conn.open_bi().await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut send, &100u32.to_le_bytes())
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut send, &[0u8; 10])
        .await
        .unwrap();
    send.finish().unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    jackalopefs_proto::write_frame(
        &mut send,
        &Request::Getattr {
            path: Some(Path::root()),
            fh: None,
        },
    )
    .await
    .unwrap();
    send.finish().unwrap();
    let resp: jackalopefs_proto::Response = jackalopefs_proto::read_frame(&mut recv).await.unwrap();
    // On the wire the root goes by its own inode number; it is the client that knows it as node 1.
    let root_ino = std::os::unix::fs::MetadataExt::ino(&fs::metadata(export.path()).unwrap());
    assert!(matches!(resp, jackalopefs_proto::Response::Attr(a) if a.ino == root_ino));
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    server.stop().await;
}

async fn wait_for_generation(
    client: &jackalopefs_client::Client,
    generation: u64,
) -> std::sync::Arc<jackalopefs_client::conn::Attached> {
    let mut state = client.state();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let ConnState::Connected(att) = &*state.borrow_and_update() {
            if att.generation >= generation {
                return att.clone();
            }
        }
        tokio::time::timeout_at(deadline, state.changed())
            .await
            .expect("reconnect in time")
            .unwrap();
    }
}

#[tokio::test]
async fn session_resumes_after_a_connection_drop() {
    let export = tempfile::tempdir().unwrap();
    let server = TestServer::start(export.path(), None).await;
    let client = server.client().await;

    let (fh, _) = client
        .create(
            Path::root(),
            name("open-then-unlinked"),
            0o100644,
            libc::O_RDWR,
            |attr| Ok(attr.ino),
        )
        .await
        .unwrap();
    client.write(fh, 0, b"survives".to_vec()).await.unwrap();
    client
        .unlink(Path::root(), name("open-then-unlinked"))
        .await
        .unwrap();

    let first = wait_for_generation(&client, 1).await;
    first.conn.close(9u32.into(), b"simulated blip");
    let second = wait_for_generation(&client, 2).await;
    assert!(second.resumed, "server should have resumed the session");
    assert_eq!(second.session_id, first.session_id);
    assert_eq!(
        client.read(fh, 0, 100).await.unwrap(),
        b"survives",
        "an unlinked-but-open file survives a resumed session"
    );
    assert_eq!(server.server.sessions.len(), 1);
    // The first connection's task ends after the second has attached; its cleanup must leave the newer attachment in place.
    let attached = wait_for(
        Duration::from_secs(3),
        "the old connection to leave the table",
        || {
            let connections = server.server.connections.lock();
            (connections.len() == 1).then(|| connections[&first.session_id].epoch)
        },
    )
    .await;
    assert_eq!(attached, 2, "the table holds the resumed attachment");
    client.release(fh).await.unwrap();
    client.shutdown().await;
    server.stop().await;
}

/// A server that comes back serving another directory is another export, whatever its paths lead to. The file here is even the same file, hardlinked into the second directory, so reopening it by path would find nothing amiss: it is the root that says the mount is no longer where it was.
#[tokio::test]
async fn a_server_that_returns_with_another_export_stales_every_handle() {
    let first_export = tempfile::tempdir().unwrap();
    let second_export = tempfile::tempdir().unwrap();
    fs::write(first_export.path().join("f"), b"contents").unwrap();
    fs::hard_link(
        first_export.path().join("f"),
        second_export.path().join("f"),
    )
    .unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let identity = jackalopefs_server::tls::Identity::generate().unwrap();
    let first = TestServer::start_with(first_export.path(), None, socket, identity.clone()).await;
    let client = jackalopefs_client::Client::connect(config_for(
        first.addr,
        first.fingerprint,
        Auth::Anonymous,
        Duration::from_secs(10),
    ))
    .await
    .unwrap();
    let (fh, _) = client
        .open(path("f"), libc::O_RDONLY, |attr| Ok(attr.ino))
        .await
        .unwrap();
    assert_eq!(client.read(fh, 0, 100).await.unwrap(), b"contents");

    first.stop().await;
    let socket = wait_for(Duration::from_secs(5), "port to be free again", || {
        std::net::UdpSocket::bind(("127.0.0.1", port)).ok()
    })
    .await;
    let second = TestServer::start_with(second_export.path(), None, socket, identity).await;
    wait_for_generation(&client, 2).await;
    let err = client.read(fh, 0, 100).await.unwrap_err();
    assert!(matches!(err, Error::Stale), "{err}");
    let root = client.getattr(Some(Path::root()), None).await.unwrap();
    assert_eq!(root.ino, 1, "the new root is the root");

    client.release(fh).await.unwrap();
    client.shutdown().await;
    second.stop().await;
}

#[tokio::test]
async fn handles_are_reopened_and_verified_after_a_server_restart() {
    let export = tempfile::tempdir().unwrap();
    fs::write(export.path().join("keep"), b"kept").unwrap();
    fs::write(export.path().join("swap"), b"old").unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let identity = jackalopefs_server::tls::Identity::generate().unwrap();
    let first = TestServer::start_with(export.path(), None, socket, identity.clone()).await;
    let client = jackalopefs_client::Client::connect(config_for(
        first.addr,
        first.fingerprint,
        Auth::Anonymous,
        Duration::from_secs(10),
    ))
    .await
    .unwrap();

    let keep_ino = fs::metadata(export.path().join("keep")).unwrap().ino();
    let swap_ino = fs::metadata(export.path().join("swap")).unwrap().ino();
    let (keep_fh, _) = client
        .open(path("keep"), libc::O_RDONLY, move |attr| {
            expect_ino(attr, keep_ino)
        })
        .await
        .unwrap();
    let (swap_fh, _) = client
        .open(path("swap"), libc::O_RDONLY, move |attr| {
            expect_ino(attr, swap_ino)
        })
        .await
        .unwrap();
    let (dir_fh, _) = client
        .opendir(Path::root(), move |attr| expect_ino(attr, 1))
        .await
        .unwrap();

    first.stop().await;
    let restart = async {
        // While the server is down, replace `swap` with a different inode; `keep` stays.
        tokio::time::sleep(Duration::from_millis(300)).await;
        fs::write(export.path().join("swap.new"), b"new").unwrap();
        fs::rename(export.path().join("swap.new"), export.path().join("swap")).unwrap();
        let socket = wait_for(Duration::from_secs(5), "port to be free again", || {
            std::net::UdpSocket::bind(("127.0.0.1", port)).ok()
        })
        .await;
        TestServer::start_with(export.path(), None, socket, identity).await
    };
    // A request issued while the server is down waits for the reconnect instead of failing.
    let (pending_read, second) = tokio::join!(client.read(keep_fh, 0, 100), restart);
    assert_eq!(pending_read.unwrap(), b"kept");

    let attached = wait_for_generation(&client, 2).await;
    assert!(
        !attached.resumed,
        "a restarted server knows nothing about the old session"
    );
    assert_eq!(client.read(keep_fh, 0, 100).await.unwrap(), b"kept");
    let err = client.read(swap_fh, 0, 100).await.unwrap_err();
    assert!(
        matches!(err, Error::Stale),
        "handle to a replaced inode must not silently read the new file: {err}"
    );
    assert_eq!(err.errno(), libc::ESTALE);
    let err = client
        .lseek(swap_fh, 0, jackalopefs_proto::Whence::Data)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Stale), "{err}");
    for (fh_in, fh_out) in [(swap_fh, keep_fh), (keep_fh, swap_fh)] {
        let err = client
            .copy_file_range(fh_in, 0, fh_out, 0, 1)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Stale),
            "a copy naming a dead handle on either side is stale: {err}"
        );
    }
    assert!(client.readdir(dir_fh, 0, 1 << 20).await.unwrap().0.len() >= 4);
    assert_eq!(
        second.server.sessions.get(1).unwrap().handles.len(),
        2,
        "keep + dir reopened, swap dropped"
    );

    client.release(keep_fh).await.unwrap();
    client.release(swap_fh).await.unwrap();
    client.releasedir(dir_fh).await.unwrap();
    client.shutdown().await;
    second.stop().await;
}

#[tokio::test]
async fn unmount_interrupts_a_connect_attempt() {
    let export = tempfile::tempdir().unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = TestServer::start_on(export.path(), None, socket).await;
    let mut config = server.config(Duration::from_secs(5));
    // Long enough that nothing but the stop signal can end the attempt the unmount lands in.
    config.connect_timeout = Duration::from_secs(30);
    let client = jackalopefs_client::Client::connect(config).await.unwrap();

    server.stop().await;
    // Hold the port for the rest of the test: left free, another test could be handed it and answer the very attempt the unmount has to interrupt.
    let _dead = wait_for(Duration::from_secs(5), "the port to be free again", || {
        std::net::UdpSocket::bind(("127.0.0.1", port)).ok()
    })
    .await;
    wait_for(Duration::from_secs(5), "a reconnect attempt", || {
        matches!(*client.state().borrow(), ConnState::Connecting { .. }).then_some(())
    })
    .await;
    // `Connecting` is published just before the attempt begins; unmounting in that gap would pass whatever the manager does with the signal afterwards.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let start = Instant::now();
    client.shutdown().await;
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "unmount waited on the connect attempt: {:?}",
        start.elapsed()
    );
}

/// A loopback address nothing will ever answer on. The socket stays bound for the caller's lifetime: freeing the port would let a concurrently starting test be handed it and complete a handshake there.
fn dead_address() -> (std::net::UdpSocket, SocketAddr) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    (socket, addr)
}

#[tokio::test]
async fn connects_past_a_dead_address_and_remembers_the_live_one() {
    let export = tempfile::tempdir().unwrap();
    let server = TestServer::start(export.path(), None).await;
    let (_dead_socket, dead) = dead_address();
    let mut config = server.config(Duration::from_secs(5));
    config.server_addrs = vec![dead, server.addr];
    config.connect_timeout = Duration::from_secs(2);
    let client = jackalopefs_client::Client::connect(config).await.unwrap();
    assert_eq!(
        client.getattr(Some(Path::root()), None).await.unwrap().ino,
        1
    );

    // The reconnect must go straight to the address that answered, not back through the dead one.
    let first = wait_for_generation(&client, 1).await;
    first.conn.close(9u32.into(), b"simulated blip");
    let start = Instant::now();
    wait_for_generation(&client, 2).await;
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "the reconnect paid for the dead address again: {:?}",
        start.elapsed()
    );
    client.shutdown().await;
    server.stop().await;
}

#[tokio::test]
async fn an_unreachable_ipv6_candidate_does_not_stop_the_mount() {
    let export = tempfile::tempdir().unwrap();
    let server = TestServer::start(export.path(), None).await;
    let mut config = server.config(Duration::from_secs(5));
    // Documentation space, so no host routes it; where there is no IPv6 stack at all the candidate is dropped for want of a socket instead.
    config.server_addrs = vec!["[2001:db8::1]:1933".parse().unwrap(), server.addr];
    config.connect_timeout = Duration::from_secs(1);
    let client = jackalopefs_client::Client::connect(config).await.unwrap();
    assert_eq!(
        client.getattr(Some(Path::root()), None).await.unwrap().ino,
        1
    );
    client.shutdown().await;
    server.stop().await;
}

#[tokio::test]
async fn a_failed_connection_names_the_address() {
    let (_dead_socket, dead) = dead_address();
    let mut config = config_for(dead, [0u8; 32], Auth::Anonymous, Duration::from_secs(5));
    config.connect_timeout = Duration::from_millis(300);
    let err = jackalopefs_client::Client::connect(config)
        .await
        .err()
        .expect("nothing answers there");
    assert!(format!("{err:#}").contains(&dead.to_string()), "{err:#}");
}

#[tokio::test]
async fn a_real_failure_is_not_buried_by_a_later_timeout() {
    let export = tempfile::tempdir().unwrap();
    let server = TestServer::start(export.path(), None).await;
    let (_dead_socket, dead) = dead_address();
    // The server answers, and refuses the pinned fingerprint; the address after it answers nothing at all.
    let mut config = config_for(
        server.addr,
        [0u8; 32],
        Auth::Anonymous,
        Duration::from_secs(5),
    );
    config.server_addrs = vec![server.addr, dead];
    config.connect_timeout = Duration::from_secs(1);
    let err = jackalopefs_client::Client::connect(config)
        .await
        .err()
        .expect("a pinned fingerprint that does not match must refuse");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains(&server.addr.to_string()) && !rendered.contains(&dead.to_string()),
        "the address that actually answered must be the one reported: {rendered}"
    );
    server.stop().await;
}

#[tokio::test]
async fn a_refusal_ends_the_candidate_sweep() {
    let hole = Blackhole::start_handshaking(vec![HelloReply::RevisionMismatch {
        revision: PROTO_REVISION ^ 1,
    }])
    .await;
    let (_dead_socket, dead) = dead_address();
    let mut config = hole.config(Duration::from_secs(5));
    config.server_addrs = vec![hole.addr, dead];
    // Long enough that trying the dead address at all would outlast the deadline below.
    config.connect_timeout = Duration::from_secs(30);
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        jackalopefs_client::Client::connect(config),
    )
    .await
    .expect("a refusal must end the sweep instead of moving on")
    .err()
    .expect("a foreign revision must refuse the connection");
    match err.downcast_ref::<ErrorConnect>().map(|e| &e.kind) {
        Some(ErrorConnectKind::Revision { .. }) => {}
        other => panic!("{other:?}: {err}"),
    }
}

#[tokio::test]
async fn server_refuses_a_foreign_revision() {
    let export = tempfile::tempdir().unwrap();
    let server = TestServer::start(export.path(), Some("s3cret".into())).await;
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(
        jackalopefs_client::transport::client_config(ServerTrust::Fingerprint(server.fingerprint))
            .unwrap(),
    );
    let hello = |revision, auth| Hello {
        revision,
        auth,
        resume: None,
    };

    // The revision is checked before the token, so a wrong token gets the revision diagnosis.
    let conn = endpoint
        .connect(server.addr, "jackalopefs")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    jackalopefs_proto::write_frame(
        &mut send,
        &hello(PROTO_REVISION ^ 1, Auth::Token("nope".into())),
    )
    .await
    .unwrap();
    send.finish().unwrap();
    let reply: HelloReply = jackalopefs_proto::read_frame(&mut recv).await.unwrap();
    assert_eq!(
        reply,
        HelloReply::RevisionMismatch {
            revision: PROTO_REVISION
        }
    );
    let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed())
        .await
        .expect("the server closes a refused connection");
    assert!(
        matches!(closed, quinn::ConnectionError::ApplicationClosed(_)),
        "{closed}"
    );

    let conn = endpoint
        .connect(server.addr, "jackalopefs")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    jackalopefs_proto::write_frame(
        &mut send,
        &hello(PROTO_REVISION, Auth::Token("s3cret".into())),
    )
    .await
    .unwrap();
    send.finish().unwrap();
    let reply: HelloReply = jackalopefs_proto::read_frame(&mut recv).await.unwrap();
    assert!(matches!(reply, HelloReply::Ack { .. }), "{reply:?}");
    conn.close(0u32.into(), b"done");
    server.stop().await;
}

#[tokio::test]
async fn client_refuses_a_foreign_revision() {
    // First connection: the mount never comes up, and the caller learns both revisions.
    let hole = Blackhole::start_handshaking(vec![HelloReply::RevisionMismatch {
        revision: PROTO_REVISION ^ 1,
    }])
    .await;
    let err = jackalopefs_client::Client::connect(hole.config(Duration::from_secs(5)))
        .await
        .err()
        .expect("a foreign revision must refuse the first connection");
    match err.downcast_ref::<ErrorConnect>().map(|e| &e.kind) {
        Some(ErrorConnectKind::Revision { client, server }) => {
            assert_eq!((*client, *server), (PROTO_REVISION, PROTO_REVISION ^ 1));
        }
        other => panic!("{other:?}: {err}"),
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let closed = hole
            .connections
            .lock()
            .first()
            .map(|c| c.close_reason().is_some());
        if closed == Some(true) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the client left the refused connection open"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // A mounted client whose server changes revision underneath it: the reconnect is refused every time, the state stays Connecting, and a call made as the connection goes fails by the offline deadline rather than at once, so a rollback can still recover the mount.
    let hole = Blackhole::start_handshaking(vec![
        Blackhole::ack(),
        HelloReply::RevisionMismatch {
            revision: PROTO_REVISION ^ 1,
        },
    ])
    .await;
    let client = jackalopefs_client::Client::connect(hole.config(Duration::from_millis(500)))
        .await
        .unwrap();
    hole.connections.lock()[0].close(0u32.into(), b"upgraded");
    let err = client.getattr(Some(Path::root()), None).await.unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err}");
    assert!(matches!(
        *client.state().borrow(),
        ConnState::Connecting { .. }
    ));
    assert!(
        hole.connections.lock().len() >= 2,
        "the client did not retry"
    );
    client.shutdown().await;
}

#[tokio::test]
async fn perf_tables_count_what_was_done() {
    let export = tempfile::tempdir().unwrap();
    fs::write(export.path().join("f"), vec![7u8; 4096]).unwrap();
    for i in 0..10 {
        fs::write(export.path().join(format!("e{i}")), b"").unwrap();
    }
    let server = TestServer::start(export.path(), None).await;
    let client = server.client().await;

    let attr = client.lookup(Path::root(), name("f")).await.unwrap();
    let (fh, _) = client
        .open(path("f"), libc::O_RDONLY, {
            let meant = attr.ino;
            move |attr| expect_ino(attr, meant)
        })
        .await
        .unwrap();
    for _ in 0..5 {
        assert_eq!(client.read(fh, 0, 1024).await.unwrap().len(), 1024);
    }
    let (dh, _) = client
        .opendir(Path::root(), move |attr| expect_ino(attr, 1))
        .await
        .unwrap();
    let (entries, _) = client.readdir(dh, 0, 1 << 20).await.unwrap();
    assert_eq!(entries.len(), 13, "10 entries, f, and the two dots");
    assert_eq!(
        client
            .lookup(Path::root(), name("nope"))
            .await
            .unwrap_err()
            .errno(),
        libc::ENOENT
    );

    let snap = client.perf().report();
    let read = &snap.call["read"];
    assert_eq!(
        (read.row.n, read.row.bytes, read.row.items),
        (5, 5 * 1024, 0)
    );
    assert!(read.row.errnos.is_empty());
    assert_eq!((read.retried, read.phased), (0, 5));
    let phased = read.phases.wait + read.phases.open + read.phases.send + read.phases.reply;
    assert!(
        phased <= read.row.total,
        "{phased:?} > {:?}",
        read.row.total
    );
    assert!(read.phases.reply > Duration::ZERO);
    assert!(read.row.max >= read.row.total / 5);
    assert_eq!(snap.call["readdir"].row.items, 13);
    assert_eq!(
        snap.call["lookup"].row.errnos,
        std::collections::BTreeMap::from([(libc::ENOENT, 1)])
    );
    assert!(snap.fuse.is_empty(), "no kernel was involved");
    assert!(
        client.perf().report().call.is_empty(),
        "a report starts a new window"
    );

    let served = server.server.perf.report();
    let read = &served.rows["read"];
    assert_eq!((read.n, read.bytes), (5, 5 * 1024));
    let phased = read.phases.read + read.phases.wait + read.phases.op + read.phases.send;
    assert!(phased <= read.total, "{phased:?} > {:?}", read.total);
    assert!(read.phases.op > Duration::ZERO);
    assert_eq!(served.rows["readdir"].items, 13);
    assert_eq!(
        served.rows["lookup"].errnos,
        std::collections::BTreeMap::from([(libc::ENOENT, 1)])
    );
    assert_eq!(
        server.server.connections.lock().len(),
        1,
        "the report has one connection to ask"
    );
    client.shutdown().await;
    wait_for(
        Duration::from_secs(3),
        "the connection to leave the table",
        || server.server.connections.lock().is_empty().then_some(()),
    )
    .await;
    server.stop().await;
}

#[tokio::test]
async fn perf_counts_a_timeout_by_its_errno() {
    let blackhole = Blackhole::start().await;
    let op_timeout = Duration::from_millis(500);
    let mut cfg = blackhole.config(Duration::from_secs(5));
    cfg.op_timeout = Some(op_timeout);
    let client = jackalopefs_client::Client::connect(cfg).await.unwrap();
    let err = client.getattr(Some(Path::root()), None).await.unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err}");

    let snap = client.perf().report();
    let row = &snap.call["getattr"];
    assert_eq!(row.row.n, 1);
    assert_eq!(
        row.row.errnos,
        std::collections::BTreeMap::from([(libc::ETIMEDOUT, 1)])
    );
    assert!(row.row.total >= op_timeout);
    // The request was sent and never answered, so the deadline was spent waiting for the reply.
    assert!(
        row.phases.reply >= op_timeout / 2,
        "reply phase {:?}",
        row.phases.reply
    );
    client.shutdown().await;
}

/// With no operation deadline, a request on a live connection is simply waited for; the client neither gives up nor cancels it on the wire.
#[tokio::test]
async fn a_call_on_a_live_connection_has_no_deadline() {
    let blackhole = Blackhole::start().await;
    let client = std::sync::Arc::new(
        jackalopefs_client::Client::connect(blackhole.config(Duration::from_millis(500)))
            .await
            .unwrap(),
    );
    let caller = client.clone();
    // Spawned rather than wrapped in a timeout: dropping the call future would itself cancel the stream.
    let pending = tokio::spawn(async move { caller.getattr(Some(Path::root()), None).await });
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !pending.is_finished(),
        "the call gave up on a live connection"
    );
    assert!(
        blackhole.stops.lock().is_empty(),
        "the call was cancelled on the wire"
    );
    pending.abort();
    client.shutdown().await;
}

/// Losing the connection is what fails a pending call: at once when it cannot be resent, and by the offline deadline when the resend finds no connection.
#[tokio::test]
async fn a_pending_call_fails_when_its_connection_is_lost() {
    let blackhole = Blackhole::start().await;
    let client = std::sync::Arc::new(
        jackalopefs_client::Client::connect(blackhole.config(Duration::from_millis(500)))
            .await
            .unwrap(),
    );
    let caller = client.clone();
    let pending = tokio::spawn(async move {
        caller
            .mkdir(Path::root(), name("d"), 0o755)
            .await
            .unwrap_err()
    });
    wait_for(
        Duration::from_secs(3),
        "the mkdir to reach the blackhole",
        || (!blackhole.requests.lock().is_empty()).then_some(()),
    )
    .await;
    let started = Instant::now();
    blackhole.connections.lock()[0].close(9u32.into(), b"simulated blip");
    let err = tokio::time::timeout(Duration::from_secs(1), pending)
        .await
        .expect("a lost mkdir fails at once")
        .unwrap();
    assert!(matches!(err, Error::Disconnected), "{err}");
    assert_eq!(err.errno(), libc::EIO);
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );
    client.shutdown().await;

    let hole = Blackhole::start_handshaking(vec![
        Blackhole::ack(),
        HelloReply::RevisionMismatch {
            revision: PROTO_REVISION ^ 1,
        },
    ])
    .await;
    let client = std::sync::Arc::new(
        jackalopefs_client::Client::connect(hole.config(Duration::from_millis(500)))
            .await
            .unwrap(),
    );
    let caller = client.clone();
    let pending =
        tokio::spawn(async move { caller.getattr(Some(Path::root()), None).await.unwrap_err() });
    wait_for(
        Duration::from_secs(3),
        "the getattr to reach the blackhole",
        || (!hole.requests.lock().is_empty()).then_some(()),
    )
    .await;
    let started = Instant::now();
    hole.connections.lock()[0].close(9u32.into(), b"simulated blip");
    let err = tokio::time::timeout(Duration::from_secs(3), pending)
        .await
        .expect("a lost getattr fails by the offline deadline")
        .unwrap();
    assert!(matches!(err, Error::Timeout), "{err}");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(400) && elapsed < Duration::from_secs(2),
        "{elapsed:?}"
    );
    client.shutdown().await;
}

/// A reply lost with its connection is an event, and a tap that selects it gets its detail with the call's identifiers.
#[tokio::test]
async fn a_lost_reply_is_an_event_naming_its_call() {
    use jackalopefs_perf::hub::{Names, Record, Selection};
    let hole = Blackhole::start_handshaking(vec![
        Blackhole::ack(),
        HelloReply::RevisionMismatch {
            revision: PROTO_REVISION ^ 1,
        },
    ])
    .await;
    let client = std::sync::Arc::new(
        jackalopefs_client::Client::connect(hole.config(Duration::from_millis(500)))
            .await
            .unwrap(),
    );
    let (_tap, mut records) = client.perf().hub.subscribe(Selection {
        events: Names::Some(vec!["call_lost_retried".into()]),
    });
    let caller = client.clone();
    let pending = tokio::spawn(async move { caller.getattr(Some(Path::root()), None).await });
    wait_for(
        Duration::from_secs(3),
        "the getattr to reach the blackhole",
        || (!hole.requests.lock().is_empty()).then_some(()),
    )
    .await;
    hole.connections.lock()[0].close(9u32.into(), b"simulated blip");
    let record = tokio::time::timeout(Duration::from_secs(3), records.recv())
        .await
        .expect("no event for the lost reply")
        .unwrap();
    let Record::Event {
        name, ids, detail, ..
    } = record
    else {
        panic!("{record:?}");
    };
    assert_eq!(name, "call_lost_retried");
    assert_eq!(ids.op, Some("getattr"));
    assert!(
        ids.session.is_some() && ids.conn.is_some() && ids.stream.is_some(),
        "{ids:?}"
    );
    assert!(!detail.is_empty());
    pending.await.unwrap().unwrap_err();
    client.shutdown().await;
}

/// Once the connection has been gone for the offline deadline, a call fails at once rather than waiting out a deadline of its own, so a program making call after call through an outage is not held for each one.
#[tokio::test]
async fn an_outage_past_the_offline_deadline_fails_calls_at_once() {
    let hole = Blackhole::start_handshaking(vec![
        Blackhole::ack(),
        HelloReply::RevisionMismatch {
            revision: PROTO_REVISION ^ 1,
        },
    ])
    .await;
    let client = std::sync::Arc::new(
        jackalopefs_client::Client::connect(hole.config(Duration::from_secs(1)))
            .await
            .unwrap(),
    );
    hole.connections.lock()[0].close(9u32.into(), b"simulated outage");
    wait_for(Duration::from_secs(3), "the loss to be seen", || {
        matches!(*client.state().borrow(), ConnState::Connecting { .. }).then_some(())
    })
    .await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        hole.connections.lock().len() >= 3,
        "the outage did not span several refused attempts"
    );

    let started = Instant::now();
    let err = client.getattr(Some(Path::root()), None).await.unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err}");
    assert!(
        started.elapsed() < Duration::from_millis(800),
        "a call late in the outage waited a deadline of its own: {:?}",
        started.elapsed()
    );
    let started = Instant::now();
    let err = client.getattr(Some(Path::root()), None).await.unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err}");
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "a call after the outage's deadline waited: {:?}",
        started.elapsed()
    );
    client.shutdown().await;
}

/// A release that fails for want of a connection is owed to the session: the server would otherwise hold that descriptor for as long as the session lives, so it is sent once the session resumes.
#[tokio::test]
async fn a_release_failed_in_an_outage_is_sent_when_the_session_resumes() {
    let refused = HelloReply::RevisionMismatch {
        revision: PROTO_REVISION ^ 1,
    };
    let mut resumed = Blackhole::ack();
    if let HelloReply::Ack { resumed, .. } = &mut resumed {
        *resumed = true;
    }
    // Four refusals hold the outage for the backoff's 100 + 200 + 400 + 800 ms before the session resumes.
    let hole = Blackhole::start_answering_handshaking(
        |_| jackalopefs_proto::Response::Ok,
        vec![
            Blackhole::ack(),
            refused.clone(),
            refused.clone(),
            refused.clone(),
            refused,
            resumed,
        ],
    )
    .await;
    let client = jackalopefs_client::Client::connect(hole.config(Duration::from_millis(200)))
        .await
        .unwrap();
    hole.connections.lock()[0].close(9u32.into(), b"simulated outage");
    wait_for(Duration::from_secs(3), "the loss to be seen", || {
        matches!(*client.state().borrow(), ConnState::Connecting { .. }).then_some(())
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let err = client.release(7).await.unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err}");
    assert!(
        matches!(*client.state().borrow(), ConnState::Connecting { .. }),
        "the session resumed before the release failed; the test proves nothing"
    );
    wait_for_generation(&client, 2).await;
    wait_for(Duration::from_secs(3), "the owed release", || {
        hole.requests
            .lock()
            .iter()
            .any(|req| matches!(req, Request::Release { fh: 7 }))
            .then_some(())
    })
    .await;
    client.shutdown().await;
}

/// The outage's deadline belongs to that outage: once the connection is back calls succeed, and the next loss gives them a full wait again.
#[tokio::test]
async fn calls_wait_again_once_the_connection_is_back() {
    let export = tempfile::tempdir().unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let identity = jackalopefs_server::tls::Identity::generate().unwrap();
    let first = TestServer::start_with(export.path(), None, socket, identity.clone()).await;
    let client = jackalopefs_client::Client::connect(first.config(Duration::from_secs(2)))
        .await
        .unwrap();
    let connecting = |client: &jackalopefs_client::Client| {
        matches!(*client.state().borrow(), ConnState::Connecting { .. }).then_some(())
    };

    first.stop().await;
    // Held until the restart, so the port cannot be handed to a concurrent test meanwhile.
    let held = wait_for(Duration::from_secs(5), "the port to be free again", || {
        std::net::UdpSocket::bind(("127.0.0.1", port)).ok()
    })
    .await;
    wait_for(Duration::from_secs(5), "the loss to be seen", || {
        connecting(&client)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let started = Instant::now();
    let err = client.getattr(Some(Path::root()), None).await.unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err}");
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "a call after the outage's deadline waited: {:?}",
        started.elapsed()
    );

    let second = TestServer::start_with(export.path(), None, held, identity).await;
    wait_for_generation(&client, 2).await;
    client.getattr(Some(Path::root()), None).await.unwrap();

    // Stopped in the background: the stop drains the endpoint, and the client has seen the close long before that ends.
    let stopping = tokio::spawn(second.stop());
    wait_for(Duration::from_secs(5), "the second loss to be seen", || {
        connecting(&client)
    })
    .await;
    let started = Instant::now();
    let err = client.getattr(Some(Path::root()), None).await.unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err}");
    assert!(
        started.elapsed() >= Duration::from_millis(1200),
        "a call at the start of a new outage did not wait for it: {:?}",
        started.elapsed()
    );
    stopping.await.unwrap();
    client.shutdown().await;
}

/// An interrupt from the kernel abandons the call it was made for, cancels it on the wire, and latches: a later call for the same kernel request fails at once.
#[tokio::test]
async fn an_interrupt_abandons_a_pending_call() {
    let blackhole = Blackhole::start().await;
    let client = std::sync::Arc::new(
        jackalopefs_client::Client::connect(blackhole.config(Duration::from_secs(5)))
            .await
            .unwrap(),
    );
    let req = RequestKernel::new(7);
    let (caller, scoped) = (client.clone(), req.clone());
    let pending = tokio::spawn(async move {
        scoped
            .scope(async move { caller.getattr(Some(Path::root()), None).await })
            .await
    });
    wait_for(
        Duration::from_secs(3),
        "the getattr to reach the blackhole",
        || (!blackhole.requests.lock().is_empty()).then_some(()),
    )
    .await;
    let started = Instant::now();
    req.interrupt();
    let err = tokio::time::timeout(Duration::from_secs(1), pending)
        .await
        .expect("an interrupted call returns at once")
        .unwrap()
        .unwrap_err();
    assert!(matches!(err, Error::Interrupted), "{err}");
    assert_eq!(err.errno(), libc::EINTR);
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );
    wait_for(
        Duration::from_secs(3),
        "the abandoned stream to be stopped",
        || {
            blackhole
                .stops
                .lock()
                .contains(&u64::from(jackalopefs_client::conn::close_code::CANCELLED))
                .then_some(())
        },
    )
    .await;

    let caller = client.clone();
    let err = req
        .scope(async move { caller.getattr(Some(Path::root()), None).await })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Interrupted), "{err}");
    assert_eq!(
        blackhole.requests.lock().len(),
        1,
        "an interrupted request made another call"
    );
    client.shutdown().await;
}

#[tokio::test]
async fn perf_counts_an_interrupt_with_its_phases() {
    let blackhole = Blackhole::start().await;
    let client = std::sync::Arc::new(
        jackalopefs_client::Client::connect(blackhole.config(Duration::from_secs(5)))
            .await
            .unwrap(),
    );
    let req = RequestKernel::new(1);
    let wait = Duration::from_millis(500);
    let (caller, scoped) = (client.clone(), req.clone());
    let pending = tokio::spawn(async move {
        scoped
            .scope(async move { caller.getattr(Some(Path::root()), None).await })
            .await
    });
    tokio::time::sleep(wait).await;
    req.interrupt();
    let err = pending.await.unwrap().unwrap_err();
    assert!(matches!(err, Error::Interrupted), "{err}");

    let snap = client.perf().report();
    let row = &snap.call["getattr"];
    assert_eq!(row.row.n, 1);
    assert_eq!(
        row.row.errnos,
        std::collections::BTreeMap::from([(libc::EINTR, 1)])
    );
    assert!(row.row.total >= wait);
    // The request was sent and never answered, so the time until the interrupt was spent waiting for the reply.
    assert!(
        row.phases.reply >= wait / 2,
        "reply phase {:?}",
        row.phases.reply
    );
    client.shutdown().await;
}

/// What the stall watchdog reads off a kernel request: the call it is making, which phase that is in and on which connection and stream, and nothing once the call is over.
#[tokio::test]
async fn a_kernel_request_shows_where_its_call_stands() {
    let blackhole = Blackhole::start_handshaking(vec![
        Blackhole::ack(),
        HelloReply::Reject {
            reason: "not now".into(),
        },
    ])
    .await;
    let client = std::sync::Arc::new(
        jackalopefs_client::Client::connect(blackhole.config(Duration::from_secs(2)))
            .await
            .unwrap(),
    );
    let patience = Duration::from_secs(1);
    let call_in = |req: &RequestKernel, phase: PhaseCall| {
        req.call_now(patience)
            .expect("the call lock is free")
            .filter(|call| call.phase == phase)
    };
    let req = RequestKernel::new(7);
    assert!(req.call_now(patience).unwrap().is_none());
    let (caller, scoped) = (client.clone(), req.clone());
    let pending = tokio::spawn(async move {
        scoped
            .scope(async move { caller.getattr(Some(Path::root()), None).await })
            .await
    });
    let call = wait_for(
        Duration::from_secs(3),
        "the getattr to await its reply",
        || call_in(&req, PhaseCall::Reply),
    )
    .await;
    assert!(req.started());
    assert_eq!(call.req.op_name(), "getattr");
    assert_eq!((call.generation, call.retries), (Some(1), 0));
    assert!(call.stream.is_some());

    // getattr is resent once when its reply is lost, and every reconnect is refused, so it waits for a connection until the offline deadline.
    blackhole.connections.lock()[0].close(9u32.into(), b"simulated blip");
    let call = wait_for(
        Duration::from_secs(3),
        "the resent getattr to wait for a connection",
        || call_in(&req, PhaseCall::Wait),
    )
    .await;
    assert_eq!(
        (call.generation, call.retries, call.stream),
        (None, 1, None)
    );
    let err = pending.await.unwrap().unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err}");
    assert!(req.call_now(patience).unwrap().is_none());
    client.shutdown().await;
}

/// A call whose future is dropped (an interrupt, a timeout, an aborted task) leaves no call behind on its kernel request.
#[tokio::test]
async fn a_dropped_call_leaves_no_trace_on_its_kernel_request() {
    let blackhole = Blackhole::start().await;
    let client = std::sync::Arc::new(
        jackalopefs_client::Client::connect(blackhole.config(Duration::from_secs(5)))
            .await
            .unwrap(),
    );
    let req = RequestKernel::new(8);
    let (caller, scoped) = (client.clone(), req.clone());
    let pending = tokio::spawn(async move {
        scoped
            .scope(async move { caller.mkdir(Path::root(), name("d"), 0o755).await })
            .await
    });
    wait_for(
        Duration::from_secs(3),
        "the mkdir to await its reply",
        || {
            req.call_now(Duration::from_secs(1))
                .unwrap()
                .filter(|call| call.phase == PhaseCall::Reply)
        },
    )
    .await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    assert!(req.call_now(Duration::from_secs(1)).unwrap().is_none());
    client.shutdown().await;
}

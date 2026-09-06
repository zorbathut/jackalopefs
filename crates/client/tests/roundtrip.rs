mod common;

use common::*;
use jackalopefs_client::{ConnState, Error, ErrorConnect, ServerTrust};
use jackalopefs_proto::{
    Auth, Hello, HelloReply, Path, Request, SetAttr, TimeOrNow, TimeSpec, PROTO_REVISION,
};
use std::collections::BTreeSet;
use std::fs;
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

#[tokio::test]
async fn file_lifecycle() {
    let export = tempfile::tempdir().unwrap();
    let server = TestServer::start(export.path(), None).await;
    let client = server.client().await;

    let (fh, attr) = client
        .create(Path::root(), name("f"), 0o100640, libc::O_RDWR)
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
        .open(attr.ino, path("f"), libc::O_WRONLY | libc::O_APPEND)
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
async fn unlink_while_open_and_stale_open() {
    let export = tempfile::tempdir().unwrap();
    let server = TestServer::start(export.path(), None).await;
    let client = server.client().await;

    let (fh, attr) = client
        .create(Path::root(), name("gone"), 0o100644, libc::O_RDWR)
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
        .open(other_ino + 1_000_000, path("other"), libc::O_RDONLY)
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

    let (fh, attr) = client.opendir(1, Path::root()).await.unwrap();
    assert_eq!(attr.ino, 1);
    let mut seen = Vec::new();
    let mut offset = 0;
    let mut pages = 0;
    loop {
        let page = client.readdir(fh, offset, 4096).await.unwrap();
        if page.is_empty() {
            break;
        }
        pages += 1;
        offset = page.last().unwrap().next_offset;
        seen.extend(page.into_iter().map(|e| e.name));
    }
    assert!(pages > 10, "expected many pages, got {pages}");
    assert_eq!(seen.len(), 5002);
    let unique: BTreeSet<_> = seen.iter().cloned().collect();
    assert_eq!(unique.len(), 5002, "no duplicates across pages");
    assert!(unique.contains(b".".as_slice()) && unique.contains(b"..".as_slice()));

    let mut plus_seen = 0;
    let mut offset = 0;
    loop {
        let page = client.readdirplus(fh, offset, 1 << 20).await.unwrap();
        if page.is_empty() {
            break;
        }
        for entry in &page {
            assert_eq!(entry.attr.is_none(), entry.entry.is_dot_or_dotdot());
        }
        plus_seen += page.len();
        offset = page.last().unwrap().entry.next_offset;
    }
    assert_eq!(plus_seen, 5002);

    let (a, b) = tokio::join!(
        client.readdir(fh, 0, 1 << 20),
        client.readdir(fh, 0, 1 << 20)
    );
    assert_eq!(a.unwrap().len(), 5002);
    assert_eq!(b.unwrap().len(), 5002);
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
    let client = jackalopefs_client::Client::connect(blackhole.config(Duration::from_millis(500)))
        .await
        .unwrap();

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
        .open(1, Path::root(), libc::O_RDONLY)
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

#[tokio::test]
async fn a_nonsense_reply_to_an_open_releases_the_handle() {
    let blackhole = Blackhole::start_with(Some(jackalopefs_proto::Response::Ok)).await;
    let client = jackalopefs_client::Client::connect(blackhole.config(Duration::from_secs(5)))
        .await
        .unwrap();
    let err = client
        .open(1, Path::root(), libc::O_RDONLY)
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
    assert!(matches!(resp, jackalopefs_proto::Response::Attr(a) if a.ino == 1));
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
    client.release(fh).await.unwrap();
    client.shutdown().await;
    server.stop().await;
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
        .open(keep_ino, path("keep"), libc::O_RDONLY)
        .await
        .unwrap();
    let (swap_fh, _) = client
        .open(swap_ino, path("swap"), libc::O_RDONLY)
        .await
        .unwrap();
    let (dir_fh, _) = client.opendir(1, Path::root()).await.unwrap();

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
    assert!(client.readdir(dir_fh, 0, 1 << 20).await.unwrap().len() >= 4);
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
    match err.downcast_ref::<ErrorConnect>() {
        Some(ErrorConnect::Revision { client, server }) => {
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

    // A mounted client whose server changes revision underneath it: the reconnect is refused every time, the state stays Connecting, and calls fail by the deadline rather than at once, so a rollback can still recover the mount.
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
    assert!(matches!(*client.state().borrow(), ConnState::Connecting));
    assert!(
        hole.connections.lock().len() >= 2,
        "the client did not retry"
    );
    client.shutdown().await;
}

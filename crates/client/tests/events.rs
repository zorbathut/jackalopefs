mod common;

use common::*;
use jackalopefs_proto::control::{Happened, Selection};
use jackalopefs_proto::{decode, Event, EventItem, Path};
use std::fs;
use std::time::Duration;
use tokio::sync::mpsc;

/// Items received so far, so a search never discards the rest of a batch.
struct Inbox {
    rx: mpsc::Receiver<Event>,
    items: Vec<EventItem>,
}

impl Inbox {
    fn new(rx: mpsc::Receiver<Event>) -> Inbox {
        Inbox {
            rx,
            items: Vec::new(),
        }
    }

    /// The first buffered or newly arriving item matching `pred`, or `None` once `limit` passes.
    async fn find(
        &mut self,
        limit: Duration,
        mut pred: impl FnMut(&EventItem) -> bool,
    ) -> Option<EventItem> {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            if let Some(pos) = self.items.iter().position(&mut pred) {
                return Some(self.items.remove(pos));
            }
            match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                Ok(Some(event)) => self.items.extend(event.items),
                Ok(None) | Err(_) => return None,
            }
        }
    }
}

#[tokio::test]
async fn server_side_changes_reach_the_client_but_own_changes_do_not() {
    let export = tempfile::tempdir().unwrap();
    fs::create_dir(export.path().join("sub")).unwrap();
    let server = TestServer::start(export.path(), None).await;
    let mut client = server.client().await;
    let mut events = Inbox::new(client.take_events().unwrap());
    let mut observer = server.client().await;
    let mut observer_events = Inbox::new(observer.take_events().unwrap());
    // A directory is watched once a request names it, as any client's does before it caches anything there.
    client
        .lookup(path("sub"), name("created"))
        .await
        .unwrap_err();

    fs::write(export.path().join("sub/created"), b"x").unwrap();
    let item = events
        .find(
            Duration::from_secs(3),
            |i| matches!(i, EventItem::Entry { name, .. } if name.as_bytes() == b"created"),
        )
        .await;
    assert_eq!(
        item,
        Some(EventItem::Entry {
            dir: path("sub"),
            name: name("created")
        })
    );

    fs::write(export.path().join("sub/created"), b"more data").unwrap();
    let item = events
        .find(
            Duration::from_secs(3),
            |i| matches!(i, EventItem::Data { path: p } if *p == path("sub/created")),
        )
        .await;
    assert!(item.is_some(), "a content change is a data event");

    // The client's own create + write must not come back to it, but the other client must hear about both.
    let (fh, _) = client
        .create(
            path("sub"),
            name("mine"),
            0o100644,
            libc::O_RDWR,
            None,
            |attr| Ok(attr.ino),
        )
        .await
        .unwrap();
    client.write(fh, 0, b"payload".to_vec()).await.unwrap();
    client.release(fh).await.unwrap();
    let echoed = events
        .find(Duration::from_millis(700), |i| match i {
            EventItem::Entry { name, .. } => name.as_bytes() == b"mine",
            EventItem::Data { path: p } => p.to_os_string() == "sub/mine",
            EventItem::Overflow => true,
            EventItem::Unwatched { .. } => false,
        })
        .await;
    assert_eq!(echoed, None, "own changes must not be echoed");
    let seen_by_observer = observer_events
        .find(
            Duration::from_secs(3),
            |i| matches!(i, EventItem::Entry { name, .. } if name.as_bytes() == b"mine"),
        )
        .await;
    assert!(seen_by_observer.is_some(), "another session hears about it");

    fs::rename(export.path().join("sub/mine"), export.path().join("moved")).unwrap();
    let from = events.find(Duration::from_secs(3), |i| matches!(i, EventItem::Entry { dir, name } if *dir == path("sub") && name.as_bytes() == b"mine")).await;
    assert!(from.is_some(), "rename source is an entry change");
    let to = events.find(Duration::from_secs(3), |i| matches!(i, EventItem::Entry { dir, name } if *dir == Path::root() && name.as_bytes() == b"moved")).await;
    assert!(to.is_some(), "rename target is an entry change");

    client.shutdown().await;
    observer.shutdown().await;
    server.stop().await;
}

#[tokio::test]
async fn a_directory_no_client_has_named_is_not_watched() {
    let export = tempfile::tempdir().unwrap();
    fs::create_dir(export.path().join("quiet")).unwrap();
    let server = TestServer::start(export.path(), None).await;
    let mut client = server.client().await;
    let mut events = Inbox::new(client.take_events().unwrap());
    let in_quiet =
        |i: &EventItem| matches!(i, EventItem::Entry { dir, .. } if *dir == path("quiet"));

    fs::write(export.path().join("quiet/unseen"), b"").unwrap();
    // The kernel queues events in order: once the root's change has come, anything the first was going to produce has too.
    fs::write(export.path().join("sentinel"), b"").unwrap();
    let sentinel = events
        .find(
            Duration::from_secs(3),
            |i| matches!(i, EventItem::Entry { name, .. } if name.as_bytes() == b"sentinel"),
        )
        .await;
    assert!(sentinel.is_some(), "the root is always watched");
    assert!(!events.items.iter().any(in_quiet), "{:?}", events.items);

    client.lookup(path("quiet"), name("unseen")).await.unwrap();
    fs::write(export.path().join("quiet/seen"), b"").unwrap();
    let item = events.find(Duration::from_secs(3), in_quiet).await;
    assert_eq!(
        item,
        Some(EventItem::Entry {
            dir: path("quiet"),
            name: name("seen")
        })
    );

    client.shutdown().await;
    server.stop().await;
}

/// Wait until `client` is connected again to the session it had.
async fn wait_for_resume(client: &jackalopefs_client::Client) {
    wait_for(
        Duration::from_secs(10),
        "the session to resume",
        || match &*client.state().borrow() {
            jackalopefs_client::conn::ConnState::Connected(attached) => {
                (attached.state.generation >= 2).then(|| {
                    assert!(
                        attached.resumed,
                        "the session was resumed, not opened afresh"
                    )
                })
            }
            _ => None,
        },
    )
    .await;
}

fn handles_reported(client: &jackalopefs_client::Client) -> u64 {
    client
        .perf()
        .events
        .counts()
        .into_iter()
        .find(|(name, _)| *name == "handles_reported")
        .map_or(0, |(_, n)| n)
}

/// A session past its share of the server's handles is told so on its own event stream, which goes on carrying changes, and told again on the connection it resumes on; another client is told nothing.
#[tokio::test]
async fn a_notice_of_many_handles_reaches_its_own_session_and_again_on_resume() {
    let export = tempfile::tempdir().unwrap();
    for dir in ["a", "b", "c", "d"] {
        fs::create_dir(export.path().join(dir)).unwrap();
    }
    let server = TestServer::start_sharing(export.path(), 2).await;
    let mut client = server.client().await;
    let mut events = Inbox::new(client.take_events().unwrap());
    let frames = Selection {
        frames: true,
        every: 1,
        ..Selection::default()
    };
    let (_server_tap, mut server_frames) = server.server.perf.hub.subscribe(frames.clone());
    let (_client_tap, mut client_frames) = client.perf().hub.subscribe(frames);
    let other = server.client().await;
    for dir in ["a", "b"] {
        client
            .opendir(path(dir), None, |attr| Ok(attr.ino))
            .await
            .unwrap();
    }
    wait_for(Duration::from_secs(5), "the notice", || {
        (handles_reported(&client) == 1).then_some(())
    })
    .await;

    fs::write(export.path().join("a/new"), b"x").unwrap();
    let item = events
        .find(
            Duration::from_secs(3),
            |i| matches!(i, EventItem::Entry { name, .. } if name.as_bytes() == b"new"),
        )
        .await;
    assert!(item.is_some(), "changes still arrive after a notice");
    // Notices are numbered with the batches alike at both ends, so a sample of one in `every` picks the same frames.
    let session = match &*client.state().borrow() {
        jackalopefs_client::conn::ConnState::Connected(attached) => attached.session_id,
        other => panic!("not connected: {other:?}"),
    };
    // Each session's stream is numbered on its own, and the server carries the other client's too.
    let numbered = |frames: &mut jackalopefs_perf::hub::TapReceiver| {
        let mut seen = std::collections::BTreeMap::new();
        while let Some(record) = frames.try_recv() {
            if let Happened::EventFrame { seq, body, ids, .. } = record.what {
                if ids.session == Some(session) {
                    seen.insert(seq, body);
                }
            }
        }
        seen
    };
    let at_server = numbered(&mut server_frames);
    let at_client = numbered(&mut client_frames);
    assert!(
        at_client
            .values()
            .any(|body| decode::<Event>(body).unwrap().handles.is_some()),
        "the notice is among the frames: {at_client:?}"
    );
    // Either end may have recorded a frame the other has not yet; those both saw must agree.
    let both: Vec<u64> = at_client
        .keys()
        .filter(|seq| at_server.contains_key(seq))
        .copied()
        .collect();
    for seq in &both {
        assert_eq!(
            at_server[seq], at_client[seq],
            "frame {seq} differs between the ends"
        );
    }
    assert!(
        both.iter()
            .any(|seq| decode::<Event>(&at_client[seq]).unwrap().handles.is_some()),
        "the notice was seen at both ends: {both:?}"
    );
    assert_eq!(handles_reported(&other), 0);

    let (_, conn) = client.connection().unwrap();
    conn.close(9u32.into(), b"simulated outage");
    wait_for_resume(&client).await;
    // A notice already written is not repeated on the next connection; the next threshold is told on it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(handles_reported(&client), 1);
    for dir in ["c", "d"] {
        client
            .opendir(path(dir), None, |attr| Ok(attr.ino))
            .await
            .unwrap();
    }
    wait_for(
        Duration::from_secs(5),
        "the next notice on the resumed connection",
        || (handles_reported(&client) == 2).then_some(()),
    )
    .await;
    assert_eq!(handles_reported(&other), 0);
    client.shutdown().await;
    other.shutdown().await;
    server.stop().await;
}

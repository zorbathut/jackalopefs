mod common;

use common::*;
use jackalopefs_proto::{Event, EventItem, Path};
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
        .create(path("sub"), name("mine"), 0o100644, libc::O_RDWR)
        .await
        .unwrap();
    client.write(fh, 0, b"payload".to_vec()).await.unwrap();
    client.release(fh).await.unwrap();
    let echoed = events
        .find(Duration::from_millis(700), |i| match i {
            EventItem::Entry { name, .. } => name.as_bytes() == b"mine",
            EventItem::Data { path: p } => p.to_os_string() == "sub/mine",
            EventItem::Overflow => true,
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

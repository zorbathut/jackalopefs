//! Taps: what a subscriber (`jackalopefs-ctl`) selected, and the records delivered to it. Nothing here costs anything while no tap exists; a tap's queue is bounded in records and in bytes, and what does not fit is dropped and counted rather than held.

use jackalopefs_proto::control::{Happened, Ids, Record, Selection, Summary};
use parking_lot::{Mutex, RwLock};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::SystemTime;
use tokio::sync::mpsc;

/// Records a tap holds at most before it drops.
const TAP_RECORDS: usize = 1024;

/// Bytes of records a tap holds at most before it drops.
const TAP_BYTES: usize = 32 << 20;

/// The identifiers that join a record to the log lines and to the other side's records, each where it is known.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdsEvent {
    pub session: Option<u64>,
    /// The connection's key ([`conn_key`](crate::conn_key)), the same on both sides.
    pub conn: Option<u64>,
    /// The QUIC stream a request travelled on.
    pub stream: Option<u64>,
    /// The client's kernel request.
    pub unique: Option<u64>,
    pub op: Option<&'static str>,
}

impl IdsEvent {
    pub fn to_ids(&self) -> Ids {
        Ids {
            session: self.session,
            conn: self.conn,
            stream: self.stream,
            unique: self.unique,
            op: self.op.map(str::to_owned),
        }
    }
}

/// Unix time in nanoseconds.
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos() as u64)
}

/// Roughly what a record holds in memory, for the tap's byte bound.
fn size(record: &Record) -> usize {
    match &record.what {
        Happened::Event { detail, .. } => 128 + detail.len(),
        Happened::Request(summary) => 192 + 32 * summary.phases.len(),
        Happened::Dropped(_) => 32,
    }
}

/// A set of counted things a tap can select by name; the hub tells it when taps come and go, so it can keep its own cheap check of whether anyone is looking.
pub(crate) trait Registry: Send + Sync {
    fn adjust(&self, selection: &Selection, delta: i32);
}

/// Every tap of one process instance, and the registries they select from. Whatever changes the taps or the registries takes the registries' lock first, so a tap is counted once in every registry however the two interleave.
#[derive(Default)]
pub struct Hub {
    taps: RwLock<Vec<Arc<Tap>>>,
    registries: Mutex<Vec<Weak<dyn Registry>>>,
    /// Taps that want request summaries.
    requests: AtomicU32,
}

struct Tap {
    selection: Selection,
    tx: mpsc::Sender<Record>,
    bytes: Arc<AtomicUsize>,
    dropped: AtomicU64,
}

impl Tap {
    /// Queue `record` unless that would pass either bound, first telling the subscriber what was dropped since it last heard.
    fn offer(&self, record: Record) {
        let dropped = self.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            let told = Record {
                at_ns: record.at_ns,
                what: Happened::Dropped(dropped),
            };
            if !self.send(told) {
                self.dropped.fetch_add(dropped, Ordering::Relaxed);
            }
        }
        if !self.send(record) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn send(&self, record: Record) -> bool {
        let size = size(&record);
        if self.bytes.fetch_add(size, Ordering::Relaxed) + size > TAP_BYTES {
            self.bytes.fetch_sub(size, Ordering::Relaxed);
            return false;
        }
        if self.tx.try_send(record).is_err() {
            self.bytes.fetch_sub(size, Ordering::Relaxed);
            return false;
        }
        true
    }
}

/// Keeps a tap subscribed; dropping it unsubscribes, and every check it made true goes back to costing nothing.
pub struct TapHandle {
    hub: Arc<Hub>,
    tap: Arc<Tap>,
}

impl Drop for TapHandle {
    fn drop(&mut self) {
        let mut registries = self.hub.registries.lock();
        self.hub
            .taps
            .write()
            .retain(|tap| !Arc::ptr_eq(tap, &self.tap));
        self.hub.adjust(&mut registries, &self.tap.selection, -1);
    }
}

/// The receiving end of a tap.
pub struct TapReceiver {
    rx: mpsc::Receiver<Record>,
    bytes: Arc<AtomicUsize>,
}

impl TapReceiver {
    /// The next record; `None` once the tap is unsubscribed and drained.
    pub async fn recv(&mut self) -> Option<Record> {
        let record = self.rx.recv().await?;
        self.bytes.fetch_sub(size(&record), Ordering::Relaxed);
        Some(record)
    }

    /// The next record if one is queued; `None` when none is, or the tap is gone.
    pub fn try_recv(&mut self) -> Option<Record> {
        let record = self.rx.try_recv().ok()?;
        self.bytes.fetch_sub(size(&record), Ordering::Relaxed);
        Some(record)
    }
}

impl Hub {
    pub fn subscribe(self: &Arc<Self>, selection: Selection) -> (TapHandle, TapReceiver) {
        let (tx, rx) = mpsc::channel(TAP_RECORDS);
        let bytes = Arc::new(AtomicUsize::new(0));
        let tap = Arc::new(Tap {
            selection,
            tx,
            bytes: bytes.clone(),
            dropped: AtomicU64::new(0),
        });
        let mut registries = self.registries.lock();
        // In the list before anyone's check turns true, so nothing offered for it is missed.
        self.taps.write().push(tap.clone());
        self.adjust(&mut registries, &tap.selection, 1);
        drop(registries);
        (
            TapHandle {
                hub: self.clone(),
                tap,
            },
            TapReceiver { rx, bytes },
        )
    }

    pub(crate) fn register(&self, registry: Weak<dyn Registry>) {
        let mut registries = self.registries.lock();
        if let Some(live) = registry.upgrade() {
            for tap in self.taps.read().iter() {
                live.adjust(&tap.selection, 1);
            }
        }
        registries.push(registry);
    }

    /// Count a tap in or out, with the registries' lock held.
    fn adjust(&self, registries: &mut Vec<Weak<dyn Registry>>, selection: &Selection, delta: i32) {
        if !selection.ops.is_none() {
            if delta > 0 {
                self.requests.fetch_add(delta as u32, Ordering::Relaxed);
            } else {
                self.requests
                    .fetch_sub(delta.unsigned_abs(), Ordering::Relaxed);
            }
        }
        registries.retain(|registry| match registry.upgrade() {
            Some(live) => {
                live.adjust(selection, delta);
                true
            }
            None => false,
        });
    }

    pub(crate) fn deliver_event(&self, name: &'static str, ids: &IdsEvent, detail: &str) {
        let at_ns = now_ns();
        for tap in self.taps.read().iter() {
            if tap.selection.events.has(name) {
                tap.offer(Record {
                    at_ns,
                    what: Happened::Event {
                        name: name.to_owned(),
                        ids: ids.to_ids(),
                        detail: detail.to_owned(),
                    },
                });
            }
        }
    }

    /// Whether any tap wants request summaries: one relaxed load, so a request costs nothing more while nobody looks.
    pub fn wants_requests(&self) -> bool {
        self.requests.load(Ordering::Relaxed) > 0
    }

    /// Hand the summary of a request of operation `op` to the taps that want it, building it only if one does.
    pub fn deliver_request(&self, op: &str, summary: impl FnOnce() -> Summary) {
        let taps = self.taps.read();
        let wanting: Vec<&Arc<Tap>> = taps
            .iter()
            .filter(|tap| tap.selection.ops.has(op))
            .collect();
        if wanting.is_empty() {
            return;
        }
        let record = Record {
            at_ns: now_ns(),
            what: Happened::Request(summary()),
        };
        for tap in wanting {
            tap.offer(record.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jackalopefs_proto::control::Names;

    fn selecting(names: &[&str]) -> Selection {
        Selection {
            events: Names::Some(names.iter().map(|n| n.to_string()).collect()),
            ..Selection::default()
        }
    }

    #[test]
    fn a_tap_gets_only_what_it_selected() {
        let hub = Arc::new(Hub::default());
        let (_handle, mut rx) = hub.subscribe(selecting(&["a"]));
        hub.deliver_event("b", &IdsEvent::default(), "not wanted");
        hub.deliver_event("a", &IdsEvent::default(), "wanted");
        match rx.try_recv().map(|r| r.what) {
            Some(Happened::Event { name, detail, .. }) => {
                assert_eq!((name.as_str(), detail.as_str()), ("a", "wanted"))
            }
            other => panic!("{other:?}"),
        }
        assert!(rx.try_recv().is_none());
    }

    #[test]
    fn a_full_tap_drops_and_says_how_many() {
        let hub = Arc::new(Hub::default());
        let (_handle, mut rx) = hub.subscribe(selecting(&["a"]));
        for _ in 0..TAP_RECORDS + 10 {
            hub.deliver_event("a", &IdsEvent::default(), "x");
        }
        let mut events = 0;
        while rx.try_recv().is_some() {
            events += 1;
        }
        assert_eq!(events, TAP_RECORDS);
        hub.deliver_event("a", &IdsEvent::default(), "after");
        assert_eq!(rx.try_recv().map(|r| r.what), Some(Happened::Dropped(10)));
        assert!(matches!(
            rx.try_recv().map(|r| r.what),
            Some(Happened::Event { .. })
        ));
    }

    #[test]
    fn a_tap_is_bounded_in_bytes_too() {
        let hub = Arc::new(Hub::default());
        let (_handle, mut rx) = hub.subscribe(selecting(&["a"]));
        let big = "x".repeat(TAP_BYTES / 4);
        for _ in 0..8 {
            hub.deliver_event("a", &IdsEvent::default(), &big);
        }
        let mut taken = 0;
        while let Some(record) = rx.try_recv() {
            if matches!(record.what, Happened::Event { .. }) {
                taken += 1;
            }
        }
        assert!(taken < 4, "{taken} records of a quarter of the bound each");
        assert!(taken >= 1);
    }

    #[test]
    fn request_summaries_are_built_only_for_a_tap_that_wants_their_op() {
        let hub = Arc::new(Hub::default());
        assert!(!hub.wants_requests());
        let (handle, mut rx) = hub.subscribe(Selection {
            ops: Names::Some(vec!["read".into()]),
            ..Selection::default()
        });
        assert!(hub.wants_requests());
        hub.deliver_request("write", || panic!("nobody wants writes"));
        hub.deliver_request("read", || Summary {
            level: "call".into(),
            bytes: 7,
            ..Summary::default()
        });
        assert!(matches!(
            rx.try_recv().map(|r| r.what),
            Some(Happened::Request(Summary { bytes: 7, .. }))
        ));
        drop(handle);
        assert!(!hub.wants_requests());
    }
}

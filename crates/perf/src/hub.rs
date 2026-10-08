//! Taps: what a subscriber (`jackalopefs-ctl`) selected, and the records delivered to it. Nothing here costs anything while no tap exists; a tap's queue is bounded in records and in bytes, and what does not fit is dropped and counted rather than held.

use parking_lot::{Mutex, RwLock};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
    /// The connection's key, the same on both sides (see the connection key in `docs/design.md`).
    pub conn: Option<u64>,
    /// The QUIC stream a request travelled on.
    pub stream: Option<u64>,
    /// The client's kernel request.
    pub unique: Option<u64>,
    pub op: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// One occurrence of a named event, with the detail built for it.
    Event {
        at: SystemTime,
        name: &'static str,
        ids: IdsEvent,
        detail: String,
    },
    /// Records this tap could not take, since the last it was told of.
    Dropped { records: u64 },
}

impl Record {
    /// Roughly what the record holds in memory, for the tap's byte bound.
    fn size(&self) -> usize {
        match self {
            Record::Event { detail, .. } => 128 + detail.len(),
            Record::Dropped { .. } => 32,
        }
    }
}

/// Which names a tap wants.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Names {
    #[default]
    None,
    All,
    Some(Vec<String>),
}

impl Names {
    pub fn has(&self, name: &str) -> bool {
        match self {
            Names::None => false,
            Names::All => true,
            Names::Some(names) => names.iter().any(|n| n == name),
        }
    }
}

/// What a tap is for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    pub events: Names,
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
        if dropped > 0 && !self.send(Record::Dropped { records: dropped }) {
            self.dropped.fetch_add(dropped, Ordering::Relaxed);
        }
        if !self.send(record) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn send(&self, record: Record) -> bool {
        let size = record.size();
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
        Hub::adjust(&mut registries, &self.tap.selection, -1);
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
        self.bytes.fetch_sub(record.size(), Ordering::Relaxed);
        Some(record)
    }

    /// The next record if one is queued; `None` when none is, or the tap is gone.
    pub fn try_recv(&mut self) -> Option<Record> {
        let record = self.rx.try_recv().ok()?;
        self.bytes.fetch_sub(record.size(), Ordering::Relaxed);
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
        Hub::adjust(&mut registries, &tap.selection, 1);
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
    fn adjust(registries: &mut Vec<Weak<dyn Registry>>, selection: &Selection, delta: i32) {
        registries.retain(|registry| match registry.upgrade() {
            Some(live) => {
                live.adjust(selection, delta);
                true
            }
            None => false,
        });
    }

    pub(crate) fn deliver_event(&self, name: &'static str, ids: &IdsEvent, detail: &str) {
        let at = SystemTime::now();
        for tap in self.taps.read().iter() {
            if tap.selection.events.has(name) {
                tap.offer(Record::Event {
                    at,
                    name,
                    ids: ids.clone(),
                    detail: detail.to_owned(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selecting(names: &[&str]) -> Selection {
        Selection {
            events: Names::Some(names.iter().map(|n| n.to_string()).collect()),
        }
    }

    #[test]
    fn a_tap_gets_only_what_it_selected() {
        let hub = Arc::new(Hub::default());
        let (_handle, mut rx) = hub.subscribe(selecting(&["a"]));
        hub.deliver_event("b", &IdsEvent::default(), "not wanted");
        hub.deliver_event("a", &IdsEvent::default(), "wanted");
        match rx.try_recv() {
            Some(Record::Event { name, detail, .. }) => {
                assert_eq!((name, detail.as_str()), ("a", "wanted"))
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
        assert_eq!(rx.try_recv(), Some(Record::Dropped { records: 10 }));
        assert!(matches!(rx.try_recv(), Some(Record::Event { .. })));
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
            if matches!(record, Record::Event { .. }) {
                taken += 1;
            }
        }
        assert!(taken < 4, "{taken} records of a quarter of the bound each");
        assert!(taken >= 1);
    }
}

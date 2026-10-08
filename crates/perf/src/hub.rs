//! Taps: what a subscriber (`jackalopefs-ctl`) selected, and the records delivered to it. Nothing here costs anything while no tap exists; a tap's queue is bounded in records and in bytes, and what does not fit is dropped and counted rather than held.

use jackalopefs_proto::control::{CensusOp, Exchange, Happened, Ids, Record, Selection, Summary};
use parking_lot::{Mutex, RwLock};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Instant, SystemTime};
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
        Happened::Exchange(x) => 256 + x.request.len() + x.reply.len(),
        Happened::Undecodable { body, .. } | Happened::EventFrame { body, .. } => 192 + body.len(),
        Happened::Dropped(_) | Happened::Header(_) | Happened::Census { .. } => 64,
    }
}

/// Which end a frame was captured at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

impl Side {
    pub fn name(self) -> &'static str {
        match self {
            Side::Client => "client",
            Side::Server => "server",
        }
    }
}

/// Whether the exchange on `stream` of connection `conn` is one of the `every`: a hash both ends compute alike from what both know, so they choose the same exchanges with nothing said between them, and one that does not fall in step with a workload's own period. The mix is splitmix64's finalizer, written out because both ends must agree on it whatever they were built with.
pub fn chosen(conn: Option<u64>, stream: u64, every: u32) -> bool {
    if every <= 1 {
        return true;
    }
    let mut x = conn.unwrap_or(0) ^ stream.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x.is_multiple_of(u64::from(every))
}

/// The body of `cut`, a message with its data taken out ([`jackalopefs_proto::Request::with_data_elided`]), and how much was taken; `None` when nothing was, or when it does not encode, in which case the capture keeps the whole body.
pub fn elided<T: jackalopefs_proto::Message>(cut: Option<(T, u64)>) -> Option<(Vec<u8>, u64)> {
    let (message, taken) = cut?;
    match jackalopefs_proto::encode(&message) {
        Ok(frame) => Some((frame[4..].to_vec(), taken)),
        Err(e) => {
            tracing::debug!(
                "a frame with its data cut out does not encode ({e}); capturing it whole"
            );
            None
        }
    }
}

/// Most of an undecodable frame a record keeps, so the record still fits a control frame.
const UNDECODABLE_KEPT: usize = 1 << 20;

/// A frame's body as each tap gets it: whole for a tap that wants payloads, with read or write data cut for one that does not. Each form is made only if some tap takes it.
struct Bodies {
    whole: Option<Vec<u8>>,
    /// The cut body and how many bytes were cut; `None` when there was nothing to cut.
    cut: Option<(Vec<u8>, u64)>,
}

impl Bodies {
    fn new(
        taps: &[Arc<Tap>],
        body: &[u8],
        elide: impl FnOnce() -> Option<(Vec<u8>, u64)>,
    ) -> Bodies {
        let any_cut = taps.iter().any(|tap| !tap.selection.payloads);
        let any_whole = taps.iter().any(|tap| tap.selection.payloads);
        let cut = if any_cut { elide() } else { None };
        // A body with nothing to cut goes whole to every tap.
        let whole = (any_whole || cut.is_none()).then(|| body.to_vec());
        Bodies { whole, cut }
    }

    /// The body for a tap, and the bytes cut from it.
    fn for_tap(&self, payloads: bool) -> (Vec<u8>, u64) {
        match (&self.cut, payloads) {
            (Some((cut, n)), false) => (cut.clone(), *n),
            _ => (self.whole.clone().unwrap_or_default(), 0),
        }
    }
}

/// An exchange chosen for capture: holds its request until the reply completes it, and delivers it with the reason when there is none.
pub struct Sampled {
    taps: Vec<Arc<Tap>>,
    side: Side,
    ids: IdsEvent,
    request: Option<Bodies>,
    started: Instant,
    outcome: &'static str,
    done: bool,
}

impl Sampled {
    /// The request as it crossed the wire; `elide` makes it without its data, when it has any to cut.
    pub fn request(&mut self, body: &[u8], elide: impl FnOnce() -> Option<(Vec<u8>, u64)>) {
        self.request = Some(Bodies::new(&self.taps, body, elide));
        self.started = Instant::now();
    }

    /// Why the exchange will have no reply, if it ends without one.
    pub fn outcome(&mut self, why: &'static str) {
        self.outcome = why;
    }

    /// The reply as it crossed the wire, which completes the exchange.
    pub fn reply(mut self, body: &[u8], elide: impl FnOnce() -> Option<(Vec<u8>, u64)>) {
        let reply = Bodies::new(&self.taps, body, elide);
        self.outcome = "replied";
        self.deliver(Some(&reply));
    }

    /// A reply that did not decode, kept as it was read.
    pub fn undecodable(mut self, body: &[u8]) {
        let kept = &body[..body.len().min(UNDECODABLE_KEPT)];
        let reply = Bodies {
            whole: Some(kept.to_vec()),
            cut: None,
        };
        self.outcome = "undecodable";
        self.deliver(Some(&reply));
    }

    fn deliver(&mut self, reply: Option<&Bodies>) {
        self.done = true;
        let at_ns = now_ns();
        let elapsed_ns = self.started.elapsed().as_nanos() as u64;
        let op = self.ids.op.unwrap_or("?");
        for tap in &self.taps {
            let payloads = tap.selection.payloads;
            let (request, request_elided) = self
                .request
                .as_ref()
                .map_or((Vec::new(), 0), |b| b.for_tap(payloads));
            let (reply, reply_elided) = reply.map_or((Vec::new(), 0), |b| b.for_tap(payloads));
            let taken = tap.offer(Record {
                at_ns,
                what: Happened::Exchange(Exchange {
                    side: self.side.name().into(),
                    ids: self.ids.to_ids(),
                    every: tap.selection.every.max(1),
                    request,
                    request_elided,
                    reply,
                    reply_elided,
                    outcome: self.outcome.into(),
                    elapsed_ns,
                }),
            });
            tap.counted(op, |c| {
                if taken {
                    c.sampled += 1;
                } else {
                    c.dropped += 1;
                }
            });
        }
    }
}

impl Drop for Sampled {
    fn drop(&mut self) {
        if !self.done {
            self.deliver(None);
        }
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
    /// Taps that want frames.
    frames: AtomicU32,
}

struct Tap {
    selection: Selection,
    tx: mpsc::Sender<Record>,
    bytes: Arc<AtomicUsize>,
    /// Records dropped since the subscriber was last told.
    dropped: AtomicU64,
    /// Records dropped since the tap began.
    dropped_ever: AtomicU64,
    /// Per operation, exchanges seen, chosen and dropped, for the census; touched only while frames are taken.
    census: Mutex<BTreeMap<String, CensusOp>>,
}

impl Tap {
    /// Queue `record` unless that would pass either bound, first telling the subscriber what was dropped since it last heard; whether it was queued.
    fn offer(&self, record: Record) -> bool {
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
        let taken = self.send(record);
        if !taken {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            self.dropped_ever.fetch_add(1, Ordering::Relaxed);
        }
        taken
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

    fn counted(&self, op: &str, change: impl FnOnce(&mut CensusOp)) {
        let mut census = self.census.lock();
        let entry = census.entry(op.to_owned()).or_insert_with(|| CensusOp {
            op: op.to_owned(),
            ..CensusOp::default()
        });
        change(entry);
    }
}

/// Keeps a tap subscribed; dropping it unsubscribes, and every check it made true goes back to costing nothing.
pub struct TapHandle {
    hub: Arc<Hub>,
    tap: Arc<Tap>,
}

impl TapHandle {
    /// The census so far: per operation, exchanges seen, chosen and dropped, and every record dropped.
    pub fn census(&self) -> Happened {
        Happened::Census {
            ops: self.tap.census.lock().values().cloned().collect(),
            dropped: self.tap.dropped_ever.load(Ordering::Relaxed),
        }
    }
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
            dropped_ever: AtomicU64::new(0),
            census: Mutex::new(BTreeMap::new()),
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
        let count = |counter: &AtomicU32| {
            if delta > 0 {
                counter.fetch_add(delta as u32, Ordering::Relaxed);
            } else {
                counter.fetch_sub(delta.unsigned_abs(), Ordering::Relaxed);
            }
        };
        // A tap that wants frames names its operations to choose frames by, not to have them summarised.
        if selection.frames {
            count(&self.frames);
        } else if !selection.ops.is_none() {
            count(&self.requests);
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
            .filter(|tap| !tap.selection.frames && tap.selection.ops.has(op))
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

    /// Whether any tap wants frames: one relaxed load, so an exchange costs nothing more while nobody looks.
    pub fn wants_frames(&self) -> bool {
        self.frames.load(Ordering::Relaxed) > 0
    }

    /// The taps that capture the exchange on `ids`' connection and stream; `None` when none does. Every frame tap whose operations it is of counts it as seen.
    pub fn sample(&self, side: Side, ids: IdsEvent) -> Option<Sampled> {
        let stream = ids.stream?;
        let op = ids.op.unwrap_or("?");
        let mut taps = Vec::new();
        for tap in self.taps.read().iter() {
            let s = &tap.selection;
            if !s.frames || !(s.ops.is_none() || s.ops.has(op)) {
                continue;
            }
            tap.counted(op, |c| c.seen += 1);
            if chosen(ids.conn, stream, s.every) {
                taps.push(tap.clone());
            }
        }
        (!taps.is_empty()).then(|| Sampled {
            taps,
            side,
            ids,
            request: None,
            started: Instant::now(),
            outcome: "abandoned",
            done: false,
        })
    }

    /// A frame that did not decode, for every tap that wants frames: its first MiB, as it was read.
    pub fn undecodable(&self, side: Side, ids: &IdsEvent, error: &str, body: &[u8]) {
        let at_ns = now_ns();
        let kept = &body[..body.len().min(UNDECODABLE_KEPT)];
        for tap in self.taps.read().iter().filter(|tap| tap.selection.frames) {
            tap.offer(Record {
                at_ns,
                what: Happened::Undecodable {
                    side: side.name().into(),
                    ids: ids.to_ids(),
                    error: format!("{error} ({} bytes)", body.len()),
                    body: kept.to_vec(),
                },
            });
        }
    }

    /// The `seq`th batch of change events a stream carried, for every frame tap that takes one in its `every`; `body` is made only if one does.
    pub fn event_frame(
        &self,
        side: Side,
        ids: &IdsEvent,
        seq: u64,
        body: impl FnOnce() -> Option<Vec<u8>>,
    ) {
        let taps = self.taps.read();
        let mut taking = Vec::new();
        for tap in taps.iter() {
            let s = &tap.selection;
            if !s.frames || !(s.ops.is_none() || s.ops.has("event")) {
                continue;
            }
            tap.counted("event", |c| c.seen += 1);
            if seq.is_multiple_of(u64::from(s.every.max(1))) {
                taking.push(tap);
            }
        }
        if taking.is_empty() {
            return;
        }
        let Some(body) = body() else { return };
        let at_ns = now_ns();
        for tap in taking {
            let taken = tap.offer(Record {
                at_ns,
                what: Happened::EventFrame {
                    side: side.name().into(),
                    ids: ids.to_ids(),
                    every: tap.selection.every.max(1),
                    seq,
                    body: body.clone(),
                },
            });
            tap.counted("event", |c| {
                if taken {
                    c.sampled += 1;
                } else {
                    c.dropped += 1;
                }
            });
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

    fn frames(every: u32, payloads: bool, ops: Names) -> Selection {
        Selection {
            ops,
            frames: true,
            every,
            payloads,
            ..Selection::default()
        }
    }

    fn on(conn: u64, stream: u64, op: &'static str) -> IdsEvent {
        IdsEvent {
            conn: Some(conn),
            stream: Some(stream),
            op: Some(op),
            ..IdsEvent::default()
        }
    }

    #[test]
    fn about_one_exchange_in_every_is_chosen_and_another_connection_chooses_others() {
        let picked: Vec<u64> = (0..400u64)
            .step_by(4)
            .filter(|s| chosen(Some(77), *s, 4))
            .collect();
        assert!(
            (10..=40).contains(&picked.len()),
            "about a quarter of 100: {}",
            picked.len()
        );
        assert!((0..100).all(|s| chosen(Some(1), s, 1)), "every 1 is all");
        let other: Vec<u64> = (0..400u64)
            .step_by(4)
            .filter(|s| chosen(Some(78), *s, 4))
            .collect();
        assert_ne!(picked, other);
    }

    #[test]
    fn an_exchange_is_delivered_whole_and_cut_for_a_tap_without_payloads() {
        let hub = Arc::new(Hub::default());
        let (_whole, mut whole) = hub.subscribe(frames(1, true, Names::None));
        let (_cut, mut cut) = hub.subscribe(frames(1, false, Names::None));
        assert!(hub.wants_frames());
        let mut sampled = hub.sample(Side::Client, on(1, 0, "write")).unwrap();
        sampled.request(&[1, 2, 3, 4, 5], || Some((vec![1], 4)));
        sampled.reply(&[9], || None);
        let exchange = |rx: &mut TapReceiver| match rx.try_recv().map(|r| r.what) {
            Some(Happened::Exchange(x)) => x,
            other => panic!("{other:?}"),
        };
        let whole = exchange(&mut whole);
        assert_eq!(
            (whole.request, whole.request_elided),
            (vec![1, 2, 3, 4, 5], 0)
        );
        assert_eq!((whole.reply, whole.outcome.as_str()), (vec![9], "replied"));
        let cut = exchange(&mut cut);
        assert_eq!((cut.request, cut.request_elided), (vec![1], 4));
    }

    #[test]
    fn an_exchange_without_a_reply_says_why() {
        let hub = Arc::new(Hub::default());
        let (_tap, mut rx) = hub.subscribe(frames(1, true, Names::None));
        let mut sampled = hub.sample(Side::Server, on(1, 4, "read")).unwrap();
        sampled.request(&[1], || None);
        sampled.outcome("stalled");
        drop(sampled);
        match rx.try_recv().map(|r| r.what) {
            Some(Happened::Exchange(x)) => {
                assert_eq!((x.outcome.as_str(), x.reply.len()), ("stalled", 0))
            }
            other => panic!("{other:?}"),
        }
        let sampled = hub.sample(Side::Server, on(1, 8, "read")).unwrap();
        drop(sampled);
        assert!(matches!(
            rx.try_recv().map(|r| r.what),
            Some(Happened::Exchange(x)) if x.outcome == "abandoned"
        ));
    }

    #[test]
    fn frames_follow_the_operations_named_and_stop_with_the_tap() {
        let hub = Arc::new(Hub::default());
        let (handle, _rx) = hub.subscribe(frames(1, false, Names::Some(vec!["read".into()])));
        assert!(
            !hub.wants_requests(),
            "naming operations for frames asks for no summaries"
        );
        assert!(hub.sample(Side::Client, on(1, 0, "write")).is_none());
        assert!(hub.sample(Side::Client, on(1, 0, "read")).is_some());
        drop(handle);
        assert!(!hub.wants_frames());
        assert!(hub.sample(Side::Client, on(1, 0, "read")).is_none());
    }
}

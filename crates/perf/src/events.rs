//! Named events, after bcachefs's counters: each is counted every time it happens, and its detail (what happened, to which request, why) is built only while a tap selects it or its side's event target is logged at `debug`, so detail costs nothing until someone looks.

use crate::hub::{Hub, IdsEvent, Registry, Selection};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

/// One side's set of events: an enum whose variants index the counts.
pub trait Kind: Copy + Send + Sync + 'static {
    const ALL: &'static [Self];
    fn name(self) -> &'static str;
    fn index(self) -> usize;
}

/// The counts of one process instance's events of kind `K`, since it started, and how many taps want each.
pub struct Events<K: Kind> {
    counts: Box<[AtomicU64]>,
    traced: Box<[AtomicU32]>,
    hub: Arc<Hub>,
    kind: PhantomData<K>,
}

impl<K: Kind> Events<K> {
    pub fn new(hub: &Arc<Hub>) -> Arc<Events<K>> {
        let events = Arc::new(Events {
            counts: K::ALL.iter().map(|_| AtomicU64::new(0)).collect(),
            traced: K::ALL.iter().map(|_| AtomicU32::new(0)).collect(),
            hub: hub.clone(),
            kind: PhantomData,
        });
        let registry: Arc<dyn Registry> = events.clone();
        hub.register(Arc::downgrade(&registry));
        events
    }

    pub fn inc(&self, kind: K) {
        self.counts[kind.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Whether a tap wants `kind`'s detail.
    pub fn traced(&self, kind: K) -> bool {
        self.traced[kind.index()].load(Ordering::Relaxed) > 0
    }

    pub fn count(&self, kind: K) -> u64 {
        self.counts[kind.index()].load(Ordering::Relaxed)
    }

    /// Every event and its count since start.
    pub fn counts(&self) -> Vec<(&'static str, u64)> {
        K::ALL
            .iter()
            .map(|kind| (kind.name(), self.count(*kind)))
            .collect()
    }

    /// Hand one occurrence's detail to the taps that want it; [`event!`](crate::event) calls this.
    pub fn deliver(&self, kind: K, ids: &IdsEvent, detail: &str) {
        if self.traced(kind) {
            self.hub.deliver_event(kind.name(), ids, detail);
        }
    }

    /// The counts since `last` (which is brought up to date) and their report line, `perf {what} (window/total): name=window/total …`, or `None` when nothing happened.
    pub fn window(
        &self,
        last: &mut Vec<u64>,
        what: &str,
    ) -> (BTreeMap<&'static str, u64>, Option<String>) {
        last.resize(K::ALL.len(), 0);
        let mut window = BTreeMap::new();
        let mut shown = Vec::new();
        for (kind, seen) in K::ALL.iter().zip(last.iter_mut()) {
            let now = self.count(*kind);
            let since = now - *seen;
            *seen = now;
            if since > 0 {
                window.insert(kind.name(), since);
                shown.push(format!("{}={since}/{now}", kind.name()));
            }
        }
        let line =
            (!shown.is_empty()).then(|| format!("perf {what} (window/total): {}", shown.join(" ")));
        (window, line)
    }
}

impl<K: Kind> Registry for Events<K> {
    fn adjust(&self, selection: &Selection, delta: i32) {
        for kind in K::ALL {
            if selection.events.has(kind.name()) {
                let traced = &self.traced[kind.index()];
                if delta > 0 {
                    traced.fetch_add(delta as u32, Ordering::Relaxed);
                } else {
                    traced.fetch_sub(delta.unsigned_abs(), Ordering::Relaxed);
                }
            }
        }
    }
}

/// Builds a detail out of line, so the code that formats it stays out of the hot path it was written in.
#[cold]
#[inline(never)]
pub fn cold(build: impl FnOnce() -> String) -> String {
    build()
}

/// Count one occurrence of `$kind` in `$events`; when a tap selects it or `$target` is enabled at `debug`, evaluate `$detail` (a `String`) and deliver and log it with `$ids`.
///
/// `$target` is each side's event target, a constant: `tracing` keeps its enabled check per call site, which is what makes the check cheap and why this is a macro.
#[macro_export]
macro_rules! event {
    (target: $target:expr, $events:expr, $kind:expr, $ids:expr, $detail:expr) => {{
        let events = &$events;
        let kind = $kind;
        events.inc(kind);
        let logged = ::tracing::enabled!(target: $target, ::tracing::Level::DEBUG);
        if logged || events.traced(kind) {
            let ids: $crate::hub::IdsEvent = $ids;
            let detail: String = $crate::events::cold(|| $detail);
            if logged {
                ::tracing::debug!(
                    target: $target,
                    event = $crate::events::Kind::name(kind),
                    session = ids.session,
                    conn = ids.conn,
                    stream = ids.stream,
                    unique = ids.unique,
                    op = ids.op,
                    "{detail}"
                );
            }
            events.deliver(kind, &ids, &detail);
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::{Names, Record};
    use std::sync::atomic::AtomicUsize;

    #[derive(Clone, Copy, Debug)]
    enum Test {
        First,
        Second,
    }

    impl Kind for Test {
        const ALL: &'static [Test] = &[Test::First, Test::Second];
        fn name(self) -> &'static str {
            match self {
                Test::First => "first",
                Test::Second => "second",
            }
        }
        fn index(self) -> usize {
            self as usize
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Other {
        Only,
    }

    impl Kind for Other {
        const ALL: &'static [Other] = &[Other::Only];
        fn name(self) -> &'static str {
            "only"
        }
        fn index(self) -> usize {
            0
        }
    }

    const TARGET: &str = "jackalopefs_perf_test::event";

    fn selecting(names: &[&str]) -> Selection {
        Selection {
            events: Names::Some(names.iter().map(|n| n.to_string()).collect()),
        }
    }

    /// Count `First`, building its detail through a counter of how often the detail was built.
    fn happen(events: &Events<Test>, built: &AtomicUsize) {
        event!(target: TARGET, events, Test::First, IdsEvent::default(), {
            built.fetch_add(1, Ordering::Relaxed);
            "detail".to_string()
        });
    }

    #[test]
    fn counts_go_up_and_detail_is_built_only_while_someone_looks() {
        let hub = Arc::new(Hub::default());
        let events = Events::<Test>::new(&hub);
        let built = AtomicUsize::new(0);
        happen(&events, &built);
        assert_eq!(events.count(Test::First), 1);
        assert_eq!(
            built.load(Ordering::Relaxed),
            0,
            "no tap and nothing logged"
        );

        let (handle, mut rx) = hub.subscribe(selecting(&["first"]));
        happen(&events, &built);
        assert_eq!(built.load(Ordering::Relaxed), 1);
        assert!(matches!(
            rx.try_recv(),
            Some(Record::Event { name: "first", .. })
        ));
        assert!(rx.try_recv().is_none(), "delivered once");

        drop(handle);
        happen(&events, &built);
        assert_eq!(built.load(Ordering::Relaxed), 1, "the tap is gone");
        assert_eq!(events.count(Test::First), 3);
        assert_eq!(events.count(Test::Second), 0);
    }

    #[test]
    fn logging_the_event_target_at_debug_builds_and_logs_the_detail() {
        use tracing_subscriber::layer::SubscriberExt;
        let logged = |filter: &str| {
            let hub = Arc::new(Hub::default());
            let events = Events::<Test>::new(&hub);
            let built = AtomicUsize::new(0);
            let lines = Arc::new(parking_lot::Mutex::new(Vec::<u8>::new()));
            let writer = {
                let lines = lines.clone();
                move || Sink(lines.clone())
            };
            let subscriber = tracing_subscriber::registry()
                .with(tracing_subscriber::EnvFilter::new(filter))
                .with(tracing_subscriber::fmt::layer().with_writer(writer));
            tracing::subscriber::with_default(subscriber, || happen(&events, &built));
            let text = String::from_utf8(lines.lock().clone()).unwrap();
            (built.load(Ordering::Relaxed), text)
        };
        let (built, text) = logged("jackalopefs_perf_test::event=debug");
        assert_eq!(built, 1);
        assert!(text.contains("detail") && text.contains("first"), "{text}");
        let (built, text) = logged("something_else=debug");
        assert_eq!((built, text.as_str()), (0, ""));
    }

    struct Sink(Arc<parking_lot::Mutex<Vec<u8>>>);

    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_tap_subscribed_before_the_events_exist_still_counts() {
        let hub = Arc::new(Hub::default());
        let (_handle, _rx) = hub.subscribe(selecting(&["first"]));
        let events = Events::<Test>::new(&hub);
        assert!(events.traced(Test::First));
        assert!(!events.traced(Test::Second));
    }

    #[test]
    fn kinds_on_one_hub_do_not_mix() {
        let hub = Arc::new(Hub::default());
        let test = Events::<Test>::new(&hub);
        let other = Events::<Other>::new(&hub);
        let (_handle, _rx) = hub.subscribe(selecting(&["only"]));
        assert!(other.traced(Other::Only));
        assert!(!test.traced(Test::First));
        other.inc(Other::Only);
        assert_eq!(test.counts(), vec![("first", 0), ("second", 0)]);
    }

    #[test]
    fn a_window_is_what_happened_since_the_last() {
        let hub = Arc::new(Hub::default());
        let events = Events::<Test>::new(&hub);
        let mut last = Vec::new();
        events.inc(Test::First);
        events.inc(Test::First);
        let (window, line) = events.window(&mut last, "events");
        assert_eq!(window, BTreeMap::from([("first", 2)]));
        assert!(line.is_some());
        events.inc(Test::Second);
        let (window, line) = events.window(&mut last, "events");
        assert_eq!(window, BTreeMap::from([("second", 1)]));
        assert!(line.unwrap().contains("second=1/1"));
        assert_eq!(events.window(&mut last, "events"), (BTreeMap::new(), None));
    }
}

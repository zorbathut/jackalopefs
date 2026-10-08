//! Per-op accounting for every request the server answers, split into reading it off the stream, waiting for a blocking thread, the filesystem work, and sending the reply. Counting is always on and costs one mutex lock per request; the report is logged on demand and starts a new window.

use jackalopefs_perf::events::{Events, Kind};
use jackalopefs_perf::hub::Hub;
use jackalopefs_perf::stall::{Ended, ErrorLockHeld, ModeScan, Progress, LOCK_PATIENCE};
use jackalopefs_perf::{fmt_bytes, fmt_duration};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Target of the per-request trace lines, so `RUST_LOG=jackalopefs_server::perf=trace` enables them alone.
pub const TRACE_TARGET: &str = "jackalopefs_server::perf";

/// Target under which events are logged at `debug`, detail and all.
pub const EVENT_TARGET: &str = "jackalopefs_server::event";

/// What one request produced: payload bytes moved, directory entries returned, and the errno it failed with (0 for success).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub bytes: u64,
    pub items: u64,
    pub errno: i32,
}

impl Outcome {
    pub fn bytes(n: usize) -> Outcome {
        Outcome {
            bytes: n as u64,
            ..Outcome::default()
        }
    }

    pub fn items(n: usize) -> Outcome {
        Outcome {
            items: n as u64,
            ..Outcome::default()
        }
    }

    pub fn errno(errno: i32) -> Outcome {
        Outcome {
            errno,
            ..Outcome::default()
        }
    }
}

/// Slowpath events, counted whether or not anything logs them; their detail is built only while a tap selects them or [`EVENT_TARGET`] is logged at `debug`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slowpath {
    /// The client ended or reset a request stream before the request was complete: a call it interrupted or gave up on.
    RequestCancelled,
    /// A request stream failed otherwise before the request was read, usually with its connection.
    RequestStreamFailed,
    /// A request was not fully sent within the read timeout.
    RequestReadTimeout,
    /// A reply could not be written: the client had given up on it, or the connection went.
    ReplyUndelivered,
    /// A reply was abandoned because the client was not reading it.
    ReplyStalled,
    /// A watched directory was dropped to stay within the watch limit, and clients told.
    WatchEvicted,
    /// A directory could not be watched (no read permission, or the system's limit), and is served unwatched for a while.
    WatchUnwatchable,
    /// The system ran out of inotify watches before the watch limit did, and the limit was lowered for a while.
    WatchLimited,
    /// The inotify queue overflowed: events were lost, and clients were told to rescan.
    InotifyOverflow,
}

impl Slowpath {
    pub fn name(self) -> &'static str {
        match self {
            Slowpath::RequestCancelled => "request_cancelled",
            Slowpath::RequestStreamFailed => "request_stream_failed",
            Slowpath::RequestReadTimeout => "request_read_timeout",
            Slowpath::ReplyUndelivered => "reply_undelivered",
            Slowpath::ReplyStalled => "reply_stalled",
            Slowpath::WatchEvicted => "watch_evicted",
            Slowpath::WatchUnwatchable => "watch_unwatchable",
            Slowpath::WatchLimited => "watch_limited",
            Slowpath::InotifyOverflow => "inotify_overflow",
        }
    }
}

impl Kind for Slowpath {
    const ALL: &'static [Slowpath] = &[
        Slowpath::RequestCancelled,
        Slowpath::RequestStreamFailed,
        Slowpath::RequestReadTimeout,
        Slowpath::ReplyUndelivered,
        Slowpath::ReplyStalled,
        Slowpath::WatchEvicted,
        Slowpath::WatchUnwatchable,
        Slowpath::WatchLimited,
        Slowpath::InotifyOverflow,
    ];

    fn name(self) -> &'static str {
        Slowpath::name(self)
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// Time one request spent in each phase.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Phases {
    /// Stream accepted to request decoded.
    pub read: Duration,
    /// `spawn_blocking` called to the closure running.
    pub wait: Duration,
    /// The filesystem work itself.
    pub op: Duration,
    /// Writing the reply and finishing the stream.
    pub send: Duration,
}

impl std::ops::AddAssign for Phases {
    fn add_assign(&mut self, other: Phases) {
        self.read += other.read;
        self.wait += other.wait;
        self.op += other.op;
        self.send += other.send;
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row {
    pub n: u64,
    pub bytes: u64,
    pub items: u64,
    pub total: Duration,
    /// The fastest request in the window; against `mean` it shows how much of the latency is queueing.
    pub min: Duration,
    pub max: Duration,
    /// Failures by the errno sent to the client.
    pub errnos: BTreeMap<i32, u64>,
    pub phases: Phases,
}

impl Row {
    fn record(&mut self, outcome: &Outcome, total: Duration, phases: Phases) {
        self.n += 1;
        self.bytes += outcome.bytes;
        self.items += outcome.items;
        self.total += total;
        self.min = if self.n == 1 {
            total
        } else {
            self.min.min(total)
        };
        self.max = self.max.max(total);
        self.phases += phases;
        if outcome.errno != 0 {
            *self.errnos.entry(outcome.errno).or_default() += 1;
        }
    }

    fn mean(&self, sum: Duration) -> Duration {
        if self.n == 0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(sum.as_secs_f64() / self.n as f64)
        }
    }
}

/// One window's worth of numbers, as logged by [`Perf::report`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub window: Duration,
    /// Requests being answered at the moment of the snapshot.
    pub inflight: u32,
    /// Most requests being answered at once during the window.
    pub peak: u32,
    /// Slowpath events in the window, by [`Slowpath::name`].
    pub events: BTreeMap<&'static str, u64>,
    pub rows: BTreeMap<&'static str, Row>,
}

/// Where a request being answered stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PhaseServer {
    /// Reading the request off its stream.
    Read,
    /// Waiting for a blocking thread to run the operation on.
    Wait,
    /// Watching the directories the request names, before it runs.
    Watch,
    /// The filesystem work itself.
    Op,
    /// Writing the reply.
    Send,
}

impl PhaseServer {
    pub fn name(self) -> &'static str {
        match self {
            PhaseServer::Read => "reading the request",
            PhaseServer::Wait => "waiting for a blocking thread",
            PhaseServer::Watch => "watching its directories",
            PhaseServer::Op => "in the filesystem",
            PhaseServer::Send => "sending the reply",
        }
    }
}

/// A request being answered, as the stall watchdog and the report describe it.
#[derive(Clone, Debug)]
pub struct Pending {
    pub session: u64,
    /// The connection's key ([`jackalopefs_perf::conn_key`]), which the client's lines name too.
    pub conn: Option<u64>,
    /// The QUIC stream it came on, which the client's stall lines name too.
    pub stream: u64,
    pub accepted: Instant,
    /// Known once the request is decoded.
    pub op: Option<&'static str>,
    /// The files it is about ([`jackalopefs_proto::Request::subject`]), formatted at decode: the operation consumes the request.
    pub subject: Option<String>,
    pub phase: PhaseServer,
    /// When it entered its phase.
    pub since: Instant,
    /// The blocking thread running the operation, once one is.
    pub tid: Option<i32>,
    /// The age at which the watchdog last reported it; zero if never.
    reported: Duration,
}

impl Pending {
    /// Session, stream, operation and the files it names, for a log line.
    pub fn what(&self) -> String {
        let mut what = format!("session {}", self.session);
        if let Some(conn) = self.conn {
            what.push_str(&format!(" connection {conn}"));
        }
        what.push_str(&format!(
            " stream {} {}",
            self.stream,
            self.op.unwrap_or(UNDECODED)
        ));
        if let Some(subject) = &self.subject {
            what.push(' ');
            what.push_str(subject);
        }
        what
    }
}

/// What a request not yet decoded is called in a log line.
pub const UNDECODED: &str = "undecoded request";

/// What a scan of the requests being answered found.
#[derive(Clone, Debug)]
pub struct ScanPending {
    pub count: usize,
    /// The ones the scan selected, oldest first, with their ages.
    pub found: Vec<(Pending, Duration)>,
    /// Requests whose own lock was held past the watchdog's patience, and so went unexamined.
    pub unreadable: usize,
}

struct Inner {
    since: Instant,
    active: HashMap<u64, Arc<Mutex<Pending>>>,
    next: u64,
    peak: u32,
    /// The event counts at the last report.
    events_seen: Vec<u64>,
    rows: BTreeMap<&'static str, Row>,
}

pub struct Perf {
    inner: Mutex<Inner>,
    /// The taps of this server: what `jackalopefs-ctl` is watching.
    pub hub: Arc<Hub>,
    pub events: Arc<Events<Slowpath>>,
    /// Requests answered, and when the last one was.
    pub progress: Progress,
    /// Requests reported as stalled that have since ended, for the watchdog to log.
    pub ended: Ended,
}

impl Default for Perf {
    fn default() -> Perf {
        let hub = Arc::new(Hub::default());
        Perf {
            events: Events::new(&hub),
            hub,
            inner: Mutex::new(Inner {
                since: Instant::now(),
                active: HashMap::new(),
                next: 0,
                peak: 0,
                events_seen: Vec::new(),
                rows: BTreeMap::new(),
            }),
            progress: Progress::default(),
            ended: Ended::default(),
        }
    }
}

/// One request being answered, until dropped; its transitions move the phase the watchdog sees.
pub struct InFlight {
    perf: Arc<Perf>,
    id: u64,
    active: Arc<Mutex<Pending>>,
}

impl InFlight {
    fn phase(&self, phase: PhaseServer) {
        let mut active = self.active.lock();
        active.phase = phase;
        active.since = Instant::now();
    }

    /// The request is decoded; it waits for a blocking thread next.
    pub fn decoded(&self, op: &'static str, subject: String) {
        let mut active = self.active.lock();
        active.op = Some(op);
        active.subject = Some(subject);
        active.phase = PhaseServer::Wait;
        active.since = Instant::now();
    }

    /// A blocking thread, `tid`, is watching the directories the request names.
    pub fn arming(&self, tid: i32) {
        let mut active = self.active.lock();
        active.tid = Some(tid);
        active.phase = PhaseServer::Watch;
        active.since = Instant::now();
    }

    /// A blocking thread, `tid`, is running the operation.
    pub fn running(&self, tid: i32) {
        let mut active = self.active.lock();
        active.tid = Some(tid);
        active.phase = PhaseServer::Op;
        active.since = Instant::now();
    }

    /// What the request names, once decoded, for the events about it.
    pub fn subject(&self) -> Option<String> {
        self.active.lock().subject.clone()
    }

    pub fn sending(&self) {
        self.phase(PhaseServer::Send);
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.perf.inner.lock().active.remove(&self.id);
        self.perf.progress.record();
        let active = self.active.lock().clone();
        if !active.reported.is_zero() {
            self.perf.ended.push(|| {
                format!(
                    "{} ended after {}, last {}",
                    active.what(),
                    fmt_duration(active.accepted.elapsed()),
                    active.phase.name()
                )
            });
        }
    }
}

impl Perf {
    /// Start counting a request that arrived on `stream` of `session`; the guard ends it.
    pub fn start(self: &Arc<Perf>, session: u64, conn: Option<u64>, stream: u64) -> InFlight {
        let now = Instant::now();
        let active = Arc::new(Mutex::new(Pending {
            session,
            conn,
            stream,
            accepted: now,
            op: None,
            subject: None,
            phase: PhaseServer::Read,
            since: now,
            tid: None,
            reported: Duration::ZERO,
        }));
        let mut inner = self.inner.lock();
        let id = inner.next;
        inner.next += 1;
        inner.active.insert(id, active.clone());
        inner.peak = inner.peak.max(inner.active.len() as u32);
        InFlight {
            perf: self.clone(),
            id,
            active,
        }
    }

    pub fn inflight(&self) -> u32 {
        self.inner.lock().active.len() as u32
    }

    /// The requests being answered that `mode` selects, oldest first. Each lock is waited for at most [`LOCK_PATIENCE`] and none is taken inside another; `Err` when the table's own lock was held longer than that, which in a hang is itself the finding.
    pub fn scan_pending(&self, now: Instant, mode: ModeScan) -> Result<ScanPending, ErrorLockHeld> {
        let active: Vec<Arc<Mutex<Pending>>> = {
            let inner = self
                .inner
                .try_lock_for(LOCK_PATIENCE)
                .ok_or(ErrorLockHeld)?;
            inner.active.values().cloned().collect()
        };
        let mut scan = ScanPending {
            count: active.len(),
            found: Vec::new(),
            unreadable: 0,
        };
        for entry in active {
            // Once one lock has been held past patience, the rest are only tried, so a crowd of held locks cannot hold the scan for long.
            let patience = if scan.unreadable == 0 {
                LOCK_PATIENCE
            } else {
                Duration::ZERO
            };
            let Some(mut entry) = entry.try_lock_for(patience) else {
                scan.unreadable += 1;
                continue;
            };
            let age = now.saturating_duration_since(entry.accepted);
            if mode.selects(age, &mut entry.reported) {
                scan.found.push((entry.clone(), age));
            }
        }
        scan.found.sort_by_key(|(_, age)| std::cmp::Reverse(*age));
        Ok(scan)
    }

    pub fn record(&self, op: &'static str, outcome: &Outcome, total: Duration, phases: Phases) {
        self.inner
            .lock()
            .rows
            .entry(op)
            .or_default()
            .record(outcome, total, phases);
    }

    /// Log the window at `info` and start a new one: the counts reset, the in-flight gauge does not, and the peak restarts from the current gauge.
    pub fn report(&self) -> Snapshot {
        let (snapshot, events) = {
            let mut inner = self.inner.lock();
            let now = Instant::now();
            let (events, line) = self.events.window(&mut inner.events_seen, "events");
            let snapshot = Snapshot {
                window: now.duration_since(inner.since),
                inflight: inner.active.len() as u32,
                peak: inner.peak,
                events,
                rows: std::mem::take(&mut inner.rows),
            };
            inner.since = now;
            inner.peak = inner.active.len() as u32;
            (snapshot, line)
        };
        tracing::info!(
            target: TRACE_TARGET,
            "perf window {} inflight={} peak={}",
            fmt_duration(snapshot.window),
            snapshot.inflight,
            snapshot.peak
        );
        if let Some(events) = events {
            tracing::info!(target: TRACE_TARGET, "{events}");
        }
        for (op, row) in &snapshot.rows {
            // `conc` is the mean number of this op in flight over the window: its summed latency divided by the window length.
            let conc = if snapshot.window.is_zero() {
                0.0
            } else {
                row.total.as_secs_f64() / snapshot.window.as_secs_f64()
            };
            let mut errnos = String::new();
            for (i, (errno, count)) in row.errnos.iter().enumerate() {
                if i > 0 {
                    errnos.push(',');
                }
                write!(errnos, "{errno}x{count}").expect("writing to a String cannot fail");
            }
            tracing::info!(
                target: TRACE_TARGET,
                "perf {op}: n={} conc={conc:.2} min={} mean={} max={} bytes={} items={}{}{} read={} wait={} op={} send={}",
                row.n,
                fmt_duration(row.min),
                fmt_duration(row.mean(row.total)),
                fmt_duration(row.max),
                fmt_bytes(row.bytes),
                row.items,
                if errnos.is_empty() { "" } else { " errno=" },
                errnos,
                fmt_duration(row.mean(row.phases.read)),
                fmt_duration(row.mean(row.phases.wait)),
                fmt_duration(row.mean(row.phases.op)),
                fmt_duration(row.mean(row.phases.send)),
            );
        }
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn rows_add_up() {
        let perf = Arc::new(Perf::default());
        let phases = Phases {
            read: ms(1),
            wait: ms(2),
            op: ms(3),
            send: ms(4),
        };
        perf.record("read", &Outcome::bytes(100), ms(10), phases);
        perf.record("read", &Outcome::bytes(50), ms(30), phases);
        perf.record(
            "lookup",
            &Outcome::errno(libc::ENOENT),
            ms(1),
            Phases::default(),
        );
        perf.record("readdir", &Outcome::items(7), ms(1), Phases::default());
        let snap = perf.report();
        let read = &snap.rows["read"];
        assert_eq!((read.n, read.bytes, read.items), (2, 150, 0));
        assert_eq!(read.total, ms(40));
        assert_eq!((read.min, read.max), (ms(10), ms(30)));
        assert_eq!(read.mean(read.total), ms(20));
        assert_eq!(read.phases.op, ms(6));
        assert_eq!(read.mean(read.phases.send), ms(4));
        assert_eq!(
            snap.rows["lookup"].errnos,
            BTreeMap::from([(libc::ENOENT, 1)])
        );
        assert_eq!(snap.rows["readdir"].items, 7);
        assert!(perf.report().rows.is_empty(), "a report empties the window");
    }

    #[test]
    fn gauge_survives_a_report_and_peak_restarts_from_it() {
        let perf = Arc::new(Perf::default());
        let a = perf.start(1, None, 0);
        let b = perf.start(1, None, 4);
        drop(perf.start(1, None, 8));
        assert_eq!(perf.inflight(), 2);
        let snap = perf.report();
        assert_eq!((snap.inflight, snap.peak), (2, 3));
        drop(b);
        let snap = perf.report();
        assert_eq!((snap.inflight, snap.peak), (1, 2));
        drop(a);
        assert_eq!(perf.inflight(), 0);
    }

    #[test]
    fn requests_are_listed_with_their_phase_and_reported_on_schedule() {
        let perf = Arc::new(Perf::default());
        let read = perf.start(3, None, 0);
        let op = perf.start(3, None, 4);
        op.decoded("rename", "/a -> /b".into());
        op.running(1234);
        let start = Instant::now();
        let listed = |at: Duration| perf.scan_pending(start + at, ModeScan::Listed).unwrap();
        assert!(
            listed(Duration::ZERO).found.is_empty(),
            "nothing is a second old yet"
        );
        let scan = listed(Duration::from_secs(2));
        assert_eq!((scan.count, scan.found.len(), scan.unreadable), (2, 2, 0));
        let renaming = scan
            .found
            .iter()
            .map(|(active, _)| active)
            .find(|active| active.op == Some("rename"))
            .unwrap();
        assert_eq!(
            (renaming.phase, renaming.tid),
            (PhaseServer::Op, Some(1234))
        );
        assert_eq!((renaming.session, renaming.stream), (3, 4));
        assert_eq!(renaming.subject.as_deref(), Some("/a -> /b"));

        let due = |at: u64| {
            perf.scan_pending(start + Duration::from_secs(at), ModeScan::Due)
                .unwrap()
                .found
                .len()
        };
        assert_eq!(due(4), 0);
        assert_eq!(due(5), 2);
        assert_eq!(due(6), 0, "reported once until the age doubles");
        assert_eq!(due(10), 2);
        drop(read);
        assert_eq!(
            perf.ended.lines().len(),
            1,
            "a reported request that ends is collected"
        );
        let completed = perf.progress.completed();
        drop(op);
        assert_eq!(perf.progress.completed(), completed + 1);
        let ended = perf.ended.lines();
        assert_eq!(ended.len(), 1);
        assert!(ended[0].contains("/a -> /b"), "{}", ended[0]);
        assert_eq!(listed(Duration::from_secs(60)).count, 0);
    }

    #[test]
    fn events_are_counted_per_window() {
        let perf = Arc::new(Perf::default());
        perf.events.inc(Slowpath::ReplyStalled);
        perf.events.inc(Slowpath::ReplyStalled);
        assert_eq!(
            perf.report().events,
            BTreeMap::from([(Slowpath::ReplyStalled.name(), 2)])
        );
        assert!(perf.report().events.is_empty());
    }

    #[test]
    fn every_event_is_listed_once_in_its_place() {
        for (i, kind) in Slowpath::ALL.iter().enumerate() {
            assert_eq!(Kind::index(*kind), i, "{kind:?}");
        }
        let names: std::collections::BTreeSet<&str> =
            Slowpath::ALL.iter().map(|k| k.name()).collect();
        assert_eq!(names.len(), Slowpath::ALL.len(), "names are distinct");
    }
}

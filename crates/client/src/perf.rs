//! Per-op accounting at the two levels of the client: what the kernel asked for and how long the answer took (`fuse`), and every request to the server with the time spent in each of its phases (`call`). Counting is always on and costs one mutex lock per op; the report is logged on demand and starts a new window.

use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Target of the per-request trace lines, so `RUST_LOG=jackalopefs_client::perf=trace` enables them alone.
pub const TRACE_TARGET: &str = "jackalopefs_client::perf";

tokio::task_local! {
    /// The kernel request id of the task answering it, so a `call` trace line can be joined to the `fuse` line it served; unset in a call made outside one (an orphan handle release).
    pub static REQUEST_ID: u64;
}

/// The kernel request the current task is answering, if any.
pub fn current_request() -> Option<u64> {
    REQUEST_ID.try_with(|id| *id).ok()
}

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

/// The columns both levels share.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row {
    pub n: u64,
    pub bytes: u64,
    pub items: u64,
    pub total: Duration,
    pub max: Duration,
    /// Failures by the errno user space saw.
    pub errnos: BTreeMap<i32, u64>,
}

impl Row {
    fn record(&mut self, outcome: &Outcome, total: Duration) {
        self.n += 1;
        self.bytes += outcome.bytes;
        self.items += outcome.items;
        self.total += total;
        self.max = self.max.max(total);
        if outcome.errno != 0 {
            *self.errnos.entry(outcome.errno).or_default() += 1;
        }
    }

    fn mean(&self) -> Duration {
        mean(self.total, self.n)
    }
}

/// Time a call spent in each phase, summed over its attempts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Phases {
    /// Waiting for a usable connection.
    pub wait: Duration,
    /// Opening the request stream.
    pub open: Duration,
    /// Writing the request and finishing the stream.
    pub send: Duration,
    /// From the request being finished to the reply being decoded: the round trip plus the server's work.
    pub reply: Duration,
}

impl std::ops::AddAssign for Phases {
    fn add_assign(&mut self, other: Phases) {
        self.wait += other.wait;
        self.open += other.open;
        self.send += other.send;
        self.reply += other.reply;
    }
}

/// A call's accounting: its phases and how many times it was resent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccountCall {
    pub phases: Phases,
    pub retries: u32,
}

/// One op at the call level. Phase sums cover only calls that were not resent, so a few reconnects cannot dominate the means; `phased` is how many calls they cover.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RowCall {
    pub row: Row,
    pub retried: u64,
    pub phased: u64,
    pub phases: Phases,
}

impl RowCall {
    fn record(&mut self, outcome: &Outcome, total: Duration, account: &AccountCall) {
        self.row.record(outcome, total);
        if account.retries > 0 {
            self.retried += 1;
        } else {
            self.phased += 1;
            self.phases += account.phases;
        }
    }

    fn phase_mean(&self, phase: Duration) -> Duration {
        mean(phase, self.phased)
    }
}

/// One window's worth of numbers, as logged by [`Perf::report`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub window: Duration,
    /// Kernel requests being answered at the moment of the snapshot.
    pub inflight: u32,
    /// Most kernel requests being answered at once during the window.
    pub peak: u32,
    pub fuse: BTreeMap<&'static str, Row>,
    pub call: BTreeMap<&'static str, RowCall>,
}

struct Inner {
    since: Instant,
    inflight: u32,
    peak: u32,
    fuse: BTreeMap<&'static str, Row>,
    call: BTreeMap<&'static str, RowCall>,
}

pub struct Perf {
    inner: Mutex<Inner>,
}

impl Default for Perf {
    fn default() -> Perf {
        Perf {
            inner: Mutex::new(Inner {
                since: Instant::now(),
                inflight: 0,
                peak: 0,
                fuse: BTreeMap::new(),
                call: BTreeMap::new(),
            }),
        }
    }
}

/// Counts one kernel request as in flight until dropped.
pub struct InFlight {
    perf: Arc<Perf>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.perf.inner.lock().inflight -= 1;
    }
}

impl Perf {
    /// Start counting a kernel request; the guard ends it.
    pub fn start(self: &Arc<Perf>) -> InFlight {
        let mut inner = self.inner.lock();
        inner.inflight += 1;
        inner.peak = inner.peak.max(inner.inflight);
        InFlight { perf: self.clone() }
    }

    /// Kernel requests being answered right now.
    pub fn inflight(&self) -> u32 {
        self.inner.lock().inflight
    }

    pub fn record_fuse(&self, op: &'static str, outcome: &Outcome, total: Duration) {
        self.inner
            .lock()
            .fuse
            .entry(op)
            .or_default()
            .record(outcome, total);
    }

    pub fn record_call(
        &self,
        op: &'static str,
        outcome: &Outcome,
        total: Duration,
        account: &AccountCall,
    ) {
        self.inner
            .lock()
            .call
            .entry(op)
            .or_default()
            .record(outcome, total, account);
    }

    /// Log the window at `info` and start a new one: the counts reset, the in-flight gauge does not, and the peak restarts from the current gauge.
    pub fn report(&self) -> Snapshot {
        let snapshot = {
            let mut inner = self.inner.lock();
            let now = Instant::now();
            let snapshot = Snapshot {
                window: now.duration_since(inner.since),
                inflight: inner.inflight,
                peak: inner.peak,
                fuse: std::mem::take(&mut inner.fuse),
                call: std::mem::take(&mut inner.call),
            };
            inner.since = now;
            inner.peak = inner.inflight;
            snapshot
        };
        tracing::info!(
            target: TRACE_TARGET,
            "perf window {} inflight={} peak={}",
            fmt_duration(snapshot.window),
            snapshot.inflight,
            snapshot.peak
        );
        for (op, row) in &snapshot.fuse {
            tracing::info!(
                target: TRACE_TARGET,
                "perf fuse {op}: {}",
                fmt_row(row, snapshot.window)
            );
        }
        for (op, row) in &snapshot.call {
            tracing::info!(
                target: TRACE_TARGET,
                "perf call {op}: {} retried={} wait={} open={} send={} reply={}",
                fmt_row(&row.row, snapshot.window),
                row.retried,
                fmt_duration(row.phase_mean(row.phases.wait)),
                fmt_duration(row.phase_mean(row.phases.open)),
                fmt_duration(row.phase_mean(row.phases.send)),
                fmt_duration(row.phase_mean(row.phases.reply)),
            );
        }
        snapshot
    }
}

fn mean(sum: Duration, n: u64) -> Duration {
    if n == 0 {
        Duration::ZERO
    } else {
        Duration::from_secs_f64(sum.as_secs_f64() / n as f64)
    }
}

/// `conc` is the mean number of this op in flight over the window (its summed latency divided by the window length).
fn fmt_row(row: &Row, window: Duration) -> String {
    let conc = if window.is_zero() {
        0.0
    } else {
        row.total.as_secs_f64() / window.as_secs_f64()
    };
    let mut out = format!(
        "n={} conc={conc:.2} mean={} max={} bytes={} items={}",
        row.n,
        fmt_duration(row.mean()),
        fmt_duration(row.max),
        fmt_bytes(row.bytes),
        row.items
    );
    if !row.errnos.is_empty() {
        out.push_str(" errno=");
        for (i, (errno, count)) in row.errnos.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            write!(out, "{errno}x{count}").expect("writing to a String cannot fail");
        }
    }
    out
}

pub fn fmt_duration(d: Duration) -> String {
    let us = d.as_micros();
    if us < 1_000 {
        format!("{us}us")
    } else if us < 1_000_000 {
        format!("{:.2}ms", us as f64 / 1_000.0)
    } else {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    }
}

pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n}B")
    } else {
        format!("{value:.1}{}", UNITS[unit])
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
        perf.record_fuse("read", &Outcome::bytes(100), ms(2));
        perf.record_fuse("read", &Outcome::bytes(50), ms(6));
        perf.record_fuse("lookup", &Outcome::errno(libc::ENOENT), ms(1));
        perf.record_fuse("lookup", &Outcome::errno(libc::ENOENT), ms(1));
        perf.record_fuse("readdir", &Outcome::items(7), ms(3));
        let snap = perf.report();
        let read = &snap.fuse["read"];
        assert_eq!((read.n, read.bytes, read.items), (2, 150, 0));
        assert_eq!(read.total, ms(8));
        assert_eq!(read.max, ms(6));
        assert_eq!(read.mean(), ms(4));
        assert!(read.errnos.is_empty());
        let lookup = &snap.fuse["lookup"];
        assert_eq!(lookup.errnos, BTreeMap::from([(libc::ENOENT, 2)]));
        assert_eq!(snap.fuse["readdir"].items, 7);
        assert!(snap.window > Duration::ZERO);
    }

    #[test]
    fn retried_calls_stay_out_of_the_phase_means() {
        let perf = Arc::new(Perf::default());
        let clean = AccountCall {
            phases: Phases {
                wait: ms(1),
                open: ms(2),
                send: ms(3),
                reply: ms(4),
            },
            retries: 0,
        };
        let retried = AccountCall {
            phases: Phases {
                wait: ms(5000),
                open: ms(2),
                send: ms(3),
                reply: ms(4),
            },
            retries: 1,
        };
        perf.record_call("read", &Outcome::bytes(10), ms(10), &clean);
        perf.record_call("read", &Outcome::bytes(10), ms(10), &clean);
        perf.record_call("read", &Outcome::errno(libc::EIO), ms(5020), &retried);
        let snap = perf.report();
        let read = &snap.call["read"];
        assert_eq!(read.row.n, 3);
        assert_eq!(read.row.bytes, 20);
        assert_eq!(read.retried, 1);
        assert_eq!(read.phased, 2);
        assert_eq!(read.phases.wait, ms(2));
        assert_eq!(read.phase_mean(read.phases.reply), ms(4));
        assert_eq!(read.row.errnos, BTreeMap::from([(libc::EIO, 1)]));
        assert_eq!(read.row.max, ms(5020));
    }

    #[test]
    fn gauge_survives_a_report_and_peak_restarts_from_it() {
        let perf = Arc::new(Perf::default());
        let a = perf.start();
        let b = perf.start();
        let c = perf.start();
        drop(c);
        assert_eq!(perf.inflight(), 2);
        let snap = perf.report();
        assert_eq!((snap.inflight, snap.peak), (2, 3));
        drop(b);
        let snap = perf.report();
        assert_eq!((snap.inflight, snap.peak), (1, 2));
        assert!(snap.fuse.is_empty() && snap.call.is_empty());
        drop(a);
        assert_eq!(perf.inflight(), 0);
    }

    #[test]
    fn report_empties_the_window() {
        let perf = Arc::new(Perf::default());
        perf.record_fuse("read", &Outcome::bytes(1), ms(1));
        assert_eq!(perf.report().fuse.len(), 1);
        assert!(perf.report().fuse.is_empty());
    }

    #[test]
    fn formatting_helpers() {
        assert_eq!(fmt_duration(Duration::from_micros(999)), "999us");
        assert_eq!(fmt_duration(ms(1)), "1.00ms");
        assert_eq!(fmt_duration(Duration::from_millis(1500)), "1.50s");
        assert_eq!(fmt_bytes(512), "512B");
        assert_eq!(fmt_bytes(1536), "1.5KiB");
        assert_eq!(fmt_bytes(200 * 1024 * 1024), "200.0MiB");
        assert_eq!(fmt_bytes(3 * 1024 * 1024 * 1024), "3.0GiB");
    }
}

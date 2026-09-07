//! Per-op accounting for every request the server answers, split into reading it off the stream, waiting for a blocking thread, the filesystem work, and sending the reply. Counting is always on and costs one mutex lock per request; the report is logged on demand and starts a new window.

use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Target of the per-request trace lines, so `RUST_LOG=jackalopefs_server::perf=trace` enables them alone.
pub const TRACE_TARGET: &str = "jackalopefs_server::perf";

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
    pub rows: BTreeMap<&'static str, Row>,
}

struct Inner {
    since: Instant,
    inflight: u32,
    peak: u32,
    rows: BTreeMap<&'static str, Row>,
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
                rows: BTreeMap::new(),
            }),
        }
    }
}

/// Counts one request as in flight until dropped.
pub struct InFlight {
    perf: Arc<Perf>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.perf.inner.lock().inflight -= 1;
    }
}

impl Perf {
    /// Start counting a request; the guard ends it.
    pub fn start(self: &Arc<Perf>) -> InFlight {
        let mut inner = self.inner.lock();
        inner.inflight += 1;
        inner.peak = inner.peak.max(inner.inflight);
        InFlight { perf: self.clone() }
    }

    pub fn inflight(&self) -> u32 {
        self.inner.lock().inflight
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
        let snapshot = {
            let mut inner = self.inner.lock();
            let now = Instant::now();
            let snapshot = Snapshot {
                window: now.duration_since(inner.since),
                inflight: inner.inflight,
                peak: inner.peak,
                rows: std::mem::take(&mut inner.rows),
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
                "perf {op}: n={} conc={conc:.2} mean={} max={} bytes={} items={}{}{} read={} wait={} op={} send={}",
                row.n,
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

pub(crate) fn fmt_duration(d: Duration) -> String {
    let us = d.as_micros();
    if us < 1_000 {
        format!("{us}us")
    } else if us < 1_000_000 {
        format!("{:.2}ms", us as f64 / 1_000.0)
    } else {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    }
}

pub(crate) fn fmt_bytes(n: u64) -> String {
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
        assert_eq!(read.max, ms(30));
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
        let a = perf.start();
        let b = perf.start();
        drop(perf.start());
        assert_eq!(perf.inflight(), 2);
        let snap = perf.report();
        assert_eq!((snap.inflight, snap.peak), (2, 3));
        drop(b);
        let snap = perf.report();
        assert_eq!((snap.inflight, snap.peak), (1, 2));
        drop(a);
        assert_eq!(perf.inflight(), 0);
    }
}

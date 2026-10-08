//! The server's stall watchdog: once a second, from a thread of its own, it reports requests being answered too long (which session and stream, what they are about, which phase, and for one in the filesystem what its thread is blocked on in the kernel), and on its own account a tokio runtime that stops running tasks, which would leave new requests unread and out of the table's sight; each with whether other requests still complete and when the runtime last ran a task. The same descriptions serve the in-flight listing of a report.

use crate::perf::{Pending, Perf, PhaseServer, TRACE_TARGET, UNDECODED};
use jackalopefs_perf::fmt_duration;
use jackalopefs_perf::stall::{
    line_progress, lines_crowd, thread_doing, ErrorLockHeld, Heartbeat, ModeScan, Persisting,
    HEARTBEAT_LATE, LOCK_PATIENCE,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// What the watchdog keeps between checks.
pub struct WatchServer {
    perf: Arc<Perf>,
    heartbeat: Heartbeat,
    /// Requests answered as of the last check.
    completed: u64,
    /// The table's lock unavailable.
    table_held: Persisting,
    /// The runtime not running the heartbeat.
    runtime_late: Persisting,
}

impl WatchServer {
    pub fn new(perf: Arc<Perf>, runtime: tokio::runtime::Handle) -> WatchServer {
        WatchServer {
            completed: perf.progress.completed(),
            perf,
            heartbeat: Heartbeat::new(runtime),
            table_held: Persisting::default(),
            runtime_late: Persisting::default(),
        }
    }

    pub fn tick(&mut self) {
        let now = Instant::now();
        for line in self.perf.ended.lines() {
            tracing::warn!("stall ended: {line}");
        }
        match self.perf.scan_pending(now, ModeScan::Due) {
            Ok(scan) => {
                self.table_held.check(now, false);
                if !scan.found.is_empty() {
                    let (count, unreadable) = (scan.count, scan.unreadable);
                    for line in lines_pending(scan.found, now) {
                        tracing::warn!("stalled: {line}");
                    }
                    let unexamined = if unreadable > 0 {
                        format!(" ({unreadable} unexamined, their lock held)")
                    } else {
                        String::new()
                    };
                    tracing::warn!(
                        "stalled: {count} requests being answered{unexamined}; {}",
                        line_progress(&self.perf.progress, self.completed, &self.heartbeat, now)
                    );
                }
            }
            Err(ErrorLockHeld) => {
                if let Some(held) = self.table_held.check(now, true) {
                    tracing::warn!(
                        "stalled: the table of requests being answered has been locked for {}; {}",
                        fmt_duration(held),
                        line_progress(&self.perf.progress, self.completed, &self.heartbeat, now)
                    );
                }
            }
        }
        let late = self.heartbeat.age() >= HEARTBEAT_LATE;
        if let Some(age) = self.runtime_late.check(now, late) {
            tracing::warn!(
                "stalled: the tokio runtime has run no task for {}, so no new request is read; {}",
                fmt_duration(age),
                line_progress(&self.perf.progress, self.completed, &self.heartbeat, now)
            );
        }
        self.completed = self.perf.progress.completed();
        self.heartbeat.ping();
    }
}

/// The in-flight listing of a report: every request being answered at least [`jackalopefs_perf::stall::INFLIGHT_LISTED`], oldest first.
pub fn report_pending(perf: &Perf) {
    let now = Instant::now();
    match perf.scan_pending(now, ModeScan::Listed) {
        Ok(scan) => {
            for line in lines_pending(scan.found, now) {
                tracing::info!(target: TRACE_TARGET, "perf inflight {line}");
            }
        }
        Err(ErrorLockHeld) => tracing::warn!(
            "the table of requests being answered was locked past {}; no listing",
            fmt_duration(LOCK_PATIENCE)
        ),
    }
}

fn lines_pending(found: Vec<(Pending, Duration)>, now: Instant) -> Vec<String> {
    lines_crowd(
        found,
        |(pending, _)| {
            format!(
                "{} {}",
                pending.op.unwrap_or(UNDECODED),
                pending.phase.name()
            )
        },
        |(pending, age)| describe(pending, *age, now),
    )
}

fn describe(pending: &Pending, age: Duration, now: Instant) -> String {
    let mut line = format!(
        "{} {} for {} ({} in all)",
        pending.what(),
        pending.phase.name(),
        fmt_duration(now.saturating_duration_since(pending.since)),
        fmt_duration(age),
    );
    if let (PhaseServer::Op, Some(tid)) = (pending.phase, pending.tid) {
        line.push_str(&format!("; {}", thread_doing(tid)));
    }
    line
}

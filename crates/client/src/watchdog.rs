//! The client's stall watchdog: once a second, from a thread of its own, it reports kernel requests in flight too long (what they are, who is blocked in them, where their call stands), and on its own account a tokio runtime that stops running tasks, a FUSE session thread that stops coming back for requests, and an invalidation call that does not return, each with what tells the stuck component apart: whether other requests still complete, the runtime, the session and invalidation threads, the kernel's queue and the connection. The same descriptions serve the in-flight listing of a report.

use crate::client::{CallNow, PhaseCall};
use crate::conn::ConnState;
use crate::fuse::{Pending, Shared};
use crate::mount::KernelLimits;
use crate::perf::TRACE_TARGET;
use jackalopefs_perf::fmt_duration;
use jackalopefs_perf::stall::{
    line_progress, lines_crowd, thread_doing, thread_wchan, ErrorLockHeld, Heartbeat, ModeScan,
    Persisting, HEARTBEAT_LATE, LOCK_PATIENCE,
};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

/// The kernel function the FUSE session thread waits in for the next request.
const SESSION_IDLE: &str = "fuse_dev_do_read";

/// What the watchdog keeps between checks.
pub struct WatchClient {
    shared: Arc<Shared>,
    heartbeat: Heartbeat,
    limits: Option<KernelLimits>,
    /// Requests answered as of the last check.
    completed: u64,
    session_ended: bool,
    /// The in-flight table's lock unavailable.
    table_held: Persisting,
    /// The runtime not running the heartbeat.
    runtime_late: Persisting,
    /// The session thread away from `/dev/fuse` while nothing completes.
    session_away: Persisting,
    /// The same notifier call in progress, and when it began.
    notifier_busy: Persisting,
    notifier_since: Option<Instant>,
}

impl WatchClient {
    pub(crate) fn new(
        shared: Arc<Shared>,
        runtime: tokio::runtime::Handle,
        limits: Option<KernelLimits>,
    ) -> WatchClient {
        WatchClient {
            completed: shared.progress.completed(),
            shared,
            heartbeat: Heartbeat::new(runtime),
            limits,
            session_ended: false,
            table_held: Persisting::default(),
            runtime_late: Persisting::default(),
            session_away: Persisting::default(),
            notifier_busy: Persisting::default(),
            notifier_since: None,
        }
    }

    pub fn tick(&mut self) {
        let now = Instant::now();
        for line in self.shared.ended.lines() {
            tracing::warn!("stall ended: {line}");
        }
        match self.shared.scan_pending(now, ModeScan::Due) {
            Ok(scan) => {
                self.table_held.check(now, false);
                if !scan.found.is_empty() {
                    for line in lines_pending(scan.found, self.shared.proc_ours()) {
                        tracing::warn!("stalled: {line}");
                    }
                    tracing::warn!(
                        "stalled: {} kernel requests being answered; {}",
                        scan.count,
                        self.summary(now)
                    );
                }
            }
            Err(ErrorLockHeld) => {
                if let Some(held) = self.table_held.check(now, true) {
                    tracing::warn!(
                        "stalled: the in-flight table's lock has been unavailable for {}; {}",
                        fmt_duration(held),
                        self.summary(now)
                    );
                }
            }
        }
        let late = self.heartbeat.age() >= HEARTBEAT_LATE;
        if let Some(age) = self.runtime_late.check(now, late) {
            tracing::warn!(
                "stalled: the tokio runtime has run no task for {}; {}",
                fmt_duration(age),
                self.summary(now)
            );
        }
        self.check_session(now);
        self.check_notifier(now);
        self.completed = self.shared.progress.completed();
        self.heartbeat.ping();
    }

    /// The session thread reads every request off `/dev/fuse`. One that has ended leaves the mount answering nothing, and it ends when the mount goes, so only an end this client did not start is reported. One that is elsewhere for long while nothing completes is blocked in a handler, and every request behind it waits in the kernel, out of the table's sight.
    fn check_session(&mut self, now: Instant) {
        let tid = self.shared.session_tid.load(Ordering::Relaxed);
        if tid == 0
            || self.session_ended
            || !self.shared.proc_ours()
            || self.shared.unmounting.load(Ordering::Relaxed)
        {
            return;
        }
        match thread_wchan(tid) {
            Ok(wchan) => {
                let away =
                    wchan != SESSION_IDLE && self.shared.progress.completed() == self.completed;
                if let Some(age) = self.session_away.check(now, away) {
                    tracing::warn!(
                        "stalled: the FUSE session thread has not come back for a request for {}, and nothing has been answered meanwhile; {}",
                        fmt_duration(age),
                        self.summary(now)
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.session_ended = true;
                tracing::warn!("the FUSE session thread ({tid}) has ended without this client unmounting: the mount was unmounted from outside (fusermount -u), or the thread failed; nothing on the mount is answered any more");
            }
            Err(e) => tracing::debug!("cannot read the FUSE session thread's wait channel: {e}"),
        }
    }

    /// A notifier call blocked on kernel locks is reported on the same schedule as a request.
    fn check_notifier(&mut self, now: Instant) {
        let Some(busy) = self
            .shared
            .notifier_busy
            .try_lock_for(LOCK_PATIENCE)
            .map(|busy| *busy)
        else {
            return;
        };
        let since = busy.map(|work| work.since);
        if since != self.notifier_since {
            self.notifier_busy.reset();
            self.notifier_since = since;
        }
        let Some(work) = busy else {
            return;
        };
        if self.notifier_busy.check(now, true).is_some() {
            tracing::warn!(
                "stalled: the invalidation thread has been in {} of {} for {}",
                work.kind,
                work.ino,
                fmt_duration(now.saturating_duration_since(work.since))
            );
        }
    }

    /// What tells the stuck component apart.
    fn summary(&self, now: Instant) -> String {
        let waiting = match self.limits.as_ref().and_then(KernelLimits::waiting) {
            Some(waiting) => format!("{waiting}"),
            None => "unknown".into(),
        };
        let session = match self.shared.session_tid.load(Ordering::Relaxed) {
            0 => "not started".into(),
            _ if !self.shared.proc_ours() => {
                "not visible (/proc is another pid namespace's)".into()
            }
            tid => thread_doing(tid),
        };
        format!(
            "the kernel counts {waiting} waiting (queued for this client or being answered); {}; FUSE session {session}; {}; invalidation {}",
            line_progress(&self.shared.progress, self.completed, &self.heartbeat, now),
            self.connection(),
            self.notifier_now(now),
        )
    }

    fn connection(&self) -> String {
        match &*self.shared.client.state().borrow() {
            ConnState::Connected(attached) => {
                format!("connected, generation {}", attached.generation)
            }
            ConnState::Connecting { since } => {
                format!("no connection for {}", fmt_duration(since.elapsed()))
            }
            ConnState::Closed => "connection closed for good".into(),
        }
    }

    fn notifier_now(&self, now: Instant) -> String {
        match self.shared.notifier_busy.try_lock_for(LOCK_PATIENCE) {
            Some(busy) => match *busy {
                Some(work) => format!(
                    "thread in {} of {} for {}",
                    work.kind,
                    work.ino,
                    fmt_duration(now.saturating_duration_since(work.since))
                ),
                None => "thread idle".into(),
            },
            None => "thread state unavailable (lock held)".into(),
        }
    }
}

/// The in-flight listing of a report: every request in flight at least [`jackalopefs_perf::stall::INFLIGHT_LISTED`], oldest first.
pub fn report_pending(shared: &Shared) {
    match shared.scan_pending(Instant::now(), ModeScan::Listed) {
        Ok(scan) => {
            for line in lines_pending(scan.found, shared.proc_ours()) {
                tracing::info!(target: TRACE_TARGET, "perf inflight {line}");
            }
        }
        Err(ErrorLockHeld) => tracing::warn!(
            "the in-flight table's lock was held past {}; no listing",
            fmt_duration(LOCK_PATIENCE)
        ),
    }
}

fn lines_pending(found: Vec<Pending>, proc_ours: bool) -> Vec<String> {
    lines_crowd(
        found,
        |p| format!("{} {}", p.key.op, phase_of(p)),
        |p| describe(p, proc_ours),
    )
}

fn describe(p: &Pending, proc_ours: bool) -> String {
    let key = &p.key;
    let mut line = format!(
        "fuse {} ino {} for {} (unique {})",
        key.op,
        key.ino,
        fmt_duration(p.age),
        key.unique
    );
    if let Some(fh) = key.fh {
        line.push_str(&format!(" fh {fh}"));
    }
    if let Some(offset) = key.offset {
        line.push_str(&format!(" offset {offset}"));
    }
    if let Some(size) = key.size {
        line.push_str(&format!(" size {size}"));
    }
    line.push_str(&format!(", caller {}; ", caller(key.pid, proc_ours)));
    line.push_str(&match &p.call {
        _ if !p.started => "its task has not run yet (the runtime is not getting to it)".into(),
        Ok(Some(call)) => describe_call(call),
        Ok(None) => "not in a call to the server".into(),
        Err(ErrorLockHeld) => format!(
            "its call's lock was held past {}",
            fmt_duration(LOCK_PATIENCE)
        ),
    });
    line
}

/// The thread blocked in a request and its process, by name, from `/proc`; never `cmdline` or anything else that takes the target's mmap lock (`crate::signals`).
fn caller(tid: u32, proc_ours: bool) -> String {
    if tid == 0 {
        return "outside this pid namespace".into();
    }
    if !proc_ours {
        return format!("thread {tid} (/proc is not this pid namespace's)");
    }
    let status = match std::fs::read_to_string(format!("/proc/{tid}/status")) {
        Ok(status) => status,
        Err(e) => return format!("thread {tid} ({e})"),
    };
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(|value| value.trim().to_string())
    };
    let thread = field("Name:").unwrap_or_else(|| "?".into());
    let state = field("State:").unwrap_or_else(|| "?".into());
    let process = match field("Tgid:") {
        Some(tgid) => match std::fs::read_to_string(format!("/proc/{tgid}/comm")) {
            Ok(comm) => format!("{} {tgid}", comm.trim()),
            Err(e) => format!("{tgid} ({e})"),
        },
        None => "?".into(),
    };
    format!("thread {thread} {tid} of {process}, {state}")
}

fn phase_of(p: &Pending) -> &'static str {
    match &p.call {
        _ if !p.started => "not started",
        Ok(Some(call)) => phase_name(call.phase),
        Ok(None) => "not in a call",
        Err(ErrorLockHeld) => "call unreadable",
    }
}

fn phase_name(phase: PhaseCall) -> &'static str {
    match phase {
        PhaseCall::Wait => "waiting for a connection",
        PhaseCall::Open => "opening a stream",
        PhaseCall::Send => "sending",
        PhaseCall::Reply => "awaiting the reply",
    }
}

fn describe_call(call: &CallNow) -> String {
    let mut line = format!(
        "call {} {} {} for {}",
        call.req.op_name(),
        call.req.subject(),
        phase_name(call.phase),
        fmt_duration(call.since.elapsed())
    );
    if let Some(generation) = call.generation {
        line.push_str(&format!(", generation {generation}"));
    }
    if let Some(conn) = call.conn {
        line.push_str(&format!(", connection {conn}"));
    }
    if let Some(stream) = call.stream {
        line.push_str(&format!(", stream {stream}"));
    }
    if call.retries > 0 {
        line.push_str(&format!(", attempt {}", call.retries + 1));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuse::KeyPerf;
    use jackalopefs_perf::stall::STALL_DETAILED;
    use jackalopefs_proto::{Name, Path, Request};
    use std::time::Duration;

    fn pending(started: bool, call: Result<Option<CallNow>, ErrorLockHeld>, pid: u32) -> Pending {
        Pending {
            key: KeyPerf {
                op: "lookup",
                unique: 9,
                pid,
                ino: 1,
                fh: None,
                offset: None,
                size: None,
            },
            age: Duration::from_secs(6),
            started,
            call,
        }
    }

    fn call(phase: PhaseCall) -> CallNow {
        CallNow {
            req: Arc::new(Request::Lookup {
                parent: Path::root(),
                name: Name::new("wanted").unwrap(),
            }),
            phase,
            since: Instant::now(),
            generation: Some(1),
            conn: Some(77),
            stream: Some(4),
            retries: 0,
        }
    }

    #[test]
    fn each_state_of_a_request_reads_differently() {
        let lines: Vec<String> = [
            pending(false, Ok(None), 1),
            pending(true, Ok(None), 1),
            pending(true, Err(ErrorLockHeld), 1),
            pending(true, Ok(Some(call(PhaseCall::Wait))), 1),
            pending(true, Ok(Some(call(PhaseCall::Reply))), 1),
        ]
        .iter()
        .map(|p| describe(p, false))
        .collect();
        for (i, a) in lines.iter().enumerate() {
            assert!(!a.is_empty());
            for b in &lines[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert!(lines[4].contains("wanted"), "{}", lines[4]);
        let outside = describe(&pending(true, Ok(None), 0), true);
        assert_ne!(outside, lines[1]);
    }

    #[test]
    fn a_crowd_of_requests_is_grouped_by_op_and_phase() {
        let found: Vec<Pending> = (0..12)
            .map(|_| pending(true, Ok(Some(call(PhaseCall::Reply))), 1))
            .collect();
        let lines = lines_pending(found, false);
        assert_eq!(lines.len(), STALL_DETAILED + 1);
        let rest = lines.last().unwrap();
        assert!(
            rest.contains(&format!("4 lookup {}", phase_name(PhaseCall::Reply))),
            "{rest}"
        );
    }
}

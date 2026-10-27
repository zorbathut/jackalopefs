//! The client's stall watchdog: once a second, from a thread of its own, it reports kernel requests in flight too long (what they are, who is blocked in them, where their call stands), and on its own account a tokio runtime that stops running tasks, a FUSE session thread that stops coming back for requests, and an invalidation call that does not return, each with what tells the stuck component apart: whether other requests still complete, the runtime, the session and invalidation threads, the kernel's queue and the connection. The same descriptions serve the in-flight listing of a report.

use crate::client::{CallNow, PhaseCall};
use crate::conn::ConnState;
use crate::fuse::{Pending, Shared};
use crate::mount::KernelLimits;
use crate::perf::TRACE_TARGET;
use jackalopefs_perf::fmt_duration;
use jackalopefs_perf::stall::{
    line_progress, lines_crowd, thread_doing, thread_wchan, ErrorLockHeld, Heartbeat, ModeScan,
    Persisting, HEARTBEAT_LATE, LOCK_PATIENCE, STALL_DETAILED,
};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

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
    /// The threads reading callers' `/proc` for [`callers_read`], which outlive a check when a read does not return.
    readers: Vec<JoinHandle<()>>,
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
            readers: Vec::new(),
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
                    let proc_ours = self.shared.proc_ours();
                    let names = self.callers(&scan.found, proc_ours);
                    for line in lines_pending(scan.found, |tid| caller_from(&names, tid, proc_ours))
                    {
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
        self.readers_reap();
    }

    /// The names of the callers of the requests a stall report describes one per line, for those `/proc` is read for.
    fn callers(&mut self, found: &[Pending], proc_ours: bool) -> HashMap<u32, String> {
        // Oldest first, so a read that does not return leaves the oldest named.
        let mut tids: Vec<u32> = Vec::new();
        for p in found.iter().take(STALL_DETAILED) {
            if p.key.pid != 0 && !tids.contains(&p.key.pid) {
                tids.push(p.key.pid);
            }
        }
        if !proc_ours || tids.is_empty() {
            return HashMap::new();
        }
        let (names, reader) = callers_read(tids, LOCK_PATIENCE, move |tid| caller(tid, proc_ours));
        self.readers.extend(reader);
        names
    }

    fn readers_reap(&mut self) {
        let (done, out): (Vec<_>, Vec<_>) = std::mem::take(&mut self.readers)
            .into_iter()
            .partition(JoinHandle::is_finished);
        self.readers = out;
        for reader in done {
            if reader.join().is_err() {
                tracing::error!("a thread naming stalled requests' callers panicked");
            }
        }
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
                format!("connected, generation {}", attached.state.generation)
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

/// Caller reads still out are joined, not left behind: one caught in a release on this mount would otherwise outlive the main thread holding the process's file table, so `/dev/fuse` would never close and the exit would hang with nothing left to abort it. An orderly unmount has usually waited such a read out already, since the session ends only once every release on the mount has; this join is for a session thread that ended with `/dev/fuse` still open, where aborting the mount is what frees the read.
impl Drop for WatchClient {
    fn drop(&mut self) {
        self.readers_reap();
        if !self.readers.is_empty() {
            tracing::warn!(
                "the stall watchdog waits for {} reads of callers' /proc that have not returned; aborting the mount ends one caught in a release on it",
                self.readers.len()
            );
        }
        for reader in self.readers.drain(..) {
            if reader.join().is_err() {
                tracing::error!("a thread naming stalled requests' callers panicked");
            }
        }
    }
}

/// The names `name` gives `tids`, read in order on a thread of their own and waited for at most `patience` in all: reading another process's `/proc` can leave the reading thread in a release on this mount (`crate::signals`), which must not silence the watchdog. A tid whose read did not return in time is missing, and so is every one after it. The thread is returned, to be joined once it ends.
fn callers_read(
    tids: Vec<u32>,
    patience: Duration,
    name: impl Fn(u32) -> String + Send + 'static,
) -> (HashMap<u32, String>, Option<JoinHandle<()>>) {
    let started = Instant::now();
    let (named, names_rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("jfs-callers".into())
        .spawn(move || {
            for tid in tids {
                if named.send((tid, name(tid))).is_err() {
                    tracing::info!(
                        "the read naming caller {tid} for the stall watchdog finished {} into its check, too late for it",
                        fmt_duration(started.elapsed())
                    );
                    return;
                }
            }
        });
    let reader = match spawned {
        Ok(reader) => reader,
        Err(e) => {
            tracing::warn!("cannot start a thread to name stalled requests' callers: {e}");
            return (HashMap::new(), None);
        }
    };
    let mut names = HashMap::new();
    let deadline = started + patience;
    // Until every tid is named (the sender is gone) or the time is up.
    while let Ok((tid, name)) =
        names_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
    {
        names.insert(tid, name);
    }
    (names, Some(reader))
}

/// A stall line's caller: as [`callers_read`] found it, or as [`caller`] tells it without reading `/proc`.
fn caller_from(names: &HashMap<u32, String>, tid: u32, proc_ours: bool) -> String {
    if tid == 0 || !proc_ours {
        return caller(tid, proc_ours);
    }
    match names.get(&tid) {
        Some(name) => name.clone(),
        None => format!(
            "thread {tid} (not named: naming the callers did not finish within {})",
            fmt_duration(LOCK_PATIENCE)
        ),
    }
}

/// The in-flight listing of a report: every request in flight at least [`jackalopefs_perf::stall::INFLIGHT_LISTED`], oldest first. It reads each caller's `/proc` ([`crate::procs::status_of`]), so never on the FUSE session thread, the runtime's worker, the main thread or the watchdog's.
pub(crate) fn report_pending(shared: &Shared) {
    match shared.scan_pending(Instant::now(), ModeScan::Listed) {
        Ok(scan) => {
            let proc_ours = shared.proc_ours();
            for line in lines_pending(scan.found, |tid| caller(tid, proc_ours)) {
                tracing::info!(target: TRACE_TARGET, "perf inflight {line}");
            }
        }
        Err(ErrorLockHeld) => tracing::warn!(
            "the in-flight table's lock was held past {}; no listing",
            fmt_duration(LOCK_PATIENCE)
        ),
    }
}

/// `name` gives the caller of each request described.
fn lines_pending(found: Vec<Pending>, name: impl Fn(u32) -> String) -> Vec<String> {
    lines_crowd(
        found,
        |p| format!("{} {}", p.key.op, phase_of(p)),
        |p| describe(p, &name(p.key.pid)),
    )
}

fn describe(p: &Pending, caller: &str) -> String {
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
    line.push_str(&format!(", caller {caller}; "));
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

/// The thread blocked in a request and its process, by name, from `/proc` ([`crate::procs`]).
fn caller(tid: u32, proc_ours: bool) -> String {
    if tid == 0 {
        return "outside this pid namespace".into();
    }
    if !proc_ours {
        return format!("thread {tid} (/proc is not this pid namespace's)");
    }
    let status = match crate::procs::status_of(tid) {
        Ok(status) => status,
        Err(e) => return format!("thread {tid} ({e})"),
    };
    let thread = status.name.unwrap_or_else(|| "?".into());
    let state = status.state.unwrap_or_else(|| "?".into());
    let process = match status.tgid {
        Some(tgid) => match crate::procs::comm_of(tgid) {
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
        PhaseCall::Cancel => "waiting for the server to answer a cancel of an earlier change",
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
        .map(|p| describe(p, &caller(p.key.pid, false)))
        .collect();
        for (i, a) in lines.iter().enumerate() {
            assert!(!a.is_empty());
            for b in &lines[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert!(lines[4].contains("wanted"), "{}", lines[4]);
        let outside = describe(&pending(true, Ok(None), 0), &caller(0, true));
        assert_ne!(outside, lines[1]);
        let names = HashMap::from([(1, "a caller read in time".to_string())]);
        let named = caller_from(&names, 1, true);
        let unnamed = caller_from(&HashMap::new(), 1, true);
        assert!(!unnamed.is_empty());
        assert_ne!(named, unnamed);
    }

    #[test]
    fn a_caller_read_that_does_not_return_names_those_before_it_and_frees_the_watchdog() {
        let patience = Duration::from_secs(2);
        let (release, released) = std::sync::mpsc::channel::<()>();
        let started = Instant::now();
        let (names, reader) = callers_read(vec![1, 2, 3], patience, move |tid| {
            if tid == 2 {
                released.recv().unwrap();
            }
            format!("named {tid}")
        });
        let took = started.elapsed();
        assert!(took >= patience, "{took:?}");
        assert!(took < patience * 5, "{took:?}");
        assert!(names.contains_key(&1), "{names:?}");
        assert!(
            !names.contains_key(&2) && !names.contains_key(&3),
            "{names:?}"
        );

        let (others, other) = callers_read(vec![4, 5], patience, |tid| format!("named {tid}"));
        assert_eq!(others.len(), 2, "{others:?}");
        other.unwrap().join().unwrap();

        release.send(()).unwrap();
        reader.unwrap().join().unwrap();
    }

    #[test]
    fn a_crowd_of_requests_is_grouped_by_op_and_phase() {
        let found: Vec<Pending> = (0..12)
            .map(|_| pending(true, Ok(Some(call(PhaseCall::Reply))), 1))
            .collect();
        let lines = lines_pending(found, |tid| caller(tid, false));
        assert_eq!(lines.len(), STALL_DETAILED + 1);
        let rest = lines.last().unwrap();
        assert!(
            rest.contains(&format!("4 lookup {}", phase_name(PhaseCall::Reply))),
            "{rest}"
        );
    }
}

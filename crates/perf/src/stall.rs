//! What both sides' stall watchdogs share: when a request in flight or a condition that persists is reported, how a crowd of stalled requests is summarized, the thread that does the watching, the instants it reads without taking a lock, and the wording of what every report carries.

use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, LazyLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// A request in flight this long is reported as stalled, and again each time its age doubles.
pub const STALL_FIRST: Duration = Duration::from_secs(5);

/// A report lists every request in flight at least this long.
pub const INFLIGHT_LISTED: Duration = Duration::from_secs(1);

/// Stalled requests described one per line; the rest are counted by what they are doing.
pub const STALL_DETAILED: usize = 8;

/// Longest the watchdog waits for a lock it shares with the code it watches. A lock held longer is itself the finding, and waiting on it would silence the watchdog in exactly the hang it is there to describe.
pub const LOCK_PATIENCE: Duration = Duration::from_millis(200);

/// A lock the watchdog shares with the code it watches was held past [`LOCK_PATIENCE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorLockHeld;

/// How often the watchdog looks.
pub const WATCH_PERIOD: Duration = Duration::from_secs(1);

/// Whether a request in flight for `age` is due a stall report, given the threshold it was `reported` at last (zero if never). The thresholds are [`STALL_FIRST`] and its doublings (5 s, 10 s, 20 s, …); a scan that comes late reports once, at the highest threshold it finds crossed.
pub fn stall_due(age: Duration, reported: &mut Duration) -> bool {
    if age < STALL_FIRST.max(*reported * 2) {
        return false;
    }
    let mut threshold = STALL_FIRST;
    while threshold * 2 <= age {
        threshold *= 2;
    }
    *reported = threshold;
    true
}

/// Which requests in flight a scan returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeScan {
    /// Those due a stall report ([`stall_due`]), each marked as reported.
    Due,
    /// Those in flight at least [`INFLIGHT_LISTED`], for a report.
    Listed,
}

impl ModeScan {
    /// Whether a request in flight for `age`, last reported at `reported`, is one this scan returns; a [`ModeScan::Due`] scan marks it reported.
    pub fn selects(self, age: Duration, reported: &mut Duration) -> bool {
        match self {
            ModeScan::Due => stall_due(age, reported),
            ModeScan::Listed => age >= INFLIGHT_LISTED,
        }
    }
}

/// The first `keep` of `items` (which come oldest first) to describe one by one, and how many of the rest there are by `key`.
pub fn split_oldest<T, K: Ord>(
    mut items: Vec<T>,
    keep: usize,
    key: impl Fn(&T) -> K,
) -> (Vec<T>, BTreeMap<K, usize>) {
    let rest = items.split_off(keep.min(items.len()));
    let mut counts = BTreeMap::new();
    for item in &rest {
        *counts.entry(key(item)).or_default() += 1;
    }
    (items, counts)
}

/// The lines for a crowd of requests (oldest first): the first [`STALL_DETAILED`] described one per line, then one line counting the rest by `key`.
pub fn lines_crowd<T>(
    found: Vec<T>,
    key: impl Fn(&T) -> String,
    describe: impl Fn(&T) -> String,
) -> Vec<String> {
    let (detailed, rest) = split_oldest(found, STALL_DETAILED, key);
    let mut lines: Vec<String> = detailed.iter().map(describe).collect();
    if !rest.is_empty() {
        let counts: Vec<String> = rest.iter().map(|(key, n)| format!("{n} {key}")).collect();
        lines.push(format!("and {}", counts.join(", ")));
    }
    lines
}

/// A condition that may persist from one check to the next (a runtime that runs no tasks, a thread that does not come back to its work), reported on the stall schedule for as long as it does.
#[derive(Default)]
pub struct Persisting {
    since: Option<Instant>,
    reported: Duration,
}

impl Persisting {
    /// Whether the condition `holds` at `now`; how long it has, when that is due a report.
    pub fn check(&mut self, now: Instant, holds: bool) -> Option<Duration> {
        if !holds {
            *self = Persisting::default();
            return None;
        }
        let age = now.saturating_duration_since(*self.since.get_or_insert(now));
        stall_due(age, &mut self.reported).then_some(age)
    }

    /// Start over: what holds now is another instance of the condition.
    pub fn reset(&mut self) {
        *self = Persisting::default();
    }
}

/// Stalled requests that have ended since the watchdog last looked, which it logs together: the first few described, the rest counted, so a crowd that stalled together does not end in a burst of lines.
#[derive(Default)]
pub struct Ended {
    inner: Mutex<(Vec<String>, usize)>,
}

impl Ended {
    /// A request that was reported as stalled has ended; `line` describes it, and is called only when it will be logged.
    pub fn push(&self, line: impl FnOnce() -> String) {
        let mut inner = self.inner.lock();
        if inner.0.len() < STALL_DETAILED {
            inner.0.push(line());
        } else {
            inner.1 += 1;
        }
    }

    /// The lines for what has ended since the last call; none when the lock was held past [`LOCK_PATIENCE`], which leaves them for the next.
    pub fn lines(&self) -> Vec<String> {
        let Some(mut inner) = self.inner.try_lock_for(LOCK_PATIENCE) else {
            return Vec::new();
        };
        let (mut lines, more) = std::mem::take(&mut *inner);
        if more > 0 {
            lines.push(format!("and {more} more stalled requests ended"));
        }
        lines
    }
}

/// What every stall report carries about progress: requests answered since the watchdog's last check (`completed_before` is the count then) and how long ago the last one was, and how long ago the runtime last ran a heartbeat.
pub fn line_progress(
    progress: &Progress,
    completed_before: u64,
    heartbeat: &Heartbeat,
    now: Instant,
) -> String {
    format!(
        "{} answered since the last check, the last {} ago; the runtime last ran a task {} ago (one is due every {})",
        progress.completed() - completed_before,
        crate::fmt_duration(now.saturating_duration_since(progress.last())),
        crate::fmt_duration(heartbeat.age()),
        crate::fmt_duration(WATCH_PERIOD),
    )
}

/// A heartbeat older than this means the runtime has missed a ping.
pub const HEARTBEAT_LATE: Duration = Duration::from_secs(2);

static ORIGIN: LazyLock<Instant> = LazyLock::new(Instant::now);

/// An instant kept in an atomic, so the watchdog can read it without a lock.
pub struct Stamp(AtomicU64);

impl Stamp {
    pub fn now() -> Stamp {
        let stamp = Stamp(AtomicU64::new(0));
        stamp.set(Instant::now());
        stamp
    }

    pub fn set(&self, at: Instant) {
        let micros = at.saturating_duration_since(*ORIGIN).as_micros() as u64;
        self.0.store(micros, Ordering::Relaxed);
    }

    pub fn get(&self) -> Instant {
        *ORIGIN + Duration::from_micros(self.0.load(Ordering::Relaxed))
    }
}

/// Requests finished, and when the last one did: whether the rest are flowing past a stalled one or everything has stopped.
pub struct Progress {
    completed: AtomicU64,
    last: Stamp,
}

impl Default for Progress {
    fn default() -> Progress {
        Progress {
            completed: AtomicU64::new(0),
            last: Stamp::now(),
        }
    }
}

impl Progress {
    pub fn record(&self) {
        self.completed.fetch_add(1, Ordering::Relaxed);
        self.last.set(Instant::now());
    }

    pub fn completed(&self) -> u64 {
        self.completed.load(Ordering::Relaxed)
    }

    pub fn last(&self) -> Instant {
        self.last.get()
    }
}

/// When the tokio runtime last ran a task the watchdog gave it. A runtime whose workers are all blocked runs none, and every call it holds looks like one waiting on the network.
pub struct Heartbeat {
    runtime: tokio::runtime::Handle,
    beat: Arc<Stamp>,
}

impl Heartbeat {
    pub fn new(runtime: tokio::runtime::Handle) -> Heartbeat {
        Heartbeat {
            runtime,
            beat: Arc::new(Stamp::now()),
        }
    }

    /// Give the runtime a task that stamps the heartbeat.
    pub fn ping(&self) {
        let beat = self.beat.clone();
        self.runtime.spawn(async move { beat.set(Instant::now()) });
    }

    /// How long ago the runtime last ran a ping; a ping is due every [`WATCH_PERIOD`], so anything much longer means its workers are busy or blocked.
    pub fn age(&self) -> Duration {
        self.beat.get().elapsed()
    }
}

/// A thread that calls `tick` every period until stopped. A thread of its own rather than a tokio task, so it still runs when the runtime is what is stuck; a tick that panics is logged and the next one runs anyway.
pub struct Watchdog {
    stop: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Watchdog {
    pub fn spawn(
        name: &str,
        period: Duration,
        mut tick: impl FnMut() + Send + 'static,
    ) -> io::Result<Watchdog> {
        let (stop, stopped) = mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                // A message or a disconnect is the stop.
                while let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(period) {
                    if let Err(panic) = catch_unwind(AssertUnwindSafe(&mut tick)) {
                        let what = panic
                            .downcast_ref::<&str>()
                            .map(|s| s.to_string())
                            .or_else(|| panic.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "a panic without a message".into());
                        tracing::error!("stall watchdog check panicked: {what}; it goes on");
                    }
                }
            })?;
        tracing::info!(
            "stall watchdog running: a request in flight for {} is reported, then each time its age doubles",
            crate::fmt_duration(STALL_FIRST)
        );
        Ok(Watchdog {
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// Stop and wait for the thread; dropping does the same.
    pub fn stop(self) {
        drop(self);
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                tracing::error!("stall watchdog thread panicked outside a check");
            }
        }
    }
}

/// The kernel function a thread of this process sleeps in (`fuse_dev_do_read` for a FUSE session thread waiting for work, `futex_wait_queue` for one waiting on a lock, `request_wait_answer` for one blocked on a FUSE filesystem); empty for one that is running.
pub fn thread_wchan(tid: i32) -> io::Result<String> {
    let wchan = std::fs::read_to_string(format!("/proc/self/task/{tid}/wchan"))?;
    Ok(if wchan == "0" { String::new() } else { wchan })
}

/// What a thread of this process is doing, from `/proc/self/task/<tid>`: its scheduler state and [`thread_wchan`]. Only `status` and `wchan` are read, never `maps` or `cmdline`, which take the mmap lock a thread faulting on a FUSE mount may hold.
pub fn thread_doing(tid: i32) -> String {
    let state = match std::fs::read_to_string(format!("/proc/self/task/{tid}/status")) {
        Ok(status) => status
            .lines()
            .find_map(|line| line.strip_prefix("State:"))
            .map(|state| state.trim().to_string())
            .unwrap_or_else(|| "no State line".into()),
        Err(e) => return format!("thread {tid}: {e}"),
    };
    let wchan = match thread_wchan(tid) {
        Ok(wchan) if wchan.is_empty() => "running".to_string(),
        Ok(wchan) => format!("in {wchan}"),
        Err(e) => format!("wchan unreadable ({e})"),
    };
    format!("thread {tid} {state} {wchan}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn s(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn stalls_are_reported_at_five_seconds_and_each_doubling() {
        let mut reported = Duration::ZERO;
        let due: Vec<u64> = (0..=45)
            .filter(|&age| stall_due(s(age), &mut reported))
            .collect();
        assert_eq!(due, [5, 10, 20, 40]);
        // Seen a little after each threshold, as a once-a-second scan sees it, the schedule does not drift.
        let mut reported = Duration::ZERO;
        let late = |age: u64| s(age) + Duration::from_millis(900);
        assert!(stall_due(late(5), &mut reported));
        assert!(!stall_due(late(9), &mut reported));
        assert!(stall_due(s(10), &mut reported));
    }

    #[test]
    fn a_late_scan_reports_once() {
        let mut reported = Duration::ZERO;
        assert!(stall_due(s(30), &mut reported));
        assert!(!stall_due(s(31), &mut reported));
        assert!(!stall_due(s(39), &mut reported));
        assert!(stall_due(s(40), &mut reported));
    }

    #[test]
    fn the_oldest_are_kept_and_the_rest_counted() {
        let items = vec![
            ("read", 9),
            ("write", 8),
            ("read", 7),
            ("write", 6),
            ("read", 5),
        ];
        let (kept, rest) = split_oldest(items, 2, |(op, _)| *op);
        assert_eq!(kept, [("read", 9), ("write", 8)]);
        assert_eq!(rest, BTreeMap::from([("read", 2), ("write", 1)]));
        let (kept, rest) = split_oldest(vec![1, 2], 8, |_| ());
        assert_eq!((kept, rest.len()), (vec![1, 2], 0));
    }

    #[test]
    fn stamps_round_trip_to_the_microsecond() {
        // The stamp first: stamps count from the first one made, and an instant before that is not one a stamp can hold.
        let stamp = Stamp::now();
        let at = Instant::now();
        stamp.set(at);
        let back = stamp.get();
        let skew = if back > at { back - at } else { at - back };
        assert!(skew < Duration::from_micros(2), "{skew:?}");
    }

    #[test]
    fn progress_counts_and_stamps() {
        let progress = Progress::default();
        let before = Instant::now();
        progress.record();
        progress.record();
        assert_eq!(progress.completed(), 2);
        assert!(progress.last() + Duration::from_micros(1) >= before);
    }

    #[test]
    fn the_watchdog_ticks_survives_a_panic_and_stops() {
        let ticks = Arc::new(Mutex::new(0u32));
        let counted = ticks.clone();
        let watchdog = Watchdog::spawn("test-watchdog", Duration::from_millis(5), move || {
            let n = {
                let mut n = counted.lock().unwrap();
                *n += 1;
                *n
            };
            if n == 2 {
                panic!("second tick");
            }
        })
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while *ticks.lock().unwrap() < 4 {
            assert!(Instant::now() < deadline, "watchdog stopped ticking");
            std::thread::sleep(Duration::from_millis(5));
        }
        watchdog.stop();
        let stopped = *ticks.lock().unwrap();
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(*ticks.lock().unwrap(), stopped, "ticked after stop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn the_heartbeat_follows_the_runtime() {
        let heartbeat = Heartbeat::new(tokio::runtime::Handle::current());
        std::thread::sleep(Duration::from_millis(20));
        assert!(heartbeat.age() >= Duration::from_millis(20));
        heartbeat.ping();
        let deadline = Instant::now() + Duration::from_secs(10);
        while heartbeat.age() >= Duration::from_millis(20) {
            assert!(Instant::now() < deadline, "the ping never ran");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[test]
    fn a_sleeping_thread_is_found_in_its_wait() {
        let (tx, rx) = mpsc::channel::<i32>();
        let (_stop, stopped) = mpsc::channel::<()>();
        let sleeper = std::thread::spawn(move || {
            tx.send(unsafe { libc::gettid() }).unwrap();
            stopped.recv().ok();
        });
        let tid = rx.recv().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while thread_wchan(tid).unwrap().is_empty() {
            assert!(Instant::now() < deadline, "the thread never slept");
            std::thread::sleep(Duration::from_millis(5));
        }
        let doing = thread_doing(tid);
        assert!(doing.contains(" in "), "{doing}");
        drop(_stop);
        sleeper.join().unwrap();
        assert!(thread_wchan(i32::MAX).is_err());
        assert_ne!(thread_doing(i32::MAX), doing);
    }

    #[test]
    fn a_crowd_is_eight_lines_and_a_count() {
        let found: Vec<u32> = (0..20).collect();
        let lines = lines_crowd(
            found,
            |n| {
                if n % 2 == 0 {
                    "even".into()
                } else {
                    "odd".into()
                }
            },
            |n| format!("item {n}"),
        );
        assert_eq!(lines.len(), STALL_DETAILED + 1);
        assert_eq!(lines[0], "item 0");
        let last = lines.last().unwrap();
        assert!(last.contains("6 even") && last.contains("6 odd"), "{last}");
        assert_eq!(
            lines_crowd(vec![1u32], |_| String::new(), |n| format!("item {n}")),
            ["item 1"]
        );
    }

    #[test]
    fn a_persisting_condition_is_reported_on_the_schedule_and_forgotten_when_it_ends() {
        let start = Instant::now();
        let mut condition = Persisting::default();
        let at = |n: u64| start + s(n);
        let due: Vec<u64> = (0..=21)
            .filter(|&n| condition.check(at(n), true).is_some())
            .collect();
        assert_eq!(due, [5, 10, 20]);
        assert_eq!(condition.check(at(22), false), None);
        assert_eq!(
            condition.check(at(23), true),
            None,
            "a new instance starts its own clock"
        );
        assert_eq!(condition.check(at(28), true), Some(s(5)));
    }

    #[test]
    fn ended_requests_are_described_up_to_a_crowd_and_then_counted() {
        let ended = Ended::default();
        assert!(ended.lines().is_empty());
        let mut formatted = 0;
        for n in 0..(STALL_DETAILED + 3) {
            ended.push(|| {
                formatted += 1;
                format!("request {n}")
            });
        }
        assert_eq!(
            formatted, STALL_DETAILED,
            "only what is logged is formatted"
        );
        let lines = ended.lines();
        assert_eq!(lines.len(), STALL_DETAILED + 1);
        assert!(lines.last().unwrap().contains('3'));
        assert!(ended.lines().is_empty(), "lines empties it");
    }
}

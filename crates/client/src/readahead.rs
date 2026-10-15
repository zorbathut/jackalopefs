//! Whether the kernel's readahead window is what holds a sequential reader back. The kernel reads a file through its page cache in pieces of the mount's `read_ahead_kb` (128 KiB unless root raises it), with one or two of them in flight, so a reader that streams a big file waits on a round trip per window however fast the link is.

use jackalopefs_perf::fmt_duration;
use jackalopefs_proto::MAX_IO;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

/// The window the warnings suggest: room for several full-size (1 MiB) reads in flight at once.
const WINDOW_SUGGESTED_KB: u64 = 4096;

/// How far a read may start from where the run's reads have reached and still continue it: the kernel's synchronous and asynchronous readahead reads arrive slightly out of order.
const RUN_SLACK: u64 = 2 * MAX_IO as u64;

/// A run this long is a heavy sequential read, not a file manager's preview or a header scan.
const RUN_HEAVY: u64 = 256 << 20;

/// The largest read below which a run is not the window's doing: readahead's reads grow to the window within a few, while the writeback cache filling pages for an unaligned rewrite asks for a page or a small folio at a time.
const RUN_LARGEST_MIN: u32 = 64 * 1024;

/// The share of a run's time with a read in flight at which the window sets its pace: in steady readahead the share is about the read latency over the longer of that and the reader's own time per window, so near 1 the reader is not what it waits on.
const RUN_BUSY: f64 = 0.9;

/// Whether a read with the kernel's file flags `flags` came through the page cache, sized by readahead: an `O_DIRECT` read is its caller's size, and a read on a write-only file is the kernel filling a page a write only partly covers.
pub fn through_page_cache(flags: i32) -> bool {
    flags & libc::O_DIRECT == 0 && flags & libc::O_ACCMODE != libc::O_WRONLY
}

/// One open file's current run of sequential reads.
pub struct RunRead {
    /// Where the run's reads have reached: the highest end asked for.
    next: u64,
    started: Instant,
    bytes: u64,
    reads: u64,
    waited: Duration,
    /// The largest read asked for; one at [`MAX_IO`] means the window was not what sized them.
    largest: u32,
    inflight: u32,
    busy_since: Option<Instant>,
    busy: Duration,
    reported: bool,
}

/// A run that read heavily, never at the request cap, with a read in flight nearly all the time.
#[derive(Clone, Debug, PartialEq)]
pub struct FindingReadahead {
    pub bytes: u64,
    pub elapsed: Duration,
    pub largest: u32,
    pub latency_mean: Duration,
    pub busy_share: f64,
}

impl RunRead {
    /// A run that begins with a read at `offset`.
    pub fn new(offset: u64, now: Instant) -> RunRead {
        RunRead {
            next: offset,
            started: now,
            bytes: 0,
            reads: 0,
            waited: Duration::ZERO,
            largest: 0,
            inflight: 0,
            busy_since: None,
            busy: Duration::ZERO,
            reported: false,
        }
    }

    /// A read of `size` at `offset` is sent at `now`.
    pub fn start(&mut self, offset: u64, size: u32, now: Instant) {
        let continues = offset.saturating_add(RUN_SLACK) >= self.next
            && offset <= self.next.saturating_add(RUN_SLACK);
        if !continues {
            // The reads still out belong to no run now, but they hold the reader up all the same.
            *self = RunRead {
                inflight: self.inflight,
                busy_since: (self.inflight > 0).then_some(now),
                ..RunRead::new(offset, now)
            };
        }
        self.next = self.next.max(offset.saturating_add(u64::from(size)));
        self.largest = self.largest.max(size);
        if self.inflight == 0 {
            self.busy_since = Some(now);
        }
        self.inflight += 1;
    }

    /// A read answered at `now` with `bytes` (none when it failed) after `took`; every [`RunRead::start`] has one. The finding comes once per run.
    pub fn end(&mut self, bytes: u64, took: Duration, now: Instant) -> Option<FindingReadahead> {
        self.inflight = self.inflight.saturating_sub(1);
        if self.inflight == 0 {
            if let Some(since) = self.busy_since.take() {
                self.busy += now.saturating_duration_since(since);
            }
        }
        self.bytes += bytes;
        self.reads += 1;
        self.waited += took;
        if self.reported
            || self.bytes < RUN_HEAVY
            || self.largest < RUN_LARGEST_MIN
            || self.largest as usize >= MAX_IO
        {
            return None;
        }
        let elapsed = now.saturating_duration_since(self.started);
        if elapsed.is_zero() {
            return None;
        }
        let busy = self.busy
            + self
                .busy_since
                .map_or(Duration::ZERO, |since| now.saturating_duration_since(since));
        let busy_share = busy.as_secs_f64() / elapsed.as_secs_f64();
        if busy_share < RUN_BUSY {
            return None;
        }
        self.reported = true;
        Some(FindingReadahead {
            bytes: self.bytes,
            elapsed,
            largest: self.largest,
            latency_mean: Duration::from_secs_f64(self.waited.as_secs_f64() / self.reads as f64),
            busy_share,
        })
    }
}

impl FindingReadahead {
    /// What the run did, and the connection's round trip `rtt` to set its reads' latency against: one far above it is the link or the server, which a larger window does not help.
    pub fn line(&self, rtt: Option<Duration>) -> String {
        let rtt = match rtt {
            Some(rtt) => format!(" against a round trip of {}", fmt_duration(rtt)),
            None => String::new(),
        };
        format!(
            "{} MiB in {} ({:.1} MB/s) in reads of at most {} KiB, each answered in {} on average{rtt}, with a read in flight {:.0}% of the time",
            self.bytes >> 20,
            fmt_duration(self.elapsed),
            self.bytes as f64 / self.elapsed.as_secs_f64() / 1e6,
            self.largest / 1024,
            fmt_duration(self.latency_mean),
            self.busy_share * 100.0,
        )
    }
}

/// Whether a readahead window of `kb` is below the request cap, so that it and not the cap sizes the kernel's page-cache reads.
pub fn window_short(kb: u64) -> bool {
    kb.saturating_mul(1024) < MAX_IO as u64
}

/// The hint at mount for a window of `kb` on the mount at `mountpoint`, whose bdi is `bdi`, when the window is short.
pub fn line_startup(kb: u64, bdi: &Path, mountpoint: &Path) -> Option<String> {
    window_short(kb).then(|| {
        format!(
            "the kernel reads ahead only {kb} KiB on this mount, so a sequential reader has at most one or two reads that size in flight, each a round trip; `{}` raises it (requests stay at most 1 MiB, more of them in flight) for files opened afterwards, until unmount; for every mount, run `echo {WINDOW_SUGGESTED_KB} | sudo tee /sys/class/bdi/\"$(mountpoint -d {})\"/read_ahead_kb` after mounting",
            fix(bdi),
            shell_quote(mountpoint)
        )
    })
}

/// What to do about a finding, given the mount's window `kb` now and its `bdi`.
pub fn advice(kb: Option<u64>, bdi: Option<&Path>) -> String {
    match (kb, bdi) {
        (Some(kb), _) if !window_short(kb) => format!(
            "the mount already reads ahead {kb} KiB: a file opened before that was set keeps its old window until it is reopened, and an application that sizes its own reads (POSIX_FADV_RANDOM) is not helped by it"
        ),
        (Some(kb), Some(bdi)) => format!(
            "the mount reads ahead only {kb} KiB; `{}` raises it for files opened afterwards, until unmount, unless the link or the server is what is slow (a read latency far above the round trip)",
            fix(bdi)
        ),
        (None, Some(bdi)) => format!(
            "its window could not be read; `{}` raises it for files opened afterwards, until unmount",
            fix(bdi)
        ),
        (_, None) => "raising the mount's read_ahead_kb in /sys/class/bdi (as root) may help files opened afterwards".into(),
    }
}

/// The command that raises the window of the mount whose bdi is `bdi`, which takes root.
fn fix(bdi: &Path) -> String {
    format!(
        "echo {WINDOW_SUGGESTED_KB} | sudo tee {}",
        shell_quote(&bdi.join("read_ahead_kb"))
    )
}

/// `path` as one shell word.
fn shell_quote(path: &Path) -> String {
    format!(
        "'{}'",
        String::from_utf8_lossy(path.as_os_str().as_bytes()).replace('\'', "'\\''")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;

    fn ms(x: f64) -> Duration {
        Duration::from_secs_f64(x / 1000.0)
    }

    /// One read after another, each `latency` long with `gap` before the next, until `total` bytes have been read from `offset`; the findings, and where and when it stopped.
    fn chain(
        run: &mut RunRead,
        mut now: Instant,
        mut offset: u64,
        size: u64,
        latency: Duration,
        gap: Duration,
        total: u64,
    ) -> (Vec<FindingReadahead>, Instant, u64) {
        let mut found = Vec::new();
        let end = offset + total;
        while offset < end {
            run.start(offset, size as u32, now);
            now += latency;
            found.extend(run.end(size, latency, now));
            now += gap;
            offset += size;
        }
        (found, now, offset)
    }

    #[test]
    fn the_incidents_reader_is_found_once_at_the_threshold() {
        let t0 = Instant::now();
        let mut run = RunRead::new(0, t0);
        // 128 KiB reads, two overlapping, 1.4 ms each, with a small gap after each pair.
        let mut now = t0;
        let mut offset = 0;
        let mut found = Vec::new();
        let size = 128 * KIB;
        while offset < 2 * RUN_HEAVY {
            run.start(offset, size as u32, now);
            run.start(offset + size, size as u32, now + ms(0.7));
            found.extend(run.end(size, ms(1.4), now + ms(1.4)));
            found.extend(run.end(size, ms(1.4), now + ms(2.1)));
            now += ms(2.2);
            offset += 2 * size;
            if found.is_empty() {
                assert!(offset < RUN_HEAVY + 2 * size, "found late, at {offset}");
            }
        }
        assert_eq!(found.len(), 1, "{found:?}");
        let finding = &found[0];
        assert!(finding.bytes >= RUN_HEAVY);
        assert_eq!(finding.largest, size as u32);
        assert!(finding.busy_share >= RUN_BUSY && finding.busy_share <= 1.0);
    }

    #[test]
    fn reads_at_the_request_cap_are_not_held_by_the_window() {
        let t0 = Instant::now();
        let mut run = RunRead::new(0, t0);
        let (found, ..) = chain(
            &mut run,
            t0,
            0,
            MAX_IO as u64,
            ms(4.0),
            Duration::ZERO,
            2 * RUN_HEAVY,
        );
        assert!(found.is_empty());
    }

    #[test]
    fn the_busy_share_decides_near_the_threshold() {
        let t0 = Instant::now();
        let mut idle = RunRead::new(0, t0);
        let (found, ..) = chain(
            &mut idle,
            t0,
            0,
            128 * KIB,
            ms(0.85),
            ms(0.15),
            2 * RUN_HEAVY,
        );
        assert!(found.is_empty(), "{found:?}");
        let mut busy = RunRead::new(0, t0);
        let (found, ..) = chain(
            &mut busy,
            t0,
            0,
            128 * KIB,
            ms(0.95),
            ms(0.05),
            2 * RUN_HEAVY,
        );
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn a_run_that_becomes_busy_later_is_found_once_when_it_does() {
        let t0 = Instant::now();
        let mut run = RunRead::new(0, t0);
        let (found, now, offset) = chain(&mut run, t0, 0, 128 * KIB, ms(1.0), ms(1.0), RUN_HEAVY);
        assert!(found.is_empty(), "half busy");
        let (found, ..) = chain(
            &mut run,
            now,
            offset,
            128 * KIB,
            ms(1.0),
            Duration::ZERO,
            16 * RUN_HEAVY,
        );
        assert_eq!(found.len(), 1, "{found:?}");
    }

    #[test]
    fn a_seek_starts_a_new_run() {
        let t0 = Instant::now();
        let mut run = RunRead::new(0, t0);
        let (found, now, _) = chain(
            &mut run,
            t0,
            0,
            128 * KIB,
            ms(1.0),
            Duration::ZERO,
            200 * MIB,
        );
        assert!(found.is_empty());
        let far = 10 << 30;
        let (found, now, offset) = chain(
            &mut run,
            now,
            far,
            128 * KIB,
            ms(1.0),
            Duration::ZERO,
            200 * MIB,
        );
        assert!(found.is_empty(), "the reads before the seek do not count");
        let (found, ..) = chain(
            &mut run,
            now,
            offset,
            128 * KIB,
            ms(1.0),
            Duration::ZERO,
            RUN_HEAVY - 200 * MIB,
        );
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn reads_out_of_order_are_one_run_and_their_overlap_is_busy_once() {
        let t0 = Instant::now();
        let mut run = RunRead::new(0, t0);
        run.start(128 * KIB, 128 * KIB as u32, t0);
        run.start(0, 128 * KIB as u32, t0 + ms(0.1));
        assert_eq!(run.end(128 * KIB, ms(1.0), t0 + ms(1.1)), None);
        assert_eq!(run.end(128 * KIB, ms(1.1), t0 + ms(1.1)), None);
        assert_eq!(run.started, t0, "one run");
        assert_eq!(run.bytes, 256 * KIB);
        assert_eq!(run.busy, ms(1.1));
        assert_eq!(run.inflight, 0);
    }

    #[test]
    fn failures_straddles_and_extra_ends_keep_the_count_in_flight_sane() {
        let t0 = Instant::now();
        let mut run = RunRead::new(0, t0);
        run.start(0, 128 * KIB as u32, t0);
        // A seek while the first read is out: the new run counts it as in flight.
        run.start(1 << 30, 128 * KIB as u32, t0 + ms(0.5));
        assert_eq!(run.inflight, 2);
        assert_eq!(
            run.end(0, ms(1.0), t0 + ms(1.0)),
            None,
            "a failure ends a read too"
        );
        assert_eq!(run.end(128 * KIB, ms(1.0), t0 + ms(1.5)), None);
        assert_eq!(run.inflight, 0);
        assert_eq!(run.busy, ms(1.0), "busy from the seek to the last end");
        assert_eq!(run.end(0, Duration::ZERO, t0 + ms(2.0)), None);
        assert_eq!(run.inflight, 0, "no underflow");
    }

    #[test]
    fn findings_and_advice_read_differently_by_what_they_say() {
        let finding = FindingReadahead {
            bytes: RUN_HEAVY,
            elapsed: Duration::from_secs(4),
            largest: 128 * 1024,
            latency_mean: ms(1.4),
            busy_share: 0.93,
        };
        let line = finding.line(Some(ms(0.15)));
        assert!(!line.is_empty());
        assert_ne!(line, finding.line(None));
        let slower = FindingReadahead {
            elapsed: Duration::from_secs(8),
            ..finding.clone()
        };
        assert_ne!(line, slower.line(Some(ms(0.15))));
        let bdi = std::path::Path::new("/sys/class/bdi/0:40");
        let low = advice(Some(128), Some(bdi));
        let raised = advice(Some(4096), Some(bdi));
        let unread = advice(None, Some(bdi));
        let unknown = advice(None, None);
        assert!(low.contains("0:40"), "{low}");
        assert!(
            unread.contains("0:40"),
            "the command is known even when the value is not: {unread}"
        );
        assert!(
            !raised.contains("0:40"),
            "advice already taken is not repeated: {raised}"
        );
        for (i, a) in [&low, &raised, &unread, &unknown].iter().enumerate() {
            for b in &[&low, &raised, &unread, &unknown][i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn the_startup_hint_is_for_a_window_below_the_request_cap() {
        let bdi = std::path::Path::new("/sys/class/bdi/0:40");
        let mnt = std::path::Path::new("/mnt/my share");
        assert!(window_short(128));
        assert!(window_short(MAX_IO as u64 / 1024 - 4));
        assert!(!window_short(MAX_IO as u64 / 1024));
        assert!(!window_short(4096));
        let hint = line_startup(128, bdi, mnt).unwrap();
        assert!(
            hint.contains("'/mnt/my share'"),
            "the mount point is quoted for the shell: {hint}"
        );
        assert_eq!(line_startup(1024, bdi, mnt), None);
    }

    #[test]
    fn a_path_is_quoted_for_the_shell() {
        assert_eq!(
            shell_quote(std::path::Path::new("/mnt/plain")),
            "'/mnt/plain'"
        );
        assert_eq!(
            shell_quote(std::path::Path::new("/mnt/it's")),
            "'/mnt/it'\\''s'"
        );
    }

    #[test]
    fn small_reads_are_not_the_window() {
        // An unaligned rewrite through the writeback cache fills pages one by one; readahead's reads grow to the window within a few.
        let t0 = Instant::now();
        let mut run = RunRead::new(0, t0);
        let (found, ..) = chain(
            &mut run,
            t0,
            0,
            4 * KIB,
            ms(0.5),
            Duration::ZERO,
            2 * RUN_HEAVY,
        );
        assert!(found.is_empty());
    }

    #[test]
    fn a_new_run_after_a_reported_one_is_reported_again() {
        let t0 = Instant::now();
        let mut run = RunRead::new(0, t0);
        let (found, now, _) = chain(
            &mut run,
            t0,
            0,
            128 * KIB,
            ms(1.0),
            Duration::ZERO,
            RUN_HEAVY,
        );
        assert_eq!(found.len(), 1);
        let (found, ..) = chain(
            &mut run,
            now,
            10 << 30,
            128 * KIB,
            ms(1.0),
            Duration::ZERO,
            RUN_HEAVY,
        );
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn only_page_cache_reads_count() {
        assert!(through_page_cache(libc::O_RDONLY));
        assert!(through_page_cache(libc::O_RDWR | libc::O_CLOEXEC));
        assert!(!through_page_cache(libc::O_RDONLY | libc::O_DIRECT));
        assert!(!through_page_cache(libc::O_WRONLY));
    }
}

//! Whether a `FUSE_INTERRUPT` stands for a signal. The kernel queues one whenever `signal_pending()` holds for a task blocked in a request, and that also holds for `TIF_NOTIFY_SIGNAL`, which is no signal at all: io_uring delivering a completion to its submitting thread, the freezers, a tracer's stop. Only a real signal is still pending when the daemon looks, because the task cannot take one while it is blocked in our request, and `/proc/<tid>/status` shows the pending and blocked sets.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// Only `status` and `stat` are read, never `cmdline`, `environ`, `maps` or the like: those take the target's mmap lock, which a caller blocked in a page fault on this mount holds, so a read would wait on the very request it is judging (and the first read runs on the FUSE session thread).

/// How often a request whose interrupt stood for no signal looks again for a real one.
pub const RECHECK: Duration = Duration::from_millis(50);

/// The judge of interrupts: whether one for a request from a given thread is to be honoured.
pub struct Judge {
    /// Off when this process's `/proc` is another pid namespace's; every interrupt is then honoured.
    enabled: bool,
    /// Interrupts that could not be judged, and were honoured; counted so the warning about them is not one per interrupt.
    unjudged: AtomicU64,
}

impl Judge {
    /// A judge for this process: one that can see its callers in `/proc`, or else one that honours every interrupt, with a warning.
    pub fn for_this_process() -> Judge {
        let enabled = match proc_is_ours() {
            Ok(true) => true,
            Ok(false) => {
                tracing::warn!("/proc is not this process's pid namespace's, so interrupts cannot be told from io_uring completions: every one is honoured, and a call can fail with EINTR although no signal was sent");
                false
            }
            Err(e) => {
                tracing::warn!("cannot read /proc/self ({e}), so interrupts cannot be told from io_uring completions: every one is honoured, and a call can fail with EINTR although no signal was sent");
                false
            }
        };
        Judge {
            enabled,
            unjudged: AtomicU64::new(0),
        }
    }

    /// Whether an interrupt for a request from thread `tid` is to be honoured: when a signal is pending for the thread, when the thread is an io_uring worker (io_uring stops one, on a cancellation, a linked timeout or the ring's teardown, with the very notification that is no signal anywhere else), and when it cannot be judged, rather than risk a call nothing can end.
    pub fn stands(&self, tid: u32) -> bool {
        self.verdict(tid, |tid| {
            Ok(unblocked_signal_pending(tid)? || is_io_worker(tid)?)
        })
    }

    /// Whether a real signal has come since an interrupt for thread `tid` stood for none; the thread is no io_uring worker, or that interrupt would have stood.
    pub fn signal_came(&self, tid: u32) -> bool {
        self.verdict(tid, unblocked_signal_pending)
    }

    fn verdict(&self, tid: u32, judge: impl FnOnce(u32) -> io::Result<bool>) -> bool {
        if !self.enabled {
            return true;
        }
        // The kernel sends no thread id for a caller outside the pid namespace of whoever mounted, which is this process's.
        let verdict = if tid == 0 {
            Err(io::Error::other(
                "the request names no thread in this pid namespace",
            ))
        } else {
            judge(tid)
        };
        verdict.unwrap_or_else(|e| {
            let count = self.unjudged.fetch_add(1, Ordering::Relaxed) + 1;
            if count.is_power_of_two() {
                tracing::warn!(
                    tid,
                    count,
                    "cannot tell whether an interrupt stands for a signal ({e}); honouring it"
                );
            }
            true
        })
    }
}

/// Whether `status` (the text of `/proc/<tid>/status`) shows a signal pending for the thread that it has not blocked; `None` if the fields are missing or malformed. A signal sent to the whole process counts although another thread may take it: `/proc` does not say which will.
fn pending_in(status: &str) -> Option<bool> {
    let mask = |field: &str| {
        let hex = status
            .lines()
            .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))?
            .trim();
        u128::from_str_radix(hex, 16).ok()
    };
    Some((mask("SigPnd")? | mask("ShdPnd")?) & !mask("SigBlk")? != 0)
}

/// Whether `stat` (the text of `/proc/<tid>/stat`) is an io_uring worker's; `None` if malformed.
fn io_worker_in(stat: &str) -> Option<bool> {
    /// `PF_IO_WORKER` (`<linux/sched.h>`): not ABI, but the same value from its introduction (5.12) through 7.2, where this was checked.
    const PF_IO_WORKER: u32 = 0x10;
    // The command name, field 2, is in parentheses and may contain anything; the fields after its last `)` are fixed, flags being the seventh of them (field 9).
    let (_, rest) = stat.rsplit_once(')')?;
    let flags: u32 = rest.split_whitespace().nth(6)?.parse().ok()?;
    Some(flags & PF_IO_WORKER != 0)
}

/// Whether thread `tid` has a signal pending that it has not blocked. Unlike the kernel's `signal_pending()`, task work does not count.
pub fn unblocked_signal_pending(tid: u32) -> io::Result<bool> {
    let status = std::fs::read_to_string(format!("/proc/{tid}/status"))?;
    pending_in(&status).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("/proc/{tid}/status has no signal masks this client can read"),
        )
    })
}

/// Whether thread `tid` is an io_uring worker.
pub fn is_io_worker(tid: u32) -> io::Result<bool> {
    let stat = std::fs::read_to_string(format!("/proc/{tid}/stat"))?;
    io_worker_in(&stat).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("/proc/{tid}/stat has no flags this client can read"),
        )
    })
}

/// Whether this process's `/proc` is its own pid namespace's. The FUSE header names the caller in the namespace of whoever mounted, which is this process's; a `/proc` of another namespace (a container with the host's bind-mounted) would name some other process by that number.
fn proc_is_ours() -> io::Result<bool> {
    Ok(std::fs::read_link("/proc/self")?.as_os_str() == std::process::id().to_string().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(pnd: &str, shd: &str, blk: &str) -> String {
        format!("Name:\tcat\nState:\tS (sleeping)\nTgid:\t4242\nPid:\t4243\nSigQ:\t0/63488\nSigPnd:\t{pnd}\nShdPnd:\t{shd}\nSigBlk:\t{blk}\nSigIgn:\t0000000000000000\nSigCgt:\t0000000000000002\n")
    }

    const NONE: &str = "0000000000000000";
    /// SIGUSR2 (12): bit 11.
    const USR2: &str = "0000000000000800";

    #[test]
    fn a_pending_signal_the_thread_has_not_blocked_counts() {
        assert_eq!(pending_in(&status(NONE, NONE, NONE)), Some(false));
        assert_eq!(
            pending_in(&status(USR2, NONE, NONE)),
            Some(true),
            "sent to the thread"
        );
        assert_eq!(
            pending_in(&status(NONE, USR2, NONE)),
            Some(true),
            "sent to the process"
        );
        assert_eq!(
            pending_in(&status(USR2, USR2, USR2)),
            Some(false),
            "blocked, so it did not wake the thread"
        );
        assert_eq!(
            pending_in(&status(USR2, NONE, "0000000000000400")),
            Some(true),
            "another one blocked"
        );
    }

    /// The masks are as wide as the architecture's signal set: 128 bits on MIPS.
    #[test]
    fn masks_of_any_width_parse() {
        let wide_none = "00000000000000000000000000000000";
        let wide_top = "80000000000000000000000000000000";
        assert_eq!(
            pending_in(&status(wide_top, wide_none, wide_none)),
            Some(true)
        );
        assert_eq!(
            pending_in(&status(wide_top, wide_none, wide_top)),
            Some(false)
        );
    }

    #[test]
    fn a_status_that_does_not_say_is_no_verdict() {
        assert_eq!(pending_in(""), None);
        assert_eq!(
            pending_in("SigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\n"),
            None,
            "no blocked set"
        );
        assert_eq!(pending_in(&status("zz", NONE, NONE)), None);
    }

    fn stat(comm: &str, flags: u32) -> String {
        format!("4243 ({comm}) S 4242 4242 4242 0 -1 {flags} 120 0 0 0 0 0 0 0 20 0 1 0 1234 0 0")
    }

    #[test]
    fn an_io_uring_worker_is_told_by_its_flags() {
        assert_eq!(io_worker_in(&stat("iou-wrk-4242", 0x0040_0010)), Some(true));
        assert_eq!(io_worker_in(&stat("fsstress", 0x0040_0000)), Some(false));
        // The command name is the thread's own and may contain anything, parentheses included.
        assert_eq!(io_worker_in(&stat("a) (b 1 2 3", 0x10)), Some(true));
        assert_eq!(io_worker_in(&stat("a) (b 1 2 3", 0)), Some(false));
        assert_eq!(io_worker_in("4243 (x) S"), None);
        assert_eq!(io_worker_in("garbage"), None);
    }

    #[test]
    fn this_proc_is_ours() {
        assert!(proc_is_ours().unwrap());
    }

    /// An interrupt the judge cannot judge is honoured, rather than risk a call nothing can end.
    #[test]
    fn an_interrupt_that_cannot_be_judged_stands() {
        let judge = Judge::for_this_process();
        let tid = nix::unistd::gettid().as_raw() as u32;
        assert!(!judge.stands(tid), "this thread has no signal pending");
        assert!(!judge.signal_came(tid));
        assert!(judge.stands(0), "no thread named");
        // Above the kernel's highest pid_max, so no such thread.
        assert!(judge.stands(0x7fff_ffff));
        assert!(judge.signal_came(0x7fff_ffff));
        let off = Judge {
            enabled: false,
            unjudged: AtomicU64::new(0),
        };
        assert!(
            off.stands(tid),
            "every interrupt stands where /proc cannot be trusted"
        );
    }

    #[test]
    fn this_thread_has_nothing_pending() {
        let tid = nix::unistd::gettid().as_raw() as u32;
        assert!(!unblocked_signal_pending(tid).unwrap());
        assert!(!is_io_worker(tid).unwrap());
    }
}

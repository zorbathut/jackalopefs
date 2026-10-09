//! What `/proc` says about the threads that call into the mount. Only `status` and `comm` are read, never `cmdline`, `environ`, `maps` or the like: those take the target's mmap lock, which a caller blocked in a page fault on this mount holds, so a read would wait on the very request it is about (`crate::signals` reads `status` for the same reason).

use crate::handles::Opener;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

/// The fields of `/proc/<tid>/status` this client uses; each is `None` when the file lacks it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadStatus {
    /// The thread's own name, which is the process's comm for its main thread.
    pub name: Option<String>,
    pub state: Option<String>,
    /// The process the thread belongs to.
    pub tgid: Option<u32>,
}

/// The fields of the text of a `/proc/<tid>/status`.
pub fn parse_status(status: &str) -> ThreadStatus {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(|value| value.trim().to_string())
    };
    ThreadStatus {
        name: field("Name:"),
        state: field("State:"),
        tgid: field("Tgid:").and_then(|tgid| tgid.parse().ok()),
    }
}

pub fn status_of(tid: u32) -> io::Result<ThreadStatus> {
    Ok(parse_status(&std::fs::read_to_string(format!(
        "/proc/{tid}/status"
    ))?))
}

/// The name of process `tgid`.
pub fn comm_of(tgid: u32) -> io::Result<String> {
    Ok(std::fs::read_to_string(format!("/proc/{tgid}/comm"))?
        .trim_end_matches('\n')
        .to_string())
}

/// The process thread `tid` belongs to.
pub fn opener_of(tid: u32) -> io::Result<Opener> {
    let status = status_of(tid)?;
    let pid = status
        .tgid
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no Tgid in its status"))?;
    // A main thread's own name is its process's.
    let name = match status.name {
        Some(name) if pid == tid => name,
        _ => comm_of(pid)?,
    };
    Ok(Opener { pid, name })
}

/// How long an opener looked up for a thread is taken as still its: a thread id outlives a process only once the process has ended, and a walker's opens come from a few threads far faster than this.
const OPENER_FRESH: Duration = Duration::from_millis(100);

/// Most threads whose openers are remembered at once.
const OPENERS_KEPT: usize = 64;

/// The processes behind the threads that open handles, as [`opener_of`] finds them, remembered for [`OPENER_FRESH`]; failures too, so that a thread `/proc` hides from this user costs one read and not one per open.
pub struct Openers {
    /// Whether `/proc` names this mount's callers; when it does not, no caller is named.
    proc_ours: bool,
    recent: Mutex<HashMap<u32, (Instant, Option<Opener>)>>,
}

impl Openers {
    pub fn new(proc_ours: bool) -> Openers {
        Openers {
            proc_ours,
            recent: Mutex::new(HashMap::new()),
        }
    }

    /// The process behind thread `tid`, or `None` when it cannot be told: thread 0 (outside the mount's pid namespace), another namespace's `/proc`, or a `/proc` that would not say.
    ///
    /// What is not remembered is read on the blocking pool, never on the FUSE session thread: reading another process's `status` can drop the last reference to its memory when it is exiting, and the file puts that follow run on the reading thread, where a release on this mount waits for writeback only the session thread can carry.
    pub async fn of(&self, tid: u32) -> Option<Opener> {
        if tid == 0 || !self.proc_ours {
            return None;
        }
        if let Some(opener) = self.fresh(tid, Instant::now()) {
            return opener;
        }
        let opener = match tokio::task::spawn_blocking(move || opener_of(tid)).await {
            Ok(Ok(opener)) => Some(opener),
            Ok(Err(e)) => {
                tracing::debug!(tid, "no process for the thread opening a handle: {e}");
                None
            }
            Err(e) => {
                tracing::warn!(tid, "looking up the process opening a handle failed: {e}");
                None
            }
        };
        self.remember(tid, opener.clone(), Instant::now());
        opener
    }

    /// What is remembered for `tid` at `now`, if it is still fresh: `Some(None)` for a thread found to have no process this client can name.
    fn fresh(&self, tid: u32, now: Instant) -> Option<Option<Opener>> {
        let recent = self.recent.lock();
        let (at, opener) = recent.get(&tid)?;
        (now.duration_since(*at) < OPENER_FRESH).then(|| opener.clone())
    }

    fn remember(&self, tid: u32, opener: Option<Opener>, now: Instant) {
        let mut recent = self.recent.lock();
        if recent.len() >= OPENERS_KEPT {
            recent.retain(|_, (at, _)| now.duration_since(*at) < OPENER_FRESH);
            if recent.len() >= OPENERS_KEPT {
                recent.clear();
            }
        }
        recent.insert(tid, (now, opener));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_fields_are_read_and_missing_ones_are_none() {
        let status = parse_status("Name:\tDefaultDispatch\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4242\nNgid:\t0\nPid:\t4243\n");
        assert_eq!(
            status,
            ThreadStatus {
                name: Some("DefaultDispatch".into()),
                state: Some("S (sleeping)".into()),
                tgid: Some(4242),
            }
        );
        assert_eq!(parse_status("Pid:\t1\n"), ThreadStatus::default());
        assert_eq!(parse_status("Tgid:\tnot a number\n").tgid, None);
    }

    #[tokio::test]
    async fn a_thread_opens_for_its_process() {
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("opener-test".into())
            .spawn(move || {
                tid_tx.send(nix::unistd::gettid().as_raw() as u32).unwrap();
                done_rx.recv().unwrap();
            })
            .unwrap();
        let tid = tid_rx.recv().unwrap();
        let openers = Openers::new(true);
        let opener = openers.of(tid).await;
        done_tx.send(()).unwrap();
        thread.join().unwrap();
        let comm = comm_of(std::process::id()).unwrap();
        assert_eq!(
            opener,
            Some(Opener {
                pid: std::process::id(),
                name: comm.clone(),
            }),
            "the process's name, not the thread's"
        );
        assert_ne!(comm, "opener-test");
        assert_eq!(openers.of(0).await, None, "outside the pid namespace");
        assert_eq!(Openers::new(false).of(tid).await, None);
        assert_eq!(
            opener_of(std::process::id()).unwrap().name,
            comm,
            "a main thread's own name is its process's"
        );
    }

    #[test]
    fn openers_are_remembered_for_a_while_failures_too_and_within_bounds() {
        let openers = Openers::new(true);
        let start = Instant::now();
        let find = Some(Opener {
            pid: 7,
            name: "find".into(),
        });
        openers.remember(70, find.clone(), start);
        openers.remember(71, None, start);
        assert_eq!(
            openers.fresh(70, start + OPENER_FRESH / 2),
            Some(find.clone())
        );
        assert_eq!(
            openers.fresh(71, start),
            Some(None),
            "a failure is remembered"
        );
        assert_eq!(openers.fresh(72, start), None, "never looked up");
        assert_eq!(openers.fresh(70, start + OPENER_FRESH), None, "stale");
        for tid in 100..100 + 2 * OPENERS_KEPT as u32 {
            openers.remember(tid, None, start);
        }
        assert!(openers.recent.lock().len() <= OPENERS_KEPT, "bounded");

        let full = Openers::new(true);
        for tid in 100..100 + OPENERS_KEPT as u32 {
            full.remember(tid, None, start);
        }
        assert_eq!(full.recent.lock().len(), OPENERS_KEPT);
        let later = start + OPENER_FRESH;
        full.remember(1, find.clone(), later);
        assert_eq!(full.recent.lock().len(), 1, "the stale ones go first");
        assert_eq!(full.fresh(1, later), Some(find));
    }

    #[test]
    fn a_thread_belongs_to_this_process_by_its_status() {
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            tid_tx.send(nix::unistd::gettid().as_raw() as u32).unwrap();
            done_rx.recv().unwrap();
        });
        let tid = tid_rx.recv().unwrap();
        let status = status_of(tid).unwrap();
        done_tx.send(()).unwrap();
        thread.join().unwrap();
        assert_ne!(tid, std::process::id());
        assert_eq!(status.tgid, Some(std::process::id()));
        assert!(status.name.is_some() && status.state.is_some());
        assert_eq!(
            comm_of(std::process::id()).unwrap(),
            std::fs::read_to_string("/proc/self/comm")
                .unwrap()
                .trim_end()
        );
    }
}

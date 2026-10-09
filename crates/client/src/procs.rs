//! What `/proc` says about the threads that call into the mount. Only `status` and `comm` are read, never `cmdline`, `environ`, `maps` or the like: those take the target's mmap lock, which a caller blocked in a page fault on this mount holds, so a read would wait on the very request it is about (`crate::signals` reads `status` for the same reason).

use std::io;

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

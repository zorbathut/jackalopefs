//! End-to-end tests through a real FUSE mount. Skipped (with a message) where `/dev/fuse` or `fusermount3` is unavailable.

mod common;

use common::*;
use jackalopefs_client::mount::{Mount, MountOptions};
use jackalopefs_proto::{Request, Response};
use std::ffi::{CString, OsStr};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};

fn fuse_available() -> bool {
    let dev = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")
        .is_ok();
    let fusermount = std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| dir.join("fusermount3").exists())
    });
    if !dev || !fusermount {
        eprintln!("skipping: /dev/fuse usable = {dev}, fusermount3 on PATH = {fusermount}");
    }
    dev && fusermount
}

struct Mounted {
    mount: Option<Mount>,
    server: Option<TestServer>,
    /// Kept alive for a mount whose server never answers.
    _blackhole: Option<Blackhole>,
    export: tempfile::TempDir,
    mountpoint: tempfile::TempDir,
}

impl Mounted {
    async fn start(offline_timeout: Duration, ttl: Duration) -> Option<Mounted> {
        Mounted::start_full(offline_timeout, ttl, true).await
    }

    /// A mount whose server sends no change events.
    async fn start_unwatched(offline_timeout: Duration, ttl: Duration) -> Option<Mounted> {
        Mounted::start_full(offline_timeout, ttl, false).await
    }

    async fn start_full(
        offline_timeout: Duration,
        ttl: Duration,
        watched: bool,
    ) -> Option<Mounted> {
        if !fuse_available() {
            return None;
        }
        let export = tempfile::tempdir().unwrap();
        let server = if watched {
            TestServer::start(export.path(), None).await
        } else {
            TestServer::start_unwatched(export.path()).await
        };
        let (mount, mountpoint) = Mounted::mount(server.config(offline_timeout), ttl).await;
        Some(Mounted {
            mount: Some(mount),
            server: Some(server),
            _blackhole: None,
            export,
            mountpoint,
        })
    }

    /// A mount whose server completes the handshake and then never answers a request: a live connection to a server that has stalled.
    async fn start_stalled() -> Option<Mounted> {
        if !fuse_available() {
            return None;
        }
        let blackhole = Blackhole::start().await;
        let (mount, mountpoint) = Mounted::mount(
            blackhole.config(Duration::from_secs(60)),
            Duration::from_secs(1),
        )
        .await;
        Some(Mounted {
            mount: Some(mount),
            server: None,
            _blackhole: Some(blackhole),
            export: tempfile::tempdir().unwrap(),
            mountpoint,
        })
    }

    async fn mount(
        config: jackalopefs_client::Config,
        ttl: Duration,
    ) -> (Mount, tempfile::TempDir) {
        let mountpoint = tempfile::tempdir().unwrap();
        let client = jackalopefs_client::Client::connect(config).await.unwrap();
        let mount = Mount::start(
            client,
            mountpoint.path(),
            MountOptions {
                entry_ttl: ttl,
                attr_ttl: ttl,
                allow_other: false,
                auto_unmount: false,
                default_permissions: false,
            },
        )
        .await
        .unwrap();
        (mount, mountpoint)
    }

    fn mnt(&self) -> PathBuf {
        self.mountpoint.path().to_path_buf()
    }

    async fn finish(mut self) {
        self.mount.take().unwrap().unmount().await.unwrap();
        if let Some(server) = self.server.take() {
            server.stop().await;
        }
    }

    /// The way down for a mount whose server will never answer: fusermount unmounts lazily, so the mount lives while any process is blocked in a request against it (on a desktop, something probes every new mount), and only an abort ends that. A test that panics before this drops the mount instead, which aborts on its own.
    async fn abort_and_finish(self) {
        self.mount.as_ref().unwrap().aborter().abort();
        tokio::time::timeout(Duration::from_secs(3), self.finish())
            .await
            .expect("unmount did not complete after the abort");
    }
}

/// Filesystem calls against the mount block the calling thread until the FUSE request round-trips; keep them off the runtime workers.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

/// Whether `pid` is blocked inside a FUSE request right now, by the wait channel the kernel reports for it.
fn blocked_in_fuse(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/wchan"))
        .is_ok_and(|wchan| wchan.trim() == "request_wait_answer")
}

/// Read a path from a child process, wait until it is blocked in its request, send it SIGINT, and return how it ended, or `None` if it was still running after `patience`. The child handles the signal and exits 42 only when its read fails with `EINTR`, so the exit code says whether this client answered the interrupt. A handled signal is what a real Ctrl-C to a program with a handler is, and it has no shortcut: the kernel fails a request that is still queued for the daemon by itself when a fatal signal arrives, and that would pass for an interrupt here. The child says when its handler is in place, since a signal before that would just kill it.
async fn read_and_interrupt(path: PathBuf, patience: Duration) -> Option<std::process::ExitStatus> {
    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg("import signal, sys; signal.signal(signal.SIGINT, lambda *_: sys.exit(42)); print('ready', flush=True); open(sys.argv[1], 'rb').read()")
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let ready = blocking(move || {
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(stdout), &mut line).unwrap();
        line
    })
    .await;
    assert_eq!(ready, "ready\n");
    let pid = child.id();
    wait_for(
        Duration::from_secs(3),
        "the reader to block in its request",
        || blocked_in_fuse(pid).then_some(()),
    )
    .await;
    let proc_of =
        |what: &str| fs::read_to_string(format!("/proc/{pid}/{what}")).unwrap_or_default();
    eprintln!(
        "reader {pid} at the signal: wchan {} syscall {}",
        proc_of("wchan").trim(),
        proc_of("syscall").trim()
    );
    // SAFETY: plain kill(2) on a pid this test owns.
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGINT) }, 0);
    let deadline = Instant::now() + patience;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() > deadline {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    if status.is_none() {
        child.kill().unwrap();
    }
    status
}

/// A libc directory stream, closed when dropped so a failed assertion cannot leave a handle open on a mount the test still has to unmount.
struct DirStream(*mut libc::DIR);

impl DirStream {
    fn open(dir: &Path) -> DirStream {
        let cpath = CString::new(dir.as_os_str().as_bytes()).unwrap();
        // SAFETY: `cpath` is a valid C string; the handle is closed exactly once, by `Drop`.
        let handle = unsafe { libc::opendir(cpath.as_ptr()) };
        assert!(!handle.is_null(), "opendir {} failed", dir.display());
        DirStream(handle)
    }

    /// Every name `readdir(3)` still yields, dots included.
    fn read_names(&self) -> Vec<Vec<u8>> {
        let mut names = Vec::new();
        loop {
            // SAFETY: `self.0` is an open stream until `Drop`, and `d_name` is NUL-terminated.
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                break;
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            names.push(name.to_bytes().to_vec());
        }
        names
    }

    /// The names `readdir(3)` yields until at least `at_least` have come, and whatever else the same `getdents` batch held.
    fn read_names_until(&self, at_least: usize) -> Vec<Vec<u8>> {
        let mut names = Vec::new();
        while names.len() < at_least {
            // SAFETY: as in `read_names`.
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                break;
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            names.push(name.to_bytes().to_vec());
        }
        names
    }

    /// Every entry `readdir(3)` still yields, with its `d_ino`: the dots included, when the directory lists them.
    fn read_entries(&self) -> Vec<(Vec<u8>, u64)> {
        let mut entries = Vec::new();
        loop {
            // SAFETY: as in `read_names`.
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                break;
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            entries.push((name.to_bytes().to_vec(), unsafe { (*entry).d_ino }));
        }
        entries
    }

    /// The `d_ino` of the entry called `wanted`, which `std::fs::read_dir` cannot show for the dots.
    fn ino_of(&self, wanted: &str) -> u64 {
        loop {
            // SAFETY: as in `read_names`.
            let entry = unsafe { libc::readdir(self.0) };
            assert!(!entry.is_null(), "no entry called {wanted}");
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() == wanted.as_bytes() {
                return unsafe { (*entry).d_ino };
            }
        }
    }

    fn rewind(&self) {
        // SAFETY: `self.0` is an open stream until `Drop`.
        unsafe { libc::rewinddir(self.0) }
    }
}

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: opened by `open`, closed only here.
        unsafe { libc::closedir(self.0) };
    }
}

fn list_with_dots(dir: &Path) -> Vec<Vec<u8>> {
    DirStream::open(dir).read_names()
}

fn process_umask() -> u32 {
    // SAFETY: umask is process-global; read it and restore it immediately.
    unsafe {
        let current = libc::umask(0);
        libc::umask(current);
        current as u32
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn posix_basics_through_the_mount() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let mnt = m.mnt();
    let export = m.export.path().to_path_buf();
    blocking(move || {
        fs::write(mnt.join("a.txt"), b"hello").unwrap();
        assert_eq!(fs::read(mnt.join("a.txt")).unwrap(), b"hello");
        assert_eq!(
            fs::read(export.join("a.txt")).unwrap(),
            b"hello",
            "the write reached the server's disk"
        );
        let mut appender = fs::OpenOptions::new()
            .append(true)
            .open(mnt.join("a.txt"))
            .unwrap();
        appender.write_all(b" world").unwrap();
        drop(appender);
        let mut f = fs::File::open(mnt.join("a.txt")).unwrap();
        f.seek(SeekFrom::Start(6)).unwrap();
        let mut tail = String::new();
        f.read_to_string(&mut tail).unwrap();
        assert_eq!(tail, "world");

        // Rename over an existing file.
        fs::write(mnt.join("b.txt"), b"old b").unwrap();
        fs::rename(mnt.join("a.txt"), mnt.join("b.txt")).unwrap();
        assert_eq!(fs::read(mnt.join("b.txt")).unwrap(), b"hello world");
        assert!(fs::metadata(mnt.join("a.txt")).is_err());

        // Unlink while open: the handle keeps working, the name is gone, and fstat and fchmod, which reach the client without a handle, are answered from one it still holds.
        let mut open = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(mnt.join("gone"))
            .unwrap();
        open.write_all(b"still here").unwrap();
        fs::remove_file(mnt.join("gone")).unwrap();
        assert_eq!(
            fs::metadata(mnt.join("gone")).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        let md = open.metadata().unwrap();
        assert_eq!((md.nlink(), md.len()), (0, 10));
        open.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        assert_eq!(open.metadata().unwrap().mode() & 0o777, 0o600);
        open.seek(SeekFrom::Start(0)).unwrap();
        let mut back = String::new();
        open.read_to_string(&mut back).unwrap();
        assert_eq!(back, "still here");
        open.write_all(b"!").unwrap();
        drop(open);

        // Unlink, then create the same name: a fresh file, not the old node.
        fs::write(mnt.join("x"), b"first").unwrap();
        let first_ino = fs::metadata(mnt.join("x")).unwrap().ino();
        fs::remove_file(mnt.join("x")).unwrap();
        fs::write(mnt.join("x"), b"second").unwrap();
        assert_eq!(fs::read(mnt.join("x")).unwrap(), b"second");
        assert_eq!(
            fs::metadata(mnt.join("x")).unwrap().ino(),
            fs::metadata(export.join("x")).unwrap().ino()
        );
        let _ = first_ino;

        // Symlinks and hardlinks.
        std::os::unix::fs::symlink("b.txt", mnt.join("l")).unwrap();
        assert_eq!(
            fs::read_link(mnt.join("l")).unwrap(),
            PathBuf::from("b.txt")
        );
        assert_eq!(fs::read(mnt.join("l")).unwrap(), b"hello world");
        fs::hard_link(mnt.join("b.txt"), mnt.join("h")).unwrap();
        let b = fs::metadata(mnt.join("b.txt")).unwrap();
        let h = fs::metadata(mnt.join("h")).unwrap();
        assert_eq!(b.ino(), h.ino(), "hardlinks share st_ino");
        assert_eq!(h.nlink(), 2);
        assert_eq!(
            b.ino(),
            fs::metadata(export.join("b.txt")).unwrap().ino(),
            "st_ino is the server's inode number"
        );

        // Times and modes.
        let stamp = UNIX_EPOCH + Duration::new(1_600_000_000, 123_000_000);
        fs::File::options()
            .write(true)
            .open(mnt.join("h"))
            .unwrap()
            .set_modified(stamp)
            .unwrap();
        assert_eq!(
            fs::metadata(mnt.join("h")).unwrap().modified().unwrap(),
            stamp
        );
        fs::DirBuilder::new()
            .mode(0o777)
            .create(mnt.join("d"))
            .unwrap();
        assert_eq!(
            fs::metadata(mnt.join("d")).unwrap().permissions().mode() & 0o777,
            0o777 & !process_umask()
        );
        fs::set_permissions(mnt.join("d"), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            fs::metadata(export.join("d")).unwrap().permissions().mode() & 0o777,
            0o700
        );

        // Large I/O.
        let big: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        fs::write(mnt.join("big"), &big).unwrap();
        assert_eq!(fs::read(mnt.join("big")).unwrap(), big);

        // Awkward names and directory listing with the dot entries.
        let weird = OsStr::from_bytes(b"\xff\xfe-not-utf8");
        fs::write(mnt.join("d").join(weird), b"w").unwrap();
        let long = "n".repeat(255);
        fs::write(mnt.join("d").join(&long), b"l").unwrap();
        let listed = list_with_dots(&mnt.join("d"));
        assert!(listed.contains(&b".".to_vec()) && listed.contains(&b"..".to_vec()));
        assert!(listed.contains(&b"\xff\xfe-not-utf8".to_vec()));
        assert!(listed.contains(&long.as_bytes().to_vec()));
        let mut names: Vec<_> = fs::read_dir(mnt.join("d"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names.len(), 2);
        assert!(fs::read_dir(&mnt).unwrap().count() >= 6);
        let e = fs::read_dir(&mnt)
            .unwrap()
            .find(|e| e.as_ref().unwrap().file_name() == "d")
            .unwrap()
            .unwrap();
        assert!(e.file_type().unwrap().is_dir());
        assert!(
            fs::remove_dir(mnt.join("d")).is_err(),
            "rmdir of a non-empty directory fails"
        );
    })
    .await;
    m.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_directory_pages_through_the_kernel_correctly() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let export = m.export.path().to_path_buf();
    for i in 0..700 {
        fs::write(export.join(format!("entry-{i:04}")), b"").unwrap();
    }
    let mnt = m.mnt();
    blocking(move || {
        // Plain readdir: the kernel asks page by page; the client serves those from one server fetch.
        let names: std::collections::BTreeSet<_> = fs::read_dir(&mnt)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 700, "every entry exactly once");
        let with_dots = list_with_dots(&mnt);
        assert_eq!(with_dots.len(), 702);
        assert_eq!(
            with_dots
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            702,
            "no duplicates across kernel pages"
        );
        // Stat every entry during the listing, the `ls -l` pattern that switches the kernel to readdirplus.
        let mut count = 0;
        for entry in fs::read_dir(&mnt).unwrap() {
            let entry = entry.unwrap();
            assert!(entry.metadata().unwrap().is_file());
            count += 1;
        }
        assert_eq!(count, 700);
        fs::remove_file(mnt.join("entry-0350")).unwrap();
        assert_eq!(
            fs::read_dir(&mnt).unwrap().count(),
            699,
            "a listing after a change reflects it"
        );
    })
    .await;
    m.finish().await;
}

/// A readdirplus page hands the kernel attributes to cache, so it is not served from a buffer fetched longer ago than the attribute TTL; a plain page, whose numbers do not depend on attributes, still is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_old_buffer_serves_plain_pages_but_not_readdirplus() {
    // No events: the files made below would reach the client during the wait, and each clears the end the fetch reported.
    let Some(m) = Mounted::start_unwatched(Duration::from_secs(10), Duration::from_secs(1)).await
    else {
        return;
    };
    let export = m.export.path().to_path_buf();
    fs::create_dir(export.join("d")).unwrap();
    // Several kernel pages, all inside the first fetch.
    for i in 0..600 {
        fs::write(export.join(format!("d/entry-{i:04}")), b"").unwrap();
    }
    let mnt = m.mnt();
    let perf = m.mount.as_ref().unwrap().perf().clone();
    for stat in [false, true] {
        perf.report();
        let dir = mnt.join("d");
        blocking(move || {
            let stream = DirStream::open(&dir);
            // The first getdents: the first kernel page, and the fetch behind it.
            assert!(!stream.read_names_until(1).is_empty());
            if stat {
                // A lookup under the directory makes the kernel ask for its next page as readdirplus.
                fs::metadata(dir.join("entry-0000")).unwrap();
            }
            std::thread::sleep(Duration::from_millis(1300));
            stream.read_names();
        })
        .await;
        let fetches = perf.report().call.get("readdirplus").map_or(0, |r| r.row.n);
        assert_eq!(fetches, if stat { 2 } else { 1 }, "stat={stat}");
    }
    m.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_listing_longer_than_one_kernel_page_is_fetched_once() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let export = m.export.path().to_path_buf();
    fs::create_dir(export.join("d")).unwrap();
    // Past one kernel readdir page (the caller's getdents buffer, 32 KiB for glibc) and well inside one client fetch, on a host where every file carries ACL names too.
    for i in 0..400 {
        fs::write(export.join(format!("d/entry-{i:04}")), b"").unwrap();
    }
    let mnt = m.mnt();
    let perf = m.mount.as_ref().unwrap().perf().clone();
    // The kernel asks for the first page as readdirplus and later pages as plain readdir; every page must come out of the one fetch.
    for stat in [false, true] {
        perf.report();
        let mnt = mnt.clone();
        let count = blocking(move || {
            let mut count = 0;
            for entry in fs::read_dir(mnt.join("d")).unwrap() {
                let entry = entry.unwrap();
                if stat {
                    assert!(entry.metadata().unwrap().is_file());
                }
                count += 1;
            }
            count
        })
        .await;
        assert_eq!(count, 400);
        wait_for(Duration::from_secs(3), "kernel requests to drain", || {
            (perf.inflight() == 0).then_some(())
        })
        .await;
        let snap = perf.report();
        let fetched: u64 = ["readdir", "readdirplus"]
            .iter()
            .filter_map(|op| snap.call.get(op))
            .map(|r| r.row.items)
            .sum();
        assert_eq!(
            fetched, 402,
            "stat={stat}: every entry, `.` and `..` included, crosses the network once: {:?}",
            snap.call
        );
    }
    m.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_complete_listing_does_not_read_past_its_end() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let export = m.export.path().to_path_buf();
    fs::create_dir(export.join("d")).unwrap();
    for i in 0..5 {
        fs::write(export.join(format!("d/f{i}")), b"").unwrap();
    }
    let mnt = m.mnt();
    let perf = m.mount.as_ref().unwrap().perf().clone();
    // The kernel reads until a page comes back empty; that empty page is answered from the end the fetch reported, whether the kernel asks for it plain or, after stats, as readdirplus.
    for stat in [false, true] {
        perf.report();
        let mnt = mnt.clone();
        let count = blocking(move || {
            let mut count = 0;
            for entry in fs::read_dir(mnt.join("d")).unwrap() {
                let entry = entry.unwrap();
                if stat {
                    assert!(entry.metadata().unwrap().is_file());
                }
                count += 1;
            }
            count
        })
        .await;
        assert_eq!(count, 5);
        // The request that answered the process is recorded a moment after the process moves on.
        wait_for(Duration::from_secs(3), "kernel requests to drain", || {
            (perf.inflight() == 0).then_some(())
        })
        .await;
        let snap = perf.report();
        let calls: u64 = ["readdir", "readdirplus"]
            .iter()
            .filter_map(|op| snap.call.get(op))
            .map(|r| r.row.n)
            .sum();
        assert_eq!(
            calls, 1,
            "stat={stat}: one fetch, no empty tail: {:?}",
            snap.call
        );
        let asked: u64 = ["readdir", "readdirplus"]
            .iter()
            .filter_map(|op| snap.fuse.get(op))
            .map(|r| r.n)
            .sum();
        assert!(
            asked >= 2,
            "the kernel did ask past the end: {:?}",
            snap.fuse
        );
    }
    m.finish().await;
}

/// The recorded end is per handle and only short-circuits a read at that exact cookie; `rewinddir` starts at offset 0, which always goes to the server, so a directory that grew is re-read in full.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rewinding_a_directory_handle_sees_entries_added_after_its_end() {
    let Some(m) = Mounted::start_unwatched(Duration::from_secs(10), Duration::from_secs(60)).await
    else {
        return;
    };
    let export = m.export.path().to_path_buf();
    fs::create_dir(export.join("d")).unwrap();
    fs::write(export.join("d/a"), b"").unwrap();
    let mnt = m.mnt();
    let names = blocking(move || {
        let handle = DirStream::open(&mnt.join("d"));
        let first = handle.read_names();
        assert_eq!(
            handle.read_names(),
            Vec::<Vec<u8>>::new(),
            "a handle at its end stays there"
        );
        fs::write(export.join("d/b"), b"").unwrap();
        handle.rewind();
        let second = handle.read_names();
        (first, second)
    })
    .await;
    assert_eq!(names.0.len(), 3, "{:?}", names.0);
    assert_eq!(names.1.len(), 4, "{:?}", names.1);
    assert!(names.1.contains(&b"b".to_vec()));
    m.finish().await;
}

/// A handle left at its end after a full listing reads there again, as a directory poller does. Whether a name added afterwards shows up there is the export filesystem's decision (a hashed or newest-first order puts it before the cursor), so the mount is held to what a handle on the export itself yields; what this client owes is to ask the server again once a name was added, by this client or in a server event, instead of answering from the end it recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_handle_parked_at_the_end_reads_like_one_on_the_export() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(60)).await else {
        return;
    };
    let export = m.export.path().to_path_buf();
    fs::create_dir(export.join("d")).unwrap();
    fs::write(export.join("d/a"), b"").unwrap();
    let mnt = m.mnt();
    let perf = m.mount.as_ref().unwrap().perf().clone();
    let probes = perf.clone();
    blocking(move || {
        let through = DirStream::open(&mnt.join("d"));
        let direct = DirStream::open(&export.join("d"));
        assert_eq!(through.read_names().len(), 3);
        assert_eq!(direct.read_names().len(), 3);
        probes.report();
        fs::write(mnt.join("d/through-the-mount"), b"").unwrap();
        assert_eq!(
            through.read_names(),
            direct.read_names(),
            "after this client's own addition"
        );
        assert!(
            probes.report().call.contains_key("readdirplus"),
            "the parked handle asked the server again"
        );
        fs::write(export.join("d/on-the-export"), b"").unwrap();
        // The server's event for the new name arrives within its debounce window; after it the parked handle must go to the server again.
        let started = Instant::now();
        while !probes.report().call.contains_key("readdirplus") {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the server's event did not reach the parked handle"
            );
            std::thread::sleep(Duration::from_millis(50));
            through.read_names();
        }
        through.rewind();
        direct.rewind();
        assert_eq!(through.read_names(), direct.read_names(), "after a rewind");
    })
    .await;
    let _ = perf;
    m.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failing_test_body_still_leaves_no_mount_behind() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let mnt = m.mnt();
    let mountpoint = m.mountpoint.path().to_path_buf();
    let outcome = tokio::task::spawn_blocking(move || {
        fs::write(mnt.join("x"), b"1").unwrap();
        panic!("simulated assertion failure inside a mount test");
    })
    .await;
    assert!(outcome.is_err());
    // Dropping without `finish()` is the panic path: the mount must still come down.
    drop(m);
    let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(
        !mounts.contains(mountpoint.to_str().unwrap()),
        "mount point still present after drop"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_side_changes_become_visible_despite_long_ttls() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(60)).await else {
        return;
    };
    let mnt = m.mnt();
    let export = m.export.path().to_path_buf();
    fs::write(export.join("f"), b"v1").unwrap();
    let (mnt2, export2) = (mnt.clone(), export.clone());
    let ino_before = blocking(move || {
        assert_eq!(fs::read_dir(&mnt2).unwrap().count(), 1);
        assert_eq!(fs::read(mnt2.join("f")).unwrap(), b"v1");
        assert!(fs::metadata(mnt2.join("new")).is_err());
        let _ = export2;
        fs::metadata(mnt2.join("f")).unwrap().ino()
    })
    .await;

    fs::write(export.join("new"), b"n").unwrap();
    fs::write(export.join("f"), b"v2 is longer").unwrap();
    let started = Instant::now();
    let (mnt2, ino_after) = blocking(move || loop {
        let new_visible = fs::metadata(mnt.join("new")).is_ok();
        let content = fs::read(mnt.join("f")).unwrap();
        if new_visible && content == b"v2 is longer" {
            return (mnt.clone(), fs::metadata(mnt.join("f")).unwrap().ino());
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "server-side change not visible in time (new={new_visible}, content={content:?})"
        );
        std::thread::sleep(Duration::from_millis(100));
    })
    .await;
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "invalidation should beat the 60s TTL by a wide margin: {:?}",
        started.elapsed()
    );
    assert_eq!(
        ino_before, ino_after,
        "st_ino is stable across invalidation and re-lookup"
    );
    let _ = mnt2;
    m.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_vanishing_times_out_and_unmounts_cleanly() {
    let Some(mut m) = Mounted::start(Duration::from_millis(500), Duration::from_secs(1)).await
    else {
        return;
    };
    let mnt = m.mnt();
    let mnt2 = mnt.clone();
    blocking(move || fs::write(mnt2.join("f"), b"data").unwrap()).await;
    m.server.take().unwrap().stop().await;

    let started = Instant::now();
    let err = blocking(move || fs::read(mnt.join("f")).unwrap_err()).await;
    let elapsed = started.elapsed();
    let code = err.raw_os_error().unwrap();
    assert!(
        [libc::ETIMEDOUT, libc::EIO, libc::ENOTCONN].contains(&code),
        "unexpected errno {code}: {err}"
    );
    assert!(elapsed < Duration::from_secs(3), "blocked for {elapsed:?}");
    m.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn perf_tables_see_the_kernel_requests() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let size = 1 << 20;
    fs::write(m.export.path().join("f"), vec![1u8; size]).unwrap();
    let mnt = m.mnt();
    let data = blocking(move || fs::read(mnt.join("f"))).await.unwrap();
    assert_eq!(data.len(), size);

    // The release that follows the close is answered a moment after `fs::read` returns.
    let perf = m.mount.as_ref().unwrap().perf().clone();
    wait_for(Duration::from_secs(3), "kernel requests to drain", || {
        (perf.inflight() == 0).then_some(())
    })
    .await;
    let snap = perf.report();
    assert!(snap.peak >= 1);
    // The kernel decides how many reads it issues and how big, so only what they add up to is fixed.
    let read = &snap.fuse["read"];
    assert!(read.n >= 1);
    assert!(read.bytes >= size as u64, "fuse read bytes {}", read.bytes);
    assert!(read.errnos.is_empty());
    let call = &snap.call["read"];
    assert!(call.row.n >= 1 && call.row.n <= read.n);
    assert!(
        call.row.bytes >= size as u64,
        "call read bytes {}",
        call.row.bytes
    );
    assert!(snap.fuse["lookup"].n >= 1 && snap.fuse["open"].n >= 1);
    m.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ioctl_is_refused_and_counted() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    fs::create_dir(m.export.path().join("d")).unwrap();
    let dir = m.mnt().join("d");
    let code = blocking(move || {
        let handle = fs::File::open(&dir).unwrap();
        // FS_IOC_GETFSLABEL, which libc does not name.
        const GETFSLABEL: libc::c_ulong = 0x8100_9431;
        let mut label = [0u8; 256];
        let rc = unsafe {
            use std::os::fd::AsRawFd;
            libc::ioctl(handle.as_raw_fd(), GETFSLABEL as _, label.as_mut_ptr())
        };
        assert_eq!(rc, -1);
        std::io::Error::last_os_error().raw_os_error().unwrap()
    })
    .await;
    assert_eq!(code, libc::ENOTTY);

    let perf = m.mount.as_ref().unwrap().perf().clone();
    wait_for(Duration::from_secs(3), "kernel requests to drain", || {
        (perf.inflight() == 0).then_some(())
    })
    .await;
    let snap = perf.report();
    let ioctl = &snap.fuse["ioctl"];
    assert_eq!(ioctl.n, 1);
    assert_eq!(ioctl.errnos.get(&libc::ENOTTY), Some(&1));
    m.finish().await;
}

fn xattr_get(path: &Path, name: &str) -> Result<Vec<u8>, i32> {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let name = CString::new(name).unwrap();
    let mut buf = vec![0u8; 256];
    let got = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if got < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    buf.truncate(got as usize);
    Ok(buf)
}

fn xattr_list(path: &Path) -> Vec<u8> {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut buf = vec![0u8; 1024];
    let got = unsafe {
        libc::listxattr(
            path.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    assert!(got >= 0, "{}", std::io::Error::last_os_error());
    buf.truncate(got as usize);
    buf
}

fn xattr_set(path: &Path, name: &str, value: &[u8]) -> Result<(), i32> {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let name = CString::new(name).unwrap();
    let rc = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap())
    }
}

/// The perf tables are the oracle: the `fuse` table counts what the kernel asked, the `call` table what went to the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn absent_xattrs_are_answered_from_the_listing() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(60)).await else {
        return;
    };
    let export = m.export.path().to_path_buf();
    fs::create_dir(export.join("d")).unwrap();
    for i in 0..40 {
        fs::write(export.join(format!("d/f{i}")), b"").unwrap();
    }
    let mnt = m.mnt();
    let export_dir = export.join("d");
    let perf = m.mount.as_ref().unwrap().perf().clone();
    let probes = perf.clone();
    let entries = blocking(move || {
        // List and stat every entry, as a file manager does; the stats make the kernel use readdirplus for every page.
        let entries: Vec<PathBuf> = fs::read_dir(mnt.join("d"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        for entry in &entries {
            fs::metadata(entry).unwrap();
        }
        probes.report();
        for entry in &entries {
            // The export's own names are the expectation: a host with SELinux or a default ACL gives every file some.
            let expected = xattr_list(&export_dir.join(entry.file_name().unwrap()));
            assert_eq!(xattr_list(entry), expected);
            for acl in ["system.posix_acl_access", "system.posix_acl_default"] {
                if !expected.split(|b| *b == 0).any(|n| n == acl.as_bytes()) {
                    assert_eq!(xattr_get(entry, acl), Err(libc::ENODATA));
                }
            }
        }
        entries
    })
    .await;
    let snap = perf.report();
    assert!(
        snap.fuse["getxattr"].n >= 80,
        "{:?}",
        snap.fuse.get("getxattr")
    );
    assert!(snap.fuse["listxattr"].n >= 40);
    assert!(
        !snap.call.contains_key("getxattr"),
        "{:?}",
        snap.call.get("getxattr")
    );
    assert!(
        !snap.call.contains_key("listxattr"),
        "{:?}",
        snap.call.get("listxattr")
    );

    // A name set on the export directly reaches the mount through the data event, long before the 60 s TTL, and a present name is fetched, not answered locally.
    if let Err(errno) = xattr_set(&export.join("d/f0"), "user.k", b"v") {
        assert_eq!(errno, libc::EOPNOTSUPP, "unexpected errno {errno}");
        eprintln!("skipping the present-name half: the export filesystem has no user xattrs");
        m.finish().await;
        return;
    }
    let f0 = entries.iter().find(|p| p.ends_with("f0")).unwrap().clone();
    let (f0, list) = blocking(move || {
        let started = Instant::now();
        loop {
            let list = xattr_list(&f0);
            if !list.is_empty() || started.elapsed() > Duration::from_secs(5) {
                return (f0, list);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    })
    .await;
    assert_eq!(list, b"user.k\0", "the event dropped the cached names");
    perf.report();
    let f0_again = f0.clone();
    blocking(move || {
        // A stat refills the names from a fresh attribute reply; the event only dropped them.
        fs::metadata(&f0_again).unwrap();
        assert_eq!(xattr_get(&f0_again, "user.k"), Ok(b"v".to_vec()));
        assert_eq!(xattr_get(&f0_again, "user.other"), Err(libc::ENODATA));
    })
    .await;
    let snap = perf.report();
    assert!(
        snap.call["getxattr"].row.n >= 1,
        "a present name is fetched"
    );
    assert!(
        snap.fuse["getxattr"].n > snap.call["getxattr"].row.n,
        "an absent one is not"
    );

    // Setting a name through the mount makes the next fetch see it, whatever the cache said a moment ago.
    blocking(move || {
        assert_eq!(xattr_get(&f0, "user.mine"), Err(libc::ENODATA));
        xattr_set(&f0, "user.mine", b"m").unwrap();
        assert_eq!(xattr_get(&f0, "user.mine"), Ok(b"m".to_vec()));
    })
    .await;
    m.finish().await;
}

/// The kernel caches writes: many small `write(2)` calls reach the server as few large requests, and the file is complete once closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writes_are_merged_by_the_kernel_before_they_reach_the_server() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let mnt = m.mnt();
    let export = m.export.path().to_path_buf();
    let perf = m.mount.as_ref().unwrap().perf().clone();
    let size = 8 << 20;
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let written = data.clone();
    perf.report();
    blocking(move || {
        let mut file = fs::File::create(mnt.join("big")).unwrap();
        for chunk in written.chunks(4096) {
            file.write_all(chunk).unwrap();
        }
        file.sync_all().unwrap();
    })
    .await;
    wait_for(Duration::from_secs(3), "kernel requests to drain", || {
        (perf.inflight() == 0).then_some(())
    })
    .await;
    let snap = perf.report();
    let write = &snap.fuse["write"];
    // Page-aligned writes to a fresh file are flushed once each, so the bytes are exact; the merge shows in the request size.
    assert_eq!(write.bytes, size as u64);
    assert!(
        write.bytes / write.n > 4096,
        "mean request {} bytes over {} requests",
        write.bytes / write.n,
        write.n
    );
    assert_eq!(fs::read(export.join("big")).unwrap(), data);
    m.finish().await;
}

/// The kernel copies through the mount by itself when the daemon refuses, and the result looks the same, so the request count is what shows the server did the work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn copy_file_range_moves_no_data_through_the_mount() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let mnt = m.mnt();
    let export = m.export.path().to_path_buf();
    let perf = m.mount.as_ref().unwrap().perf().clone();
    let size = 8 << 20;
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    fs::write(export.join("src"), &data).unwrap();
    perf.report();
    blocking(move || {
        use std::os::fd::AsRawFd;
        let src = fs::File::open(mnt.join("src")).unwrap();
        let dst = fs::File::create(mnt.join("dst")).unwrap();
        let mut left = size;
        while left > 0 {
            let copied = unsafe {
                libc::copy_file_range(
                    src.as_raw_fd(),
                    std::ptr::null_mut(),
                    dst.as_raw_fd(),
                    std::ptr::null_mut(),
                    left,
                    0,
                )
            };
            assert!(
                copied > 0,
                "copy_file_range: {copied}, {}",
                std::io::Error::last_os_error()
            );
            left -= copied as usize;
        }
    })
    .await;
    wait_for(Duration::from_secs(3), "kernel requests to drain", || {
        (perf.inflight() == 0).then_some(())
    })
    .await;
    let snap = perf.report();
    let copy = snap.fuse.get("copy_file_range").expect(
        "no copy_file_range reached the daemon: the kernel copied through the mount itself",
    );
    assert_eq!(copy.bytes, size as u64);
    assert!(copy.errnos.is_empty(), "{:?}", copy.errnos);
    let moved: u64 = snap.call.values().map(|call| call.row.bytes).sum();
    assert_eq!(moved, 0, "server calls moved payload to copy {size} bytes");
    assert_eq!(fs::read(export.join("dst")).unwrap(), data);
    m.finish().await;
}

/// Refused, `posix_fallocate` succeeds all the same, by writing into every block, so the request count is what shows the server did the work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fallocate_reaches_the_server_and_moves_no_data() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let mnt = m.mnt();
    let export = m.export.path().to_path_buf();
    let perf = m.mount.as_ref().unwrap().perf().clone();
    let size = 8 << 20;
    perf.report();
    blocking(move || {
        use std::os::fd::AsRawFd;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(mnt.join("f"))
            .unwrap();
        file.write_all(b"head").unwrap();
        let rc = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, size) };
        assert_eq!(
            rc,
            0,
            "posix_fallocate: {}",
            std::io::Error::from_raw_os_error(rc)
        );
        assert_eq!(file.metadata().unwrap().len(), size as u64);
        let punch = libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE;
        let rc = unsafe { libc::fallocate(file.as_raw_fd(), punch, 0, 2) };
        assert_eq!(rc, 0, "punch: {}", std::io::Error::last_os_error());
        let mut head = [0u8; 4];
        std::os::unix::fs::FileExt::read_exact_at(&file, &mut head, 0).unwrap();
        assert_eq!(
            &head, b"\0\0ad",
            "the punched bytes read as zeros through the cache"
        );
    })
    .await;
    wait_for(Duration::from_secs(3), "kernel requests to drain", || {
        (perf.inflight() == 0).then_some(())
    })
    .await;
    let snap = perf.report();
    let fallocate = snap
        .fuse
        .get("fallocate")
        .expect("no fallocate reached the daemon: glibc wrote the file out instead");
    assert_eq!(fallocate.n, 2);
    assert!(fallocate.errnos.is_empty(), "{:?}", fallocate.errnos);
    let moved: u64 = snap.call.values().map(|call| call.row.bytes).sum();
    // The kernel writes the dirty first page back before it asks for the punch; nothing else carries data.
    assert!(
        moved <= 64 << 10,
        "server calls moved {moved} bytes of payload to allocate {size}"
    );
    let on_export = fs::read(export.join("f")).unwrap();
    assert_eq!(on_export.len(), size as usize);
    assert_eq!(&on_export[..4], b"\0\0ad");
    m.finish().await;
}

/// `lseek(2)` on `file`, as the offset found or the errno.
fn seek(file: &fs::File, offset: i64, whence: i32) -> Result<i64, i32> {
    use std::os::fd::AsRawFd;
    let found = unsafe { libc::lseek(file.as_raw_fd(), offset, whence) };
    if found < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        Ok(found)
    }
}

/// Refused, the kernel answers by itself that the whole file is data, so the request count is what shows the server was asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seeking_data_and_holes_asks_the_server_unless_this_client_is_writing() {
    use std::os::unix::fs::FileExt;
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let mnt = m.mnt();
    let perf = m.mount.as_ref().unwrap().perf().clone();
    let on_export = fs::File::create(m.export.path().join("sparse")).unwrap();
    on_export.write_all_at(b"data", 1 << 20).unwrap();
    on_export.set_len(2 << 20).unwrap();
    perf.report();
    blocking(move || {
        let reader = fs::File::open(mnt.join("sparse")).unwrap();
        for offset in [0, 1 << 20, (1 << 20) + 4096] {
            for whence in [libc::SEEK_DATA, libc::SEEK_HOLE] {
                assert_eq!(
                    seek(&reader, offset, whence),
                    seek(&on_export, offset, whence),
                    "whence {whence} from {offset}"
                );
            }
        }
        assert_eq!(seek(&reader, 2 << 20, libc::SEEK_DATA), Err(libc::ENXIO));

        // With the file open for writing here, the kernel may hold data the server has not seen.
        let writer = fs::OpenOptions::new()
            .write(true)
            .open(mnt.join("sparse"))
            .unwrap();
        writer.write_all_at(b"cached", 0).unwrap();
        assert_eq!(seek(&reader, 0, libc::SEEK_DATA), Err(libc::EINVAL));
        assert_eq!(seek(&reader, 0, libc::SEEK_HOLE), Err(libc::EINVAL));
        drop(writer);
    })
    .await;
    wait_for(Duration::from_secs(3), "kernel requests to drain", || {
        (perf.inflight() == 0).then_some(())
    })
    .await;
    let snap = perf.report();
    let lseek = snap
        .fuse
        .get("lseek")
        .expect("no lseek reached the daemon: the kernel answered that the file is all data");
    assert_eq!(lseek.errnos.get(&libc::EINVAL), Some(&2));
    assert_eq!(
        snap.call["lseek"].row.n + 2,
        lseek.n,
        "a refused seek asks the server nothing"
    );

    // Once the writer is released the kernel holds nothing unwritten, and the server is asked again.
    let mnt = m.mnt();
    wait_for(Duration::from_secs(3), "the writer's release", || {
        let reader = fs::File::open(mnt.join("sparse")).unwrap();
        (seek(&reader, 0, libc::SEEK_DATA) == Ok(0)).then_some(())
    })
    .await;
    m.finish().await;
}

/// A file with two names, opened through one of them; that name is then removed through the mount and the other looked up. It is one file throughout, so the descriptor must go on working: the client used to take the lookup for a new file with a recycled inode number, and the kernel then declared the open inode bad.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_descriptor_survives_its_name_when_the_file_has_another() {
    use std::os::unix::fs::MetadataExt;
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let export = m.export.path().to_path_buf();
    fs::create_dir(export.join("d")).unwrap();
    fs::create_dir(export.join("e")).unwrap();
    fs::write(export.join("d/a"), b"contents").unwrap();
    fs::hard_link(export.join("d/a"), export.join("e/b")).unwrap();
    let mnt = m.mnt();
    blocking(move || {
        let mut file = fs::File::open(mnt.join("d/a")).unwrap();
        fs::remove_file(mnt.join("d/a")).unwrap();
        let other = fs::metadata(mnt.join("e/b")).unwrap();
        let mut contents = String::new();
        std::io::Read::read_to_string(&mut file, &mut contents).unwrap();
        assert_eq!(contents, "contents");
        assert_eq!(
            file.metadata().unwrap().ino(),
            other.ino(),
            "one file by either route"
        );
        assert_eq!(
            other.ino(),
            fs::metadata(export.join("e/b")).unwrap().ino(),
            "and by its real number"
        );
    })
    .await;
    m.finish().await;
}

/// The client addresses a node by the last name it was reached through. When someone else replaces that name with another file, the node is still the file it was, reachable by its other name, and must not take on the other file's attributes. Two ways there: with the replaced name's directory still held, the client asks by the stale name, is told about another file, and has to notice; with nothing holding it, the kernel forgets the directory and the client has to pass over a name it can no longer spell.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_whose_newest_name_was_replaced_is_reached_by_its_other_name() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for directory_held in [true, false] {
        let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
            return;
        };
        let export = m.export.path().to_path_buf();
        fs::create_dir(export.join("d")).unwrap();
        fs::create_dir(export.join("e")).unwrap();
        fs::write(export.join("d/a"), b"the file").unwrap();
        fs::hard_link(export.join("d/a"), export.join("e/b")).unwrap();
        let mnt = m.mnt();
        blocking(move || {
            use std::os::fd::FromRawFd;
            use std::os::unix::ffi::OsStrExt;
            // An `O_PATH` descriptor holds the node without a handle, so its `fstat` asks about the node itself and the client has to find a path to it.
            let path = std::ffi::CString::new(mnt.join("d/a").as_os_str().as_bytes()).unwrap();
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH) };
            assert!(fd >= 0, "open: {}", std::io::Error::last_os_error());
            let held = unsafe { fs::File::from_raw_fd(fd) };
            let first = held.metadata().unwrap();
            let _directory = directory_held.then(|| fs::File::open(mnt.join("e")).unwrap());
            assert_eq!(fs::metadata(mnt.join("e/b")).unwrap().ino(), first.ino());
            // The other file differs in its mode: of what a reply says, the size and times of a regular file are what the kernel keeps to itself while it caches writes, and would show nothing.
            fs::write(export.join("e/other"), b"another file, and longer").unwrap();
            fs::set_permissions(export.join("e/other"), fs::Permissions::from_mode(0o600)).unwrap();
            fs::rename(export.join("e/other"), export.join("e/b")).unwrap();
            // Past the attribute TTL, so the kernel asks again.
            std::thread::sleep(Duration::from_millis(1200));
            let again = held.metadata().unwrap();
            assert_eq!(
                (again.ino(), again.mode()),
                (first.ino(), first.mode()),
                "directory held: {directory_held}"
            );
            assert_eq!(fs::read(mnt.join("d/a")).unwrap(), b"the file");
            let started = Instant::now();
            while fs::read(mnt.join("e/b")).unwrap() != b"another file, and longer" {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "the replaced name never showed its new file"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            assert_ne!(fs::metadata(mnt.join("e/b")).unwrap().ino(), first.ino());
        })
        .await;
        m.finish().await;
    }
}

/// Replaced on the export while open here, a file stays what it was for the descriptor, and its name leads to the new file, which is another node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_replaced_on_the_export_is_another_file_by_name_and_the_same_by_descriptor() {
    use std::os::unix::fs::MetadataExt;
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let export = m.export.path().to_path_buf();
    fs::write(export.join("f"), b"old").unwrap();
    let mnt = m.mnt();
    blocking(move || {
        let mut file = fs::File::open(mnt.join("f")).unwrap();
        let before = file.metadata().unwrap().ino();
        fs::remove_file(export.join("f")).unwrap();
        fs::write(export.join("f"), b"new contents").unwrap();
        let started = Instant::now();
        let by_name = loop {
            if let Ok(found) = fs::read(mnt.join("f")) {
                if found == b"new contents" {
                    break fs::metadata(mnt.join("f")).unwrap().ino();
                }
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the new file never showed"
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        assert_ne!(
            by_name, before,
            "two files, two numbers, while the kernel holds both"
        );
        let mut contents = String::new();
        std::io::Read::read_to_string(&mut file, &mut contents).unwrap();
        assert_eq!(contents, "old");
        assert_eq!(file.metadata().unwrap().ino(), before);
    })
    .await;
    m.finish().await;
}

/// A scripted export: the root (inode 2, the fake server's root), a directory `d` in it, and in `d` the files `f-0000`, `f-0001`… in another subvolume, as a snapshot's are: each goes by a substitute, never by its own inode number, which the scripted numbers make plain by starting at 100.
fn script_foreign_files(files: usize) -> impl Fn(&Request) -> Response + Send + Sync {
    use jackalopefs_proto::{Attr, DirEntry, DirEntryPlus, FileKind, Identity, TimeSpec};
    let attr = |ino: u64, kind: FileKind, foreign: bool, handle: Vec<u8>| Attr {
        ino,
        size: 0,
        blocks: 0,
        atime: TimeSpec { sec: 0, nsec: 0 },
        mtime: TimeSpec { sec: 0, nsec: 0 },
        ctime: TimeSpec { sec: 0, nsec: 0 },
        kind,
        perm: if kind == FileKind::Directory {
            0o755
        } else {
            0o644
        },
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        xattr_names: Some(Vec::new()),
        identity: Identity {
            handle_type: 1,
            handle,
        },
        foreign,
    };
    let root = attr(2, FileKind::Directory, false, vec![2, 0, 0, 0, 0, 0, 0, 0]);
    let dir = attr(3, FileKind::Directory, false, vec![3, 0, 0, 0, 0, 0, 0, 0]);
    // A snapshot's handle names its subvolume: here, 7.
    let file = move |i: usize| {
        attr(
            100 + i as u64,
            FileKind::Regular,
            true,
            [(100 + i as u64).to_le_bytes(), 7u64.to_le_bytes()].concat(),
        )
    };
    let named = move |name: &[u8]| -> Option<usize> {
        std::str::from_utf8(name)
            .ok()?
            .strip_prefix("f-")?
            .parse()
            .ok()
            .filter(|i| *i < files)
    };
    let describe = move |path: &jackalopefs_proto::Path| -> Option<Attr> {
        match path.names() {
            [] => Some(root.clone()),
            [d] if d.as_bytes() == b"d" => Some(dir.clone()),
            [d, f] if d.as_bytes() == b"d" => named(f.as_bytes()).map(file),
            _ => None,
        }
    };
    let enoent = Response::Err(libc::ENOENT);
    move |req: &Request| match req {
        Request::Getattr {
            path: Some(path), ..
        }
        | Request::Opendir { path, .. } => match (describe(path), req) {
            (Some(attr), Request::Opendir { .. }) => Response::Opened { attr },
            (Some(attr), _) => Response::Attr(attr),
            (None, _) => enoent.clone(),
        },
        Request::Lookup { parent, name } => parent
            .join(name.clone())
            .ok()
            .and_then(|path| describe(&path))
            .map_or(enoent.clone(), Response::Entry),
        // Pages of 500 entries; a cookie is the index of the entry after it.
        Request::Readdir { offset, .. } => {
            let first = *offset as usize;
            let last = (first + 500).min(files);
            let entries = (first..last)
                .map(|i| DirEntryPlus {
                    entry: DirEntry {
                        ino: 100 + i as u64,
                        next_offset: i as u64 + 1,
                        kind: FileKind::Regular,
                        name: format!("f-{i:04}").into_bytes(),
                    },
                    attr: Some(file(i)),
                })
                .collect();
            Response::ReaddirPlus {
                entries,
                end: last == files,
            }
        }
        Request::Releasedir { .. } | Request::Release { .. } | Request::Access { .. } => {
            Response::Ok
        }
        Request::Getxattr { .. } => Response::Err(libc::ENODATA),
        Request::Listxattr { .. } => Response::Xattr(Vec::new()),
        _ => Response::Err(libc::ENOSYS),
    }
}

/// The reported case: a large directory of files in another subvolume. Its first page comes as readdirplus and the rest as plain pages, since nothing stats in between, and every file must be listed under the number `stat` then reports, its substitute, not the inode number it has in its subvolume.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plain_page_lists_a_file_in_another_subvolume_as_stat_reports_it() {
    if !fuse_available() {
        return;
    }
    const FILES: usize = 2000;
    let blackhole = Blackhole::start_answering(script_foreign_files(FILES)).await;
    let (mount, mountpoint) = Mounted::mount(
        blackhole.config(Duration::from_secs(10)),
        Duration::from_secs(1),
    )
    .await;
    let m = Mounted {
        mount: Some(mount),
        server: None,
        _blackhole: Some(blackhole),
        export: tempfile::tempdir().unwrap(),
        mountpoint,
    };
    let dir = m.mnt().join("d");
    let (disagree, plain_pages) = {
        let dir = dir.clone();
        let (listed, disagree) = blocking(move || {
            let listed = DirStream::open(&dir).read_entries();
            let disagree: Vec<_> = listed
                .iter()
                .filter_map(|(name, listed)| {
                    let stat = fs::symlink_metadata(dir.join(OsStr::from_bytes(name)))
                        .unwrap()
                        .ino();
                    (*listed != stat)
                        .then(|| (String::from_utf8_lossy(name).into_owned(), *listed, stat))
                })
                .collect();
            (listed, disagree)
        })
        .await;
        assert_eq!(listed.len(), FILES, "every file, once");
        let snapshot = m.mount.as_ref().unwrap().perf().report();
        (
            disagree,
            snapshot.fuse.get("readdir").map_or(0, |row| row.n),
        )
    };
    assert!(
        plain_pages > 0,
        "no plain page was asked for, so this tests nothing"
    );
    assert!(
        disagree.is_empty(),
        "{} of {FILES} files listed under another number than stat's, e.g. {:?}",
        disagree.len(),
        disagree.first()
    );
    m.finish().await;
}

/// What a directory listing says an entry's inode number is must be what `stat` says, for `.` and `..` too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listings_and_stat_agree_on_inode_numbers() {
    use std::os::unix::fs::{DirEntryExt, MetadataExt};
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let export = m.export.path().to_path_buf();
    fs::create_dir(export.join("d")).unwrap();
    for i in 0..300 {
        fs::write(export.join(format!("d/file-{i:03}")), b"").unwrap();
    }
    let mnt = m.mnt();
    blocking(move || {
        // Twice: the second listing finds every name already known to the kernel. Stats in between keep the kernel asking for readdirplus; plain pages are `a_plain_page_lists_a_file_in_another_subvolume_as_stat_reports_it`'s.
        for round in 0..2 {
            let mut seen = 0;
            for entry in fs::read_dir(mnt.join("d")).unwrap() {
                let entry = entry.unwrap();
                assert_eq!(
                    entry.ino(),
                    entry.metadata().unwrap().ino(),
                    "round {round}: {:?}",
                    entry.file_name()
                );
                assert_eq!(
                    entry.ino(),
                    fs::metadata(export.join("d").join(entry.file_name()))
                        .unwrap()
                        .ino(),
                    "round {round}: an ordinary file goes by its real number"
                );
                seen += 1;
            }
            assert_eq!(seen, 300);
        }
        for (name, dir) in [(".", mnt.join("d")), ("..", mnt.clone())] {
            let listed = DirStream::open(&mnt.join("d")).ino_of(name);
            assert_eq!(listed, fs::metadata(&dir).unwrap().ino(), "{name}");
        }
    })
    .await;
    m.finish().await;
}

/// `syncfs(2)` on `dir`, as the errno. It reports a writeback error recorded on the mount since `dir` was opened, once.
fn syncfs(dir: &fs::File) -> Result<(), i32> {
    use std::os::fd::AsRawFd;
    match unsafe { libc::syncfs(dir.as_raw_fd()) } {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error().raw_os_error().unwrap()),
    }
}

/// The kernel keeps a written file's times itself and flushes them, with a setattr that names no handle, from inside the `unlink(2)` or `rename(2)` that takes the file's name away. A failure there is recorded against the whole mount and reported by the next `syncfs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_written_file_leaves_no_error_for_syncfs() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let mnt = m.mnt();
    let perf = m.mount.as_ref().unwrap().perf().clone();
    perf.report();
    blocking(move || {
        let dir = fs::File::open(&mnt).unwrap();
        fs::write(mnt.join("unlinked"), b"x").unwrap();
        fs::remove_file(mnt.join("unlinked")).unwrap();
        assert_eq!(syncfs(&dir), Ok(()), "after an unlink");

        let dir = fs::File::open(&mnt).unwrap();
        fs::write(mnt.join("replaced"), b"x").unwrap();
        fs::write(mnt.join("replacement"), b"y").unwrap();
        fs::rename(mnt.join("replacement"), mnt.join("replaced")).unwrap();
        assert_eq!(syncfs(&dir), Ok(()), "after a rename over a file");
    })
    .await;
    wait_for(Duration::from_secs(3), "kernel requests to drain", || {
        (perf.inflight() == 0).then_some(())
    })
    .await;
    let snap = perf.report();
    let setattr = snap
        .fuse
        .get("setattr")
        .expect("the kernel flushed no times, so this test saw nothing");
    assert!(setattr.errnos.is_empty(), "{:?}", setattr.errnos);
    m.finish().await;
}

/// An `O_PATH` descriptor reaches a file without the daemon ever having a handle for it, so with its name gone the daemon cannot address it; only the kernel's own flush is answered then, and anything else still fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unlinked_file_with_no_handle_takes_nothing_but_the_time_flush() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let mnt = m.mnt();
    // Made on the export, so that no handle was ever opened for it through the mount: one whose release is still on its way would serve the daemon as a way to reach the file.
    fs::write(m.export.path().join("f"), b"x").unwrap();
    blocking(move || {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(mnt.join("f").as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH) };
        assert!(fd >= 0, "open: {}", std::io::Error::last_os_error());
        let file = unsafe { fs::File::from_raw_fd(fd) };
        fs::remove_file(mnt.join("f")).unwrap();
        let both = [
            libc::timespec {
                tv_sec: 1_000_000,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: 1_000_000,
                tv_nsec: 0,
            },
        ];
        let rc = unsafe {
            libc::utimensat(
                file.as_raw_fd(),
                c"".as_ptr(),
                both.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!((rc, errno), (-1, Some(libc::ESTALE)));
        let rc =
            unsafe { libc::fchmodat(file.as_raw_fd(), c"".as_ptr(), 0o600, libc::AT_EMPTY_PATH) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!((rc, errno), (-1, Some(libc::ESTALE)));
    })
    .await;
    m.finish().await;
}

/// A file with no name left but a descriptor open is still there, and setting its times must reach the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn times_set_on_an_unlinked_open_file_reach_the_server() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let mnt = m.mnt();
    let perf = m.mount.as_ref().unwrap().perf().clone();
    blocking(move || {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        fs::write(mnt.join("f"), b"x").unwrap();
        let file = fs::File::open(mnt.join("f")).unwrap();
        fs::remove_file(mnt.join("f")).unwrap();
        perf.report();
        let times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: 1_000_000,
                tv_nsec: 0,
            },
        ];
        let rc = unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) };
        assert_eq!(rc, 0, "futimens: {}", std::io::Error::last_os_error());
        assert_eq!(file.metadata().unwrap().mtime(), 1_000_000);
        let snap = perf.report();
        assert!(
            snap.call.get("setattr").is_some_and(|call| call.row.n >= 1),
            "the server was not asked to set the times"
        );
    })
    .await;
    m.finish().await;
}

/// With the kernel positioning appends and the server's descriptor not appending on its own, re-flushed pages land where they belong.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn appends_through_the_mount_land_once_and_in_order() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let mnt = m.mnt();
    let export = m.export.path().to_path_buf();
    let expected = blocking(move || {
        let mut expected = Vec::new();
        for i in 0..50 {
            let line = format!("line {i:03}\n");
            fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(mnt.join("log"))
                .unwrap()
                .write_all(line.as_bytes())
                .unwrap();
            expected.extend_from_slice(line.as_bytes());
        }
        assert_eq!(
            fs::read(mnt.join("log")).unwrap(),
            expected,
            "through the mount"
        );
        expected
    })
    .await;
    assert_eq!(
        fs::read(export.join("log")).unwrap(),
        expected,
        "on the export"
    );
    m.finish().await;
}

/// The kernel reads the rest of a partially rewritten page through the handle it has, so a write-only open must be readable on the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_only_handle_can_rewrite_part_of_a_page() {
    let Some(m) = Mounted::start(Duration::from_secs(10), Duration::from_secs(1)).await else {
        return;
    };
    let mnt = m.mnt();
    let export = m.export.path().to_path_buf();
    blocking(move || {
        fs::write(mnt.join("f"), vec![b'a'; 8192]).unwrap();
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(mnt.join("f"))
            .unwrap();
        file.seek(SeekFrom::Start(100)).unwrap();
        file.write_all(b"BBBB").unwrap();
    })
    .await;
    let got = fs::read(export.join("f")).unwrap();
    assert_eq!(got.len(), 8192);
    assert_eq!(&got[100..104], b"BBBB");
    assert!(got[..100].iter().chain(&got[104..]).all(|b| *b == b'a'));
    m.finish().await;
}

/// A write lands in the kernel's cache and returns; it is the flush that learns the server is gone, here through `fsync(2)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_after_the_server_vanished_fails_at_the_fsync() {
    let Some(mut m) = Mounted::start(Duration::from_millis(500), Duration::from_secs(60)).await
    else {
        return;
    };
    let mnt = m.mnt();
    let file = blocking(move || fs::File::create(mnt.join("f")).unwrap()).await;
    m.server.take().unwrap().stop().await;
    blocking(move || {
        let mut file = file;
        file.write_all(b"cached").unwrap();
        let err = file.sync_all().unwrap_err();
        let code = err.raw_os_error().unwrap();
        assert!(
            [libc::ETIMEDOUT, libc::EIO, libc::ENOTCONN].contains(&code),
            "unexpected errno {code}: {err}"
        );
    })
    .await;
    m.finish().await;
}

/// The same failure reaches a program that never syncs: `close(2)` writes the cached data back first and reports the loss as `EIO`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_after_the_server_vanished_fails_at_the_close() {
    let Some(mut m) = Mounted::start(Duration::from_millis(500), Duration::from_secs(60)).await
    else {
        return;
    };
    let mnt = m.mnt();
    let file = blocking(move || fs::File::create(mnt.join("f")).unwrap()).await;
    m.server.take().unwrap().stop().await;
    blocking(move || {
        use std::os::fd::IntoRawFd;
        let mut file = file;
        file.write_all(b"cached").unwrap();
        let fd = file.into_raw_fd();
        // SAFETY: the descriptor was just taken out of the File and is closed exactly once here.
        let rc = unsafe { libc::close(fd) };
        let err = std::io::Error::last_os_error();
        assert_eq!(
            rc, -1,
            "close succeeded although the data could not be written back"
        );
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EIO),
            "close failed with {err}"
        );
    })
    .await;
    m.finish().await;
}

/// After the last close of a file written through the mount, the mount shows the server's size and mtime. The kernel does not always push its own mtime at close (a write in the same clock tick as the file's creation leaves the inode clean), so a fresh file written at once is the case that exposes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_written_file_shows_the_servers_attributes_after_its_last_close() {
    let Some(m) = Mounted::start_unwatched(Duration::from_secs(10), Duration::from_secs(10)).await
    else {
        return;
    };
    let mnt = m.mnt();
    let export = m.export.path().to_path_buf();
    blocking(move || {
        for i in 0..20 {
            let name = format!("f{i}");
            fs::write(mnt.join(&name), b"written at once").unwrap();
            let started = Instant::now();
            loop {
                let seen = fs::metadata(mnt.join(&name)).unwrap();
                let truth = fs::metadata(export.join(&name)).unwrap();
                if seen.len() == truth.len()
                    && seen.modified().unwrap() == truth.modified().unwrap()
                {
                    break;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(2),
                    "{name}: mount shows {:?}, export has {:?}",
                    seen.modified().unwrap(),
                    truth.modified().unwrap()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    })
    .await;
    m.finish().await;
}

/// Without any event, a file grown on the export is seen through the mount within the attribute TTL plus one access: the refresh notices the size the kernel would otherwise keep, and the file is taken away from the kernel by name. The probe is a `stat`, which refreshes attributes without opening the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_external_size_change_is_seen_within_the_attribute_ttl_without_events() {
    let Some(m) = Mounted::start_unwatched(Duration::from_secs(10), Duration::from_secs(1)).await
    else {
        return;
    };
    let mnt = m.mnt();
    let export = m.export.path().to_path_buf();
    fs::write(export.join("f"), b"v1").unwrap();
    let mnt2 = mnt.clone();
    blocking(move || assert_eq!(fs::read(mnt2.join("f")).unwrap(), b"v1")).await;
    fs::write(export.join("f"), b"v2 is longer").unwrap();
    let started = Instant::now();
    blocking(move || loop {
        let size = fs::metadata(mnt.join("f")).unwrap().len();
        if size == 12 {
            assert_eq!(fs::read(mnt.join("f")).unwrap(), b"v2 is longer");
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "external growth not visible within a 1 s attribute TTL: size {size}"
        );
        std::thread::sleep(Duration::from_millis(100));
    })
    .await;
    m.finish().await;
}

/// Server calls the kernel's interrupt abandoned, summed over every op, so a test need not know which request of the reader was the one that blocked.
fn interrupted_calls(mount: &Mount) -> u64 {
    mount
        .perf()
        .report()
        .call
        .values()
        .filter_map(|row| row.row.errnos.get(&libc::EINTR))
        .sum()
}

/// A process blocked in a call while the server is away can be interrupted: the call fails with `EINTR` and the pending signal ends the process. Twice, because a wrong answer to the first interrupt can make the kernel stop sending them for the life of the mount.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_signal_interrupts_a_call_waiting_for_the_server() {
    let Some(mut m) = Mounted::start(Duration::from_secs(60), Duration::from_secs(1)).await else {
        return;
    };
    let mnt = m.mnt();
    let mnt2 = mnt.clone();
    blocking(move || fs::write(mnt2.join("f"), b"data").unwrap()).await;
    m.server.take().unwrap().stop().await;
    for round in 1..=2 {
        let status = read_and_interrupt(mnt.join("f"), Duration::from_secs(3))
            .await
            .unwrap_or_else(|| panic!("round {round}: the reader was not interrupted"));
        assert_eq!(status.code(), Some(42), "round {round}: {status}");
    }
    assert_eq!(interrupted_calls(m.mount.as_ref().unwrap()), 2);
    // The server is gone, so anything else that touched the mount meanwhile is still waiting for it.
    m.abort_and_finish().await;
}

/// The reported case: the connection is fine and the server simply does not answer. The call has no deadline, and a signal is what ends the wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_signal_interrupts_a_call_blocked_on_a_live_connection() {
    let Some(m) = Mounted::start_stalled().await else {
        return;
    };
    let mnt = m.mnt();
    for round in 1..=2 {
        let status = read_and_interrupt(mnt.join("never"), Duration::from_secs(3))
            .await
            .unwrap_or_else(|| panic!("round {round}: the reader was not interrupted"));
        assert_eq!(status.code(), Some(42), "round {round}: {status}");
    }
    assert_eq!(interrupted_calls(m.mount.as_ref().unwrap()), 2);
    m.abort_and_finish().await;
}

/// Interrupts received and not honoured, summed until `until` holds or `patience` runs out; a report resets the counts, so the sums are the test's own.
async fn interrupts_until(
    mount: &Mount,
    patience: Duration,
    until: impl Fn(u64, u64) -> bool,
) -> (u64, u64) {
    let deadline = Instant::now() + patience;
    let (mut received, mut ignored) = (0, 0);
    loop {
        let snapshot = mount.perf().report();
        received += snapshot.interrupts;
        ignored += snapshot.interrupts_ignored;
        if until(received, ignored) || Instant::now() > deadline {
            return (received, ignored);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

extern "C" fn ignore_signal(_: libc::c_int) {}

/// A handled SIGUSR2, so a signal to a thread blocked in a call is a real, harmless one. Nothing else in this test binary catches a signal process-wide; one that did could leave a signal in the process's shared pending set and make these tests see a signal where there is none.
fn handle_sigusr2() {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = ignore_signal as extern "C" fn(libc::c_int) as usize;
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR2, &action, std::ptr::null_mut()) },
        0
    );
}

/// Only a pending signal interrupts a call. io_uring hands a completion to the thread that submitted it as task work, which the kernel counts as a pending signal and answers with `FUSE_INTERRUPT`; the call the thread is blocked in must go on. A real signal that comes later still ends it, although the kernel sends no second interrupt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_io_uring_completion_does_not_interrupt_a_call_but_a_signal_still_does() {
    let Some(m) = Mounted::start_stalled().await else {
        return;
    };
    handle_sigusr2();
    let (pipe_read, mut pipe_write) = std::io::pipe().unwrap();
    let (tid_tx, tid_rx) = std::sync::mpsc::channel();
    let dir = m.mnt().join("d");
    let caller = std::thread::spawn(move || {
        use std::os::fd::AsRawFd;
        let mut ring = match io_uring::IoUring::new(4) {
            Ok(ring) => ring,
            Err(e) => {
                tid_tx.send(Err(e)).unwrap();
                return None;
            }
        };
        let mut buf = [0u8; 1];
        let read = io_uring::opcode::Read::new(
            io_uring::types::Fd(pipe_read.as_raw_fd()),
            buf.as_mut_ptr(),
            1,
        )
        .build();
        // SAFETY: the buffer and the pipe outlive the ring, which is dropped at the end of this closure.
        unsafe { ring.submission().push(&read).unwrap() };
        ring.submit().unwrap();
        tid_tx
            .send(Ok(nix::unistd::gettid().as_raw() as u32))
            .unwrap();
        let made = fs::create_dir(&dir);
        drop(ring);
        Some(made)
    });
    let tid = match tid_rx.recv().unwrap() {
        Ok(tid) => tid,
        Err(e) => {
            eprintln!("skipping: io_uring is not available here: {e}");
            caller.join().unwrap();
            return m.abort_and_finish().await;
        }
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while !blocked_in_fuse(tid) {
        assert!(
            Instant::now() < deadline,
            "the caller never blocked in the mount"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mount = m.mount.as_ref().unwrap();
    // The completion lands on a thread known to be blocked in the call.
    pipe_write.write_all(b"x").unwrap();
    let (received, ignored) =
        interrupts_until(mount, Duration::from_secs(3), |received, _| received > 0).await;
    assert!(
        received > 0,
        "the completion did not interrupt the request, so this tests nothing"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        blocked_in_fuse(tid),
        "the call ended on a completion that was no signal"
    );
    let (more, more_ignored) = interrupts_until(mount, Duration::ZERO, |_, _| true).await;
    assert_eq!(
        ignored + more_ignored,
        received + more,
        "every interrupt so far stood for no signal"
    );
    assert_eq!(interrupted_calls(mount), 0, "a call was abandoned");

    use std::os::unix::thread::JoinHandleExt;
    assert_eq!(
        unsafe { libc::pthread_kill(caller.as_pthread_t(), libc::SIGUSR2) },
        0
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while !caller.is_finished() {
        assert!(
            Instant::now() < deadline,
            "a real signal after the completion did not end the call"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let made = caller.join().unwrap().unwrap();
    assert_eq!(made.unwrap_err().raw_os_error(), Some(libc::EINTR));
    m.abort_and_finish().await;
}

/// io_uring stops its own worker threads (a cancellation, a linked timeout, the ring's teardown) with the same notification that is no signal elsewhere, and there it does mean stop: an open the server never answers, linked to a timeout, is cancelled instead of waiting for ever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_io_uring_timeout_still_cancels_its_worker() {
    let Some(m) = Mounted::start_stalled().await else {
        return;
    };
    let path = CString::new(m.mnt().join("never").as_os_str().as_bytes()).unwrap();
    let caller = std::thread::spawn(move || -> std::io::Result<Vec<i32>> {
        let mut ring = io_uring::IoUring::new(4)?;
        let timeout = io_uring::types::Timespec::new().nsec(200_000_000);
        let open =
            io_uring::opcode::OpenAt::new(io_uring::types::Fd(libc::AT_FDCWD), path.as_ptr())
                .flags(libc::O_RDONLY)
                .build()
                .flags(io_uring::squeue::Flags::IO_LINK)
                .user_data(1);
        let link = io_uring::opcode::LinkTimeout::new(&timeout)
            .build()
            .user_data(2);
        // SAFETY: the path and the timespec outlive the ring, which is dropped at the end of this closure.
        unsafe {
            ring.submission().push(&open).unwrap();
            ring.submission().push(&link).unwrap();
        }
        ring.submit_and_wait(2)?;
        let mut results: Vec<(u64, i32)> = ring
            .completion()
            .map(|c| (c.user_data(), c.result()))
            .collect();
        results.sort();
        Ok(results.into_iter().map(|(_, r)| r).collect())
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    while !caller.is_finished() {
        assert!(
            Instant::now() < deadline,
            "the timeout did not cancel the open its worker was blocked in"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    match caller.join().unwrap() {
        Ok(results) => {
            assert!(
                results[0] == -libc::ECANCELED || results[0] == -libc::EINTR,
                "{results:?}"
            );
            // Cancelled from its queue before a worker took it, the open would prove nothing here.
            let (received, ignored) =
                interrupts_until(m.mount.as_ref().unwrap(), Duration::ZERO, |_, _| true).await;
            assert!(
                received > 0,
                "the timeout cancelled the open before it reached the mount, so this tests nothing"
            );
            assert_eq!(ignored, 0, "the worker's interrupt was not honoured");
        }
        Err(e) => eprintln!("skipping: io_uring is not available here: {e}"),
    }
    m.abort_and_finish().await;
}

/// Aborting the mount's FUSE connection fails every pending request and lets an unmount complete however stuck the server is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abort_fails_pending_requests_and_frees_the_unmount() {
    let Some(m) = Mounted::start_stalled().await else {
        return;
    };
    let mnt = m.mnt();
    let mut child = std::process::Command::new("cat")
        .arg(mnt.join("never"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(child.try_wait().unwrap().is_none(), "cat did not block");
    m.mount.as_ref().unwrap().aborter().abort();
    let status = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the blocked cat was not released by the abort");
    assert!(
        !status.success(),
        "cat succeeded against a server that never answered"
    );
    tokio::time::timeout(Duration::from_secs(3), m.finish())
        .await
        .expect("unmount did not complete after the abort");
}

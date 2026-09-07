//! End-to-end tests through a real FUSE mount. Skipped (with a message) where `/dev/fuse` or `fusermount3` is unavailable.

mod common;

use common::*;
use jackalopefs_client::mount::{Mount, MountOptions};
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
    export: tempfile::TempDir,
    mountpoint: tempfile::TempDir,
}

impl Mounted {
    async fn start(op_timeout: Duration, ttl: Duration) -> Option<Mounted> {
        Mounted::start_full(op_timeout, ttl, true).await
    }

    /// A mount whose server sends no change events.
    async fn start_unwatched(op_timeout: Duration, ttl: Duration) -> Option<Mounted> {
        Mounted::start_full(op_timeout, ttl, false).await
    }

    async fn start_full(op_timeout: Duration, ttl: Duration, watched: bool) -> Option<Mounted> {
        if !fuse_available() {
            return None;
        }
        let export = tempfile::tempdir().unwrap();
        let mountpoint = tempfile::tempdir().unwrap();
        let server = if watched {
            TestServer::start(export.path(), None).await
        } else {
            TestServer::start_unwatched(export.path()).await
        };
        let client = jackalopefs_client::Client::connect(server.config(op_timeout))
            .await
            .unwrap();
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
        Some(Mounted {
            mount: Some(mount),
            server: Some(server),
            export,
            mountpoint,
        })
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
}

/// Filesystem calls against the mount block the calling thread until the FUSE request round-trips; keep them off the runtime workers.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

fn list_with_dots(dir: &Path) -> Vec<Vec<u8>> {
    let cpath = CString::new(dir.as_os_str().as_bytes()).unwrap();
    let mut names = Vec::new();
    // SAFETY: plain libc directory iteration; `dir` is a valid open handle until `closedir`.
    unsafe {
        let handle = libc::opendir(cpath.as_ptr());
        assert!(!handle.is_null(), "opendir failed");
        loop {
            let entry = libc::readdir(handle);
            if entry.is_null() {
                break;
            }
            let name = std::ffi::CStr::from_ptr((*entry).d_name.as_ptr());
            names.push(name.to_bytes().to_vec());
        }
        libc::closedir(handle);
    }
    names
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

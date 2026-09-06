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
        if !fuse_available() {
            return None;
        }
        let export = tempfile::tempdir().unwrap();
        let mountpoint = tempfile::tempdir().unwrap();
        let server = TestServer::start(export.path(), None).await;
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

        // Unlink while open: the handle keeps working, the name is gone.
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

//! What becomes of a request when its connection goes, or its caller gives up, at a known point: one test per request kind ("case") and fault, each judged against fault-free runs of the same case.
//!
//! A [`Gate`] on the server parks the case's request on its blocking thread, and the fault is played around it:
//! - `reply_lost`: the request has run and its reply is waiting; the connection is closed, the session resumes, and the client resends the request or fails it.
//! - `original_late`: the request is about to run; the connection is closed, and the request runs only after the client has resent or failed it and made a later change (the case's follow-up).
//! - `cancelled`: the request is about to run on a live connection when the call is interrupted; it is let go after the follow-up.
//! - `cancelled_running`: the request is running on a live connection when the call is interrupted; it finishes after the follow-up.
//!
//! Each cell also runs controls on fresh exports: A (the op, then the follow-up), B (the follow-up alone, as if the op never happened) and C (the follow-up, then the op: the order a late original makes). The cell's run must report the op's outcome as A did (`Outcome`), unless the client could not tell whether it was applied (a lost connection, a timeout, an interrupt). It must then match A, or B when the outcome is unknown, by the follow-up's outcome and the export's [`snapshot`]. Where the late original can act, the state is checked just before it is released too, which says whether a failure is the late original's doing (`StateLate`) or the resend's (`StateResend`). After every handle the case opened is released, the server must hold none (`Leak`). Control C must match neither A nor B for a case that changes the export, or its follow-up could not show a late original at all.
//!
//! Whatever holds the parked original back is the server's to decide: it may run it, refuse it or drop it. When the client makes no progress for 10 s with the original parked (a server that holds the resend back until the original has run, say), the gate lets it go, and the cell is judged by the state it ends in.
//!
//! Every cell prints one line (`cargo test --test disconnect -- --nocapture`). A cell listed with `Fail(..)` must fail with exactly those classes, and every other cell must pass, so the list cannot go stale.

mod common;

use common::*;
use jackalopefs_client::{Client, Error, RequestKernel};
use jackalopefs_proto::{Path, SetAttr, Whence};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

const FILE_F: &[u8] = b"0123456789abcdef";
const FILE_G: &[u8] = b"ghijklmnopqrstuv";

/// How long the client may make no progress while the gate holds the original before the gate lets it go.
const STALL_LIMIT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    ReplyLost,
    OriginalLate,
    OriginalRunning,
    Cancelled,
    CancelledRunning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Outcome,
    StateResend,
    StateLate,
    Leak,
}

use Class::*;

enum Expect {
    Pass,
    Fail(&'static [Class], &'static str),
}

use Expect::*;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Observed {
    Ok(String),
    Err(i32),
    /// A failure that leaves open whether the request was applied: the connection went, a deadline passed, or the call was interrupted.
    Unknown(i32),
}

impl Observed {
    fn of<T>(result: Result<T, Error>, describe: impl FnOnce(T) -> String) -> Observed {
        match result {
            Ok(v) => Observed::Ok(describe(v)),
            Err(e @ (Error::Disconnected | Error::Timeout | Error::Interrupted)) => {
                Observed::Unknown(e.errno())
            }
            Err(e) => Observed::Err(e.errno()),
        }
    }

    fn done(result: Result<(), Error>) -> Observed {
        Observed::of(result, |()| String::new())
    }
}

fn attr(a: jackalopefs_proto::Attr) -> String {
    format!("{:?} {:o} {}", a.kind, a.perm, a.size)
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Lookup,
    Getattr,
    Readlink,
    Read,
    Readdir,
    Getxattr,
    Listxattr,
    Access,
    Statfs,
    Lseek,
    Fsync,
    Write,
    WriteAppend,
    SetattrSize,
    SetattrMode,
    Mknod,
    Mkdir,
    Unlink,
    Rmdir,
    Symlink,
    Rename,
    Link,
    Open,
    OpenTrunc,
    Create,
    CreateExcl,
    CreateTrunc,
    Setxattr,
    SetxattrCreate,
    SetxattrReplace,
    Removexattr,
    Fallocate,
    CopyFileRange,
    Opendir,
    Release,
    Releasedir,
}

/// The handles a case works through, opened before the gate is armed, and every handle still to be released at the end.
#[derive(Default)]
struct Prep {
    f: Option<u64>,
    f_append: Option<u64>,
    g: Option<u64>,
    root: Option<u64>,
    /// The handle the op itself opened.
    opened: Option<u64>,
    live: Vec<Opened>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Opened {
    File(u64),
    Dir(u64),
}

impl Prep {
    fn f(&self) -> u64 {
        self.f.expect("the case opens f")
    }

    fn forget(&mut self, fh: u64) {
        self.live
            .retain(|live| !matches!(live, Opened::File(live) | Opened::Dir(live) if *live == fh));
    }
}

async fn open(client: &Client, prep: &mut Prep, at: &str, flags: i32) -> Result<u64, Error> {
    let (fh, _) = client.open(path(at), flags, None, |a| Ok(a.ino)).await?;
    prep.live.push(Opened::File(fh));
    Ok(fh)
}

async fn create(client: &Client, prep: &mut Prep, at: &str, flags: i32) -> Result<u64, Error> {
    let (fh, _) = client
        .create(Path::root(), name(at), 0o100644, flags, None, |a| Ok(a.ino))
        .await?;
    prep.live.push(Opened::File(fh));
    Ok(fh)
}

impl Case {
    fn xattrs(self) -> bool {
        matches!(
            self,
            Case::Getxattr
                | Case::Listxattr
                | Case::Setxattr
                | Case::SetxattrCreate
                | Case::SetxattrReplace
                | Case::Removexattr
        )
    }

    /// Whether the server orders the op behind a resumed session's earlier changes: every op but the reads and the releases.
    fn ordered(self) -> bool {
        !matches!(
            self,
            Case::Lookup
                | Case::Getattr
                | Case::Readlink
                | Case::Read
                | Case::Readdir
                | Case::Getxattr
                | Case::Listxattr
                | Case::Access
                | Case::Statfs
                | Case::Lseek
                | Case::Fsync
                | Case::Release
                | Case::Releasedir
        )
    }

    /// Whether the op changes the export, which control C must show.
    fn changes_files(self) -> bool {
        !matches!(
            self,
            Case::Lookup
                | Case::Getattr
                | Case::Readlink
                | Case::Read
                | Case::Readdir
                | Case::Getxattr
                | Case::Listxattr
                | Case::Access
                | Case::Statfs
                | Case::Lseek
                | Case::Fsync
                | Case::Open
                | Case::Opendir
                | Case::Release
                | Case::Releasedir
        )
    }

    /// Whether the op opens a handle, which the client releases in the background when the outcome is unknown.
    fn opens(self) -> bool {
        matches!(
            self,
            Case::Open
                | Case::OpenTrunc
                | Case::Create
                | Case::CreateExcl
                | Case::CreateTrunc
                | Case::Opendir
        )
    }

    fn op_name(self) -> &'static str {
        match self {
            Case::Lookup => "lookup",
            Case::Getattr => "getattr",
            Case::Readlink => "readlink",
            Case::Read => "read",
            Case::Readdir => "readdir",
            Case::Getxattr => "getxattr",
            Case::Listxattr => "listxattr",
            Case::Access => "access",
            Case::Statfs => "statfs",
            Case::Lseek => "lseek",
            Case::Fsync => "fsync",
            Case::Write | Case::WriteAppend => "write",
            Case::SetattrSize | Case::SetattrMode => "setattr",
            Case::Mknod => "mknod",
            Case::Mkdir => "mkdir",
            Case::Unlink => "unlink",
            Case::Rmdir => "rmdir",
            Case::Symlink => "symlink",
            Case::Rename => "rename",
            Case::Link => "link",
            Case::Open | Case::OpenTrunc => "open",
            Case::Create | Case::CreateExcl | Case::CreateTrunc => "create",
            Case::Setxattr | Case::SetxattrCreate | Case::SetxattrReplace => "setxattr",
            Case::Removexattr => "removexattr",
            Case::Fallocate => "fallocate",
            Case::CopyFileRange => "copy_file_range",
            Case::Opendir => "opendir",
            Case::Release => "release",
            Case::Releasedir => "releasedir",
        }
    }

    /// Open what the op and the follow-up work through.
    async fn prepare(self, client: &Client) -> Prep {
        let mut prep = Prep::default();
        match self {
            Case::Read | Case::Lseek | Case::Release => {
                prep.f = Some(open(client, &mut prep, "f", libc::O_RDONLY).await.unwrap());
            }
            Case::Fsync
            | Case::Write
            | Case::SetattrSize
            | Case::OpenTrunc
            | Case::CreateTrunc
            | Case::Fallocate => {
                prep.f = Some(open(client, &mut prep, "f", libc::O_RDWR).await.unwrap());
            }
            Case::WriteAppend => {
                prep.f = Some(open(client, &mut prep, "f", libc::O_RDWR).await.unwrap());
                let fh = open(client, &mut prep, "f", libc::O_RDWR | libc::O_APPEND).await;
                prep.f_append = Some(fh.unwrap());
            }
            Case::CopyFileRange => {
                prep.f = Some(open(client, &mut prep, "f", libc::O_RDONLY).await.unwrap());
                prep.g = Some(open(client, &mut prep, "g", libc::O_RDWR).await.unwrap());
            }
            Case::Readdir | Case::Releasedir => {
                let (fh, _) = client
                    .opendir(Path::root(), None, |a| Ok(a.ino))
                    .await
                    .unwrap();
                prep.live.push(Opened::Dir(fh));
                prep.root = Some(fh);
            }
            _ => {}
        }
        prep
    }

    async fn op(self, client: &Client, prep: &mut Prep) -> Observed {
        match self {
            Case::Lookup => Observed::of(client.lookup(Path::root(), name("f")).await, attr),
            Case::Getattr => Observed::of(client.getattr(Some(path("f")), None).await, attr),
            Case::Readlink => Observed::of(client.readlink(path("s")).await, |t| format!("{t:?}")),
            Case::Read => Observed::of(client.read(prep.f(), 0, 100).await, |d| format!("{d:?}")),
            Case::Readdir => {
                let fh = prep.root.unwrap();
                Observed::of(client.readdir(fh, 0, 64 * 1024).await, |(entries, end)| {
                    let mut names: Vec<String> = entries
                        .iter()
                        .map(|e| String::from_utf8_lossy(&e.name).into_owned())
                        .filter(|n| n != "." && n != "..")
                        .collect();
                    names.sort();
                    format!("{names:?} end={end}")
                })
            }
            Case::Getxattr => {
                Observed::of(client.getxattr(path("f"), b"user.k".to_vec()).await, |v| {
                    format!("{v:?}")
                })
            }
            Case::Listxattr => {
                Observed::of(client.listxattr(path("f")).await, |v| format!("{v:?}"))
            }
            Case::Access => Observed::done(client.access(path("f"), libc::R_OK).await),
            Case::Statfs => Observed::of(client.statfs(Path::root()).await, |_| String::new()),
            Case::Lseek => Observed::of(client.lseek(prep.f(), 0, Whence::Data).await, |o| {
                o.to_string()
            }),
            Case::Fsync => Observed::done(client.fsync(prep.f(), false).await),
            Case::Write => Observed::of(client.write(prep.f(), 0, b"old!".to_vec()).await, |n| {
                n.to_string()
            }),
            Case::WriteAppend => {
                let fh = prep.f_append.unwrap();
                Observed::of(client.write(fh, 0, b"tail".to_vec()).await, |n| {
                    n.to_string()
                })
            }
            Case::SetattrSize => {
                let set = SetAttr {
                    size: Some(4),
                    ..SetAttr::default()
                };
                Observed::of(client.setattr(Some(path("f")), None, set).await, attr)
            }
            Case::SetattrMode => {
                let set = SetAttr {
                    mode: Some(0o600),
                    ..SetAttr::default()
                };
                Observed::of(client.setattr(Some(path("f")), None, set).await, attr)
            }
            Case::Mknod => Observed::of(
                client
                    .mknod(Path::root(), name("n"), libc::S_IFIFO | 0o644, 0)
                    .await,
                attr,
            ),
            Case::Mkdir => Observed::of(client.mkdir(Path::root(), name("m"), 0o755).await, attr),
            Case::Unlink => Observed::done(client.unlink(Path::root(), name("f")).await),
            Case::Rmdir => Observed::done(client.rmdir(Path::root(), name("d")).await),
            Case::Symlink => Observed::of(
                client.symlink(Path::root(), name("t"), b"f".to_vec()).await,
                attr,
            ),
            Case::Rename => Observed::done(
                client
                    .rename(Path::root(), name("f"), Path::root(), name("h"), 0)
                    .await,
            ),
            Case::Link => Observed::of(client.link(path("f"), Path::root(), name("l")).await, attr),
            Case::Open | Case::OpenTrunc => {
                let flags = match self {
                    Case::OpenTrunc => libc::O_RDWR | libc::O_TRUNC,
                    _ => libc::O_RDWR,
                };
                let result = open(client, prep, "f", flags).await;
                Observed::of(result, |fh| {
                    prep.opened = Some(fh);
                    String::new()
                })
            }
            Case::Create | Case::CreateExcl | Case::CreateTrunc => {
                let (at, flags) = match self {
                    Case::Create => ("c", libc::O_RDWR),
                    Case::CreateExcl => ("c", libc::O_RDWR | libc::O_EXCL),
                    _ => ("f", libc::O_RDWR | libc::O_TRUNC),
                };
                let result = create(client, prep, at, flags).await;
                Observed::of(result, |fh| {
                    prep.opened = Some(fh);
                    String::new()
                })
            }
            Case::Setxattr => Observed::done(
                client
                    .setxattr(path("f"), b"user.k".to_vec(), b"v2".to_vec(), 0)
                    .await,
            ),
            Case::SetxattrCreate => Observed::done(
                client
                    .setxattr(
                        path("f"),
                        b"user.n".to_vec(),
                        b"v".to_vec(),
                        libc::XATTR_CREATE,
                    )
                    .await,
            ),
            Case::SetxattrReplace => Observed::done(
                client
                    .setxattr(
                        path("f"),
                        b"user.k".to_vec(),
                        b"v2".to_vec(),
                        libc::XATTR_REPLACE,
                    )
                    .await,
            ),
            Case::Removexattr => {
                Observed::done(client.removexattr(path("f"), b"user.k".to_vec()).await)
            }
            Case::Fallocate => Observed::done(
                client
                    .fallocate(
                        prep.f(),
                        0,
                        4,
                        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                    )
                    .await,
            ),
            Case::CopyFileRange => {
                let (f, g) = (prep.f(), prep.g.unwrap());
                Observed::of(client.copy_file_range(f, 0, g, 0, 4).await, |n| {
                    n.to_string()
                })
            }
            Case::Opendir => {
                let result = client.opendir(Path::root(), None, |a| Ok(a.ino)).await;
                Observed::of(result, |(fh, _)| {
                    prep.live.push(Opened::Dir(fh));
                    prep.opened = Some(fh);
                    String::new()
                })
            }
            Case::Release => {
                let fh = prep.f();
                prep.forget(fh);
                Observed::done(client.release(fh).await)
            }
            Case::Releasedir => {
                let fh = prep.root.unwrap();
                prep.forget(fh);
                Observed::done(client.releasedir(fh).await)
            }
        }
    }

    /// A later change to what the op touched, which a late original would land after; none for an op that changes nothing a later one could undo.
    async fn follow_up(self, client: &Client, prep: &mut Prep) -> Observed {
        match self {
            Case::Lookup
            | Case::Getattr
            | Case::Readlink
            | Case::Read
            | Case::Readdir
            | Case::Getxattr
            | Case::Listxattr
            | Case::Access
            | Case::Statfs
            | Case::Lseek
            | Case::Fsync
            | Case::Release
            | Case::Releasedir => Observed::Ok("none".into()),
            Case::Write => Observed::of(client.write(prep.f(), 0, b"new!".to_vec()).await, |n| {
                n.to_string()
            }),
            Case::WriteAppend => {
                Observed::of(client.write(prep.f(), 16, b"TAIL".to_vec()).await, |n| {
                    n.to_string()
                })
            }
            Case::SetattrSize => {
                Observed::of(client.write(prep.f(), 8, b"late".to_vec()).await, |n| {
                    n.to_string()
                })
            }
            Case::SetattrMode => {
                let set = SetAttr {
                    mode: Some(0o640),
                    ..SetAttr::default()
                };
                Observed::of(client.setattr(Some(path("f")), None, set).await, attr)
            }
            Case::Mknod => Observed::done(client.unlink(Path::root(), name("n")).await),
            Case::Mkdir => Observed::done(client.rmdir(Path::root(), name("m")).await),
            Case::Unlink | Case::Rename => {
                let result = create(client, prep, "f", libc::O_WRONLY | libc::O_TRUNC).await;
                match result {
                    Ok(fh) => Observed::of(client.write(fh, 0, b"new".to_vec()).await, |n| {
                        n.to_string()
                    }),
                    Err(e) => Observed::Err(e.errno()),
                }
            }
            Case::Rmdir => Observed::of(client.mkdir(Path::root(), name("d"), 0o755).await, attr),
            Case::Symlink => Observed::done(client.unlink(Path::root(), name("t")).await),
            Case::Link => Observed::done(client.unlink(Path::root(), name("l")).await),
            Case::Create | Case::CreateExcl => {
                Observed::done(client.unlink(Path::root(), name("c")).await)
            }
            Case::OpenTrunc | Case::CreateTrunc => {
                Observed::of(client.write(prep.f(), 0, b"new".to_vec()).await, |n| {
                    n.to_string()
                })
            }
            Case::Open => match prep.opened.take() {
                Some(fh) => {
                    prep.forget(fh);
                    Observed::done(client.release(fh).await)
                }
                None => Observed::Ok("none".into()),
            },
            Case::Opendir => match prep.opened.take() {
                Some(fh) => {
                    prep.forget(fh);
                    Observed::done(client.releasedir(fh).await)
                }
                None => Observed::Ok("none".into()),
            },
            Case::Setxattr | Case::SetxattrCreate => {
                let name = match self {
                    Case::Setxattr => b"user.k".to_vec(),
                    _ => b"user.n".to_vec(),
                };
                Observed::done(client.removexattr(path("f"), name).await)
            }
            Case::SetxattrReplace | Case::Removexattr => Observed::done(
                client
                    .setxattr(path("f"), b"user.k".to_vec(), b"v3".to_vec(), 0)
                    .await,
            ),
            Case::Fallocate => {
                Observed::of(client.write(prep.f(), 0, b"new!".to_vec()).await, |n| {
                    n.to_string()
                })
            }
            Case::CopyFileRange => {
                let g = prep.g.unwrap();
                Observed::of(client.write(g, 0, b"new!".to_vec()).await, |n| {
                    n.to_string()
                })
            }
        }
    }
}

/// The export every run starts from, with modes set explicitly: the test server zeroes the process's umask, which other tests' fixtures race. Returns whether the filesystem takes `user.` xattrs.
fn setup(root: &std::path::Path) -> bool {
    let perm = |at: &std::path::Path, mode| {
        std::fs::set_permissions(at, std::fs::Permissions::from_mode(mode)).unwrap()
    };
    perm(root, 0o755);
    std::fs::write(root.join("f"), FILE_F).unwrap();
    perm(&root.join("f"), 0o644);
    std::fs::write(root.join("g"), FILE_G).unwrap();
    perm(&root.join("g"), 0o644);
    std::fs::create_dir(root.join("d")).unwrap();
    perm(&root.join("d"), 0o755);
    std::os::unix::fs::symlink("f", root.join("s")).unwrap();
    let f = std::ffi::CString::new(root.join("f").into_os_string().into_encoded_bytes()).unwrap();
    // SAFETY: both strings are NUL-terminated and the value is valid for its length.
    let rc = unsafe { libc::lsetxattr(f.as_ptr(), c"user.k".as_ptr(), b"v".as_ptr().cast(), 1, 0) };
    if rc == 0 {
        return true;
    }
    let e = std::io::Error::last_os_error();
    assert_eq!(
        e.raw_os_error(),
        Some(libc::EOPNOTSUPP),
        "setting a user xattr: {e}"
    );
    false
}

type Snapshot = BTreeMap<std::path::PathBuf, EntrySnapshot>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Order {
    /// Control A: the op, then the follow-up.
    OpFirst,
    /// Control B: the follow-up alone.
    FollowUpOnly,
    /// Control C: the follow-up, then the op.
    FollowUpFirst,
    Faulted(Fault),
}

struct Run {
    op: Option<Observed>,
    follow: Observed,
    /// The state before the parked original was let go, for the faults that hold it past the follow-up.
    before: Option<Snapshot>,
    after: Snapshot,
    handles: u64,
    pool: usize,
    /// What became of the parked original: its errno once it ran (`Some(None)` for success), `None` if the server never ran it.
    original: Option<Option<i32>>,
    /// Why the gate let the original go before the follow-up was done, if it did.
    early: Option<Early>,
    /// The server's `request_superseded` and `request_held` counts.
    superseded: u64,
    held: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Early {
    /// The server held a request back for the parked one.
    Held,
    /// The client made no progress for [`STALL_LIMIT`].
    Stalled,
}

/// `future`, unless the server holds a request back behind the parked one, or the client makes no progress for [`STALL_LIMIT`]: then the gate lets its request go, and `future` is awaited to the end.
async fn unless_stalled<T>(
    gate: &Gate,
    server: &TestServer,
    early: &mut Option<Early>,
    future: impl std::future::Future<Output = T>,
) -> T {
    tokio::pin!(future);
    let deadline = tokio::time::Instant::now() + STALL_LIMIT;
    loop {
        tokio::select! {
            output = &mut future => return output,
            () = tokio::time::sleep(Duration::from_millis(20)) => {
                let why = if server_holds(server) {
                    Early::Held
                } else if tokio::time::Instant::now() >= deadline {
                    Early::Stalled
                } else {
                    continue;
                };
                if !gate.released() {
                    *early = Some(why);
                    gate.release();
                }
                return future.await;
            }
        }
    }
}

/// Whether the server lists a request waiting for its session's earlier connections; asked as if a listing's age had passed, so it answers at once.
fn server_holds(server: &TestServer) -> bool {
    let now = std::time::Instant::now() + jackalopefs_perf::stall::INFLIGHT_LISTED;
    server
        .server
        .perf
        .scan_pending(now, jackalopefs_perf::stall::ModeScan::Listed)
        .expect("the in-flight table's lock is free")
        .found
        .iter()
        .any(|(pending, _)| pending.phase == jackalopefs_server::perf::PhaseServer::Held)
}

/// The server's count of the event `name`.
fn count(server: &TestServer, name: &str) -> u64 {
    server
        .server
        .perf
        .events
        .counts()
        .into_iter()
        .find_map(|(n, count)| (n == name).then_some(count))
        .expect("the server counts that event")
}

/// One run of `case` on a fresh export and server, in `order`. `None` when the filesystem takes no `user.` xattrs and the case needs them.
async fn run(case: Case, order: Order) -> Option<Run> {
    let export = tempfile::tempdir().unwrap();
    if !setup(export.path()) && case.xattrs() {
        return None;
    }
    let server = TestServer::start(export.path(), None).await;
    let gate = Gate::install(&server);
    let client = server.client().await;
    let mut prep = case.prepare(&client).await;
    let blip = || async {
        gate.wait_parked().await;
        wait_for_generation(&client, 1)
            .await
            .conn
            .close(9u32.into(), b"simulated blip");
    };
    let mut early = None;
    let mut follow = None;
    let op = match order {
        Order::FollowUpOnly => None,
        Order::OpFirst => Some(case.op(&client, &mut prep).await),
        Order::FollowUpFirst => {
            follow = Some(case.follow_up(&client, &mut prep).await);
            Some(case.op(&client, &mut prep).await)
        }
        Order::Faulted(Fault::ReplyLost) => {
            gate.arm(case.op_name(), Hold::After);
            let resume = async {
                blip().await;
                wait_for_generation(&client, 2).await;
                gate.release();
            };
            Some(tokio::join!(case.op(&client, &mut prep), resume).0)
        }
        Order::Faulted(fault @ (Fault::OriginalLate | Fault::OriginalRunning)) => {
            let hold = match fault {
                Fault::OriginalLate => Hold::Before,
                _ => Hold::Running,
            };
            gate.arm(case.op_name(), hold);
            let late = async { tokio::join!(case.op(&client, &mut prep), blip()).0 };
            Some(unless_stalled(&gate, &server, &mut early, late).await)
        }
        Order::Faulted(fault @ (Fault::Cancelled | Fault::CancelledRunning)) => {
            let hold = match fault {
                Fault::Cancelled => Hold::Before,
                _ => Hold::Running,
            };
            gate.arm(case.op_name(), hold);
            let req = RequestKernel::new(1);
            let scoped = req.clone();
            let interrupt = async {
                gate.wait_parked().await;
                req.interrupt();
            };
            let cancelled =
                async { tokio::join!(scoped.scope(case.op(&client, &mut prep)), interrupt).0 };
            Some(unless_stalled(&gate, &server, &mut early, cancelled).await)
        }
    };
    let holds = matches!(
        order,
        Order::Faulted(
            Fault::OriginalLate
                | Fault::OriginalRunning
                | Fault::Cancelled
                | Fault::CancelledRunning
        )
    );
    let follow = match follow {
        Some(follow) => follow,
        None if holds => {
            unless_stalled(
                &gate,
                &server,
                &mut early,
                case.follow_up(&client, &mut prep),
            )
            .await
        }
        None => case.follow_up(&client, &mut prep).await,
    };
    // The client releases an open of unknown outcome from a task of its own; whether that release reaches the server before the late original is what the cell is about, so it must have arrived before the original is let go.
    if holds && !gate.released() && case.opens() && matches!(op, Some(Observed::Unknown(_))) {
        let fh = gate.taken().expect("the gate took the op").fh;
        wait_for(
            Duration::from_secs(10),
            "the orphan release of the op's handle",
            || {
                gate.log()
                    .iter()
                    .any(|d| matches!(d.op, "release" | "releasedir") && d.fh == fh)
                    .then_some(())
            },
        )
        .await;
    }
    let before = (holds && !gate.released()).then(|| snapshot(export.path()));
    gate.release();
    // The original runs now, unless the server refuses or drops it; either way nothing is in flight once it is settled.
    wait_for(
        Duration::from_secs(10),
        "the server to finish every request",
        || (server.server.perf.inflight() == 0).then_some(()),
    )
    .await;
    let original = gate.taken().and_then(|taken| taken.ran);
    for opened in std::mem::take(&mut prep.live) {
        match opened {
            Opened::File(fh) => client.release(fh).await.unwrap(),
            Opened::Dir(fh) => client.releasedir(fh).await.unwrap(),
        }
    }
    // Every handle the server opened must have been released before the server's table is counted: by the client, as an orphan, or before a late open.
    wait_for(
        Duration::from_secs(10),
        "a release of every handle opened",
        || {
            let log = gate.log();
            log.iter()
                .filter(|d| matches!(d.op, "open" | "create" | "opendir") && d.errno.is_none())
                .all(|o| {
                    log.iter()
                        .any(|r| matches!(r.op, "release" | "releasedir") && r.fh == o.fh)
                })
                .then_some(())
        },
    )
    .await;
    let totals = server.server.sessions.handle_totals();
    let handles = totals.files + totals.dirs;
    let pool = server.server.sessions.pool().used();
    let after = snapshot(export.path());
    let (superseded, held) = (
        count(&server, "request_superseded"),
        count(&server, "request_held"),
    );
    client.shutdown().await;
    server.stop().await;
    Some(Run {
        op,
        follow,
        before,
        after,
        handles,
        pool,
        original,
        early,
        superseded,
        held,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Matched {
    A,
    B,
    Neither,
}

/// Which control a run's follow-up outcome and `state` match.
fn matched(follow: &Observed, state: &Snapshot, a: &Run, b: &Run) -> Matched {
    if (follow, state) == (&a.follow, &a.after) {
        Matched::A
    } else if (follow, state) == (&b.follow, &b.after) {
        Matched::B
    } else {
        Matched::Neither
    }
}

/// What failed in `run`, judged against controls A and B.
fn judge(run: &Run, a: &Run, b: &Run) -> Vec<Class> {
    let op = run.op.as_ref().unwrap();
    let unknown = matches!(op, Observed::Unknown(_));
    let allowed = |state: &Snapshot| match matched(&run.follow, state, a, b) {
        Matched::A => true,
        Matched::B => unknown,
        Matched::Neither => false,
    };
    let mut classes = Vec::new();
    if Some(op) != a.op.as_ref() && !unknown {
        classes.push(Outcome);
    }
    match &run.before {
        Some(before) if !allowed(before) => classes.push(StateResend),
        Some(_) if !allowed(&run.after) => classes.push(StateLate),
        None if !allowed(&run.after) => classes.push(StateResend),
        _ => {}
    }
    if run.handles != 0 || run.pool != 0 {
        classes.push(Leak);
    }
    classes
}

/// Where `a` and `b` differ, path by path.
fn diff(a: &Snapshot, b: &Snapshot) -> String {
    let mut out = Vec::new();
    for path in a
        .keys()
        .chain(b.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        if a.get(path) != b.get(path) {
            out.push(format!("{path:?}: {:?} vs {:?}", a.get(path), b.get(path)));
        }
    }
    out.join("; ")
}

async fn cell(case: Case, fault: Fault, expect: Expect) {
    let Some(a) = run(case, Order::OpFirst).await else {
        println!("{case:?} {fault:?}: skipped, no user xattrs");
        return;
    };
    if a.op == Some(Observed::Err(libc::EOPNOTSUPP)) {
        println!("{case:?} {fault:?}: skipped, the export's filesystem does not support it");
        return;
    }
    let b = run(case, Order::FollowUpOnly).await.unwrap();
    if case.changes_files() {
        let c = run(case, Order::FollowUpFirst).await.unwrap();
        assert_eq!(
            matched(&c.follow, &c.after, &a, &b),
            Matched::Neither,
            "{case:?}: the op after the follow-up ends like a control, so the follow-up cannot show a late original"
        );
    }
    let faulted = run(case, Order::Faulted(fault)).await.unwrap();
    let classes = judge(&faulted, &a, &b);
    println!(
        "{case:?} {fault:?}: op {:?} (A {:?}), follow-up {:?}, before {:?}, after {:?}, original {:?}, early {:?}, superseded {} held {}, handles {} pool {} => {classes:?}",
        faulted.op.as_ref().unwrap(),
        a.op.as_ref().unwrap(),
        faulted.follow,
        faulted.before.as_ref().map(|before| matched(&faulted.follow, before, &a, &b)),
        matched(&faulted.follow, &faulted.after, &a, &b),
        faulted.original,
        faulted.early,
        faulted.superseded,
        faulted.held,
        faulted.handles,
        faulted.pool,
    );
    if !classes.is_empty() {
        println!("  after vs A: {}", diff(&faulted.after, &a.after));
    }
    // Which way the server kept the original from overtaking: dropped unrun when it had not begun, waited for when it had.
    if !case.ordered() {
        assert_eq!(faulted.superseded, 0, "{case:?}: a read was dropped");
        assert_ne!(
            faulted.early,
            Some(Early::Held),
            "{case:?}: a read was held"
        );
    } else {
        match fault {
            Fault::OriginalLate => assert_eq!(
                faulted.superseded, 1,
                "{case:?}: the parked original was not dropped"
            ),
            Fault::OriginalRunning => {
                assert_eq!(
                    faulted.early,
                    Some(Early::Held),
                    "{case:?}: nothing was held back for the parked original"
                );
                assert!(faulted.held >= 1, "{case:?}: no request_held event");
            }
            Fault::ReplyLost | Fault::Cancelled | Fault::CancelledRunning => {}
        }
    }
    match expect {
        Pass => assert!(classes.is_empty(), "{case:?} {fault:?} failed: {classes:?}"),
        Fail(expected, why) => assert_eq!(
            classes, expected,
            "{case:?} {fault:?} is expected to fail with {expected:?} ({why})"
        ),
    }
}

macro_rules! grid {
    ($($module:ident($case:expr) { reply_lost: $reply_lost:expr, original_late: $original_late:expr, original_running: $original_running:expr, cancelled: $cancelled:expr, cancelled_running: $cancelled_running:expr $(,)? })*) => {
        $(
            mod $module {
                use super::*;

                #[tokio::test]
                async fn reply_lost() {
                    cell($case, Fault::ReplyLost, $reply_lost).await;
                }

                #[tokio::test]
                async fn original_late() {
                    cell($case, Fault::OriginalLate, $original_late).await;
                }

                #[tokio::test]
                async fn original_running() {
                    cell($case, Fault::OriginalRunning, $original_running).await;
                }

                #[tokio::test]
                async fn cancelled() {
                    cell($case, Fault::Cancelled, $cancelled).await;
                }

                #[tokio::test]
                async fn cancelled_running() {
                    cell($case, Fault::CancelledRunning, $cancelled_running).await;
                }
            }
        )*
    };
}

/// An interrupted call's request still runs on the server, after whatever the caller did next.
const ABANDONED: &str = "the abandoned original lands after the follow-up";

grid! {
    lookup(Case::Lookup) { reply_lost: Pass, original_late: Pass, original_running: Pass, cancelled: Pass, cancelled_running: Pass }
    getattr(Case::Getattr) { reply_lost: Pass, original_late: Pass, original_running: Pass, cancelled: Pass, cancelled_running: Pass }
    readlink(Case::Readlink) { reply_lost: Pass, original_late: Pass, original_running: Pass, cancelled: Pass, cancelled_running: Pass }
    read(Case::Read) { reply_lost: Pass, original_late: Pass, original_running: Pass, cancelled: Pass, cancelled_running: Pass }
    readdir(Case::Readdir) { reply_lost: Pass, original_late: Pass, original_running: Pass, cancelled: Pass, cancelled_running: Pass }
    getxattr(Case::Getxattr) { reply_lost: Pass, original_late: Pass, original_running: Pass, cancelled: Pass, cancelled_running: Pass }
    listxattr(Case::Listxattr) { reply_lost: Pass, original_late: Pass, original_running: Pass, cancelled: Pass, cancelled_running: Pass }
    access(Case::Access) { reply_lost: Pass, original_late: Pass, original_running: Pass, cancelled: Pass, cancelled_running: Pass }
    statfs(Case::Statfs) { reply_lost: Pass, original_late: Pass, original_running: Pass, cancelled: Pass, cancelled_running: Pass }
    lseek(Case::Lseek) { reply_lost: Pass, original_late: Pass, original_running: Pass, cancelled: Pass, cancelled_running: Pass }
    fsync(Case::Fsync) { reply_lost: Pass, original_late: Pass, original_running: Pass, cancelled: Pass, cancelled_running: Pass }
    write(Case::Write) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    write_append(Case::WriteAppend) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    setattr_size(Case::SetattrSize) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    setattr_mode(Case::SetattrMode) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    mknod(Case::Mknod) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    mkdir(Case::Mkdir) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    unlink(Case::Unlink) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    rmdir(Case::Rmdir) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    symlink(Case::Symlink) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    rename(Case::Rename) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    link(Case::Link) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    open(Case::Open) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Pass,
        cancelled_running: Pass,
    }
    open_trunc(Case::OpenTrunc) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Pass,
        cancelled_running: Pass,
    }
    create(Case::Create) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Pass,
        cancelled_running: Pass,
    }
    create_excl(Case::CreateExcl) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Pass,
        cancelled_running: Pass,
    }
    create_trunc(Case::CreateTrunc) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Pass,
        cancelled_running: Pass,
    }
    setxattr(Case::Setxattr) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    setxattr_create(Case::SetxattrCreate) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    setxattr_replace(Case::SetxattrReplace) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    removexattr(Case::Removexattr) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    fallocate(Case::Fallocate) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    copy_file_range(Case::CopyFileRange) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Fail(&[StateLate], ABANDONED),
        cancelled_running: Fail(&[StateLate], ABANDONED),
    }
    opendir(Case::Opendir) {
        reply_lost: Pass,
        original_late: Pass,
        original_running: Pass,
        cancelled: Pass,
        cancelled_running: Pass,
    }
    release(Case::Release) { reply_lost: Pass, original_late: Pass, original_running: Pass, cancelled: Pass, cancelled_running: Pass }
    releasedir(Case::Releasedir) { reply_lost: Pass, original_late: Pass, original_running: Pass, cancelled: Pass, cancelled_running: Pass }
}

//! Real servers on loopback for the client tests: the jackalopefs server itself, and a "blackhole" that completes the handshake and then never answers a request.

#![allow(dead_code)]

use jackalopefs_client::ids::ModeIds as ModeIdsClient;
use jackalopefs_client::{Client, Config, ServerTrust};
use jackalopefs_proto::{read_frame, write_frame, Auth, Hello, HelloReply, Request, Response};
use jackalopefs_server::export::Export;
use jackalopefs_server::ids::{IdMap, ModeIds};
use jackalopefs_server::perf::Perf;
use jackalopefs_server::session::{self, Notification, Server};
use jackalopefs_server::tls::{self, Identity};
use jackalopefs_server::watch::{self, ChangeLog, EventBatch, WatcherHandle, Watches};
use jackalopefs_server::Limits;
use parking_lot::Mutex;
use quinn::{Connection, Endpoint, EndpointConfig, TokioRuntime};
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

/// Directories a test server watches at most, besides the export root, unless a test says otherwise.
pub const WATCH_BUDGET: usize = 1024;

pub struct TestServer {
    pub addr: SocketAddr,
    pub fingerprint: [u8; 32],
    pub server: Arc<Server>,
    pub events: broadcast::Sender<Arc<EventBatch>>,
    endpoint: Endpoint,
    task: tokio::task::JoinHandle<()>,
    _watcher: Option<WatcherHandle>,
    launch: Launch,
}

/// Everything a [`TestServer`] was started with but its socket, so it can be started again as it was.
#[derive(Clone)]
struct Launch {
    export: std::path::PathBuf,
    token: Option<String>,
    identity: Identity,
    watch_budget: Option<usize>,
    ids: ModeIds,
    handle_share: usize,
}

impl Launch {
    /// The defaults every constructor starts from: no token, a fresh identity, the usual watch budget, owners passed through, and no handle limit worth reporting.
    fn new(export: &Path) -> Launch {
        Launch {
            export: export.to_path_buf(),
            token: None,
            identity: Identity::generate().unwrap(),
            watch_budget: Some(WATCH_BUDGET),
            ids: ModeIds::Direct,
            handle_share: jackalopefs_server::handles::SHARE_MAX,
        }
    }
}

fn any_port() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").unwrap()
}

/// A [`TestServer`] stopped by [`TestServer::stop_held`]. Its port stays bound, so no other test can take it, and the connection attempt a client makes during the outage waits in the socket's buffer for the restarted server to answer.
pub struct TestServerStopped {
    socket: UdpSocket,
    launch: Launch,
}

impl TestServerStopped {
    /// The server back on its port with its identity and settings, as a restarted server is; it remembers no session.
    pub async fn start(self) -> TestServer {
        TestServer::start_full(self.socket, self.launch).await
    }
}

impl TestServer {
    pub async fn start(export: &Path, token: Option<String>) -> TestServer {
        TestServer::start_on(export, token, any_port()).await
    }

    pub async fn start_on(export: &Path, token: Option<String>, socket: UdpSocket) -> TestServer {
        TestServer::start_full(
            socket,
            Launch {
                token,
                ..Launch::new(export)
            },
        )
        .await
    }

    /// A server that sends no change events, so a test can see what the client's own refreshes find out.
    pub async fn start_unwatched(export: &Path) -> TestServer {
        TestServer::start_full(
            any_port(),
            Launch {
                watch_budget: None,
                ..Launch::new(export)
            },
        )
        .await
    }

    /// A server that watches at most `budget` directories besides the export root.
    pub async fn start_watching(export: &Path, budget: usize) -> TestServer {
        TestServer::start_full(
            any_port(),
            Launch {
                watch_budget: Some(budget),
                ..Launch::new(export)
            },
        )
        .await
    }

    /// A server that reports a session past `share` handles, with a pool that never runs out.
    pub async fn start_sharing(export: &Path, share: usize) -> TestServer {
        TestServer::start_full(
            any_port(),
            Launch {
                handle_share: share,
                ..Launch::new(export)
            },
        )
        .await
    }

    /// A server with the given owner policy; every other constructor passes owners through (`direct`), so tests about something else see the export's own.
    pub async fn start_ids(export: &Path, ids: ModeIds) -> TestServer {
        TestServer::start_full(
            any_port(),
            Launch {
                ids,
                ..Launch::new(export)
            },
        )
        .await
    }

    /// Start with a given identity, as a restarted server does when it reloads its persisted certificate.
    pub async fn start_with(
        export: &Path,
        token: Option<String>,
        socket: UdpSocket,
        identity: Identity,
    ) -> TestServer {
        TestServer::start_full(
            socket,
            Launch {
                token,
                identity,
                ..Launch::new(export)
            },
        )
        .await
    }

    async fn start_full(socket: UdpSocket, launch: Launch) -> TestServer {
        // The server binary zeroes its umask so client modes are honoured; the in-process server needs the same.
        unsafe { libc::umask(0) };
        let Launch {
            export,
            token,
            identity,
            watch_budget,
            ids,
            handle_share,
        } = launch.clone();
        let export = export.as_path();
        let fingerprint = jackalopefs_proto::fingerprint_bytes(identity.cert.as_ref());
        let config = tls::server_config(identity, jackalopefs_server::transport_config()).unwrap();
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(config),
            socket,
            Arc::new(TokioRuntime),
        )
        .unwrap();
        let (events, _) = broadcast::channel(64);
        let changes = Arc::new(ChangeLog::default());
        let opened = Arc::new(Export::open(export).unwrap());
        let perf = Arc::new(Perf::default());
        let (watches, watcher) = match watch_budget {
            Some(budget) => watch::spawn(
                opened.clone(),
                export,
                budget,
                perf.events.clone(),
                changes.clone(),
                events.clone(),
            ),
            None => (Watches::disabled(), None),
        };
        let server = Arc::new(Server::new(
            opened,
            token,
            Notification {
                events: events.clone(),
                changes,
                watches,
            },
            perf,
            Limits {
                connections: 64,
                handle_share,
                handle_pool: usize::MAX,
            },
            IdMap::of_process(ids).unwrap(),
        ));
        let task = tokio::spawn(session::serve(endpoint.clone(), server.clone()));
        TestServer {
            addr: endpoint.local_addr().unwrap(),
            fingerprint,
            server,
            events,
            endpoint,
            task,
            _watcher: watcher,
            launch,
        }
    }

    /// Stop the server but keep its port, for [`TestServerStopped::start`].
    pub async fn stop_held(self) -> TestServerStopped {
        let port = self.addr.port();
        let launch = self.launch.clone();
        self.stop().await;
        let socket = wait_for(Duration::from_secs(5), "the port to be free again", || {
            UdpSocket::bind(("127.0.0.1", port)).ok()
        })
        .await;
        TestServerStopped { socket, launch }
    }

    /// Close every connection and release the socket.
    pub async fn stop(self) {
        self.endpoint
            .close(session::close_code::SHUTDOWN.into(), b"test stop");
        self.task.await.unwrap();
        self.endpoint.wait_idle().await;
    }

    pub fn config(&self, offline_timeout: Duration) -> Config {
        config_for(
            self.addr,
            self.fingerprint,
            Auth::Anonymous,
            offline_timeout,
        )
    }

    pub async fn client(&self) -> Client {
        Client::connect(self.config(Duration::from_secs(10)))
            .await
            .unwrap()
    }
}

/// A client with the production default of no deadline on a request in flight; tests that need one set `op_timeout` themselves.
pub fn config_for(
    addr: SocketAddr,
    fingerprint: [u8; 32],
    auth: Auth,
    offline_timeout: Duration,
) -> Config {
    Config {
        server_addrs: vec![addr],
        server_name: "jackalopefs".into(),
        trust: ServerTrust::Fingerprint(fingerprint),
        auth,
        connect_timeout: Duration::from_secs(5),
        op_timeout: None,
        offline_timeout,
        // Owners as the server has them, so tests about something else see the export's own.
        ids: ModeIdsClient::Direct,
    }
}

/// The ids a [`Blackhole`] says it runs as: not the test's own, so what a client maps is visible.
pub const SERVER_UID: u32 = 4242;
pub const SERVER_GID: u32 = 4343;

/// How a [`Blackhole`] answers a request.
pub type Answer = Arc<dyn Fn(&Request) -> Response + Send + Sync>;

/// Accepts connections and answers the hello from a list (one reply per connection in order, the last one repeating; a refusal closes that connection), then either swallows every request forever (recording when the client gives up on a stream) or answers each with what `answer` makes of it.
pub struct Blackhole {
    pub addr: SocketAddr,
    pub fingerprint: [u8; 32],
    pub requests: Arc<Mutex<Vec<Request>>>,
    /// Every connection accepted, in order, so a test can close one.
    pub connections: Arc<Mutex<Vec<Connection>>>,
    /// STOP_SENDING codes received on swallowed request streams, i.e. cancellations the client made explicit.
    pub stops: Arc<Mutex<Vec<u64>>>,
    endpoint: Endpoint,
}

impl Blackhole {
    pub async fn start() -> Blackhole {
        Blackhole::start_with(None).await
    }

    pub async fn start_with(canned: Option<Response>) -> Blackhole {
        Blackhole::start_full(canned, vec![Blackhole::ack()]).await
    }

    /// A server that answers every request as `answer` says: a script of a filesystem, for what the real server cannot be made to produce.
    pub async fn start_answering(
        answer: impl Fn(&Request) -> Response + Send + Sync + 'static,
    ) -> Blackhole {
        Blackhole::start_answer(Some(Arc::new(answer)), vec![Blackhole::ack()]).await
    }

    /// Answers every request as `answer` says, and each connection's hello from `hellos` as [`Self::start_handshaking`] does.
    pub async fn start_answering_handshaking(
        answer: impl Fn(&Request) -> Response + Send + Sync + 'static,
        hellos: Vec<HelloReply>,
    ) -> Blackhole {
        Blackhole::start_answer(Some(Arc::new(answer)), hellos).await
    }

    pub async fn start_handshaking(hellos: Vec<HelloReply>) -> Blackhole {
        Blackhole::start_full(None, hellos).await
    }

    pub fn ack() -> HelloReply {
        HelloReply::Ack {
            session_id: 1,
            resume_token: [0; 16],
            resumed: false,
            root_ino: 2,
            root_identity: jackalopefs_proto::Identity {
                handle_type: 1,
                handle: vec![2, 0, 0, 0, 0, 0, 0, 0],
            },
            uid: SERVER_UID,
            gid: SERVER_GID,
        }
    }

    /// Answer the hellos in turn (the last repeating) and every request with `canned`.
    pub async fn start_full(canned: Option<Response>, hellos: Vec<HelloReply>) -> Blackhole {
        let answer = canned.map(|reply| -> Answer { Arc::new(move |_: &Request| reply.clone()) });
        Blackhole::start_answer(answer, hellos).await
    }

    async fn start_answer(answer: Option<Answer>, hellos: Vec<HelloReply>) -> Blackhole {
        let identity = Identity::generate().unwrap();
        let fingerprint = jackalopefs_proto::fingerprint_bytes(identity.cert.as_ref());
        let config = tls::server_config(identity, jackalopefs_server::transport_config()).unwrap();
        let endpoint = Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stops = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let accept_endpoint = endpoint.clone();
        let seen = requests.clone();
        let seen_stops = stops.clone();
        let accepted = connections.clone();
        let hellos = Arc::new(hellos);
        tokio::spawn(async move {
            let mut count = 0usize;
            while let Some(incoming) = accept_endpoint.accept().await {
                let seen = seen.clone();
                let seen_stops = seen_stops.clone();
                let answer = answer.clone();
                let reply = hellos[count.min(hellos.len() - 1)].clone();
                count += 1;
                let accepted = accepted.clone();
                tokio::spawn(async move {
                    let conn = incoming.await.unwrap();
                    accepted.lock().push(conn.clone());
                    let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                    let _hello: Hello = read_frame(&mut recv).await.unwrap();
                    let refused = !matches!(reply, HelloReply::Ack { .. });
                    write_frame(&mut send, &reply).await.unwrap();
                    send.finish().unwrap();
                    if refused {
                        // As the real server does: let the client read the reply, then close.
                        if tokio::time::timeout(Duration::from_secs(2), send.stopped())
                            .await
                            .is_err()
                        {
                            eprintln!("blackhole: the client did not read the refusal in time");
                        }
                        conn.close(session::close_code::HANDSHAKE.into(), b"refused");
                        return;
                    }
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let seen = seen.clone();
                        let seen_stops = seen_stops.clone();
                        let answer = answer.clone();
                        tokio::spawn(async move {
                            let req = match read_frame::<_, Request>(&mut recv).await {
                                Ok(req) => Some(req),
                                Err(e) => {
                                    eprintln!("blackhole: unreadable request, not answered: {e}");
                                    None
                                }
                            };
                            let reply = answer
                                .as_ref()
                                .zip(req.as_ref())
                                .map(|(answer, req)| answer(req));
                            if let Some(req) = req {
                                seen.lock().push(req);
                            }
                            match reply {
                                Some(reply) => {
                                    write_frame(&mut send, &reply).await.unwrap();
                                    send.finish().unwrap();
                                }
                                None => {
                                    if let Ok(Some(code)) = send.stopped().await {
                                        seen_stops.lock().push(code.into_inner());
                                    }
                                }
                            }
                        });
                    }
                });
            }
        });
        Blackhole {
            addr: endpoint.local_addr().unwrap(),
            fingerprint,
            requests,
            connections,
            stops,
            endpoint,
        }
    }

    pub fn config(&self, offline_timeout: Duration) -> Config {
        config_for(
            self.addr,
            self.fingerprint,
            Auth::Anonymous,
            offline_timeout,
        )
    }
}

/// For a test that opens by path and says which inode number it means, as the FUSE layer says which file: the node is the inode number, or the open is refused as stale.
pub fn expect_ino(
    attr: &jackalopefs_proto::Attr,
    ino: u64,
) -> Result<u64, jackalopefs_client::Error> {
    if attr.ino == ino {
        Ok(ino)
    } else {
        Err(jackalopefs_client::Error::Stale)
    }
}

pub fn name(s: &str) -> jackalopefs_proto::Name {
    jackalopefs_proto::Name::new(s.as_bytes()).unwrap()
}

pub fn path(s: &str) -> jackalopefs_proto::Path {
    if s.is_empty() {
        return jackalopefs_proto::Path::root();
    }
    jackalopefs_proto::Path::from_names(s.split('/').map(name).collect()).unwrap()
}

/// Poll `check` until it returns `Some`, or panic after `limit`.
pub async fn wait_for<T>(limit: Duration, what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if let Some(v) = check() {
            return v;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Where a [`Gate`] holds the request it is armed for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hold {
    Before,
    After,
}

/// A request the server ran while a [`Gate`] was installed: its operation, its handle, and its errno (`None` for success).
#[derive(Clone, Debug)]
pub struct Dispatched {
    pub op: &'static str,
    pub fh: Option<u64>,
    pub errno: Option<i32>,
}

/// The request a [`Gate`] took.
#[derive(Clone, Debug)]
pub struct Taken {
    pub fh: Option<u64>,
    pub parked: bool,
    /// Its errno once it has run (`Some(None)` for success); `None` while it has not.
    pub ran: Option<Option<i32>>,
}

#[derive(Default)]
struct GateState {
    armed: Option<(&'static str, Hold)>,
    taken: Option<Taken>,
    released: bool,
    log: Vec<Dispatched>,
}

#[derive(Default)]
struct GateInner {
    state: std::sync::Mutex<GateState>,
    release: std::sync::Condvar,
}

impl GateInner {
    fn state(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Hold the taken request's blocking thread until the gate is released.
    fn park(&self, mut state: std::sync::MutexGuard<'_, GateState>) {
        state
            .taken
            .as_mut()
            .expect("only the taken request parks")
            .parked = true;
        drop(
            self.release
                .wait_while(state, |state| !state.released)
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
    }
}

/// A server's dispatch hook that parks the first request of one operation, once armed, before or after it runs until the test releases it, and logs every request the server runs. Dropping it releases the parked request, so a failing test cannot leave a blocking thread that the runtime's shutdown waits on forever.
pub struct Gate {
    inner: Arc<GateInner>,
}

impl Gate {
    /// Install a fresh gate on `server`.
    pub fn install(server: &TestServer) -> Gate {
        let inner = Arc::new(GateInner::default());
        let hooked = inner.clone();
        let hook: session::HookDispatch = Arc::new(move |req| {
            let (op, fh) = (req.op_name(), req.perf_fields().0);
            let mut state = hooked.state();
            let hold = match state.armed {
                Some((armed, hold)) if armed == op && state.taken.is_none() => {
                    state.taken = Some(Taken {
                        fh,
                        parked: false,
                        ran: None,
                    });
                    Some(hold)
                }
                _ => None,
            };
            if hold == Some(Hold::Before) {
                hooked.park(state);
            } else {
                drop(state);
            }
            let hooked = hooked.clone();
            Some(Box::new(move |resp: &Response| {
                let errno = match resp {
                    Response::Err(errno) => Some(*errno),
                    _ => None,
                };
                let mut state = hooked.state();
                state.log.push(Dispatched { op, fh, errno });
                if hold.is_none() {
                    return;
                }
                state
                    .taken
                    .as_mut()
                    .expect("the gate took this request")
                    .ran = Some(errno);
                if hold == Some(Hold::After) {
                    hooked.park(state);
                }
            }))
        });
        if server.server.dispatch_hook.set(hook).is_err() {
            panic!("the server already has a dispatch hook");
        }
        Gate { inner }
    }

    /// Park the next request for `op` at `hold`; later ones, a resend included, go through.
    pub fn arm(&self, op: &'static str, hold: Hold) {
        self.inner.state().armed = Some((op, hold));
    }

    pub async fn wait_parked(&self) {
        wait_for(
            Duration::from_secs(5),
            "the gate to park its request",
            || {
                self.inner
                    .state()
                    .taken
                    .as_ref()
                    .is_some_and(|taken| taken.parked)
                    .then_some(())
            },
        )
        .await;
    }

    pub fn taken(&self) -> Option<Taken> {
        self.inner.state().taken.clone()
    }

    pub fn released(&self) -> bool {
        self.inner.state().released
    }

    pub fn release(&self) {
        self.inner.state().released = true;
        self.inner.release.notify_all();
    }

    pub fn log(&self) -> Vec<Dispatched> {
        self.inner.state().log.clone()
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.release();
    }
}

/// One path in a [`snapshot`]: what a client could see of it, short of times and inode numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntrySnapshot {
    pub kind: &'static str,
    pub mode: u32,
    pub nlink: u64,
    /// The first path, in sorted order, of the files sharing this one's inode, so hard links show without inode numbers.
    pub link_group: std::path::PathBuf,
    /// A file's size and contents; a symlink's target. Directory sizes are left out: they depend on the filesystem.
    pub size: Option<u64>,
    pub data: Vec<u8>,
    pub xattrs: std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Everything under `root` (the root itself included, as `""`), by path relative to it.
pub fn snapshot(root: &Path) -> std::collections::BTreeMap<std::path::PathBuf, EntrySnapshot> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let mut entries = std::collections::BTreeMap::new();
    let mut groups: std::collections::HashMap<u64, std::path::PathBuf> = Default::default();
    let mut pending = vec![std::path::PathBuf::new()];
    let mut seen = Vec::new();
    while let Some(rel) = pending.pop() {
        let full = root.join(&rel);
        let meta = std::fs::symlink_metadata(&full).unwrap();
        let kind = meta.file_type();
        if kind.is_dir() {
            for entry in std::fs::read_dir(&full).unwrap() {
                pending.push(rel.join(entry.unwrap().file_name()));
            }
        }
        seen.push((rel, meta));
    }
    seen.sort_by(|a, b| a.0.cmp(&b.0));
    for (rel, meta) in seen {
        let full = root.join(&rel);
        let kind = meta.file_type();
        let (kind_name, size, data) = if kind.is_dir() {
            ("dir", None, Vec::new())
        } else if kind.is_symlink() {
            let target = std::fs::read_link(&full).unwrap();
            (
                "symlink",
                None,
                target.into_os_string().into_encoded_bytes(),
            )
        } else if kind.is_fifo() {
            ("fifo", None, Vec::new())
        } else if kind.is_file() {
            ("file", Some(meta.len()), std::fs::read(&full).unwrap())
        } else {
            ("other", None, Vec::new())
        };
        let link_group = groups
            .entry(meta.ino())
            .or_insert_with(|| rel.clone())
            .clone();
        let xattrs = if kind.is_symlink() {
            Default::default()
        } else {
            user_xattrs(&full)
        };
        entries.insert(
            rel,
            EntrySnapshot {
                kind: kind_name,
                mode: meta.mode() & 0o7777,
                nlink: if kind.is_dir() { 0 } else { meta.nlink() },
                link_group,
                size,
                data,
                xattrs,
            },
        );
    }
    entries
}

/// The `user.` extended attributes of `path`, by name.
fn user_xattrs(path: &Path) -> std::collections::BTreeMap<Vec<u8>, Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut names = vec![0u8; 64 * 1024];
    // SAFETY: `c` is NUL-terminated and `names` is writable for its length.
    let n = unsafe { libc::llistxattr(c.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    assert!(
        n >= 0,
        "listing xattrs of {path:?}: {}",
        std::io::Error::last_os_error()
    );
    names.truncate(n as usize);
    let mut xattrs = std::collections::BTreeMap::new();
    for name in names.split(|b| *b == 0).filter(|n| n.starts_with(b"user.")) {
        let cname = std::ffi::CString::new(name).unwrap();
        let mut value = vec![0u8; 64 * 1024];
        // SAFETY: both strings are NUL-terminated and `value` is writable for its length.
        let n = unsafe {
            libc::lgetxattr(
                c.as_ptr(),
                cname.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        assert!(
            n >= 0,
            "reading xattr {name:?} of {path:?}: {}",
            std::io::Error::last_os_error()
        );
        value.truncate(n as usize);
        xattrs.insert(name.to_vec(), value);
    }
    xattrs
}

/// The connection a client has attached at `generation` or later, waiting up to 15 s for it.
pub async fn wait_for_generation(
    client: &Client,
    generation: u64,
) -> Arc<jackalopefs_client::conn::Attached> {
    let mut state = client.state();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let jackalopefs_client::ConnState::Connected(att) = &*state.borrow_and_update() {
            if att.generation >= generation {
                return att.clone();
            }
        }
        tokio::time::timeout_at(deadline, state.changed())
            .await
            .expect("reconnect in time")
            .unwrap();
    }
}

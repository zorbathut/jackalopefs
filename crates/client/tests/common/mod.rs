//! Real servers on loopback for the client tests: the jackalopefs server itself, and a "blackhole" that completes the handshake and then never answers a request.

#![allow(dead_code)]

use jackalopefs_client::ids::ModeIds as ModeIdsClient;
use jackalopefs_client::{Client, Config, ServerTrust};
use jackalopefs_proto::{read_frame, write_frame, Auth, Hello, HelloReply, Request, Response};
use jackalopefs_server::export::Export;
use jackalopefs_server::ids::{IdMap, ModeIds};
use jackalopefs_server::session::{self, Server};
use jackalopefs_server::tls::{self, Identity};
use jackalopefs_server::watch::{self, ChangeLog, EventBatch, WatcherHandle};
use jackalopefs_server::Limits;
use parking_lot::Mutex;
use quinn::{Connection, Endpoint, EndpointConfig, TokioRuntime};
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

pub struct TestServer {
    pub addr: SocketAddr,
    pub fingerprint: [u8; 32],
    pub server: Arc<Server>,
    pub events: broadcast::Sender<Arc<EventBatch>>,
    endpoint: Endpoint,
    task: tokio::task::JoinHandle<()>,
    _watcher: Option<WatcherHandle>,
}

impl TestServer {
    pub async fn start(export: &Path, token: Option<String>) -> TestServer {
        TestServer::start_on(export, token, UdpSocket::bind("127.0.0.1:0").unwrap()).await
    }

    pub async fn start_on(export: &Path, token: Option<String>, socket: UdpSocket) -> TestServer {
        TestServer::start_with(export, token, socket, Identity::generate().unwrap()).await
    }

    /// A server that sends no change events, so a test can see what the client's own refreshes find out.
    pub async fn start_unwatched(export: &Path) -> TestServer {
        TestServer::start_full(
            export,
            None,
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            Identity::generate().unwrap(),
            false,
            ModeIds::Direct,
        )
        .await
    }

    /// A server with the given owner policy; every other constructor passes owners through (`direct`), so tests about something else see the export's own.
    pub async fn start_ids(export: &Path, ids: ModeIds) -> TestServer {
        TestServer::start_full(
            export,
            None,
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            Identity::generate().unwrap(),
            true,
            ids,
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
        TestServer::start_full(export, token, socket, identity, true, ModeIds::Direct).await
    }

    async fn start_full(
        export: &Path,
        token: Option<String>,
        socket: UdpSocket,
        identity: Identity,
        watched: bool,
        ids: ModeIds,
    ) -> TestServer {
        // The server binary zeroes its umask so client modes are honoured; the in-process server needs the same.
        unsafe { libc::umask(0) };
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
        let watcher = if watched {
            watch::spawn(export, changes.clone(), events.clone())
        } else {
            None
        };
        let server = Arc::new(Server::new(
            Arc::new(Export::open(export).unwrap()),
            token,
            events.clone(),
            changes,
            Limits {
                connections: 64,
                handles_per_session: jackalopefs_server::handles::MAX_HANDLES,
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
        }
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

//! Real servers on loopback for the client tests: the jackalopefs server itself, and a "blackhole" that completes the handshake and then never answers a request.

#![allow(dead_code)]

use jackalopefs_client::{Client, Config, ServerTrust};
use jackalopefs_proto::{read_frame, write_frame, Auth, Hello, HelloReply, Request, Response};
use jackalopefs_server::export::Export;
use jackalopefs_server::session::{self, Server};
use jackalopefs_server::tls::{self, Identity};
use jackalopefs_server::watch::{self, ChangeLog, EventBatch, WatcherHandle};
use parking_lot::Mutex;
use quinn::{Endpoint, EndpointConfig, TokioRuntime};
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

    /// Start with a given identity, as a restarted server does when it reloads its persisted certificate.
    pub async fn start_with(
        export: &Path,
        token: Option<String>,
        socket: UdpSocket,
        identity: Identity,
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
        let watcher = watch::spawn(export, changes.clone(), events.clone());
        let server = Arc::new(Server::new(
            Arc::new(Export::open(export).unwrap()),
            token,
            events.clone(),
            changes,
            64,
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

    pub fn config(&self, op_timeout: Duration) -> Config {
        config_for(self.addr, self.fingerprint, Auth::Anonymous, op_timeout)
    }

    pub async fn client(&self) -> Client {
        Client::connect(self.config(Duration::from_secs(10)))
            .await
            .unwrap()
    }
}

pub fn config_for(
    addr: SocketAddr,
    fingerprint: [u8; 32],
    auth: Auth,
    op_timeout: Duration,
) -> Config {
    Config {
        server_addr: addr,
        server_name: "jackalopefs".into(),
        trust: ServerTrust::Fingerprint(fingerprint),
        auth,
        connect_timeout: Duration::from_secs(5),
        op_timeout,
    }
}

/// Accepts connections and completes the hello, then either swallows every request forever (recording when the client gives up on a stream) or answers every one with the same canned reply.
pub struct Blackhole {
    pub addr: SocketAddr,
    pub fingerprint: [u8; 32],
    pub requests: Arc<Mutex<Vec<Request>>>,
    /// STOP_SENDING codes received on swallowed request streams, i.e. cancellations the client made explicit.
    pub stops: Arc<Mutex<Vec<u64>>>,
    endpoint: Endpoint,
}

impl Blackhole {
    pub async fn start() -> Blackhole {
        Blackhole::start_with(None).await
    }

    pub async fn start_with(canned: Option<Response>) -> Blackhole {
        let identity = Identity::generate().unwrap();
        let fingerprint = jackalopefs_proto::fingerprint_bytes(identity.cert.as_ref());
        let config = tls::server_config(identity, jackalopefs_server::transport_config()).unwrap();
        let endpoint = Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stops = Arc::new(Mutex::new(Vec::new()));
        let accept_endpoint = endpoint.clone();
        let seen = requests.clone();
        let seen_stops = stops.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accept_endpoint.accept().await {
                let seen = seen.clone();
                let seen_stops = seen_stops.clone();
                let canned = canned.clone();
                tokio::spawn(async move {
                    let conn = incoming.await.unwrap();
                    let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                    let _hello: Hello = read_frame(&mut recv).await.unwrap();
                    write_frame(
                        &mut send,
                        &HelloReply::Ack {
                            session_id: 1,
                            resume_token: [0; 16],
                            resumed: false,
                        },
                    )
                    .await
                    .unwrap();
                    send.finish().unwrap();
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let seen = seen.clone();
                        let seen_stops = seen_stops.clone();
                        let canned = canned.clone();
                        tokio::spawn(async move {
                            if let Ok(req) = read_frame::<_, Request>(&mut recv).await {
                                seen.lock().push(req);
                            }
                            match canned {
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
            stops,
            endpoint,
        }
    }

    pub fn config(&self, op_timeout: Duration) -> Config {
        config_for(self.addr, self.fingerprint, Auth::Anonymous, op_timeout)
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

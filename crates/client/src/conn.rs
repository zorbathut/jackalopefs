//! The connection manager: one background task that owns the QUIC connection, reconnects with backoff when it drops, resumes (or reopens) the handle table, and forwards the server's event stream.

use crate::client::{exchange, Error, Timing};
use crate::handles::{HandleKind, HandleTable};
use crate::transport::{client_config, ServerTrust};
use jackalopefs_proto::{
    read_frame, write_frame, Auth, Event, EventItem, Hello, HelloReply, Resume, PROTO_REVISION,
};
use quinn::{Connection, Endpoint};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;

const BACKOFF_MIN: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(5);
const EVENT_QUEUE: usize = 256;
const BIND_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
const BIND_V6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);

/// Application error codes sent in CONNECTION_CLOSE.
pub mod close_code {
    pub const UNMOUNT: u32 = 0;
    pub const CANCELLED: u32 = 3;
}

#[derive(Clone, Debug)]
pub struct ConfigConn {
    /// Every address the server name resolved to, in the resolver's order; they are tried in turn and the one that answers is tried first from then on.
    pub server_addrs: Vec<SocketAddr>,
    /// SNI name; the server's self-signed certificate is not checked against it, only against the fingerprint.
    pub server_name: String,
    pub trust: ServerTrust,
    pub auth: Auth,
    pub connect_timeout: Duration,
    pub op_timeout: Duration,
}

/// A live, handshaken connection.
#[derive(Debug)]
pub struct Attached {
    pub conn: Connection,
    pub session_id: u64,
    pub resumed: bool,
    /// Increments with every successful connection; callers that lost a reply wait for a strictly newer generation before retrying.
    pub generation: u64,
}

#[derive(Clone, Debug)]
pub enum ConnState {
    Connecting,
    Connected(Arc<Attached>),
    /// The manager has stopped for good (unmount, or the first connection attempt failed).
    Closed,
}

pub struct ConnManager {
    pub state: watch::Receiver<ConnState>,
    events: Option<mpsc::Receiver<Event>>,
    stop: watch::Sender<bool>,
    task: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// One per address family among the candidates; closed at unmount.
    endpoints: Vec<Endpoint>,
}

/// A failed connection attempt, naming the address it was made to.
#[derive(Debug, thiserror::Error)]
#[error("{addr}: {kind}")]
pub struct ErrorConnect {
    pub addr: SocketAddr,
    pub kind: ErrorConnectKind,
}

#[derive(Debug, thiserror::Error)]
pub enum ErrorConnectKind {
    #[error("connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("control stream: {0}")]
    Codec(#[from] jackalopefs_proto::ErrorCodec),
    #[error("server rejected the session: {0}")]
    Rejected(String),
    #[error("protocol revision mismatch: this client speaks {client:016x}, the server {server:016x}; both must be built from the same schema")]
    Revision { client: u64, server: u64 },
    #[error("timed out")]
    Timeout,
}

impl ErrorConnectKind {
    fn at(self, addr: SocketAddr) -> ErrorConnect {
        ErrorConnect { addr, kind: self }
    }
}

impl ConnManager {
    /// Establish the first connection (failing loudly if it can't be made) and start the reconnect loop.
    pub async fn start(cfg: ConfigConn, handles: Arc<HandleTable>) -> anyhow::Result<ConnManager> {
        anyhow::ensure!(
            !cfg.server_addrs.is_empty(),
            "no server address to connect to"
        );
        let (endpoints, candidates) =
            bind_candidates(&cfg.server_addrs, client_config(cfg.trust.clone())?)?;
        let (state_tx, state_rx) = watch::channel(ConnState::Connecting);
        let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE);
        let (stop_tx, stop_rx) = watch::channel(false);
        let (first_tx, first_rx) = oneshot::channel();
        let task = tokio::spawn(run(
            cfg, candidates, handles, state_tx, events_tx, stop_rx, first_tx,
        ));
        match first_rx.await {
            Ok(Ok(())) => Ok(ConnManager {
                state: state_rx,
                events: Some(events_rx),
                stop: stop_tx,
                task: parking_lot::Mutex::new(Some(task)),
                endpoints,
            }),
            Ok(Err(e)) => {
                close_all(&endpoints, b"connect failed");
                Err(anyhow::anyhow!(e))
            }
            Err(_) => Err(anyhow::anyhow!(
                "connection manager exited before the first connection"
            )),
        }
    }

    /// The server's event stream; can be taken once.
    pub fn take_events(&mut self) -> Option<mpsc::Receiver<Event>> {
        self.events.take()
    }

    /// Stop reconnecting and close the endpoint without waiting; for drop paths that cannot await.
    pub fn stop_now(&self) {
        if self.stop.send(true).is_err() {
            tracing::debug!("connection manager already stopped");
        }
        close_all(&self.endpoints, b"unmount");
    }

    /// Close the connection and stop reconnecting; safe to call more than once.
    pub async fn shutdown(&self) {
        if self.stop.send(true).is_err() {
            tracing::debug!("connection manager already stopped");
        }
        let task = self.task.lock().take();
        if let Some(task) = task {
            if let Err(e) = timeout(Duration::from_secs(5), task).await {
                tracing::warn!("connection manager did not stop in time: {e}");
            }
        }
        close_all(&self.endpoints, b"unmount");
        for endpoint in &self.endpoints {
            if timeout(Duration::from_secs(2), endpoint.wait_idle())
                .await
                .is_err()
            {
                tracing::debug!("endpoint did not drain before shutdown deadline");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    cfg: ConfigConn,
    mut candidates: Vec<Candidate>,
    handles: Arc<HandleTable>,
    state: watch::Sender<ConnState>,
    events: mpsc::Sender<Event>,
    mut stop: watch::Receiver<bool>,
    first: oneshot::Sender<Result<(), ErrorConnect>>,
) {
    let mut first = Some(first);
    let mut resume: Option<Resume> = None;
    let mut generation = 0u64;
    let mut backoff = BACKOFF_MIN;
    let mut failures = 0u32;
    loop {
        if *stop.borrow() {
            break;
        }
        if state.send(ConnState::Connecting).is_err() {
            break;
        }
        let attempt = tokio::select! {
            attempt = connect_any(&cfg, &candidates, resume) => attempt,
            _ = stop.changed() => break,
        };
        let (winner, attached) = match attempt {
            Ok(connected) => connected,
            Err(e) => {
                if let Some(first) = first.take() {
                    if first.send(Err(e)).is_err() {
                        tracing::debug!("nobody waiting for the first connection result");
                    }
                    break;
                }
                failures += 1;
                // A revision mismatch is refused every time until one side is rebuilt; retrying still lets a server rollback recover the mount, and every refusal is logged so the reason is never far up the log.
                if matches!(e.kind, ErrorConnectKind::Revision { .. }) {
                    tracing::error!(failures, "reconnect refused: {e}; retrying in {backoff:?}");
                } else if failures == 1 || failures.is_power_of_two() {
                    tracing::warn!(failures, "reconnect failed: {e}; retrying in {backoff:?}");
                }
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = stop.changed() => break,
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };
        failures = 0;
        backoff = BACKOFF_MIN;
        generation += 1;
        resume = Some(Resume {
            session_id: attached.session_id,
            token: attached.resume_token,
        });
        // Try the address that answered first from now on, so a dead candidate ahead of it costs its deadline once instead of on every reconnect.
        candidates.rotate_left(winner);
        let (conn, resumed) = (attached.conn, attached.resumed);
        tracing::info!(
            session = attached.session_id,
            resumed,
            generation,
            "connected to {}",
            attached.addr
        );

        if !resumed {
            tokio::select! {
                _ = reopen_handles(&conn, &handles, cfg.op_timeout) => {}
                _ = stop.changed() => {
                    conn.close(close_code::UNMOUNT.into(), b"unmount");
                    break;
                }
            }
        }
        let attached = Arc::new(Attached {
            conn: conn.clone(),
            session_id: attached.session_id,
            resumed,
            generation,
        });
        if state.send(ConnState::Connected(attached)).is_err() {
            break;
        }
        if let Some(first) = first.take() {
            if first.send(Ok(())).is_err() {
                tracing::debug!("nobody waiting for the first connection result");
            }
        }
        let reader = tokio::spawn(read_events(conn.clone(), events.clone()));
        tokio::select! {
            reason = conn.closed() => {
                tracing::warn!(generation, "connection lost: {reason}");
            }
            _ = stop.changed() => {
                conn.close(close_code::UNMOUNT.into(), b"unmount");
                reader.abort();
                break;
            }
        }
        reader.abort();
    }
    if state.send(ConnState::Closed).is_err() {
        tracing::debug!("connection state has no subscribers at shutdown");
    }
}

struct Handshaken {
    conn: Connection,
    addr: SocketAddr,
    session_id: u64,
    resume_token: [u8; 16],
    resumed: bool,
}

/// A resolved server address and the socket that can reach it.
type Candidate = (SocketAddr, Endpoint);

fn close_all(endpoints: &[Endpoint], reason: &[u8]) {
    for endpoint in endpoints {
        endpoint.close(close_code::UNMOUNT.into(), reason);
    }
}

/// A socket for each address family the candidates need, and every candidate paired with the socket that can reach it. Two sockets rather than one dual-stack socket, because whether an IPv6 socket also reaches IPv4 peers is the host's decision (`bindv6only`, a sandboxed setsockopt) and quinn reports losing that argument only at debug level; a family that cannot be bound at all then costs its own candidates rather than every candidate.
fn bind_candidates(
    addrs: &[SocketAddr],
    config: quinn::ClientConfig,
) -> anyhow::Result<(Vec<Endpoint>, Vec<Candidate>)> {
    let mut refusal = None;
    let mut bind = |wildcard: SocketAddr, wanted: bool| -> Option<Endpoint> {
        if !wanted {
            return None;
        }
        match Endpoint::client(wildcard) {
            Ok(mut endpoint) => {
                endpoint.set_default_client_config(config.clone());
                Some(endpoint)
            }
            Err(e) => {
                tracing::warn!("cannot bind {wildcard}: {e}");
                refusal = Some(e);
                None
            }
        }
    };
    let v4 = bind(BIND_V4, addrs.iter().any(|addr| addr.is_ipv4()));
    let v6 = bind(BIND_V6, addrs.iter().any(|addr| addr.is_ipv6()));
    let candidates: Vec<Candidate> = addrs
        .iter()
        .filter_map(|&addr| {
            let endpoint = if addr.is_ipv6() {
                v6.clone()
            } else {
                v4.clone()
            };
            match endpoint {
                Some(endpoint) => Some((addr, endpoint)),
                None => {
                    tracing::warn!("dropping {addr}: no socket for its address family");
                    None
                }
            }
        })
        .collect();
    if candidates.is_empty() {
        return Err(match refusal {
            Some(e) => anyhow::Error::new(e).context("no usable client socket"),
            None => anyhow::anyhow!("no server address to connect to"),
        });
    }
    Ok(([v4, v6].into_iter().flatten().collect(), candidates))
}

/// Try the candidates in order, each on its own connect deadline, and take the first that completes the handshake. A refusal ends the sweep: it is an answer from a reachable server, every address behind the name would give the same one, and a later address's timeout would bury the reason.
async fn connect_any(
    cfg: &ConfigConn,
    candidates: &[Candidate],
    resume: Option<Resume>,
) -> Result<(usize, Handshaken), ErrorConnect> {
    let mut worst: Option<ErrorConnect> = None;
    for (i, (addr, endpoint)) in candidates.iter().enumerate() {
        let attempt = timeout(
            cfg.connect_timeout,
            connect_once(endpoint, cfg, *addr, resume),
        )
        .await
        .unwrap_or(Err(ErrorConnectKind::Timeout));
        match attempt {
            Ok(handshaken) => return Ok((i, handshaken)),
            Err(kind @ (ErrorConnectKind::Rejected(_) | ErrorConnectKind::Revision { .. })) => {
                return Err(kind.at(*addr))
            }
            Err(kind) => {
                let e = kind.at(*addr);
                // Only worth its own line when there is another address to move on to; with one candidate the caller reports this same failure.
                if candidates.len() > 1 {
                    tracing::warn!("{e}");
                }
                // A timeout says nothing about the server, so it never displaces an address that did answer: a fingerprint or protocol failure has to survive to the caller even when a later address goes unanswered.
                if worst.is_none() || !matches!(e.kind, ErrorConnectKind::Timeout) {
                    worst = Some(e);
                }
            }
        }
    }
    // bind_candidates refuses a list with nothing reachable in it, so the loop ran at least once.
    Err(worst.expect("a candidate list is never empty"))
}

async fn connect_once(
    endpoint: &Endpoint,
    cfg: &ConfigConn,
    addr: SocketAddr,
    resume: Option<Resume>,
) -> Result<Handshaken, ErrorConnectKind> {
    let conn = endpoint.connect(addr, &cfg.server_name)?.await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    write_frame(
        &mut send,
        &Hello {
            revision: PROTO_REVISION,
            auth: cfg.auth.clone(),
            resume,
        },
    )
    .await?;
    if let Err(e) = send.finish() {
        tracing::debug!("control stream already closed: {e}");
    }
    match read_frame::<_, HelloReply>(&mut recv).await? {
        HelloReply::Ack {
            session_id,
            resume_token,
            resumed,
        } => Ok(Handshaken {
            conn,
            addr,
            session_id,
            resume_token,
            resumed,
        }),
        HelloReply::Reject { reason } => {
            conn.close(close_code::UNMOUNT.into(), b"rejected");
            Err(ErrorConnectKind::Rejected(reason))
        }
        HelloReply::RevisionMismatch { revision } => {
            conn.close(close_code::UNMOUNT.into(), b"revision mismatch");
            Err(ErrorConnectKind::Revision {
                client: PROTO_REVISION,
                server: revision,
            })
        }
    }
}

/// The server has no memory of our handles: reopen each by path, concurrently, keep only those that still name the same inode, and release the rest so the server doesn't hold what we won't use. Every step has the operation deadline, and the steps run concurrently, so the whole phase is bounded by two of them.
async fn reopen_handles(conn: &Connection, handles: &HandleTable, op_timeout: Duration) {
    let live = handles.live();
    if live.is_empty() {
        return;
    }
    tracing::info!(count = live.len(), "reopening handles after a new session");
    let mut reopens = tokio::task::JoinSet::new();
    for (fh, rec) in live {
        let conn = conn.clone();
        reopens.spawn(async move {
            let outcome = match timeout(
                op_timeout,
                exchange(&conn, &rec.reopen_request(fh), &mut Timing::default()),
            )
            .await
            {
                Ok(result) => result.map_err(Error::from),
                Err(_) => Err(Error::Timeout),
            };
            (fh, rec, outcome)
        });
    }
    let mut releases = tokio::task::JoinSet::new();
    while let Some(joined) = reopens.join_next().await {
        match joined {
            Ok((fh, rec, outcome)) => {
                handles.apply_reopen(fh, &rec, outcome);
                if rec.is_dead() {
                    let conn = conn.clone();
                    let release = match rec.kind {
                        HandleKind::File => jackalopefs_proto::Request::Release { fh },
                        HandleKind::Dir => jackalopefs_proto::Request::Releasedir { fh },
                    };
                    releases.spawn(async move {
                        match timeout(
                            op_timeout,
                            exchange(&conn, &release, &mut Timing::default()),
                        )
                        .await
                        {
                            Ok(Ok(_)) => {}
                            Ok(Err(e)) => {
                                tracing::debug!(fh, "releasing a stale handle failed: {e:?}")
                            }
                            Err(_) => tracing::debug!(fh, "releasing a stale handle timed out"),
                        }
                    });
                }
            }
            Err(e) => tracing::error!("reopen task failed: {e}"),
        }
    }
    while let Some(joined) = releases.join_next().await {
        if let Err(e) = joined {
            tracing::error!("release task failed: {e}");
        }
    }
}

/// Reads the server's uni event stream into the bounded queue. When the consumer falls behind, batches are dropped and a single `Overflow` is queued as soon as there is room, so the consumer knows to distrust its cache rather than miss changes silently.
async fn read_events(conn: Connection, events: mpsc::Sender<Event>) {
    let mut recv = match conn.accept_uni().await {
        Ok(recv) => recv,
        Err(e) => {
            tracing::debug!("no event stream: {e}");
            return;
        }
    };
    let mut overflow_pending = false;
    loop {
        let event: Event = match read_frame(&mut recv).await {
            Ok(event) => event,
            Err(e) => {
                tracing::debug!("event stream ended: {e}");
                return;
            }
        };
        if overflow_pending {
            match events.try_send(Event {
                items: vec![EventItem::Overflow],
            }) {
                Ok(()) => overflow_pending = false,
                Err(_) => continue,
            }
        }
        match events.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("event queue full; collapsing to an overflow");
                overflow_pending = true;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => return,
        }
    }
}

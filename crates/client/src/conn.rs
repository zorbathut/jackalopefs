//! The connection manager: one background task that owns the QUIC connection, reconnects with backoff when it drops, resumes (or reopens) the handle table, and forwards the server's event stream.
//!
//! Connections by generation, reopens, publishing and the releases sent in the background are modelled in `spec/session.qnt`; a change to them updates the model, or its commit says why not (`spec/README.md`, "Keeping it in sync").

use crate::client::{exchange, given_up, Error, ErrorExchange, KeyRoot, Tapping, Timing};
use crate::handles::HandleTable;
use crate::ids::{IdMap, ModeIds};
use crate::machine::{counts_give_up, owed_sendable, AttachedState, ReopenRound};
use crate::perf::{Perf, Slowpath};
use crate::transport::{client_config, ServerTrust};
use jackalopefs_perf::hub::{Hub, IdsEvent, Side};
use jackalopefs_perf::spec_trace::Origin;
use jackalopefs_proto::control::{HandlesProcess, HandlesTotals};
use jackalopefs_proto::{
    read_frame, read_frame_body, write_frame, Auth, Event, EventItem, Hello, HelloReply,
    NoticeHandles, Response, Resume, PROTO_REVISION,
};
use quinn::{Connection, Endpoint};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{timeout, Instant};

const BACKOFF_MIN: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(5);
const EVENT_QUEUE: usize = 256;
const BIND_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
const BIND_V6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);

/// Application error codes sent in CONNECTION_CLOSE.
pub mod close_code {
    pub const UNMOUNT: u32 = 0;
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
    /// Bounds each step of reopening the handles after a new session, and how long an outage lasts before it is logged as failing calls at once.
    pub offline_timeout: Duration,
    pub ids: ModeIds,
}

/// A live, handshaken connection.
#[derive(Debug)]
pub struct Attached {
    pub conn: Connection,
    pub session_id: u64,
    pub resumed: bool,
    /// [`conn_key`](jackalopefs_perf::conn_key): what the server's lines call this connection.
    pub conn_key: Option<u64>,
    pub root: KeyRoot,
    pub ids: IdMap,
    /// Its generation, pending cancels and publication.
    pub state: AttachedState,
}

#[derive(Clone, Debug)]
pub enum ConnState {
    /// No connection since `since`: when the last one was lost, or when the manager started.
    Connecting {
        since: Instant,
    },
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
    /// `perf` is where the frames of reconnects, releases and events go when a tap captures them, and where the server's notices are counted.
    pub async fn start(
        cfg: ConfigConn,
        handles: Arc<HandleTable>,
        perf: Arc<Perf>,
    ) -> anyhow::Result<ConnManager> {
        anyhow::ensure!(
            !cfg.server_addrs.is_empty(),
            "no server address to connect to"
        );
        let (endpoints, candidates) =
            bind_candidates(&cfg.server_addrs, client_config(cfg.trust.clone())?)?;
        let (state_tx, state_rx) = watch::channel(ConnState::Connecting {
            since: Instant::now(),
        });
        let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE);
        let (stop_tx, stop_rx) = watch::channel(false);
        let (first_tx, first_rx) = oneshot::channel();
        let offline_timeout = cfg.offline_timeout;
        let task = tokio::spawn(run(
            cfg, candidates, handles, perf, state_tx, events_tx, stop_rx, first_tx,
        ));
        match first_rx.await {
            Ok(Ok(())) => {
                tokio::spawn(announce_outages(state_rx.clone(), offline_timeout));
                Ok(ConnManager {
                    state: state_rx,
                    events: Some(events_rx),
                    stop: stop_tx,
                    task: parking_lot::Mutex::new(Some(task)),
                    endpoints,
                })
            }
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
    perf: Arc<Perf>,
    state: watch::Sender<ConnState>,
    events: mpsc::Sender<Event>,
    mut stop: watch::Receiver<bool>,
    first: oneshot::Sender<Result<(), ErrorConnect>>,
) {
    let hub = perf.hub.clone();
    let mut first = Some(first);
    let mut resume: Option<Resume> = None;
    let mut generation = 0u64;
    let mut root_mounted: Option<KeyRoot> = None;
    let mut backoff = BACKOFF_MIN;
    let mut failures = 0u32;
    let mut offline_since = Instant::now();
    loop {
        if *stop.borrow() {
            break;
        }
        if state
            .send(ConnState::Connecting {
                since: offline_since,
            })
            .is_err()
        {
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
        let (conn, resumed, root, ids) =
            (attached.conn, attached.resumed, attached.root, attached.ids);
        let conn_key = jackalopefs_perf::conn_key(&conn);
        jackalopefs_perf::spec_trace!(
            hub.recorder(),
            jackalopefs_perf::spec_trace::EventSpec::Connected {
                generation,
                conn: conn_key.unwrap_or(0),
                session: attached.session_id,
                resumed,
            }
        );
        tracing::info!(
            session = attached.session_id,
            resumed,
            generation,
            conn = conn_key,
            offline = (generation > 1)
                .then(|| tracing::field::display(format!("{:.1?}", offline_since.elapsed()))),
            ids = ids.describe(),
            "connected to {}",
            attached.addr
        );
        if let Some(caveat) = ids.caveat() {
            tracing::warn!("{caveat}");
        }

        // The mount is of one directory. If the server now serves another one here (the export replaced or restored, a filesystem whose handles did not survive a remount), every name may lead to another file: nothing open can be reopened by its path, and what the kernel caches is swept as after any reconnect.
        if root_mounted
            .as_ref()
            .is_some_and(|mounted| *mounted != root)
        {
            tracing::error!(was = ?root_mounted, now = ?root, "the server's export is not the directory this mount attached to; every open file is stale");
            handles.kill_all();
        }
        root_mounted = Some(root.clone());
        let tapping = Tapping {
            hub: &hub,
            session: attached.session_id,
            conn: conn_key,
        };
        // Made before the reopens, which count on its pending cancels the ones they give up on, so that a stale release waits for the answer.
        let attached_state = AttachedState::new(generation);
        let restore = async {
            if !resumed {
                handles.owed_moot();
                reopen_handles(
                    &conn,
                    &root,
                    ids,
                    &handles,
                    cfg.offline_timeout,
                    &attached_state.cancels,
                    tapping,
                )
                .await
            }
        };
        tokio::select! {
            () = restore => {}
            _ = stop.changed() => {
                conn.close(close_code::UNMOUNT.into(), b"unmount");
                break;
            }
        };
        let attached = Arc::new(Attached {
            conn: conn.clone(),
            session_id: attached.session_id,
            resumed,
            conn_key,
            root: root.clone(),
            ids,
            state: attached_state,
        });
        let releasing_on = attached.clone();
        // Recorded first, since a call can take the connection as soon as it is published.
        jackalopefs_perf::spec_trace!(
            hub.recorder(),
            jackalopefs_perf::spec_trace::EventSpec::Published {
                conn: conn_key.unwrap_or(0)
            }
        );
        attached.state.publish();
        if state.send(ConnState::Connected(attached)).is_err() {
            break;
        }
        if let Some(first) = first.take() {
            if first.send(Ok(())).is_err() {
                tracing::debug!("nobody waiting for the first connection result");
            }
        }
        // The handles this client no longer has are released once the connection is published, so a server slow to answer holds up no call: their ids are never reused, and nothing on this side waits on them. Each release owed from then on is sent on this connection too. The next connection waits for the releasing to end, so one this connection could not deliver stays owed for its resume to send.
        let releasing = {
            let (handles, hub) = (handles.clone(), hub.clone());
            tokio::spawn(async move {
                send_releases(releasing_on, &handles, hub).await;
            })
        };
        let reader = tokio::spawn(read_events(
            conn.clone(),
            events.clone(),
            perf.clone(),
            handles.clone(),
            tapping.session,
            conn_key,
        ));
        tokio::select! {
            reason = conn.closed() => {
                jackalopefs_perf::spec_trace!(hub.recorder(), jackalopefs_perf::spec_trace::EventSpec::ConnLost { conn: conn_key.unwrap_or(0) });
                offline_since = Instant::now();
                tracing::warn!(generation, "connection lost: {reason}");
            }
            _ = stop.changed() => {
                conn.close(close_code::UNMOUNT.into(), b"unmount");
                reader.abort();
                if let Err(e) = releasing.await {
                    tracing::error!("release task failed: {e}");
                }
                break;
            }
        }
        reader.abort();
        if let Err(e) = releasing.await {
            tracing::error!("release task failed: {e}");
        }
    }
    if state.send(ConnState::Closed).is_err() {
        tracing::debug!("connection state has no subscribers at shutdown");
    }
}

/// Log each outage once it has lasted the offline timeout, the moment calls start failing at once; started after the first connection, so a slow mount is not reported as an outage, and ends with the manager.
async fn announce_outages(mut state: watch::Receiver<ConnState>, offline_timeout: Duration) {
    let mut announced = None;
    loop {
        let since = match *state.borrow_and_update() {
            ConnState::Connecting { since } if announced != Some(since) => Some(since),
            _ => None,
        };
        let changed = match since {
            Some(since) => tokio::select! {
                _ = tokio::time::sleep_until(since + offline_timeout) => {
                    tracing::warn!("connection lost {:.1?} ago: calls fail with ETIMEDOUT at once until it is back", since.elapsed());
                    announced = Some(since);
                    continue;
                }
                changed = state.changed() => changed,
            },
            None => state.changed().await,
        };
        if changed.is_err() {
            return;
        }
    }
}

struct Handshaken {
    conn: Connection,
    addr: SocketAddr,
    session_id: u64,
    resume_token: [u8; 16],
    resumed: bool,
    root: KeyRoot,
    ids: IdMap,
}

/// A resolved server address and the socket that can reach it.
type Candidate = (SocketAddr, Endpoint);

fn close_all(endpoints: &[Endpoint], reason: &[u8]) {
    for endpoint in endpoints {
        endpoint.close(close_code::UNMOUNT.into(), reason);
    }
}

/// A client endpoint on `wildcard`, as `Endpoint::client` makes one, with its receive buffer sized for the bursts a lone worker leaves waiting.
fn client_endpoint(wildcard: SocketAddr) -> std::io::Result<Endpoint> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(wildcard),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.bind(&wildcard.into())?;
    let socket = std::net::UdpSocket::from(socket);
    jackalopefs_perf::udp_receive_buffer(&socket);
    Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
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
        match client_endpoint(wildcard) {
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
            root_ino,
            root_identity,
            uid,
            gid,
        } => Ok(Handshaken {
            conn,
            addr,
            session_id,
            resume_token,
            resumed,
            root: KeyRoot {
                ino: root_ino,
                identity: root_identity,
            },
            ids: IdMap::new(cfg.ids, uid, gid),
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

/// The server has no memory of our handles: reopen each by path, concurrently, keep only those that still name the same inode, and owe the releases of the rest, so the server doesn't hold what we won't use. Every reopen has the offline deadline: reopening is part of getting the connection back, and the connection is not published until it is done, so a reopen without a bound would keep every call on the mount waiting. The reopens run concurrently, so the whole phase is bounded by one of them.
#[allow(clippy::too_many_arguments)]
async fn reopen_handles(
    conn: &Connection,
    root: &KeyRoot,
    ids: IdMap,
    handles: &HandleTable,
    offline_timeout: Duration,
    cancels: &watch::Sender<usize>,
    tapping: Tapping<'_>,
) {
    let mut round = ReopenRound::new(handles);
    if round.publishable() {
        return;
    }
    tracing::info!(
        count = round.unsent().len(),
        "reopening handles after a new session"
    );
    let mut reopens = tokio::task::JoinSet::new();
    let mut reopening = std::collections::HashMap::new();
    for fh in round.unsent() {
        let reopen = round.send(fh);
        let (conn, root, hub, cancels) = (
            conn.clone(),
            root.clone(),
            tapping.hub.clone(),
            cancels.clone(),
        );
        let (session, conn_key) = (tapping.session, tapping.conn);
        let task = reopens.spawn(async move {
            let tapping = Tapping {
                hub: &hub,
                session,
                conn: conn_key,
            };
            let mut timing = Timing::for_origin(Some(Origin::Reopen(fh)));
            // A reopen given up on is a change given up on: its answer is read in the background and counted until it comes, so the release of its handle waits for it.
            let outcome = match exchange(&conn, &root, &ids, &reopen, &mut timing, tapping, async {
                tokio::time::sleep(offline_timeout).await;
                Error::Timeout
            })
            .await
            {
                Err(ErrorExchange::GaveUp {
                    error,
                    written,
                    pending,
                }) => {
                    let counted = counts_give_up(true, written, true);
                    Err(given_up(
                        error,
                        written,
                        pending.filter(|_| counted),
                        &cancels,
                        tapping,
                        &timing,
                    ))
                }
                exchanged => exchanged.map_err(Error::from),
            };
            (fh, outcome)
        });
        reopening.insert(task.id(), fh);
    }
    while !round.publishable() {
        match reopens.join_next_with_id().await {
            Some(Ok((_, (fh, outcome)))) => round.ended(handles, fh, outcome),
            Some(Err(e)) => {
                tracing::error!("reopen task failed: {e}");
                // Its handle is held all the same, so it is dead, and its release owed.
                let fh = reopening[&e.id()];
                round.ended(
                    handles,
                    fh,
                    Err(Error::Protocol(format!("reopen task failed: {e}"))),
                );
            }
            None => unreachable!("a round with reopens to end has their tasks"),
        }
    }
}

/// Send the releases owed, concurrently, for as long as the connection lasts: each as soon as it is owed and the connection's pending cancels (`AttachedState::cancels`) are answered, since each is ordered like any change and one of those may be the open of its id. Each goes once on this connection; one the server does not answer stays owed, for the session's next connection: sending it again here would only have it fail again on the connection that just failed it.
///
/// Every input of that decision (the releases owed, the pending cancels, a release settled) is marked seen before it is looked at, and waited on after, so none that changes in between goes unnoticed.
async fn send_releases(attached: Arc<Attached>, handles: &HandleTable, hub: Arc<Hub>) {
    let mut owed = handles.owed_changes();
    let mut cancels = attached.state.cancels.subscribe();
    let mut sends = tokio::task::JoinSet::new();
    let settle = |joined: Result<
        (u64, Result<Response, ErrorExchange>),
        tokio::task::JoinError,
    >| match joined {
        Ok((fh, Ok(_))) => handles.owed_delivered(fh, attached.state.generation),
        // The server may hold the handle until the session's next connection sends the release again.
        Ok((fh, Err(e))) if attached.conn.close_reason().is_none() => {
            tracing::warn!(fh, "a release owed failed on a live connection: {e:?}; it is sent again on the session's next connection")
        }
        Ok((fh, Err(e))) => tracing::debug!(fh, "a release owed failed with its connection: {e:?}"),
        Err(e) => tracing::error!("release task failed: {e}"),
    };
    loop {
        owed.borrow_and_update();
        {
            let pending = cancels.borrow_and_update();
            for fh in owed_sendable(handles, &attached.state, *pending) {
                let release = handles.owed_send(fh, attached.state.generation);
                // Recorded while the count is read, so no give-up comes between the two.
                #[cfg(feature = "spec-trace")]
                if let Some(recorder) = hub.recorder() {
                    recorder.record(jackalopefs_perf::spec_trace::EventSpec::ReleaseReady {
                        fh,
                        conn: attached.conn_key.unwrap_or(0),
                    });
                }
                let (attached, hub) = (attached.clone(), hub.clone());
                sends.spawn(async move {
                    let tapping = Tapping {
                        hub: &hub,
                        session: attached.session_id,
                        conn: attached.conn_key,
                    };
                    let mut timing = Timing::for_origin(Some(Origin::Owed(fh)));
                    let sent = exchange(
                        &attached.conn,
                        &attached.root,
                        &attached.ids,
                        &release,
                        &mut timing,
                        tapping,
                        std::future::pending(),
                    )
                    .await;
                    (fh, sent)
                });
            }
        }
        tokio::select! {
            changed = owed.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            changed = cancels.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            Some(joined) = sends.join_next() => settle(joined),
            _ = attached.conn.closed() => break,
        }
    }
    while let Some(joined) = sends.join_next().await {
        settle(joined);
    }
    handles.owed_connection_ended(attached.state.generation);
}

/// Most processes a report of the handles names one by one.
const REPORT_PROCESSES: usize = 10;

/// What a report of the handles says, for the server's `notice`: what the server counts and what this client counts, which differ by handles the server holds that this client has not recorded yet (an open whose reply is on its way, the one that crossed the threshold among them), has forgotten, or is still releasing; then the processes that opened them, the largest first.
pub fn lines_handles(
    notice: NoticeHandles,
    totals: HandlesTotals,
    rows: &[HandlesProcess],
) -> Vec<String> {
    let mut lines = vec![format!(
        "the server reports this mount holds {} handles, past its share of {}; this client holds {} ({} files, {} dirs), by the process that opened them:",
        notice.held,
        notice.share,
        totals.files + totals.dirs,
        totals.files,
        totals.dirs
    )];
    for row in rows.iter().take(REPORT_PROCESSES) {
        let who = if row.pid == 0 {
            "(unattributed)".to_owned()
        } else {
            format!("{}[{}]", row.name, row.pid)
        };
        lines.push(format!(
            "  {who} {} files, {} dirs, within {}",
            row.files, row.dirs, row.within
        ));
    }
    if rows.len() > REPORT_PROCESSES {
        let rest = &rows[REPORT_PROCESSES..];
        lines.push(format!(
            "  and {} more processes holding {}",
            rest.len(),
            rest.iter().map(|r| r.files + r.dirs).sum::<u64>()
        ));
    }
    lines
}

fn report_handles(perf: &Perf, handles: &HandleTable, notice: NoticeHandles) {
    let lines = lines_handles(notice, handles.totals(), &handles.processes());
    perf.events.inc(Slowpath::HandlesReported);
    for line in lines {
        tracing::warn!("{line}");
    }
}

/// Reads the server's uni event stream into the bounded queue. When the consumer falls behind, batches are dropped and a single `Overflow` is queued as soon as there is room, so the consumer knows to distrust its cache rather than miss changes silently.
async fn read_events(
    conn: Connection,
    events: mpsc::Sender<Event>,
    perf: Arc<Perf>,
    handles: Arc<HandleTable>,
    session: u64,
    conn_key: Option<u64>,
) {
    let hub = perf.hub.clone();
    let mut recv = match conn.accept_uni().await {
        Ok(recv) => recv,
        Err(e) => {
            tracing::debug!("no event stream: {e}");
            return;
        }
    };
    let tap_ids = IdsEvent {
        session: Some(session),
        conn: conn_key,
        stream: Some(u64::from(recv.id())),
        op: Some("event"),
        ..IdsEvent::default()
    };
    let mut overflow_pending = false;
    for seq in 0u64.. {
        let (body, decoded) = match read_frame_body::<_, Event>(&mut recv).await {
            Ok(read) => read,
            Err(e) => {
                tracing::debug!("event stream ended: {e}");
                return;
            }
        };
        let event = match decoded {
            Ok(event) => event,
            Err(e) => {
                if hub.wants_frames() {
                    hub.undecodable(Side::Client, &tap_ids, &e.to_string(), &body);
                }
                tracing::debug!("event stream ended: {e}");
                return;
            }
        };
        if hub.wants_frames() {
            hub.event_frame(Side::Client, &tap_ids, seq, || Some(body));
        }
        let mut event = event;
        if let Some(notice) = event.handles.take() {
            let (perf, handles) = (perf.clone(), handles.clone());
            // The report walks every handle, which is no work for the runtime's one worker.
            tokio::task::spawn_blocking(move || report_handles(&perf, &handles, notice));
            if event.items.is_empty() {
                continue;
            }
        }
        if overflow_pending {
            match events.try_send(Event {
                items: vec![EventItem::Overflow],
                handles: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pid: u32, held: u64) -> HandlesProcess {
        HandlesProcess {
            pid,
            name: format!("p{pid}"),
            files: 0,
            dirs: held,
            within: format!("/w{pid}"),
        }
    }

    #[test]
    fn a_report_of_the_handles_names_the_largest_openers_and_counts_the_rest() {
        let notice = NoticeHandles {
            held: 4100,
            share: 4080,
        };
        let totals = HandlesTotals {
            files: 7,
            dirs: 4093,
        };
        let rows: Vec<HandlesProcess> = (1..=REPORT_PROCESSES as u32 + 3)
            .map(|pid| row(pid, 100 - u64::from(pid)))
            .chain([HandlesProcess {
                files: 1,
                ..HandlesProcess::default()
            }])
            .collect();
        let lines = lines_handles(notice, totals, &rows);
        assert!(
            lines[0].contains("4100") && lines[0].contains("4080") && lines[0].contains("4093")
        );
        for pid in 1..=REPORT_PROCESSES as u32 {
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains(&format!("p{pid}[{pid}]"))
                        && l.contains(&format!("/w{pid}"))),
                "{pid} in {lines:?}"
            );
        }
        assert!(!lines.iter().any(|l| l.contains("p11[")));
        assert_eq!(lines.len(), 1 + REPORT_PROCESSES + 1, "{lines:?}");
        let few = lines_handles(notice, totals, &rows[..2]);
        assert_eq!(
            few.len(),
            3,
            "no tail line when every opener is named: {few:?}"
        );
    }
}

//! The connection manager: one background task that owns the QUIC connection, reconnects with backoff when it drops, resumes (or reopens) the handle table, and forwards the server's event stream.

use crate::client::{exchange, Error};
use crate::handles::{HandleKind, HandleTable};
use crate::transport::{client_config, ServerTrust};
use jackalopefs_proto::{
    read_frame, write_frame, Auth, Event, EventItem, Hello, HelloReply, Resume, PROTO_VERSION,
};
use quinn::{Connection, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;

const BACKOFF_MIN: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(5);
const EVENT_QUEUE: usize = 256;

/// Application error codes sent in CONNECTION_CLOSE.
pub mod close_code {
    pub const UNMOUNT: u32 = 0;
    pub const CANCELLED: u32 = 3;
}

#[derive(Clone, Debug)]
pub struct ConfigConn {
    pub server_addr: SocketAddr,
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
    endpoint: Endpoint,
}

#[derive(Debug, thiserror::Error)]
pub enum ErrorConnect {
    #[error("connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("control stream: {0}")]
    Codec(#[from] jackalopefs_proto::ErrorCodec),
    #[error("server rejected the session: {0}")]
    Rejected(String),
    #[error("timed out")]
    Timeout,
}

impl ConnManager {
    /// Establish the first connection (failing loudly if it can't be made) and start the reconnect loop.
    pub async fn start(cfg: ConfigConn, handles: Arc<HandleTable>) -> anyhow::Result<ConnManager> {
        let mut endpoint = Endpoint::client(match cfg.server_addr {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().expect("valid address"),
            SocketAddr::V6(_) => "[::]:0".parse().expect("valid address"),
        })?;
        endpoint.set_default_client_config(client_config(cfg.trust.clone())?);
        let (state_tx, state_rx) = watch::channel(ConnState::Connecting);
        let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE);
        let (stop_tx, stop_rx) = watch::channel(false);
        let (first_tx, first_rx) = oneshot::channel();
        let task = tokio::spawn(run(
            cfg,
            endpoint.clone(),
            handles,
            state_tx,
            events_tx,
            stop_rx,
            first_tx,
        ));
        match first_rx.await {
            Ok(Ok(())) => Ok(ConnManager {
                state: state_rx,
                events: Some(events_rx),
                stop: stop_tx,
                task: parking_lot::Mutex::new(Some(task)),
                endpoint,
            }),
            Ok(Err(e)) => {
                endpoint.close(close_code::UNMOUNT.into(), b"connect failed");
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
        self.endpoint.close(close_code::UNMOUNT.into(), b"unmount");
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
        self.endpoint.close(close_code::UNMOUNT.into(), b"unmount");
        if timeout(Duration::from_secs(2), self.endpoint.wait_idle())
            .await
            .is_err()
        {
            tracing::debug!("endpoint did not drain before shutdown deadline");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    cfg: ConfigConn,
    endpoint: Endpoint,
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
        let attempt = timeout(cfg.connect_timeout, connect_once(&endpoint, &cfg, resume))
            .await
            .unwrap_or(Err(ErrorConnect::Timeout));
        let attached = match attempt {
            Ok(attached) => attached,
            Err(e) => {
                if let Some(first) = first.take() {
                    if first.send(Err(e)).is_err() {
                        tracing::debug!("nobody waiting for the first connection result");
                    }
                    break;
                }
                failures += 1;
                if failures == 1 || failures.is_power_of_two() {
                    tracing::warn!(
                        failures,
                        "reconnect to {} failed: {e}; retrying in {backoff:?}",
                        cfg.server_addr
                    );
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
        let (conn, resumed) = (attached.conn, attached.resumed);
        tracing::info!(
            session = attached.session_id,
            resumed,
            generation,
            "connected to {}",
            cfg.server_addr
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
    session_id: u64,
    resume_token: [u8; 16],
    resumed: bool,
}

async fn connect_once(
    endpoint: &Endpoint,
    cfg: &ConfigConn,
    resume: Option<Resume>,
) -> Result<Handshaken, ErrorConnect> {
    let conn = endpoint.connect(cfg.server_addr, &cfg.server_name)?.await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    write_frame(
        &mut send,
        &Hello {
            proto_version: PROTO_VERSION,
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
            session_id,
            resume_token,
            resumed,
        }),
        HelloReply::Reject { reason } => {
            conn.close(close_code::UNMOUNT.into(), b"rejected");
            Err(ErrorConnect::Rejected(reason))
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
            let outcome = match timeout(op_timeout, exchange(&conn, &rec.reopen_request(fh))).await
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
                        match timeout(op_timeout, exchange(&conn, &release)).await {
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

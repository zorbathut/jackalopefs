//! Connection handling: the hello handshake, session resumption, the event stream, and one task per request stream.

use crate::export::Export;
use crate::handles::Handles;
use crate::ops::{self, Ops};
use crate::watch::{ChangeLog, EventBatch};
use crate::SESSION_GRACE;
use jackalopefs_proto::{
    read_frame, write_frame, Auth, Event, EventItem, Hello, HelloReply, Request, Response,
    PROTO_REVISION,
};
use parking_lot::Mutex;
use quinn::{Connection, RecvStream, SendStream};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::{broadcast, Semaphore};
use tokio::time::timeout;

const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);
const EVENT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const REAP_INTERVAL: Duration = Duration::from_secs(5);
const REJECT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const REPLY_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Detached sessions kept for resumption at once; beyond this the oldest is dropped early, closing its handles.
pub const MAX_DETACHED_SESSIONS: usize = 64;

/// Application error codes sent in CONNECTION_CLOSE.
pub mod close_code {
    pub const SHUTDOWN: u32 = 0;
    pub const HANDSHAKE: u32 = 1;
    pub const EVENT_STREAM_STALLED: u32 = 2;
}

pub struct SessionState {
    pub id: u64,
    pub resume_token: [u8; 16],
    pub handles: Arc<Handles>,
    /// `attached` counts attachments so that only the connection currently holding the session can detach it; `detached_at` starts the grace period.
    attachment: Mutex<Attachment>,
}

#[derive(Default)]
struct Attachment {
    epoch: u64,
    detached_at: Option<Instant>,
}

#[derive(Default)]
pub struct Sessions {
    map: Mutex<HashMap<u64, Arc<SessionState>>>,
    next_id: AtomicU64,
}

impl Sessions {
    /// A brand-new session, attached to the caller. Makes room by dropping the longest-detached session when too many are waiting for a resume that may never come.
    pub fn create(&self) -> (Arc<SessionState>, u64) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let state = Arc::new(SessionState {
            id,
            resume_token: rand::random(),
            handles: Arc::new(Handles::default()),
            attachment: Mutex::new(Attachment {
                epoch: 1,
                detached_at: None,
            }),
        });
        let mut map = self.map.lock();
        let mut detached: Vec<(u64, Instant)> = map
            .iter()
            .filter_map(|(id, s)| s.attachment.lock().detached_at.map(|at| (*id, at)))
            .collect();
        if detached.len() >= MAX_DETACHED_SESSIONS {
            detached.sort_by_key(|(_, at)| *at);
            for (old, _) in detached
                .iter()
                .take(detached.len() + 1 - MAX_DETACHED_SESSIONS)
            {
                tracing::warn!(
                    session = old,
                    limit = MAX_DETACHED_SESSIONS,
                    "too many detached sessions; dropping the oldest"
                );
                map.remove(old);
            }
        }
        map.insert(id, state.clone());
        (state, 1)
    }

    /// Reattach `id` if the token matches; a session still attached elsewhere is taken over, since the client evidently lost that connection.
    pub fn resume(&self, id: u64, token: &[u8; 16]) -> Option<(Arc<SessionState>, u64)> {
        let state = self.map.lock().get(&id)?.clone();
        if !bool::from(state.resume_token.ct_eq(token)) {
            return None;
        }
        let mut attachment = state.attachment.lock();
        attachment.epoch += 1;
        attachment.detached_at = None;
        let epoch = attachment.epoch;
        drop(attachment);
        Some((state, epoch))
    }

    /// Mark the session detached, unless a newer connection has already taken it over.
    pub fn detach(&self, id: u64, epoch: u64) {
        let Some(state) = self.map.lock().get(&id).cloned() else {
            return;
        };
        let mut attachment = state.attachment.lock();
        if attachment.epoch == epoch {
            attachment.detached_at = Some(Instant::now());
        }
    }

    /// Drop sessions detached for longer than `grace`, closing their handles.
    pub fn reap(&self, grace: Duration) -> usize {
        let now = Instant::now();
        let mut map = self.map.lock();
        let before = map.len();
        map.retain(|_, state| match state.attachment.lock().detached_at {
            Some(at) => now.duration_since(at) < grace,
            None => true,
        });
        before - map.len()
    }

    pub fn len(&self) -> usize {
        self.map.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, id: u64) -> Option<Arc<SessionState>> {
        self.map.lock().get(&id).cloned()
    }
}

pub struct Server {
    pub export: Arc<Export>,
    pub sessions: Arc<Sessions>,
    pub events: broadcast::Sender<Arc<EventBatch>>,
    pub changes: Arc<ChangeLog>,
    token: Option<String>,
    connection_permits: Arc<Semaphore>,
}

impl Server {
    pub fn new(
        export: Arc<Export>,
        token: Option<String>,
        events: broadcast::Sender<Arc<EventBatch>>,
        changes: Arc<ChangeLog>,
        max_connections: usize,
    ) -> Server {
        Server {
            export,
            sessions: Arc::new(Sessions::default()),
            events,
            changes,
            token,
            connection_permits: Arc::new(Semaphore::new(max_connections)),
        }
    }

    fn authenticate(&self, auth: &Auth) -> Result<(), String> {
        match (&self.token, auth) {
            (None, _) => Ok(()),
            (Some(expected), Auth::Token(given))
                if bool::from(expected.as_bytes().ct_eq(given.as_slice())) =>
            {
                Ok(())
            }
            (Some(_), Auth::Token(_)) => Err("invalid token".to_string()),
            (Some(_), Auth::Anonymous) => Err("this server requires a token".to_string()),
        }
    }
}

/// Accept connections until the endpoint is closed.
pub async fn serve(endpoint: quinn::Endpoint, server: Arc<Server>) {
    let reaper = {
        let sessions = server.sessions.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(REAP_INTERVAL);
            loop {
                tick.tick().await;
                let reaped = sessions.reap(SESSION_GRACE);
                if reaped > 0 {
                    tracing::info!(reaped, "expired detached sessions");
                }
            }
        })
    };
    while let Some(incoming) = endpoint.accept().await {
        let permit = match server.connection_permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(remote = %incoming.remote_address(), "connection limit reached; refusing");
                incoming.refuse();
                continue;
            }
        };
        let server = server.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match incoming.await {
                Ok(conn) => handle_connection(conn, server).await,
                Err(e) => tracing::debug!("connection handshake failed: {e}"),
            }
        });
    }
    reaper.abort();
}

async fn handle_connection(conn: Connection, server: Arc<Server>) {
    let remote = conn.remote_address();
    let (session, epoch, resumed) = match timeout(HELLO_TIMEOUT, handshake(&conn, &server)).await {
        Ok(Ok(attached)) => attached,
        Ok(Err(e)) => {
            match &e {
                ErrorHandshake::Revision { client } => tracing::warn!(
                    %remote,
                    client_revision = %format_args!("{client:016x}"),
                    server_revision = %format_args!("{PROTO_REVISION:016x}"),
                    "refusing: {e}"
                ),
                _ => tracing::info!(%remote, "handshake failed: {e}"),
            }
            conn.close(close_code::HANDSHAKE.into(), b"handshake");
            return;
        }
        Err(_) => {
            tracing::info!(%remote, "handshake timed out");
            conn.close(close_code::HANDSHAKE.into(), b"handshake timeout");
            return;
        }
    };
    tracing::info!(%remote, session = session.id, resumed, "session attached");
    let _detach = DetachOnDrop {
        sessions: server.sessions.clone(),
        session: session.clone(),
        epoch,
        remote,
    };
    let events = tokio::spawn(forward_events(
        conn.clone(),
        server.events.subscribe(),
        session.id,
    ));
    let ops = Arc::new(Ops {
        export: server.export.clone(),
        handles: session.handles.clone(),
        session_id: session.id,
        changes: server.changes.clone(),
    });
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                tokio::spawn(handle_request(ops.clone(), send, recv));
            }
            Err(e) => {
                tracing::debug!(session = session.id, "connection ended: {e}");
                break;
            }
        }
    }
    events.abort();
}

/// Starts the session's grace period however the connection task ends, including by panic.
struct DetachOnDrop {
    sessions: Arc<Sessions>,
    session: Arc<SessionState>,
    epoch: u64,
    remote: std::net::SocketAddr,
}

impl Drop for DetachOnDrop {
    fn drop(&mut self) {
        self.sessions.detach(self.session.id, self.epoch);
        tracing::info!(remote = %self.remote, session = self.session.id, open_handles = self.session.handles.len(), "session detached");
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorHandshake {
    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("control stream: {0}")]
    Codec(#[from] jackalopefs_proto::ErrorCodec),
    #[error("rejected: {0}")]
    Rejected(String),
    #[error(
        "protocol revision mismatch: the client speaks {client:016x}, this server {:016x}",
        PROTO_REVISION
    )]
    Revision { client: u64 },
}

/// A handshake the server turns down: what the client is told, and what the log gets.
struct Refusal {
    reply: HelloReply,
    error: ErrorHandshake,
}

async fn handshake(
    conn: &Connection,
    server: &Server,
) -> Result<(Arc<SessionState>, u64, bool), ErrorHandshake> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let hello: Hello = read_frame(&mut recv).await?;
    // The revision is checked before the token so that a peer built from another schema learns that, whatever its credentials.
    let outcome = if hello.revision != PROTO_REVISION {
        Err(Refusal {
            reply: HelloReply::RevisionMismatch {
                revision: PROTO_REVISION,
            },
            error: ErrorHandshake::Revision {
                client: hello.revision,
            },
        })
    } else {
        match server.authenticate(&hello.auth) {
            Ok(()) => {
                let resumed = hello
                    .resume
                    .and_then(|r| server.sessions.resume(r.session_id, &r.token));
                Ok(match resumed {
                    Some((state, epoch)) => (state, epoch, true),
                    None => {
                        let (state, epoch) = server.sessions.create();
                        (state, epoch, false)
                    }
                })
            }
            Err(reason) => Err(Refusal {
                reply: HelloReply::Reject {
                    reason: reason.clone(),
                },
                error: ErrorHandshake::Rejected(reason),
            }),
        }
    };
    match outcome {
        Ok((state, epoch, resumed)) => {
            write_frame(
                &mut send,
                &HelloReply::Ack {
                    session_id: state.id,
                    resume_token: state.resume_token,
                    resumed,
                },
            )
            .await?;
            if let Err(e) = send.finish() {
                tracing::debug!("control stream already closed: {e}");
            }
            Ok((state, epoch, resumed))
        }
        Err(Refusal { reply, error }) => {
            write_frame(&mut send, &reply).await?;
            if let Err(e) = send.finish() {
                tracing::debug!("control stream already closed: {e}");
            }
            // Closing the connection discards undelivered stream data, so give the client a moment to read the reason.
            if timeout(REJECT_DRAIN_TIMEOUT, send.stopped()).await.is_err() {
                tracing::debug!("client did not read the rejection in time");
            }
            Err(error)
        }
    }
}

/// Copy event batches to this session's uni stream, dropping its own echoes; a lagging receiver tells the client to distrust everything instead of silently losing events.
async fn forward_events(
    conn: Connection,
    mut events: broadcast::Receiver<Arc<EventBatch>>,
    session_id: u64,
) {
    let mut send = match conn.open_uni().await {
        Ok(send) => send,
        Err(e) => {
            tracing::debug!(session_id, "could not open event stream: {e}");
            return;
        }
    };
    loop {
        let event = match events.recv().await {
            Ok(batch) => batch.for_session(session_id),
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(
                    session_id,
                    dropped = n,
                    "event stream lagged; sending overflow"
                );
                Some(Event {
                    items: vec![EventItem::Overflow],
                })
            }
            Err(broadcast::error::RecvError::Closed) => break,
        };
        let Some(event) = event else { continue };
        match timeout(EVENT_WRITE_TIMEOUT, write_frame(&mut send, &event)).await {
            Ok(Ok(())) => {}
            Ok(Err(e @ jackalopefs_proto::ErrorCodec::TooLarge(_))) => {
                tracing::warn!(
                    session_id,
                    "event batch could not be sent: {e}; the client falls back to its cache TTL"
                );
                break;
            }
            Ok(Err(e)) => {
                tracing::debug!(session_id, "event stream closed: {e}");
                break;
            }
            Err(_) => {
                tracing::warn!(
                    session_id,
                    "client stopped draining the event stream; closing connection"
                );
                conn.close(
                    close_code::EVENT_STREAM_STALLED.into(),
                    b"event stream stalled",
                );
                break;
            }
        }
    }
}

async fn handle_request(ops: Arc<Ops>, mut send: SendStream, mut recv: RecvStream) {
    let req: Request = match timeout(REQUEST_READ_TIMEOUT, read_frame(&mut recv)).await {
        Ok(Ok(req)) => req,
        Ok(Err(e)) if e.is_eof() => {
            tracing::debug!("request cancelled before it was fully sent");
            return;
        }
        Ok(Err(jackalopefs_proto::ErrorCodec::Io(e))) => {
            tracing::debug!("request stream ended: {e}");
            return;
        }
        Ok(Err(jackalopefs_proto::ErrorCodec::Decode(
            jackalopefs_proto::ErrorDecode::NotInSchema(n),
        ))) => {
            tracing::info!(
                discriminant = n,
                "request uses a schema variant this server does not know; the client may be newer"
            );
            return;
        }
        Ok(Err(e)) => {
            tracing::warn!("malformed request: {e}");
            return;
        }
        Err(_) => {
            tracing::debug!("request read timed out");
            return;
        }
    };
    let op = req.op_name();
    let started = Instant::now();
    let resp = match tokio::task::spawn_blocking(move || ops::dispatch(&ops, req)).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(op, "operation panicked: {e}");
            Response::Err(nix::errno::Errno::EIO as i32)
        }
    };
    tracing::trace!(
        op,
        elapsed_us = started.elapsed().as_micros() as u64,
        "done"
    );
    match timeout(REPLY_WRITE_TIMEOUT, write_frame(&mut send, &resp)).await {
        Ok(Ok(())) => {
            if let Err(e) = send.finish() {
                tracing::debug!(op, "reply stream already closed: {e}");
            }
        }
        Ok(Err(e)) => tracing::debug!(op, "reply not delivered: {e}"),
        Err(_) => {
            tracing::warn!(op, "client is not reading its reply; abandoning it");
            if let Err(e) = send.reset(close_code::EVENT_STREAM_STALLED.into()) {
                tracing::debug!(op, "reset after stalled reply: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_resume_detach_and_reap() {
        let sessions = Sessions::default();
        let (state, epoch) = sessions.create();
        assert!(
            sessions.resume(state.id, &[0u8; 16]).is_none(),
            "wrong token"
        );
        assert!(
            sessions.resume(state.id + 1, &state.resume_token).is_none(),
            "unknown id"
        );

        let (again, new_epoch) = sessions.resume(state.id, &state.resume_token).unwrap();
        assert!(Arc::ptr_eq(&state, &again));
        assert!(new_epoch > epoch);

        sessions.detach(state.id, epoch);
        assert_eq!(
            sessions.reap(Duration::ZERO),
            0,
            "a stale epoch cannot detach a taken-over session"
        );
        sessions.detach(state.id, new_epoch);
        assert_eq!(
            sessions.reap(Duration::from_secs(60)),
            0,
            "still inside the grace period"
        );
        assert_eq!(sessions.reap(Duration::ZERO), 1);
        assert!(sessions.is_empty());
    }

    #[test]
    fn detached_sessions_are_capped() {
        let sessions = Sessions::default();
        let mut ids = Vec::new();
        for _ in 0..MAX_DETACHED_SESSIONS {
            let (state, epoch) = sessions.create();
            sessions.detach(state.id, epoch);
            ids.push(state.id);
        }
        assert_eq!(sessions.len(), MAX_DETACHED_SESSIONS);
        let (fresh, _) = sessions.create();
        assert_eq!(
            sessions.len(),
            MAX_DETACHED_SESSIONS,
            "creating one more evicted the oldest detached session"
        );
        assert!(sessions.get(ids[0]).is_none());
        assert!(sessions.get(ids[1]).is_some());
        assert!(sessions.get(fresh.id).is_some());
    }
}

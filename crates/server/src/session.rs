//! Connection handling: the hello handshake, session resumption, the event stream, and one task per request stream.

use crate::export::Export;
use crate::handles::{HandlePool, Handles};
use crate::ids::IdMap;
use crate::ops::{self, Ops};
use crate::perf::{Outcome, Perf, Phases, Slowpath, EVENT_TARGET, TRACE_TARGET};
use crate::watch::{ChangeLog, EventBatch, Watches};
use crate::{Limits, SESSION_GRACE};
use jackalopefs_perf::event;
use jackalopefs_perf::hub::{elided, Hub, IdsEvent, Side};
use jackalopefs_perf::{
    fmt_duration, line_process, line_quic, line_udp, lines_link, verdict, MeterLink, MeterProcess,
    MeterUdp, SampleLink, TrackerQuic,
};
use jackalopefs_proto::control::{HandlesSession, HandlesTotals, Summary};
use jackalopefs_proto::{
    encode, read_frame, read_frame_body, write_frame, Auth, Event, EventItem, Hello, HelloReply,
    NoticeHandles, Request, Response, PROTO_REVISION,
};
use parking_lot::Mutex;
use quinn::{Connection, RecvStream, SendStream};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
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
    /// The session has resumed on a newer connection: this one's requests are no longer its own.
    pub const SUPERSEDED: u32 = 3;
}

/// An attached session's connection, the attachment epoch it belongs to, and the tracker of its last sample.
#[derive(Clone)]
pub struct ConnectionEntry {
    pub epoch: u64,
    pub conn: Connection,
    pub tracker: Arc<Mutex<TrackerQuic>>,
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
    /// The client's address on the connection that last attached.
    remote: Option<std::net::SocketAddr>,
}

pub struct Sessions {
    map: Mutex<HashMap<u64, Arc<SessionState>>>,
    next_id: AtomicU64,
    /// The handles a session holds before it is reported.
    handle_share: usize,
    /// The handles every session draws on.
    pool: Arc<HandlePool>,
}

impl Sessions {
    pub fn new(handle_share: usize, pool: Arc<HandlePool>) -> Sessions {
        Sessions {
            map: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            handle_share,
            pool,
        }
    }

    pub fn pool(&self) -> &HandlePool {
        &self.pool
    }

    /// A brand-new session, attached to the caller. Makes room by dropping the longest-detached session when too many are waiting for a resume that may never come.
    pub fn create(&self) -> (Arc<SessionState>, u64) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let state = Arc::new(SessionState {
            id,
            resume_token: rand::random(),
            handles: Arc::new(Handles::new(self.handle_share, self.pool.clone())),
            attachment: Mutex::new(Attachment {
                epoch: 1,
                ..Attachment::default()
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

    /// Every session's handles by kind, its client's last address and whether it is detached, in id order.
    pub fn handle_rows(&self) -> Vec<HandlesSession> {
        let mut rows: Vec<HandlesSession> = self
            .map
            .lock()
            .iter()
            .map(|(id, s)| {
                let totals = s.handles.totals();
                let attachment = s.attachment.lock();
                HandlesSession {
                    session: *id,
                    remote: attachment
                        .remote
                        .map_or_else(String::new, |remote| remote.to_string()),
                    detached: attachment.detached_at.is_some(),
                    files: totals.files,
                    dirs: totals.dirs,
                }
            })
            .collect();
        rows.sort_unstable_by_key(|row| row.session);
        rows
    }

    /// The handles every session holds, by kind.
    pub fn handle_totals(&self) -> HandlesTotals {
        self.map.lock().values().map(|s| s.handles.totals()).fold(
            HandlesTotals::default(),
            |sum, t| HandlesTotals {
                files: sum.files + t.files,
                dirs: sum.dirs + t.dirs,
            },
        )
    }
}

pub struct Server {
    pub export: Arc<Export>,
    pub sessions: Arc<Sessions>,
    pub events: broadcast::Sender<Arc<EventBatch>>,
    pub changes: Arc<ChangeLog>,
    pub watches: Arc<Watches>,
    /// Which owners cross to clients; its ids are this process's, which the hello tells every client.
    pub ids: IdMap,
    /// Request accounting across every session.
    pub perf: Arc<Perf>,
    /// The connection of every attached session with the attachment epoch it belongs to and the tracker of its last sample, so a report can ask each for its QUIC statistics over the window; the epoch keeps a takeover's newer connection from being displaced or removed by the older one.
    pub connections: Mutex<HashMap<u64, ConnectionEntry>>,
    /// The host's ports and UDP drop counters, sampled once per report.
    meters: Mutex<Meters>,
    token: Option<String>,
    connection_permits: Arc<Semaphore>,
    /// Called on a request's blocking thread when it gets there, and what it returns as the request goes on, so a test can hold a request at any of those points and see what it answered; never set outside tests.
    pub dispatch_hook: OnceLock<HookDispatch>,
}

pub type HookDispatch = Arc<dyn Fn(&Request) -> Option<HookRequest> + Send + Sync>;

/// What a [`HookDispatch`] keeps for one request.
pub type HookRequest = Box<dyn FnMut(PhaseDispatch<'_>) + Send>;

/// Where a request a [`HookDispatch`] took has got to.
pub enum PhaseDispatch<'a> {
    /// About to touch the filesystem.
    Running,
    /// Done, with its response.
    Done(&'a Response),
}

/// What change notification hands the server: the batches to fan out, the record of which session made which change, and the watch table requests arm.
pub struct Notification {
    pub events: broadcast::Sender<Arc<EventBatch>>,
    pub changes: Arc<ChangeLog>,
    pub watches: Arc<Watches>,
}

impl Server {
    /// `perf` is made first because change notification counts into it too. Called from within the runtime that serves, whose workers the reports measure.
    pub fn new(
        export: Arc<Export>,
        token: Option<String>,
        notification: Notification,
        perf: Arc<Perf>,
        limits: Limits,
        ids: IdMap,
    ) -> Server {
        Server {
            export,
            ids,
            sessions: Arc::new(Sessions::new(
                limits.handle_share,
                Arc::new(HandlePool::new(limits.handle_pool)),
            )),
            events: notification.events,
            changes: notification.changes,
            watches: notification.watches,
            perf,
            connections: Mutex::new(HashMap::new()),
            meters: Mutex::new(Meters {
                link: MeterLink::system(),
                udp: MeterUdp::system(),
                process: MeterProcess::new(tokio::runtime::Handle::current(), 0, 0),
            }),
            token,
            connection_permits: Arc::new(Semaphore::new(limits.connections)),
            dispatch_hook: OnceLock::new(),
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

    /// Log the per-op table for the window since the last report, the requests being answered at least a second, the process's open file descriptors and every session's open handles, the host's physical ports and UDP drop counters, and then, per attached session, its connection's QUIC statistics with the window and the verdict against those ports, so a verdict follows the lines it is drawn from. The server is the sending side of every read a client makes, so its window and losses are what bound a download.
    pub fn report(&self) {
        self.perf.report();
        crate::watchdog::report_pending(&self.perf);
        self.watches.report();
        // The walk holds a descriptor of its own, which is not counted.
        match std::fs::read_dir("/proc/self/fd") {
            Ok(fds) => {
                let open = fds
                    .filter_map(|entry| {
                        entry
                            .map_err(|e| tracing::warn!("listing /proc/self/fd: {e}"))
                            .ok()
                    })
                    .count()
                    .saturating_sub(1);
                tracing::info!(target: TRACE_TARGET, "perf fds open={open}");
            }
            Err(e) => tracing::warn!("counting open file descriptors: {e}"),
        }
        for row in self.sessions.handle_rows() {
            let state = if row.detached { "detached" } else { "attached" };
            tracing::info!(target: TRACE_TARGET, "perf handles session={} open={} files={} dirs={} state={state} remote={}", row.session, row.files + row.dirs, row.files, row.dirs, row.remote);
        }
        let pool = self.sessions.pool();
        tracing::info!(target: TRACE_TARGET, "perf handles pool used={} capacity={}", pool.used(), pool.capacity());
        let (served, moved) = self.perf.served();
        let (process, links, udp) = {
            let mut meters = self.meters.lock();
            (
                meters.process.sample(served, moved),
                meters.link.sample(),
                meters.udp.sample(),
            )
        };
        if let Some(process) = process {
            tracing::info!(target: TRACE_TARGET, "{}", line_process(&process));
        }
        for line in lines_link(&links) {
            tracing::info!(target: TRACE_TARGET, "{line}");
        }
        if let Some(udp) = udp {
            tracing::info!(target: TRACE_TARGET, "{}", line_udp(&udp));
        }
        let connections: Vec<(u64, ConnectionEntry)> = self
            .connections
            .lock()
            .iter()
            .map(|(id, entry)| (*id, entry.clone()))
            .collect();
        if connections.is_empty() {
            tracing::info!(target: TRACE_TARGET, "perf quic: no attached sessions");
        }
        for (session, entry) in connections {
            log_quic(session, &entry.conn, &entry.tracker, &links);
        }
    }
}

struct Meters {
    link: MeterLink,
    udp: MeterUdp,
    process: MeterProcess,
}

/// One connection's QUIC line for the window since its last sample, and the verdict against the ports when there is one to give.
fn log_quic(session: u64, conn: &Connection, tracker: &Mutex<TrackerQuic>, links: &[SampleLink]) {
    let sample = tracker.lock().sample(conn.stats());
    tracing::info!(
        target: TRACE_TARGET,
        "{}",
        line_quic(
            &format!("session={session} remote={}", conn.remote_address()),
            &sample
        )
    );
    if let Some(verdict) = verdict(links, &sample) {
        tracing::info!(target: TRACE_TARGET, "{}", verdict.describe());
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
    let conn_key = jackalopefs_perf::conn_key(&conn);
    tracing::info!(%remote, session = session.id, conn = conn_key, resumed, "session attached");
    {
        let mut attachment = session.attachment.lock();
        if attachment.epoch == epoch {
            attachment.remote = Some(remote);
        }
    }
    let tracker = Arc::new(Mutex::new(TrackerQuic::default()));
    let taken_over = {
        let mut connections = server.connections.lock();
        match connections.get(&session.id) {
            // Another resume of the session got here first, from a newer connection.
            Some(entry) if entry.epoch > epoch => None,
            _ => Some(connections.insert(
                session.id,
                ConnectionEntry {
                    epoch,
                    conn: conn.clone(),
                    tracker: tracker.clone(),
                },
            )),
        }
    };
    match taken_over {
        None => {
            tracing::info!(%remote, session = session.id, conn = conn_key, "the session resumed on a newer connection before this one attached; closing it");
            conn.close(close_code::SUPERSEDED.into(), b"session resumed elsewhere");
            return;
        }
        // A takeover: the client has given up on the older connection, and whatever arrives on it now is no longer the session's.
        Some(Some(old)) => old
            .conn
            .close(close_code::SUPERSEDED.into(), b"session resumed elsewhere"),
        Some(None) => {}
    }
    let _detach = DetachOnDrop {
        server: server.clone(),
        session: session.clone(),
        conn: conn.clone(),
        tracker,
        epoch,
        remote,
    };
    let events = tokio::spawn(forward_events(
        conn.clone(),
        server.events.subscribe(),
        session.handles.notice(),
        session.id,
        conn_key,
        server.perf.hub.clone(),
    ));
    let ops = Arc::new(Ops {
        export: server.export.clone(),
        handles: session.handles.clone(),
        session_id: session.id,
        conn: conn_key,
        changes: server.changes.clone(),
        watches: server.watches.clone(),
        ids: server.ids,
        remote,
        events: server.perf.events.clone(),
        refusals: Mutex::new(ops::Refusals::default()),
    });
    let serving = Arc::new(Serving {
        ops,
        server: server.clone(),
    });
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                tokio::spawn(handle_request(serving.clone(), send, recv));
            }
            Err(e) => {
                tracing::debug!(session = session.id, "connection ended: {e}");
                break;
            }
        }
    }
    events.abort();
}

/// Starts the session's grace period however the connection task ends, including by panic, and logs the connection's final QUIC statistics, since a report after this point can no longer ask for them.
struct DetachOnDrop {
    server: Arc<Server>,
    session: Arc<SessionState>,
    conn: Connection,
    tracker: Arc<Mutex<TrackerQuic>>,
    epoch: u64,
    remote: std::net::SocketAddr,
}

impl Drop for DetachOnDrop {
    fn drop(&mut self) {
        {
            let mut connections = self.server.connections.lock();
            if connections
                .get(&self.session.id)
                .is_some_and(|entry| entry.epoch == self.epoch)
            {
                connections.remove(&self.session.id);
            }
        }
        self.server.sessions.detach(self.session.id, self.epoch);
        tracing::info!(remote = %self.remote, session = self.session.id, open_handles = self.session.handles.len(), "session detached");
        // The final window, with no port sample to judge it against: the totals are what matter here.
        log_quic(self.session.id, &self.conn, &self.tracker, &[]);
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
                    root_ino: server.export.root_key().0,
                    root_identity: server.export.root_key().1.clone(),
                    uid: server.ids.uid,
                    gid: server.ids.gid,
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

/// Copy event batches to this session's uni stream, dropping its own echoes; a lagging receiver tells the client to distrust everything instead of silently losing events. The session's notice that it holds many handles goes on the same stream: one still pending when the connection attaches first (its last connection went before it was written), then each new one as it is set, and each is cleared once written.
async fn forward_events(
    conn: Connection,
    mut events: broadcast::Receiver<Arc<EventBatch>>,
    notice: tokio::sync::watch::Sender<Option<NoticeHandles>>,
    session_id: u64,
    conn_key: Option<u64>,
    hub: Arc<Hub>,
) {
    let send = match conn.open_uni().await {
        Ok(send) => send,
        Err(e) => {
            tracing::debug!(session_id, "could not open event stream: {e}");
            return;
        }
    };
    let mut stream = StreamEvents {
        tap_ids: IdsEvent {
            session: Some(session_id),
            conn: conn_key,
            stream: Some(u64::from(send.id())),
            op: Some("event"),
            ..IdsEvent::default()
        },
        send,
        seq: 0,
        session_id,
        conn,
        hub,
    };
    let mut notices = notice.subscribe();
    let pending = *notices.borrow_and_update();
    if let Some(pending) = pending {
        if stream.send(&notice_event(pending)).await.is_break() {
            return;
        }
        delivered(&notice, pending);
    }
    // Once the session is gone its notices are too, and only batches remain.
    let mut noticing = true;
    loop {
        let event = tokio::select! {
            batch = events.recv() => match batch {
                Ok(batch) => batch.for_session(session_id),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        session_id,
                        dropped = n,
                        "event stream lagged; sending overflow"
                    );
                    Some(Event {
                        items: vec![EventItem::Overflow],
                        handles: None,
                    })
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            changed = notices.changed(), if noticing => match changed {
                Ok(()) => (*notices.borrow_and_update()).map(notice_event),
                Err(_) => {
                    noticing = false;
                    None
                }
            },
        };
        let Some(event) = event else { continue };
        if stream.send(&event).await.is_break() {
            break;
        }
        if let Some(sent) = event.handles {
            delivered(&notice, sent);
        }
    }
}

/// Clear a notice once written, unless a newer one has replaced it; clearing it wakes nobody.
fn delivered(notice: &tokio::sync::watch::Sender<Option<NoticeHandles>>, sent: NoticeHandles) {
    notice.send_if_modified(|pending| {
        if *pending == Some(sent) {
            *pending = None;
        }
        false
    });
}

fn notice_event(notice: NoticeHandles) -> Event {
    Event {
        items: vec![],
        handles: Some(notice),
    }
}

/// A session's event stream on one connection, and how many frames it has carried.
struct StreamEvents {
    send: SendStream,
    tap_ids: IdsEvent,
    /// Frames written so far, batches and notices alike; the client counts the ones it reads, so the two agree on which `every`th is which.
    seq: u64,
    session_id: u64,
    conn: Connection,
    hub: Arc<Hub>,
}

impl StreamEvents {
    /// Write one frame; a break means the stream is finished with.
    async fn send(&mut self, event: &Event) -> std::ops::ControlFlow<()> {
        use std::ops::ControlFlow;
        let session_id = self.session_id;
        match timeout(EVENT_WRITE_TIMEOUT, write_frame(&mut self.send, event)).await {
            Ok(Ok(())) => {
                if self.hub.wants_frames() {
                    // The frame encoded for the write just made, so it encodes again.
                    self.hub
                        .event_frame(Side::Server, &self.tap_ids, self.seq, || {
                            encode(event).ok().map(|frame| frame[4..].to_vec())
                        });
                }
                self.seq += 1;
                ControlFlow::Continue(())
            }
            Ok(Err(e @ jackalopefs_proto::ErrorCodec::TooLarge(_))) => {
                tracing::warn!(
                    session_id,
                    "event batch could not be sent: {e}; the client falls back to its cache TTL"
                );
                ControlFlow::Break(())
            }
            Ok(Err(e)) => {
                tracing::debug!(session_id, "event stream closed: {e}");
                ControlFlow::Break(())
            }
            Err(_) => {
                tracing::warn!(
                    session_id,
                    "client stopped draining the event stream; closing connection"
                );
                self.conn.close(
                    close_code::EVENT_STREAM_STALLED.into(),
                    b"event stream stalled",
                );
                ControlFlow::Break(())
            }
        }
    }
}

/// What a reply carries, or the errno it refuses with.
fn outcome_of(resp: &Response) -> Outcome {
    match resp {
        Response::Err(errno) => Outcome::errno(*errno),
        Response::Read(data) => Outcome::bytes(data.len()),
        Response::Written(n) => Outcome::bytes(*n as usize),
        // No payload, but bytes this server moved all the same.
        Response::Copied(n) => Outcome::bytes(*n as usize),
        Response::Readdir { entries, .. } => Outcome::items(entries.len()),
        _ => Outcome::default(),
    }
}

/// What every request on one connection is answered with.
struct Serving {
    ops: Arc<Ops>,
    server: Arc<Server>,
}

/// A request that ran on its blocking thread.
struct Ran {
    started: Instant,
    finished: Instant,
    resp: Response,
    armed: Vec<crate::watch::Armed>,
}

async fn handle_request(serving: Arc<Serving>, mut send: SendStream, mut recv: RecvStream) {
    let ops = serving.ops.clone();
    let perf = serving.server.perf.clone();
    let hook = serving.server.dispatch_hook.get().cloned();
    let accepted = Instant::now();
    let stream = u64::from(recv.id());
    let inflight = Arc::new(perf.start(ops.session_id, ops.conn, stream));
    let ids = IdsEvent {
        session: Some(ops.session_id),
        conn: ops.conn,
        stream: Some(stream),
        ..IdsEvent::default()
    };
    let (body, req) = match timeout(
        REQUEST_READ_TIMEOUT,
        read_frame_body::<_, Request>(&mut recv),
    )
    .await
    {
        Ok(Ok((body, Ok(req)))) => (body, req),
        Ok(Ok((body, Err(e)))) => {
            if perf.hub.wants_frames() {
                perf.hub
                    .undecodable(Side::Server, &ids, &e.to_string(), &body);
            }
            match e {
                jackalopefs_proto::ErrorCodec::Decode(
                    jackalopefs_proto::ErrorDecode::NotInSchema(n),
                ) => tracing::info!(
                    discriminant = n,
                    "request uses a schema variant this server does not know; the client may be newer"
                ),
                e => tracing::warn!("malformed request: {e}"),
            }
            return;
        }
        // The client finishes a stream early or resets it when it gives up on a call.
        Ok(Err(e))
            if e.is_eof()
                || matches!(&e, jackalopefs_proto::ErrorCodec::Io(io) if io.kind() == std::io::ErrorKind::ConnectionReset) =>
        {
            event!(
                target: EVENT_TARGET,
                perf.events,
                Slowpath::RequestCancelled,
                ids,
                format!("the request ended before it was fully sent: {e}")
            );
            return;
        }
        Ok(Err(jackalopefs_proto::ErrorCodec::Io(e))) => {
            event!(
                target: EVENT_TARGET,
                perf.events,
                Slowpath::RequestStreamFailed,
                ids,
                format!("the request stream failed: {e}")
            );
            return;
        }
        Ok(Err(e)) => {
            tracing::warn!("malformed request: {e}");
            return;
        }
        Err(_) => {
            event!(
                target: EVENT_TARGET,
                perf.events,
                Slowpath::RequestReadTimeout,
                ids,
                format!(
                    "the request was not fully sent within {}",
                    fmt_duration(REQUEST_READ_TIMEOUT)
                )
            );
            return;
        }
    };
    let mut phases = Phases {
        read: accepted.elapsed(),
        ..Phases::default()
    };
    let op = req.op_name();
    let (fh, offset, size) = req.perf_fields();
    inflight.decoded(op, req.subject());
    let mut sampled = if perf.hub.wants_frames() {
        perf.hub.sample(
            Side::Server,
            IdsEvent {
                op: Some(op),
                ..ids.clone()
            },
        )
    } else {
        None
    };
    if let Some(sampled) = sampled.as_mut() {
        sampled.request(&body, || elided(req.with_data_elided()));
    }
    drop(body);
    let queued = Instant::now();
    let running = inflight.clone();
    let resp = match tokio::task::spawn_blocking(move || {
        let mut hooked = hook.and_then(|hook| hook(&req));
        if let Some(hooked) = hooked.as_mut() {
            hooked(PhaseDispatch::Running);
        }
        let tid = nix::unistd::gettid().as_raw();
        let started = Instant::now();
        running.arming(tid);
        let armed = ops.watches.arm_request(&req);
        running.running(tid);
        let resp = ops::dispatch(&ops, req);
        let finished = Instant::now();
        if let Some(mut hooked) = hooked {
            hooked(PhaseDispatch::Done(&resp));
        }
        Ran {
            started,
            finished,
            resp,
            armed,
        }
    })
    .await
    {
        Ok(Ran {
            started,
            finished,
            resp,
            armed,
        }) => {
            phases.wait = started - queued;
            phases.op = finished - started;
            (resp, armed)
        }
        Err(e) => {
            tracing::error!(op, "operation panicked: {e}");
            phases.wait = queued.elapsed();
            (Response::Err(nix::errno::Errno::EIO as i32), Vec::new())
        }
    };
    // The directories the request named stay watched until its reply is out: a notice that they were dropped must not reach the client ahead of the reply it would cache.
    let (resp, _armed) = resp;
    let outcome = outcome_of(&resp);
    inflight.sending();
    let sending = Instant::now();
    let written = match encode(&resp) {
        Ok(frame) => match timeout(REPLY_WRITE_TIMEOUT, send.write_all(&frame)).await {
            Ok(Ok(())) => Ok(Ok(frame)),
            Ok(Err(e)) => Ok(Err(e.to_string())),
            Err(stalled) => Err(stalled),
        },
        Err(e) => Ok(Err(e.to_string())),
    };
    match written {
        Ok(Ok(frame)) => {
            if let Err(e) = send.finish() {
                tracing::debug!(op, "reply stream already closed: {e}");
            }
            if let Some(sampled) = sampled.take() {
                sampled.reply(&frame[4..], || elided(resp.with_data_elided()));
            }
        }
        Ok(Err(e)) => {
            if let Some(sampled) = sampled.as_mut() {
                sampled.outcome("undelivered");
            }
            event!(
                target: EVENT_TARGET,
                perf.events,
                Slowpath::ReplyUndelivered,
                IdsEvent {
                    op: Some(op),
                    ..ids.clone()
                },
                format!(
                    "{}: the reply could not be written: {e}",
                    inflight.subject().unwrap_or_default()
                )
            );
        }
        Err(_) => {
            if let Some(sampled) = sampled.as_mut() {
                sampled.outcome("stalled");
            }
            tracing::warn!(op, "client is not reading its reply; abandoning it");
            event!(
                target: EVENT_TARGET,
                perf.events,
                Slowpath::ReplyStalled,
                IdsEvent {
                    op: Some(op),
                    ..ids.clone()
                },
                format!(
                    "{}: the client did not read the reply within {}",
                    inflight.subject().unwrap_or_default(),
                    fmt_duration(REPLY_WRITE_TIMEOUT)
                )
            );
            if let Err(e) = send.reset(close_code::EVENT_STREAM_STALLED.into()) {
                tracing::debug!(op, "reset after stalled reply: {e}");
            }
        }
    }
    phases.send = sending.elapsed();
    let total = accepted.elapsed();
    perf.record(op, &outcome, total, phases);
    if tracing::enabled!(target: TRACE_TARGET, tracing::Level::TRACE) {
        tracing::trace!(
            target: TRACE_TARGET,
            session = ids.session,
            conn = ids.conn,
            stream,
            op,
            fh,
            offset,
            size,
            bytes = outcome.bytes,
            items = outcome.items,
            errno = outcome.errno,
            read_us = phases.read.as_micros() as u64,
            wait_us = phases.wait.as_micros() as u64,
            op_us = phases.op.as_micros() as u64,
            send_us = phases.send.as_micros() as u64,
            total_us = total.as_micros() as u64,
            "request"
        );
    }
    if perf.hub.wants_requests() {
        perf.hub.deliver_request(op, || {
            let ns = |d: Duration| d.as_nanos() as u64;
            Summary {
                level: "request".into(),
                ids: jackalopefs_proto::control::Ids {
                    op: Some(op.into()),
                    ..ids.to_ids()
                },
                fh,
                offset,
                size,
                bytes: outcome.bytes,
                items: outcome.items,
                errno: outcome.errno,
                phases: vec![
                    ("read".into(), ns(phases.read)),
                    ("wait".into(), ns(phases.wait)),
                    ("op".into(), ns(phases.op)),
                    ("send".into(), ns(phases.send)),
                ],
                total_ns: ns(total),
                ..Summary::default()
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sessions_unlimited() -> Sessions {
        Sessions::new(
            crate::handles::SHARE_MAX,
            Arc::new(HandlePool::new(usize::MAX)),
        )
    }

    #[test]
    fn a_session_dropped_gives_its_handles_back_to_the_pool() {
        let sessions = sessions_unlimited();
        let (state, epoch) = sessions.create();
        let file = std::fs::File::open("/dev/null").unwrap();
        state
            .handles
            .insert(
                1,
                crate::handles::Handle::File {
                    file: Arc::new(file),
                    path: jackalopefs_proto::Path::root(),
                    watch: None,
                },
            )
            .unwrap();
        assert_eq!(sessions.pool().used(), 1);
        sessions.detach(state.id, epoch);
        assert_eq!(sessions.reap(Duration::ZERO), 1);
        assert_eq!(
            sessions.pool().used(),
            1,
            "the request holding it still runs"
        );
        drop(state);
        assert_eq!(sessions.pool().used(), 0);
    }

    #[test]
    fn sessions_resume_detach_and_reap() {
        let sessions = sessions_unlimited();
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
        let sessions = sessions_unlimited();
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

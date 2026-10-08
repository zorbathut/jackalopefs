//! The typed request API. A request on a live connection is waited for as long as that connection lives, or up to an optional deadline; only the wait for a connection is always bounded. A call whose reply was lost to a dropped connection is retried once on the next connection only when that is safe, and a call made for a kernel request is abandoned when the kernel interrupts that request.

use crate::conn::{close_code, Attached, ConfigConn, ConnManager, ConnState};
use crate::handles::{HandleKind, HandleTable};
use crate::ids::{IdMap, ModeIds};
use crate::inodes::KeyNode;
use crate::perf::{AccountCall, Outcome, Perf, Phases, Slowpath, EVENT_TARGET, TRACE_TARGET};
use crate::transport::ServerTrust;
use jackalopefs_perf::event;
use jackalopefs_perf::hub::IdsEvent;
use jackalopefs_perf::stall::ErrorLockHeld;
use jackalopefs_proto::{
    read_frame, write_frame, Attr, Auth, DirEntry, ErrorCodec, Event, Identity, Name, Path,
    Request, Response, SetAttr, Statfs, Whence, MAX_FALLOCATE,
};
use quinn::{Connection, RecvStream, SendStream};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::time::{timeout, timeout_at, Instant};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("operation timed out")]
    Timeout,
    #[error("interrupted by a signal")]
    Interrupted,
    #[error("connection to the server was lost")]
    Disconnected,
    #[error("handle refers to a file that no longer exists at its path")]
    Stale,
    #[error("server returned errno {0}")]
    Remote(i32),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("client is shut down")]
    Closed,
    #[error("owner has no counterpart on the server")]
    Unmapped,
}

impl Error {
    /// The errno a FUSE reply should carry.
    pub fn errno(&self) -> i32 {
        match self {
            Error::Timeout => libc::ETIMEDOUT,
            Error::Interrupted => libc::EINTR,
            Error::Disconnected => libc::EIO,
            Error::Stale => libc::ESTALE,
            Error::Remote(e) if *e > 0 && *e < 4096 => *e,
            Error::Remote(_) => libc::EIO,
            Error::Protocol(_) => libc::EIO,
            Error::Closed => libc::ENOTCONN,
            // What chown(2) says of an id with no mapping in the caller's user namespace.
            Error::Unmapped => libc::EINVAL,
        }
    }
}

/// Outcome of one stream exchange, distinguishing "never sent" from "sent, reply lost" because the former is always safe to retry; the connection failures say why, for the events that report them.
#[derive(Debug)]
pub(crate) enum ErrorExchange {
    NotSent(String),
    Lost(String),
    Protocol(String),
}

impl From<ErrorExchange> for Error {
    fn from(e: ErrorExchange) -> Error {
        match e {
            ErrorExchange::NotSent(_) | ErrorExchange::Lost(_) => Error::Disconnected,
            ErrorExchange::Protocol(msg) => Error::Protocol(msg),
        }
    }
}

/// The kernel request a call is made for: its id, so a `call` trace line can be joined to the `fuse` line it served; the kernel's signal that it wants the request abandoned; and the call it is making right now, for the stall watchdog. A call made outside one (an orphan handle release, a reopen after a reconnect) has none, cannot be interrupted, and is not watched.
pub struct RequestKernel {
    pub unique: u64,
    interrupt: watch::Sender<bool>,
    /// Whether the task answering the request has run at all; one registered but never run is waiting for the runtime, not the server.
    started: AtomicBool,
    call: parking_lot::Mutex<Option<CallNow>>,
}

/// Where a call stands, as the stall watchdog reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseCall {
    /// For a usable connection.
    Wait,
    /// For a request stream; the server's limit on concurrent streams holds a call here while others are outstanding.
    Open,
    /// Writing the request, which flow control can hold up.
    Send,
    /// The request is with the server, and the reply has not come back.
    Reply,
}

/// The call a kernel request is making.
#[derive(Clone, Debug)]
pub struct CallNow {
    pub req: Arc<Request>,
    pub phase: PhaseCall,
    /// When the call entered its phase.
    pub since: std::time::Instant,
    /// The connection the phase is on, once there is one.
    pub generation: Option<u64>,
    /// That connection's key, which the server's lines name it by.
    pub conn: Option<u64>,
    /// The QUIC stream carrying the request, which the server's stall lines name too.
    pub stream: Option<u64>,
    pub retries: u32,
}

impl RequestKernel {
    pub fn new(unique: u64) -> Arc<RequestKernel> {
        Arc::new(RequestKernel {
            unique,
            interrupt: watch::Sender::new(false),
            started: AtomicBool::new(false),
            call: parking_lot::Mutex::new(None),
        })
    }

    /// Run `f` as the work of this request, so every call it makes can be interrupted with it.
    pub async fn scope<F: Future>(self: Arc<Self>, f: F) -> F::Output {
        self.started.store(true, Ordering::Relaxed);
        REQUEST_KERNEL.scope(self, f).await
    }

    pub fn started(&self) -> bool {
        self.started.load(Ordering::Relaxed)
    }

    /// The call this request is making, if any. Waits at most `patience` for the lock, as a watchdog must; `Err` if it is held longer than that.
    pub fn call_now(&self, patience: Duration) -> Result<Option<CallNow>, ErrorLockHeld> {
        self.call
            .try_lock_for(patience)
            .map(|call| call.clone())
            .ok_or(ErrorLockHeld)
    }

    /// A kernel request makes its calls one at a time: a second call while one is in progress would have its record wiped by the first one's end.
    fn call_begin(&self, req: Arc<Request>) {
        let mut call = self.call.lock();
        debug_assert!(
            call.is_none(),
            "a kernel request is making two calls at once"
        );
        *call = Some(CallNow {
            req,
            phase: PhaseCall::Wait,
            since: std::time::Instant::now(),
            generation: None,
            conn: None,
            stream: None,
            retries: 0,
        });
    }

    /// The call enters `phase`. An `attached` names the connection the phase starts on, by generation and key, and is kept until a resend clears it; the `stream` is the phase's own, absent before one is open.
    fn call_phase(&self, phase: PhaseCall, attached: Option<&Attached>, stream: Option<u64>) {
        if let Some(call) = self.call.lock().as_mut() {
            call.phase = phase;
            call.since = std::time::Instant::now();
            if let Some(attached) = attached {
                call.generation = Some(attached.generation);
                call.conn = attached.conn_key;
            }
            call.stream = stream;
        }
    }

    fn call_retried(&self, retries: u32) {
        if let Some(call) = self.call.lock().as_mut() {
            call.retries = retries;
            call.generation = None;
            call.conn = None;
        }
    }

    /// The kernel wants the request abandoned. Latches: a call made after this fails at once.
    pub fn interrupt(&self) {
        self.interrupt.send_replace(true);
    }

    async fn interrupted(&self) {
        let mut seen = self.interrupt.subscribe();
        seen.wait_for(|interrupted| *interrupted)
            .await
            .expect("the sender lives as long as the request");
    }
}

tokio::task_local! {
    static REQUEST_KERNEL: Arc<RequestKernel>;
}

/// Marks a call on its kernel request for as long as it runs, however it ends: finished, failed, or its future dropped by an interrupt or a timeout.
struct CallTracked {
    kernel: Option<Arc<RequestKernel>>,
}

impl CallTracked {
    fn begin(kernel: Option<Arc<RequestKernel>>, req: &Arc<Request>) -> CallTracked {
        if let Some(kernel) = &kernel {
            kernel.call_begin(req.clone());
        }
        CallTracked { kernel }
    }
}

impl Drop for CallTracked {
    fn drop(&mut self) {
        if let Some(kernel) = &self.kernel {
            *kernel.call.lock() = None;
        }
    }
}

/// The kernel request the current task is answering, if any.
fn current_request() -> Option<Arc<RequestKernel>> {
    REQUEST_KERNEL.try_with(Arc::clone).ok()
}

/// `f` under an optional deadline.
async fn within<T>(limit: Option<Duration>, f: impl Future<Output = T>) -> Result<T, Error> {
    match limit {
        Some(limit) => timeout(limit, f).await.map_err(|_| Error::Timeout),
        None => Ok(f.await),
    }
}

/// `f`, abandoned if the kernel interrupts the request it is made for; a request already interrupted is not even started.
async fn interruptible<T>(
    req: Option<&RequestKernel>,
    f: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    match req {
        Some(req) => tokio::select! {
            biased;
            _ = req.interrupted() => Err(Error::Interrupted),
            out = f => out,
        },
        None => f.await,
    }
}

/// Owns a request's streams; dropping it before the reply arrived (a timeout, an interrupt) resets both directions so the server sees a cancellation rather than a clean end of stream.
struct Streams {
    send: SendStream,
    recv: RecvStream,
    done: bool,
}

impl Drop for Streams {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        if let Err(e) = self.send.reset(close_code::CANCELLED.into()) {
            tracing::trace!("reset after cancel: {e}");
        }
        if let Err(e) = self.recv.stop(close_code::CANCELLED.into()) {
            tracing::trace!("stop after cancel: {e}");
        }
    }
}

/// When each step of an exchange completed; a step that never completed leaves its instant unset. Each step also moves the phase of the kernel request's call, when the exchange is made for one.
#[derive(Default)]
pub(crate) struct Timing<'a> {
    pub opened: Option<Instant>,
    pub sent: Option<Instant>,
    pub replied: Option<Instant>,
    /// The QUIC stream the request went on, once one was opened.
    pub stream: Option<u64>,
    kernel: Option<&'a RequestKernel>,
}

impl<'a> Timing<'a> {
    fn for_kernel(kernel: Option<&'a RequestKernel>) -> Timing<'a> {
        Timing {
            kernel,
            ..Timing::default()
        }
    }

    fn stamp_opened(&mut self, stream: u64) {
        self.opened = Some(Instant::now());
        self.stream = Some(stream);
        if let Some(kernel) = self.kernel {
            kernel.call_phase(PhaseCall::Send, None, Some(stream));
        }
    }

    fn stamp_sent(&mut self, stream: u64) {
        self.sent = Some(Instant::now());
        if let Some(kernel) = self.kernel {
            kernel.call_phase(PhaseCall::Reply, None, Some(stream));
        }
    }

    /// The phases of one attempt that began at `started`; a phase still in progress is charged up to now, so a timeout shows where it was spent.
    fn phases(&self, started: Instant) -> Phases {
        let now = Instant::now();
        let mut phases = Phases::default();
        let opened = self.opened.unwrap_or(now);
        phases.open = opened - started;
        let Some(opened) = self.opened else {
            return phases;
        };
        let sent = self.sent.unwrap_or(now);
        phases.send = sent - opened;
        let Some(sent) = self.sent else {
            return phases;
        };
        phases.reply = self.replied.unwrap_or(now) - sent;
        phases
    }
}

/// The export root as its server describes it. The kernel knows the root as node 1 and a server knows it by its real inode number, so every reply is passed through [`KeyRoot::as_node_one`] on its way in.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyRoot {
    pub ino: u64,
    pub identity: Identity,
}

impl KeyRoot {
    fn as_node_one(&self, resp: &mut Response) {
        let rewrite = |attr: &mut Attr| {
            if attr.ino == self.ino && attr.identity == self.identity {
                attr.ino = crate::inodes::ROOT;
            }
        };
        match resp {
            Response::Entry(attr) | Response::Attr(attr) | Response::Opened { attr } => {
                rewrite(attr)
            }
            Response::Readdir { entries, .. } => entries
                .iter_mut()
                .filter_map(|e| e.attr.as_mut())
                .for_each(rewrite),
            _ => {}
        }
    }
}

/// One request on one fresh bidi stream.
pub(crate) async fn exchange(
    conn: &Connection,
    root: &KeyRoot,
    ids: &IdMap,
    req: &Request,
    timing: &mut Timing<'_>,
) -> Result<Response, ErrorExchange> {
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| ErrorExchange::NotSent(format!("cannot open a stream: {e}")))?;
    let stream = u64::from(send.id());
    timing.stamp_opened(stream);
    let mut streams = Streams {
        send,
        recv,
        done: false,
    };
    write_frame(&mut streams.send, req)
        .await
        .map_err(|e| codec_error(e, ErrorExchange::NotSent))?;
    streams
        .send
        .finish()
        .map_err(|e| ErrorExchange::Lost(format!("cannot finish the request: {e}")))?;
    timing.stamp_sent(stream);
    let mut resp: Response = read_frame(&mut streams.recv)
        .await
        .map_err(|e| codec_error(e, ErrorExchange::Lost))?;
    timing.replied = Some(Instant::now());
    streams.done = true;
    root.as_node_one(&mut resp);
    ids.incoming(req, &mut resp);
    Ok(resp)
}

/// What a call moved, or how it failed.
fn outcome_of(result: &Result<Response, Error>) -> Outcome {
    match result {
        Ok(Response::Read(data)) => Outcome::bytes(data.len()),
        Ok(Response::Written(n)) => Outcome::bytes(*n as usize),
        // A copy moves no payload; what the server copied is counted by the kernel-level row.
        Ok(Response::Copied(_)) => Outcome::default(),
        Ok(Response::Readdir { entries, .. }) => Outcome::items(entries.len()),
        Ok(_) => Outcome::default(),
        Err(e) => Outcome::errno(e.errno()),
    }
}

fn codec_error(e: ErrorCodec, on_io: fn(String) -> ErrorExchange) -> ErrorExchange {
    match e {
        ErrorCodec::Io(io) => on_io(format!("the stream failed: {io}")),
        other => ErrorExchange::Protocol(other.to_string()),
    }
}

/// The identifiers of a call's attempt on `attached`, for the events it raises.
fn call_ids(req: &Request, attached: &Attached, timing: &Timing<'_>) -> IdsEvent {
    IdsEvent {
        session: Some(attached.session_id),
        conn: attached.conn_key,
        stream: timing.stream,
        unique: timing.kernel.map(|kernel| kernel.unique),
        op: Some(req.op_name()),
    }
}

/// Whether a request whose reply was lost may be sent again without changing the outcome.
fn retry_safe(req: &Request) -> bool {
    match req {
        Request::Lookup { .. }
        | Request::Getattr { .. }
        | Request::Setattr { .. }
        | Request::Readlink { .. }
        | Request::Read { .. }
        | Request::Write { .. }
        | Request::Release { .. }
        | Request::Fsync { .. }
        | Request::Opendir { .. }
        | Request::Readdir { .. }
        | Request::Releasedir { .. }
        | Request::Statfs { .. }
        | Request::Getxattr { .. }
        | Request::Listxattr { .. }
        | Request::Access { .. }
        | Request::CopyFileRange { .. }
        | Request::Fallocate { .. }
        | Request::Lseek { .. } => true,
        Request::Open { flags, .. } => flags & libc::O_TRUNC == 0,
        Request::Create { flags, .. } => flags & (libc::O_EXCL | libc::O_TRUNC) == 0,
        Request::Setxattr { flags, .. } => *flags == 0,
        Request::Mknod { .. }
        | Request::Mkdir { .. }
        | Request::Unlink { .. }
        | Request::Rmdir { .. }
        | Request::Symlink { .. }
        | Request::Rename { .. }
        | Request::Link { .. }
        | Request::Removexattr { .. } => false,
    }
}

/// The part of a client that can be cloned into a background task.
#[derive(Clone)]
struct Caller {
    state: watch::Receiver<ConnState>,
    handles: Arc<HandleTable>,
    perf: Arc<Perf>,
    /// Longest one exchange on a live connection may take; `None` waits as long as the connection lives.
    op_timeout: Option<Duration>,
    /// Longest a call waits for a connection, and longest an outage holds calls before they fail at once.
    offline_timeout: Duration,
}

impl Caller {
    /// Wait for a connection of at least `min_generation` until `deadline`, or until the current outage has lasted the offline timeout if that comes first.
    async fn wait_connected(
        &self,
        deadline: Instant,
        min_generation: u64,
    ) -> Result<Arc<Attached>, Error> {
        let mut state = self.state.clone();
        loop {
            let current = state.borrow_and_update().clone();
            let limit = match current {
                ConnState::Connected(attached) if attached.generation >= min_generation => {
                    return Ok(attached)
                }
                ConnState::Closed => return Err(Error::Closed),
                ConnState::Connecting { since } => deadline.min(since + self.offline_timeout),
                _ => deadline,
            };
            if Instant::now() >= limit {
                return Err(Error::Timeout);
            }
            match timeout_at(limit, state.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(Error::Closed),
                Err(_) => return Err(Error::Timeout),
            }
        }
    }

    /// Send one request and account for it: the outcome and phase times go to the table, and one trace line per call to [`TRACE_TARGET`].
    async fn call(&self, req: Request) -> Result<Response, Error> {
        let started = Instant::now();
        let req = Arc::new(req);
        let kernel = current_request();
        let _tracked = CallTracked::begin(kernel.clone(), &req);
        let mut account = AccountCall::default();
        let result = self.attempt(&req, kernel.as_deref(), &mut account).await;
        let total = started.elapsed();
        let outcome = outcome_of(&result);
        let op = req.op_name();
        self.perf.record_call(op, &outcome, total, &account);
        if tracing::enabled!(target: TRACE_TARGET, tracing::Level::TRACE) {
            let (fh, offset, size) = req.perf_fields();
            tracing::trace!(
                target: TRACE_TARGET,
                unique = kernel.as_ref().map(|r| r.unique),
                session = account.session,
                generation = account.generation,
                conn = account.conn,
                stream = account.stream,
                op,
                fh,
                offset,
                size,
                bytes = outcome.bytes,
                items = outcome.items,
                errno = outcome.errno,
                retries = account.retries,
                wait_us = account.phases.wait.as_micros() as u64,
                open_us = account.phases.open.as_micros() as u64,
                send_us = account.phases.send.as_micros() as u64,
                reply_us = account.phases.reply.as_micros() as u64,
                total_us = total.as_micros() as u64,
                "call"
            );
        }
        result
    }

    /// The exchange and its retries; every attempt's phases are added to `account`. The two waits have different clocks. The wait for a connection is bounded by the offline deadline, set once and renewed only for the one resend a lost reply gets, so a server that keeps accepting connections and failing streams cannot hold a call forever; it also ends when the outage itself has lasted the offline timeout, so through a long outage calls fail at once instead of each waiting out a deadline of its own. The exchange itself is bounded only by the optional operation deadline: a server slow to answer on a live connection is not an error, and the connection's own idle timeout fails the exchange if the server dies. Either wait ends early when the kernel interrupts the request the call is made for.
    async fn attempt(
        &self,
        req: &Request,
        kernel: Option<&RequestKernel>,
        account: &mut AccountCall,
    ) -> Result<Response, Error> {
        let mut offline_deadline = Instant::now() + self.offline_timeout;
        let handles = req.fhs().map(|fh| fh.and_then(|fh| self.handles.get(fh)));
        let mut min_generation = 0;
        let mut lost_once = false;
        loop {
            if handles.iter().flatten().any(|h| h.is_dead()) {
                return Err(Error::Stale);
            }
            if let Some(kernel) = kernel {
                kernel.call_phase(PhaseCall::Wait, None, None);
            }
            let waiting = Instant::now();
            let attached = interruptible(
                kernel,
                self.wait_connected(offline_deadline, min_generation),
            )
            .await;
            account.phases.wait += waiting.elapsed();
            let attached = attached?;
            // Owners are put in server terms against the connection that carries the request, so a retry on the next one uses that one's.
            let mapped = attached.ids.outgoing(req)?;
            let sent = mapped.as_ref().unwrap_or(req);
            if let Some(kernel) = kernel {
                kernel.call_phase(PhaseCall::Open, Some(&attached), None);
            }
            let mut timing = Timing::for_kernel(kernel);
            let attempt = Instant::now();
            let exchanged = interruptible(
                kernel,
                within(
                    self.op_timeout,
                    exchange(
                        &attached.conn,
                        &attached.root,
                        &attached.ids,
                        sent,
                        &mut timing,
                    ),
                ),
            )
            .await;
            account.phases += timing.phases(attempt);
            account.session = Some(attached.session_id);
            account.generation = Some(attached.generation);
            account.conn = attached.conn_key;
            account.stream = timing.stream;
            match exchanged {
                Ok(Ok(Response::Err(errno))) => return Err(Error::Remote(errno)),
                Ok(Ok(resp)) => return Ok(resp),
                Ok(Err(ErrorExchange::NotSent(cause))) => {
                    event!(
                        target: EVENT_TARGET,
                        self.perf.events,
                        Slowpath::CallNotSent,
                        call_ids(req, &attached, &timing),
                        format!(
                            "{} {} on generation {}: {cause}; waiting for the next connection",
                            req.op_name(),
                            req.subject(),
                            attached.generation
                        )
                    );
                    min_generation = attached.generation + 1;
                }
                Ok(Err(ErrorExchange::Lost(cause))) => {
                    if lost_once || !retry_safe(req) {
                        return Err(Error::Disconnected);
                    }
                    event!(
                        target: EVENT_TARGET,
                        self.perf.events,
                        Slowpath::CallLostRetried,
                        call_ids(req, &attached, &timing),
                        format!(
                            "{} {} on generation {}: {cause}; the reply was lost with the connection, so it is sent once more on the next",
                            req.op_name(),
                            req.subject(),
                            attached.generation
                        )
                    );
                    lost_once = true;
                    offline_deadline = Instant::now() + self.offline_timeout;
                    min_generation = attached.generation + 1;
                }
                Ok(Err(ErrorExchange::Protocol(msg))) => return Err(Error::Protocol(msg)),
                Err(e) => return Err(e),
            }
            account.retries += 1;
            if let Some(kernel) = kernel {
                kernel.call_retried(account.retries);
            }
        }
    }

    /// An open whose reply was not received may have succeeded on the server; tell it to let go of that id, in the background. Spawned, so it carries no kernel request: the cleanup after an interrupted open must not itself be interrupted. Bounded by the offline deadline, so best-effort releases cannot pile up against a server that never answers.
    fn release_orphan(&self, req: Request) {
        let mut caller = self.clone();
        caller.op_timeout = self.op_timeout.or(Some(self.offline_timeout));
        tokio::spawn(async move {
            if let Err(e) = caller.release(req).await {
                tracing::debug!("orphan handle release failed: {e}");
            }
        });
    }

    /// Release a handle on the server. One that fails for want of a connection is owed: without it the server would hold the descriptor for as long as the session lives, so it is sent again if the session resumes.
    async fn release(&self, req: Request) -> Result<(), Error> {
        match self.call(req.clone()).await {
            Ok(Response::Ok) => Ok(()),
            Ok(other) => Err(unexpected(other)),
            Err(e @ (Error::Timeout | Error::Disconnected)) => {
                self.handles.owe_release(req);
                Err(e)
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    /// Every address the server name resolved to, in the resolver's order; they are tried in turn.
    pub server_addrs: Vec<SocketAddr>,
    pub server_name: String,
    pub trust: ServerTrust,
    pub auth: Auth,
    pub connect_timeout: Duration,
    /// Longest to wait for the server's reply once a request is on a live connection; `None` waits as long as the connection lives.
    pub op_timeout: Option<Duration>,
    /// Longest a call waits for a connection before failing with `ETIMEDOUT`; once the connection has been gone this long, calls fail at once until it is back.
    pub offline_timeout: Duration,
    /// How file owners are shown (`crate::ids`).
    pub ids: ModeIds,
}

pub struct Client {
    caller: Caller,
    conn: ConnManager,
}

impl Client {
    /// Connect and complete the hello; fails if the first attempt does, so a bad address, fingerprint or token is reported immediately.
    pub async fn connect(cfg: Config) -> anyhow::Result<Client> {
        let handles = Arc::new(HandleTable::default());
        let perf = Arc::new(Perf::default());
        let conn = ConnManager::start(
            ConfigConn {
                server_addrs: cfg.server_addrs,
                server_name: cfg.server_name,
                trust: cfg.trust,
                auth: cfg.auth,
                connect_timeout: cfg.connect_timeout,
                offline_timeout: cfg.offline_timeout,
                ids: cfg.ids,
            },
            handles.clone(),
        )
        .await?;
        Ok(Client {
            caller: Caller {
                state: conn.state.clone(),
                handles,
                perf,
                op_timeout: cfg.op_timeout,
                offline_timeout: cfg.offline_timeout,
            },
            conn,
        })
    }

    pub fn state(&self) -> watch::Receiver<ConnState> {
        self.conn.state.clone()
    }

    pub fn perf(&self) -> &Arc<Perf> {
        &self.caller.perf
    }

    /// The current connection and its generation, if there is one.
    pub fn connection(&self) -> Option<(u64, Connection)> {
        match &*self.conn.state.borrow() {
            ConnState::Connected(attached) => Some((attached.generation, attached.conn.clone())),
            _ => None,
        }
    }

    pub fn take_events(&mut self) -> Option<mpsc::Receiver<Event>> {
        self.conn.take_events()
    }

    pub fn handles(&self) -> &HandleTable {
        &self.caller.handles
    }

    pub async fn shutdown(&self) {
        self.conn.shutdown().await;
    }

    /// Synchronous best-effort shutdown for drop paths: stops reconnecting and closes the endpoint without waiting.
    pub fn stop(&self) {
        self.conn.stop_now();
    }

    /// Send one request. `Response::Err` comes back as [`Error::Remote`].
    pub async fn call(&self, req: Request) -> Result<Response, Error> {
        self.caller.call(req).await
    }

    async fn call_attr(&self, req: Request) -> Result<Attr, Error> {
        match self.call(req).await? {
            Response::Entry(attr) | Response::Attr(attr) => Ok(attr),
            other => Err(unexpected(other)),
        }
    }

    async fn call_ok(&self, req: Request) -> Result<(), Error> {
        match self.call(req).await? {
            Response::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    async fn call_bytes(&self, req: Request) -> Result<Vec<u8>, Error> {
        match self.call(req).await? {
            Response::Readlink(b) | Response::Read(b) | Response::Xattr(b) => Ok(b),
            other => Err(unexpected(other)),
        }
    }

    /// Open (or opendir, or create) under a fresh handle id. `node` says which node the reply's attributes belong to, or refuses them (an open whose path led to a file other than the one meant; a created file that cannot be registered), in which case the handle is released. Whenever the outcome leaves any doubt about whether the server opened something, the id is released in the background; only a definite refusal from the server needs no cleanup.
    async fn open_handle(
        &self,
        path: Path,
        flags: i32,
        kind: HandleKind,
        build: impl FnOnce(u64) -> Request,
        node: impl FnOnce(&Attr) -> Result<u64, Error>,
    ) -> Result<(u64, Attr), Error> {
        let fh = self.caller.handles.alloc();
        let req = build(fh);
        match self.call(req).await {
            Ok(Response::Opened { attr }) => match node(&attr) {
                Ok(nodeid) => {
                    self.caller
                        .handles
                        .insert(fh, nodeid, KeyNode::of(&attr), path, flags, kind);
                    Ok((fh, attr))
                }
                Err(e) => {
                    self.caller.release_orphan(release_request(kind, fh));
                    Err(e)
                }
            },
            Ok(other) => {
                self.caller.release_orphan(release_request(kind, fh));
                Err(unexpected(other))
            }
            Err(
                e
                @ (Error::Timeout | Error::Interrupted | Error::Disconnected | Error::Protocol(_)),
            ) => {
                self.caller.release_orphan(release_request(kind, fh));
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    pub async fn lookup(&self, parent: Path, name: Name) -> Result<Attr, Error> {
        self.call_attr(Request::Lookup { parent, name }).await
    }

    /// `path` may be `None` only with a handle.
    pub async fn getattr(&self, path: Option<Path>, fh: Option<u64>) -> Result<Attr, Error> {
        self.call_attr(Request::Getattr { path, fh }).await
    }

    pub async fn setattr(
        &self,
        path: Option<Path>,
        fh: Option<u64>,
        set: SetAttr,
    ) -> Result<Attr, Error> {
        self.call_attr(Request::Setattr { path, fh, set }).await
    }

    pub async fn readlink(&self, path: Path) -> Result<Vec<u8>, Error> {
        self.call_bytes(Request::Readlink { path }).await
    }

    pub async fn mknod(
        &self,
        parent: Path,
        name: Name,
        mode: u32,
        rdev: u64,
    ) -> Result<Attr, Error> {
        self.call_attr(Request::Mknod {
            parent,
            name,
            mode,
            rdev,
        })
        .await
    }

    pub async fn mkdir(&self, parent: Path, name: Name, mode: u32) -> Result<Attr, Error> {
        self.call_attr(Request::Mkdir { parent, name, mode }).await
    }

    pub async fn unlink(&self, parent: Path, name: Name) -> Result<(), Error> {
        self.call_ok(Request::Unlink { parent, name }).await
    }

    pub async fn rmdir(&self, parent: Path, name: Name) -> Result<(), Error> {
        self.call_ok(Request::Rmdir { parent, name }).await
    }

    pub async fn symlink(&self, parent: Path, name: Name, target: Vec<u8>) -> Result<Attr, Error> {
        self.call_attr(Request::Symlink {
            parent,
            name,
            target,
        })
        .await
    }

    pub async fn rename(
        &self,
        parent: Path,
        name: Name,
        newparent: Path,
        newname: Name,
        flags: u32,
    ) -> Result<(), Error> {
        self.call_ok(Request::Rename {
            parent,
            name,
            newparent,
            newname,
            flags,
        })
        .await
    }

    pub async fn link(&self, path: Path, newparent: Path, newname: Name) -> Result<Attr, Error> {
        self.call_attr(Request::Link {
            path,
            newparent,
            newname,
        })
        .await
    }

    /// `node` says which node the file the path led to is, or refuses it as not the one meant.
    pub async fn open(
        &self,
        path: Path,
        flags: i32,
        node: impl FnOnce(&Attr) -> Result<u64, Error>,
    ) -> Result<(u64, Attr), Error> {
        let p = path.clone();
        self.open_handle(
            path,
            flags,
            HandleKind::File,
            move |fh| Request::Open { fh, path: p, flags },
            node,
        )
        .await
    }

    /// `node` registers the new file and says which node it is; the handle is recorded under that node, so it cannot exist before the node does.
    pub async fn create(
        &self,
        parent: Path,
        name: Name,
        mode: u32,
        flags: i32,
        node: impl FnOnce(&Attr) -> Result<u64, Error>,
    ) -> Result<(u64, Attr), Error> {
        let path = match parent.join(name.clone()) {
            Ok(path) => path,
            Err(e) => {
                tracing::debug!(?parent, %name, "cannot create: {e}");
                return Err(Error::Remote(libc::ENAMETOOLONG));
            }
        };
        self.open_handle(
            path,
            flags,
            HandleKind::File,
            move |fh| Request::Create {
                fh,
                parent,
                name,
                mode,
                flags,
            },
            node,
        )
        .await
    }

    pub async fn read(&self, fh: u64, offset: u64, size: u32) -> Result<Vec<u8>, Error> {
        self.call_bytes(Request::Read { fh, offset, size }).await
    }

    pub async fn write(&self, fh: u64, offset: u64, data: Vec<u8>) -> Result<u32, Error> {
        match self.call(Request::Write { fh, offset, data }).await? {
            Response::Written(n) => Ok(n),
            other => Err(unexpected(other)),
        }
    }

    /// How many bytes the server copied, which may be fewer than `len`.
    pub async fn copy_file_range(
        &self,
        fh_in: u64,
        offset_in: u64,
        fh_out: u64,
        offset_out: u64,
        len: u64,
    ) -> Result<u32, Error> {
        let req = Request::CopyFileRange {
            fh_in,
            offset_in,
            fh_out,
            offset_out,
            len,
        };
        match self.call(req).await? {
            Response::Copied(n) if u64::from(n) <= len => Ok(n),
            other => Err(unexpected(other)),
        }
    }

    /// One request for every [`MAX_FALLOCATE`] of the range, in order, stopping at the first failure; what came before it stays done, as after a `fallocate(2)` that ran out of space.
    pub async fn fallocate(&self, fh: u64, offset: u64, len: u64, mode: i32) -> Result<(), Error> {
        let mut done = 0;
        loop {
            let chunk = (len - done).min(MAX_FALLOCATE);
            self.call_ok(Request::Fallocate {
                fh,
                offset: offset + done,
                len: chunk,
                mode,
            })
            .await?;
            done += chunk;
            if done == len {
                return Ok(());
            }
        }
    }

    /// The offset of the next data or hole at or after `offset`, as the server's filesystem sees the file.
    pub async fn lseek(&self, fh: u64, offset: u64, whence: Whence) -> Result<u64, Error> {
        match self.call(Request::Lseek { fh, offset, whence }).await? {
            Response::Seeked(found) => Ok(found),
            other => Err(unexpected(other)),
        }
    }

    /// Forget the handle locally first so a reconnect never reopens it, then tell the server.
    pub async fn release(&self, fh: u64) -> Result<(), Error> {
        self.caller.handles.remove(fh);
        self.caller.release(Request::Release { fh }).await
    }

    pub async fn fsync(&self, fh: u64, datasync: bool) -> Result<(), Error> {
        self.call_ok(Request::Fsync { fh, datasync }).await
    }

    /// `node` as for [`Self::open`].
    pub async fn opendir(
        &self,
        path: Path,
        node: impl FnOnce(&Attr) -> Result<u64, Error>,
    ) -> Result<(u64, Attr), Error> {
        let p = path.clone();
        self.open_handle(
            path,
            libc::O_RDONLY | libc::O_DIRECTORY,
            HandleKind::Dir,
            move |fh| Request::Opendir { fh, path: p },
            node,
        )
        .await
    }

    /// A page of entries, every one but the dots with its attributes, and whether the directory ended with its last one.
    pub async fn readdir(
        &self,
        fh: u64,
        offset: u64,
        max_bytes: u32,
    ) -> Result<(Vec<DirEntry>, bool), Error> {
        match self
            .call(Request::Readdir {
                fh,
                offset,
                max_bytes,
            })
            .await?
        {
            Response::Readdir { entries, end } => Ok((entries, end)),
            other => Err(unexpected(other)),
        }
    }

    pub async fn releasedir(&self, fh: u64) -> Result<(), Error> {
        self.caller.handles.remove(fh);
        self.caller.release(Request::Releasedir { fh }).await
    }

    pub async fn statfs(&self, path: Path) -> Result<Statfs, Error> {
        match self.call(Request::Statfs { path }).await? {
            Response::Statfs(s) => Ok(s),
            other => Err(unexpected(other)),
        }
    }

    pub async fn setxattr(
        &self,
        path: Path,
        name: Vec<u8>,
        value: Vec<u8>,
        flags: i32,
    ) -> Result<(), Error> {
        self.call_ok(Request::Setxattr {
            path,
            name,
            value,
            flags,
        })
        .await
    }

    pub async fn getxattr(&self, path: Path, name: Vec<u8>) -> Result<Vec<u8>, Error> {
        self.call_bytes(Request::Getxattr { path, name }).await
    }

    pub async fn listxattr(&self, path: Path) -> Result<Vec<u8>, Error> {
        self.call_bytes(Request::Listxattr { path }).await
    }

    pub async fn removexattr(&self, path: Path, name: Vec<u8>) -> Result<(), Error> {
        self.call_ok(Request::Removexattr { path, name }).await
    }

    pub async fn access(&self, path: Path, mask: i32) -> Result<(), Error> {
        self.call_ok(Request::Access { path, mask }).await
    }
}

fn release_request(kind: HandleKind, fh: u64) -> Request {
    match kind {
        HandleKind::File => Request::Release { fh },
        HandleKind::Dir => Request::Releasedir { fh },
    }
}

fn unexpected(resp: Response) -> Error {
    Error::Protocol(format!("unexpected reply {}", response_name(&resp)))
}

fn response_name(resp: &Response) -> &'static str {
    match resp {
        Response::Err(_) => "Err",
        Response::Entry(_) => "Entry",
        Response::Attr(_) => "Attr",
        Response::Readlink(_) => "Readlink",
        Response::Ok => "Ok",
        Response::Opened { .. } => "Opened",
        Response::Read(_) => "Read",
        Response::Written(_) => "Written",
        Response::Readdir { .. } => "Readdir",
        Response::Statfs(_) => "Statfs",
        Response::Xattr(_) => "Xattr",
        Response::Copied(_) => "Copied",
        Response::Seeked(_) => "Seeked",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jackalopefs_proto::{Path, SetAttr};

    #[test]
    fn errno_mapping_clamps_garbage() {
        assert_eq!(Error::Timeout.errno(), libc::ETIMEDOUT);
        assert_eq!(Error::Interrupted.errno(), libc::EINTR);
        assert_eq!(Error::Disconnected.errno(), libc::EIO);
        assert_eq!(Error::Stale.errno(), libc::ESTALE);
        assert_eq!(Error::Unmapped.errno(), libc::EINVAL);
        assert_eq!(Error::Remote(libc::ENOENT).errno(), libc::ENOENT);
        assert_eq!(Error::Remote(0).errno(), libc::EIO);
        assert_eq!(Error::Remote(-5).errno(), libc::EIO);
        assert_eq!(Error::Remote(1 << 20).errno(), libc::EIO);
    }

    #[test]
    fn retry_policy() {
        let name = Name::new(b"x").unwrap();
        assert!(retry_safe(&Request::Read {
            fh: 1,
            offset: 0,
            size: 1
        }));
        assert!(retry_safe(&Request::Write {
            fh: 1,
            offset: 0,
            data: Vec::new()
        }));
        assert!(retry_safe(&Request::CopyFileRange {
            fh_in: 1,
            offset_in: 0,
            fh_out: 2,
            offset_out: 0,
            len: 1
        }));
        assert!(retry_safe(&Request::Fallocate {
            fh: 1,
            offset: 0,
            len: 1,
            mode: libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE
        }));
        assert!(retry_safe(&Request::Lseek {
            fh: 1,
            offset: 0,
            whence: Whence::Data
        }));
        assert!(retry_safe(&Request::Open {
            fh: 4,
            path: Path::root(),
            flags: libc::O_RDWR
        }));
        assert!(!retry_safe(&Request::Open {
            fh: 4,
            path: Path::root(),
            flags: libc::O_RDWR | libc::O_TRUNC
        }));
        assert!(!retry_safe(&Request::Create {
            fh: 4,
            parent: Path::root(),
            name: name.clone(),
            mode: 0,
            flags: libc::O_EXCL
        }));
        assert!(retry_safe(&Request::Setattr {
            path: Some(Path::root()),
            fh: None,
            set: SetAttr::default()
        }));
        assert!(retry_safe(&Request::Release { fh: 1 }));
        assert!(!retry_safe(&Request::Unlink {
            parent: Path::root(),
            name: name.clone()
        }));
        assert!(!retry_safe(&Request::Rename {
            parent: Path::root(),
            name: name.clone(),
            newparent: Path::root(),
            newname: name.clone(),
            flags: 0
        }));
        assert!(!retry_safe(&Request::Mkdir {
            parent: Path::root(),
            name,
            mode: 0
        }));
    }
}

//! The typed request API. A request on a live connection is waited for as long as that connection lives, or up to an optional deadline; only the wait for a connection is always bounded. A call whose reply was lost to a dropped connection is retried once on the next connection only when that is safe, and a call made for a kernel request is abandoned when the kernel interrupts that request.

use crate::conn::{Attached, ConfigConn, ConnManager, ConnState};
use crate::handles::Opener;
use crate::handles::{HandleKind, HandleRec, HandleTable};
use crate::ids::{IdMap, ModeIds};
use crate::inodes::KeyNode;
use crate::perf::{AccountCall, Outcome, Perf, Phases, Slowpath, EVENT_TARGET, TRACE_TARGET};
use crate::transport::ServerTrust;
use jackalopefs_perf::event;
use jackalopefs_perf::hub::{elided, Hub, IdsEvent, Side};
use jackalopefs_perf::stall::ErrorLockHeld;
use jackalopefs_proto::control::{Ids, Summary};
use jackalopefs_proto::{
    code_reset, encode, read_frame_body, Attr, Auth, DirEntry, ErrorCodec, Event, Identity, Name,
    Path, Request, Response, SetAttr, Statfs, Whence, MAX_FALLOCATE,
};
use quinn::{Connection, RecvStream, SendStream};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::time::{timeout_at, Instant};

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
    /// The call stopped waiting for the reply.
    GaveUp(Error),
}

impl From<ErrorExchange> for Error {
    fn from(e: ErrorExchange) -> Error {
        match e {
            ErrorExchange::NotSent(_) | ErrorExchange::Lost(_) => Error::Disconnected,
            ErrorExchange::Protocol(msg) => Error::Protocol(msg),
            ErrorExchange::GaveUp(e) => e,
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
    /// For the server to say what became of an earlier change on the connection that a call gave up on; a change waits for that before it is sent.
    Cancel,
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

/// The reason a call stops waiting for its reply, when one comes: the kernel interrupts the request it is made for, or the optional deadline passes.
async fn give_up(kernel: Option<&RequestKernel>, limit: Option<Duration>) -> Error {
    let interrupted = async {
        match kernel {
            Some(kernel) => kernel.interrupted().await,
            None => std::future::pending().await,
        }
    };
    let expired = async {
        match limit {
            Some(limit) => tokio::time::sleep(limit).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        biased;
        () = interrupted => Error::Interrupted,
        () = expired => Error::Timeout,
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

/// A request's send side. Dropped before it is done with (a timeout, an interrupt), it resets the side so the server sees a cancellation rather than a clean end of stream.
struct SideSend {
    send: SendStream,
    done: bool,
}

impl SideSend {
    /// End the side cleanly, the request whole.
    fn finish(&mut self) -> Result<(), quinn::ClosedStream> {
        self.done = true;
        self.send.finish()
    }

    /// Tell the server the call gave up on the request.
    fn cancel(&mut self) {
        self.done = true;
        if let Err(e) = self.send.reset(code_reset::CANCELLED.into()) {
            tracing::trace!("reset after cancel: {e}");
        }
    }
}

impl Drop for SideSend {
    fn drop(&mut self) {
        if !self.done {
            self.cancel();
        }
    }
}

/// A request's receive side. Dropped before the reply was read, it stops the side so the server sees the call gave up.
struct SideRecv {
    recv: RecvStream,
    done: bool,
}

impl Drop for SideRecv {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        if let Err(e) = self.recv.stop(code_reset::CANCELLED.into()) {
            tracing::trace!("stop after cancel: {e}");
        }
    }
}

/// A change on a connection that the call gave up on and the server has not yet said what became of, counted on the connection's [`Attached::cancels`] until dropped.
struct CancelPending(watch::Sender<usize>);

impl CancelPending {
    fn count(cancels: &watch::Sender<usize>) -> CancelPending {
        cancels.send_modify(|n| *n += 1);
        CancelPending(cancels.clone())
    }
}

impl Drop for CancelPending {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n -= 1);
    }
}

/// Read the stream's end if it has already arrived, as it does with the reply the server finishes it after, without waiting for it: a receive side dropped before its end was read sends the server a STOP_SENDING.
fn read_end_now(recv: &mut RecvStream) {
    let mut byte = [0u8; 1];
    let read = std::pin::pin!(recv.read(&mut byte));
    let polled = read.poll(&mut std::task::Context::from_waker(std::task::Waker::noop()));
    match polled {
        std::task::Poll::Ready(Ok(Some(_))) => {
            tracing::debug!("data after the reply on its stream")
        }
        std::task::Poll::Ready(Err(e)) => {
            tracing::trace!("reply stream ended without finishing: {e}")
        }
        std::task::Poll::Ready(Ok(None)) | std::task::Poll::Pending => {}
    }
}

/// What the server said became of a change the call gave up on, read from how its reply stream ended.
fn verdict_of(read: &Result<(Vec<u8>, Result<Response, ErrorCodec>), ErrorCodec>) -> &'static str {
    let reset = match read {
        Ok((_, Ok(_))) => return "finished",
        Ok((_, Err(_))) => return "undecodable",
        Err(ErrorCodec::Io(io)) => io
            .get_ref()
            .and_then(|e| e.downcast_ref::<quinn::ReadError>()),
        Err(_) => None,
    };
    match reset {
        Some(quinn::ReadError::Reset(code)) if *code == code_reset::UNRUN.into() => "unrun",
        Some(quinn::ReadError::Reset(code)) if *code == code_reset::FENCED.into() => "fenced",
        Some(quinn::ReadError::Reset(code)) if *code == code_reset::SUPERSEDED.into() => {
            "superseded"
        }
        _ if matches!(read, Err(ErrorCodec::Io(io)) if io.kind() == std::io::ErrorKind::UnexpectedEof) => {
            "unread"
        }
        _ => "lost",
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

/// Where an exchange goes, for the frames a tap captures: the process's hub, and the session and connection on which it is made.
#[derive(Clone, Copy)]
pub(crate) struct Tapping<'a> {
    pub hub: &'a Arc<Hub>,
    pub session: u64,
    pub conn: Option<u64>,
}

/// One request on one fresh bidi stream, until `give_up` says the call stops waiting. When a tap captures this exchange ([`Hub::sample`]), it gets the request as sent and the reply as received, before any rewriting here, so its bytes are the server's.
///
/// A change keeps its send side open until the reply is in, so that giving up on it can still reach the server: the side is reset, and the server answers by resetting its own, having dropped the change unrun or made the session's later changes wait for it, or with the reply if the change was done. That answer is waited for in the background, the change counted on `cancels` meanwhile; with no `cancels`, a change given up on is dropped like a read, both sides reset at once.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn exchange(
    conn: &Connection,
    root: &KeyRoot,
    ids: &IdMap,
    req: &Request,
    timing: &mut Timing<'_>,
    tapping: Tapping<'_>,
    cancels: Option<&watch::Sender<usize>>,
    give_up: impl Future<Output = Error>,
) -> Result<Response, ErrorExchange> {
    tokio::pin!(give_up);
    let opened = tokio::select! {
        biased;
        e = &mut give_up => return Err(ErrorExchange::GaveUp(e)),
        opened = conn.open_bi() => opened,
    };
    let (send, recv) =
        opened.map_err(|e| ErrorExchange::NotSent(format!("cannot open a stream: {e}")))?;
    let stream = u64::from(send.id());
    timing.stamp_opened(stream);
    let mut send = SideSend { send, done: false };
    let recv = SideRecv { recv, done: false };
    let unique = timing.kernel.map(|kernel| kernel.unique);
    let tap_ids = || IdsEvent {
        session: Some(tapping.session),
        conn: tapping.conn,
        stream: Some(stream),
        unique,
        op: Some(req.op_name()),
    };
    let frame = encode(req).map_err(|e| ErrorExchange::Protocol(e.to_string()))?;
    let mut sampled = if tapping.hub.wants_frames() {
        tapping.hub.sample(Side::Client, tap_ids())
    } else {
        None
    };
    if let Some(sampled) = sampled.as_mut() {
        sampled.request(&frame[4..], || elided(req.with_data_elided()));
        sampled.outcome("not sent");
    }
    tokio::select! {
        biased;
        e = &mut give_up => return Err(ErrorExchange::GaveUp(e)),
        written = send.send.write_all(&frame) => {
            written.map_err(|e| ErrorExchange::NotSent(format!("the stream failed: {e}")))?
        }
    }
    let changes = req.changes();
    if !changes {
        if let Err(e) = send.finish() {
            if let Some(sampled) = sampled.as_mut() {
                sampled.outcome("lost");
            }
            return Err(ErrorExchange::Lost(format!(
                "cannot finish the request: {e}"
            )));
        }
    }
    timing.stamp_sent(stream);
    // From here, a reply that never comes is the call giving up, unless the stream fails.
    if let Some(sampled) = sampled.as_mut() {
        sampled.outcome("abandoned");
    }
    let mut reply = Box::pin(async move {
        let mut recv = recv;
        let read = read_frame_body::<_, Response>(&mut recv.recv).await;
        recv.done = true;
        if read.is_ok() {
            read_end_now(&mut recv.recv);
        }
        read
    });
    let read = tokio::select! {
        biased;
        read = &mut reply => read,
        e = &mut give_up => {
            let Some(cancels) = cancels.filter(|_| changes) else {
                return Err(ErrorExchange::GaveUp(e));
            };
            let pending = CancelPending::count(cancels);
            send.cancel();
            let op = req.op_name();
            tokio::spawn(async move {
                let read = reply.await;
                let verdict = verdict_of(&read);
                tracing::debug!(op, stream, verdict, "a change given up on was answered");
                match (sampled, &read) {
                    (Some(sampled), Ok((body, Ok(resp)))) => {
                        sampled.reply(body, || elided(resp.with_data_elided()))
                    }
                    (Some(mut sampled), _) => sampled.outcome(verdict),
                    (None, _) => {}
                }
                drop(pending);
            });
            return Err(ErrorExchange::GaveUp(e));
        }
    };
    let (body, decoded) = match read {
        Ok(read) => read,
        Err(e) => {
            if let Some(sampled) = sampled.as_mut() {
                sampled.outcome("lost");
            }
            return Err(codec_error(e, ErrorExchange::Lost));
        }
    };
    let mut resp = match decoded {
        Ok(resp) => resp,
        Err(e) => {
            match sampled {
                Some(sampled) => sampled.undecodable(&body),
                None if tapping.hub.wants_frames() => {
                    tapping
                        .hub
                        .undecodable(Side::Client, &tap_ids(), &e.to_string(), &body)
                }
                None => {}
            }
            return Err(ErrorExchange::Protocol(e.to_string()));
        }
    };
    timing.replied = Some(Instant::now());
    if changes {
        if let Err(e) = send.finish() {
            tracing::trace!("finishing a change's request after its reply: {e}");
        }
    }
    if let Some(sampled) = sampled {
        sampled.reply(&body, || elided(resp.with_data_elided()));
    }
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

/// Whether a request whose reply was lost may be sent again without changing the outcome, given the records of the handles it names. A write is positional unless its handle was opened with `O_APPEND`, which the server honours by writing at its own end of file each time; one on a handle this client has no record of is not resent.
fn retry_safe(req: &Request, handles: &[Option<Arc<HandleRec>>; 2]) -> bool {
    match req {
        Request::Lookup { .. }
        | Request::Getattr { .. }
        | Request::Setattr { .. }
        | Request::Readlink { .. }
        | Request::Read { .. }
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
        Request::Write { .. } => handles[0].as_ref().is_some_and(|rec| !rec.appends()),
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
        if self.perf.hub.wants_requests() {
            self.perf.hub.deliver_request(op, || {
                let (fh, offset, size) = req.perf_fields();
                let ns = |d: Duration| d.as_nanos() as u64;
                Summary {
                    level: "call".into(),
                    ids: Ids {
                        session: account.session,
                        conn: account.conn,
                        stream: account.stream,
                        unique: kernel.as_ref().map(|r| r.unique),
                        op: Some(op.into()),
                    },
                    fh,
                    offset,
                    size,
                    bytes: outcome.bytes,
                    items: outcome.items,
                    errno: outcome.errno,
                    phases: vec![
                        ("wait".into(), ns(account.phases.wait)),
                        ("open".into(), ns(account.phases.open)),
                        ("send".into(), ns(account.phases.send)),
                        ("reply".into(), ns(account.phases.reply)),
                    ],
                    total_ns: ns(total),
                    ..Summary::default()
                }
            });
        }
        result
    }

    /// The exchange and its retries; every attempt's phases are added to `account`. The two waits have different clocks. The wait for a connection is bounded by the offline deadline, set once and renewed only for the one resend a lost reply gets, so a server that keeps accepting connections and failing streams cannot hold a call forever; it also ends when the outage itself has lasted the offline timeout, so through a long outage calls fail at once instead of each waiting out a deadline of its own. The exchange itself, with a change's wait for the server to answer the connection's earlier cancels, is bounded only by the optional operation deadline: a server slow to answer on a live connection is not an error, and the connection's own idle timeout fails the exchange if the server dies. Either wait ends early when the kernel interrupts the request the call is made for.
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
            let give_up = give_up(kernel, self.op_timeout);
            tokio::pin!(give_up);
            // A change goes out only once the server has said what became of every change this connection gave up on, so none of those can land after it.
            if req.changes() && *attached.cancels.borrow() != 0 {
                if let Some(kernel) = kernel {
                    kernel.call_phase(PhaseCall::Cancel, Some(&attached), None);
                }
                let mut cancels = attached.cancels.subscribe();
                let waiting = Instant::now();
                let answered = tokio::select! {
                    biased;
                    e = &mut give_up => Err(e),
                    answered = cancels.wait_for(|pending| *pending == 0) => {
                        answered.expect("the connection's count lives as long as the connection");
                        Ok(())
                    }
                };
                account.phases.wait += waiting.elapsed();
                answered?;
            }
            if let Some(kernel) = kernel {
                kernel.call_phase(PhaseCall::Open, Some(&attached), None);
            }
            let mut timing = Timing::for_kernel(kernel);
            let attempt = Instant::now();
            let exchanged = exchange(
                &attached.conn,
                &attached.root,
                &attached.ids,
                sent,
                &mut timing,
                Tapping {
                    hub: &self.perf.hub,
                    session: attached.session_id,
                    conn: attached.conn_key,
                },
                Some(&attached.cancels),
                &mut give_up,
            )
            .await;
            account.phases += timing.phases(attempt);
            account.session = Some(attached.session_id);
            account.generation = Some(attached.generation);
            account.conn = attached.conn_key;
            account.stream = timing.stream;
            match exchanged {
                Ok(Response::Err(errno)) => return Err(Error::Remote(errno)),
                Ok(resp) => return Ok(resp),
                Err(ErrorExchange::NotSent(cause)) => {
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
                Err(ErrorExchange::Lost(cause)) => {
                    if lost_once || !retry_safe(req, &handles) {
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
                Err(ErrorExchange::Protocol(msg)) => return Err(Error::Protocol(msg)),
                Err(ErrorExchange::GaveUp(e)) => return Err(e),
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
            perf.clone(),
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

    /// Open (or opendir, or create) under a fresh handle id, recorded with the process whose open it is. `node` says which node the reply's attributes belong to, or refuses them (an open whose path led to a file other than the one meant; a created file that cannot be registered), in which case the handle is released. Whenever the outcome leaves any doubt about whether the server opened something, the id is released in the background; only a definite refusal from the server needs no cleanup.
    async fn open_handle(
        &self,
        path: Path,
        flags: i32,
        kind: HandleKind,
        opener: Option<Opener>,
        build: impl FnOnce(u64) -> Request,
        node: impl FnOnce(&Attr) -> Result<u64, Error>,
    ) -> Result<(u64, Attr), Error> {
        let fh = self.caller.handles.alloc();
        let req = build(fh);
        match self.call(req).await {
            Ok(Response::Opened { attr }) => match node(&attr) {
                Ok(nodeid) => {
                    self.caller.handles.insert(
                        fh,
                        nodeid,
                        KeyNode::of(&attr),
                        path,
                        flags,
                        kind,
                        opener,
                    );
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
        opener: Option<Opener>,
        node: impl FnOnce(&Attr) -> Result<u64, Error>,
    ) -> Result<(u64, Attr), Error> {
        let p = path.clone();
        self.open_handle(
            path,
            flags,
            HandleKind::File,
            opener,
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
        opener: Option<Opener>,
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
            opener,
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
        opener: Option<Opener>,
        node: impl FnOnce(&Attr) -> Result<u64, Error>,
    ) -> Result<(u64, Attr), Error> {
        let p = path.clone();
        self.open_handle(
            path,
            libc::O_RDONLY | libc::O_DIRECTORY,
            HandleKind::Dir,
            opener,
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
    Error::Protocol(format!("unexpected reply {}", resp.kind_name()))
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
        let table = HandleTable::default();
        let opened = |flags| {
            let key = KeyNode {
                ino: 1,
                identity: jackalopefs_proto::Identity {
                    handle_type: 1,
                    handle: Vec::new(),
                },
            };
            Some(table.insert(
                table.alloc(),
                1,
                key,
                Path::root(),
                flags,
                HandleKind::File,
                None,
            ))
        };
        let write = Request::Write {
            fh: 1,
            offset: 0,
            data: Vec::new(),
        };
        assert!(retry_safe(&write, &[opened(libc::O_WRONLY), None]));
        assert!(!retry_safe(
            &write,
            &[opened(libc::O_WRONLY | libc::O_APPEND), None]
        ));
        assert!(
            !retry_safe(&write, &[None, None]),
            "a handle this client never recorded"
        );
        assert!(retry_safe(
            &Request::Read {
                fh: 1,
                offset: 0,
                size: 1
            },
            &[None, None]
        ));
        assert!(retry_safe(
            &Request::CopyFileRange {
                fh_in: 1,
                offset_in: 0,
                fh_out: 2,
                offset_out: 0,
                len: 1
            },
            &[None, None]
        ));
        assert!(retry_safe(
            &Request::Fallocate {
                fh: 1,
                offset: 0,
                len: 1,
                mode: libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE
            },
            &[None, None]
        ));
        assert!(retry_safe(
            &Request::Lseek {
                fh: 1,
                offset: 0,
                whence: Whence::Data
            },
            &[None, None]
        ));
        assert!(retry_safe(
            &Request::Open {
                fh: 4,
                path: Path::root(),
                flags: libc::O_RDWR
            },
            &[None, None]
        ));
        assert!(!retry_safe(
            &Request::Open {
                fh: 4,
                path: Path::root(),
                flags: libc::O_RDWR | libc::O_TRUNC
            },
            &[None, None]
        ));
        assert!(!retry_safe(
            &Request::Create {
                fh: 4,
                parent: Path::root(),
                name: name.clone(),
                mode: 0,
                flags: libc::O_EXCL
            },
            &[None, None]
        ));
        assert!(retry_safe(
            &Request::Setattr {
                path: Some(Path::root()),
                fh: None,
                set: SetAttr::default()
            },
            &[None, None]
        ));
        assert!(retry_safe(&Request::Release { fh: 1 }, &[None, None]));
        assert!(!retry_safe(
            &Request::Unlink {
                parent: Path::root(),
                name: name.clone()
            },
            &[None, None]
        ));
        assert!(!retry_safe(
            &Request::Rename {
                parent: Path::root(),
                name: name.clone(),
                newparent: Path::root(),
                newname: name.clone(),
                flags: 0
            },
            &[None, None]
        ));
        assert!(!retry_safe(
            &Request::Mkdir {
                parent: Path::root(),
                name,
                mode: 0
            },
            &[None, None]
        ));
    }
}

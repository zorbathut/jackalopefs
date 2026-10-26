//! Connection handling: the hello handshake, session resumption, the event stream, and one task per request stream.
//!
//! The session protocol here (sessions and their epochs, the fence, the phases of a request) is modelled in `spec/session.qnt`; a change to it updates the model, or its commit says why not (`spec/README.md`, "Keeping it in sync").

use crate::export::Export;
use crate::handles::{HandlePool, Handles};
use crate::ids::IdMap;
use crate::ops::{self, Ops};
use crate::perf::{Outcome, Perf, Phases, Slowpath, EVENT_TARGET, TRACE_TARGET};
use crate::watch::{ChangeLog, EventBatch, Watches};
use crate::{Limits, SESSION_GRACE};
use jackalopefs_perf::event;
use jackalopefs_perf::hub::{elided, Hub, IdsEvent, Side};
use jackalopefs_perf::spec_trace;
#[cfg(feature = "spec-trace")]
use jackalopefs_perf::spec_trace::{
    Begun, CauseUndecoded, EndHeld, EventSpec, KeyExchange, Recorder, Verdict as VerdictSpec,
};
use jackalopefs_perf::{
    fmt_duration, line_process, line_quic, line_udp, lines_link, verdict, MeterLink, MeterProcess,
    MeterUdp, SampleLink, TrackerQuic,
};
use jackalopefs_proto::control::{HandlesSession, HandlesTotals, StateSession, Summary};
use jackalopefs_proto::{
    code_reset, encode, read_frame, read_frame_body, write_frame, Auth, Event, EventItem, Hello,
    HelloReply, NoticeHandles, Request, Response, PROTO_REVISION,
};
use parking_lot::Mutex;
use quinn::{Connection, RecvStream, SendStream};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
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
/// How long a request stream is read for the client's end of it once the reply is out.
const REQUEST_FIN_TIMEOUT: Duration = Duration::from_secs(2);

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
    /// Woken when the last change a later one waits for finishes: the last of an earlier connection's, or the last the client gave up on.
    drained: tokio::sync::Notify,
    /// What of the session is under way ([`Holder`]): its requests from when their streams are accepted until they end, and its attached connection. The session model's `alive`.
    holders: AtomicUsize,
    #[cfg(feature = "spec-trace")]
    recorder: Option<Arc<jackalopefs_perf::spec_trace::Recorder>>,
}

#[derive(Default)]
struct Attachment {
    epoch: u64,
    detached_at: Option<Instant>,
    /// The client's address on the connection that last attached.
    remote: Option<std::net::SocketAddr>,
    /// Changes running now from the connection attached at `epoch`; of those, the ones the client gave up on; and the changes running from the session's earlier connections.
    running: usize,
    abandoned: usize,
    running_older: usize,
}

#[cfg(feature = "spec-trace")]
impl Attachment {
    fn counts(&self) -> jackalopefs_perf::spec_trace::Counts {
        jackalopefs_perf::spec_trace::Counts {
            epoch: self.epoch,
            running: self.running,
            abandoned: self.abandoned,
            running_older: self.running_older,
        }
    }
}

/// One request, from decoding to its end, in the phases of the session model's requests (`spec/session.qnt`). A change ([`Request::changes`]) takes part in the session's ordering and moves only under its session's attachment lock, with the counts it is part of; any other request has no counts, and moves under its own lock alone.
pub(crate) struct Exchange {
    ordered: bool,
    phase: Mutex<PhaseExchange>,
    /// Its request's hold on the session, let go as it ends.
    holder: Mutex<Option<Holder>>,
    /// The exchange and operation it is, for the events recorded under the attachment lock.
    #[cfg(feature = "spec-trace")]
    traced: std::sync::OnceLock<(jackalopefs_perf::spec_trace::KeyExchange, &'static str)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PhaseExchange {
    /// A change waiting for the changes it is fenced behind ([`SessionState::drained`]).
    Held,
    /// Waiting for a blocking thread to begin it.
    Ready,
    /// Given up on before it began; it will not run.
    Cancelled,
    /// Its connection stopped being the session's current one before it began; it will not run.
    Superseded,
    /// Its stream ended while it was held; it will not run.
    Dropped,
    Running,
    /// Given up on while it ran; later changes wait for it.
    Abandoned,
    Finished,
}

impl Exchange {
    /// The request just decoded, with the hold it has had on the session since its stream was accepted.
    pub(crate) fn new(ordered: bool, holder: Holder) -> Arc<Exchange> {
        Arc::new(Exchange {
            ordered,
            phase: Mutex::new(PhaseExchange::Ready),
            holder: Mutex::new(Some(holder)),
            #[cfg(feature = "spec-trace")]
            traced: std::sync::OnceLock::new(),
        })
    }

    #[cfg(feature = "spec-trace")]
    fn key(&self) -> jackalopefs_perf::spec_trace::KeyExchange {
        self.traced
            .get()
            .expect("an exchange is keyed when it is decoded")
            .0
    }

    /// Move to the terminal `to`, letting go of the session.
    fn end(&self, phase: &mut PhaseExchange, to: PhaseExchange) {
        *phase = to;
        self.holder.lock().take();
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        if self.holder.get_mut().is_some() {
            tracing::debug!(phase = ?self.phase.get_mut(), "a request was dropped before it ended");
        }
    }
}

/// A hold on a session by something of it under way, which keeps a dropped session resumable ([`Sessions::resume`]); let go when dropped.
pub(crate) struct Holder {
    session: Arc<SessionState>,
}

impl Drop for Holder {
    fn drop(&mut self) {
        self.session.holders.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What became of a change the client gave up on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// It had not begun, and will not run.
    Unrun,
    /// It is running, and the session's later changes wait for it.
    Fenced,
    /// It has run; its reply goes out as usual.
    Finished,
    /// The session resumed on a newer connection before it began, and it will not run; it is answered as superseded.
    Superseded,
}

impl SessionState {
    /// A hold on the session for a request whose stream was just accepted.
    pub(crate) fn hold(self: &Arc<Self>) -> Holder {
        self.holders.fetch_add(1, Ordering::SeqCst);
        Holder {
            session: self.clone(),
        }
    }

    /// Begin `exchange`, from the connection attached at `epoch`. A change is counted as running, unless the client gave up on it, or the session has resumed on a newer connection since: then the client has already resent the change or failed it. Either way it must not run. Any other request begins whatever the epoch, and is counted nowhere.
    fn begin(self: &Arc<Self>, epoch: u64, exchange: &Arc<Exchange>) -> Option<GuardExchange> {
        if !exchange.ordered {
            let mut phase = exchange.phase.lock();
            assert_eq!(*phase, PhaseExchange::Ready, "a request begins once");
            *phase = PhaseExchange::Running;
            spec_trace!(
                self.recorder.as_ref(),
                EventSpec::Began {
                    key: exchange.key(),
                    begun: Begun::Running,
                    counts: None,
                }
            );
            return Some(GuardExchange {
                session: self.clone(),
                epoch,
                exchange: exchange.clone(),
                #[cfg(feature = "spec-trace")]
                errno: false,
            });
        }
        let change = exchange;
        let mut attachment = self.attachment.lock();
        let mut phase = change.phase.lock();
        let cancelled = match *phase {
            PhaseExchange::Ready => false,
            PhaseExchange::Cancelled => true,
            other => unreachable!("a change begins once it is ready, not {other:?}"),
        };
        if cancelled || attachment.epoch != epoch {
            if !cancelled {
                change.end(&mut phase, PhaseExchange::Superseded);
            }
            spec_trace!(
                self.recorder.as_ref(),
                EventSpec::Began {
                    key: change.key(),
                    begun: if cancelled {
                        Begun::Cancelled
                    } else {
                        Begun::Superseded
                    },
                    counts: Some(attachment.counts()),
                }
            );
            return None;
        }
        *phase = PhaseExchange::Running;
        attachment.running += 1;
        spec_trace!(
            self.recorder.as_ref(),
            EventSpec::Began {
                key: change.key(),
                begun: Begun::Running,
                counts: Some(attachment.counts()),
            }
        );
        Some(GuardExchange {
            session: self.clone(),
            epoch,
            exchange: change.clone(),
            #[cfg(feature = "spec-trace")]
            errno: false,
        })
    }

    /// The client gave up on `change`, from the connection attached at `epoch`. One that has not begun never will; one running holds the session's later changes until it ends, unless an earlier connection's change already does.
    fn abandon(&self, epoch: u64, change: &Exchange) -> Verdict {
        assert!(change.ordered, "only a change is given up on");
        let mut attachment = self.attachment.lock();
        let mut phase = change.phase.lock();
        let verdict = match *phase {
            PhaseExchange::Held | PhaseExchange::Ready => {
                change.end(&mut phase, PhaseExchange::Cancelled);
                Verdict::Unrun
            }
            // `begin` refused it a moment before the cancel came: nothing is left to do, and it is answered as a superseded change is.
            PhaseExchange::Superseded => return Verdict::Superseded,
            PhaseExchange::Running => {
                *phase = PhaseExchange::Abandoned;
                if attachment.epoch == epoch {
                    attachment.abandoned += 1;
                }
                Verdict::Fenced
            }
            PhaseExchange::Cancelled | PhaseExchange::Abandoned => {
                unreachable!("a change is given up on once")
            }
            PhaseExchange::Dropped => {
                unreachable!("a change dropped while held is not given up on")
            }
            PhaseExchange::Finished => Verdict::Finished,
        };
        spec_trace!(
            self.recorder.as_ref(),
            EventSpec::Abandoned {
                key: change.key(),
                verdict: match verdict {
                    Verdict::Unrun => VerdictSpec::Unrun,
                    Verdict::Fenced => VerdictSpec::Fenced,
                    Verdict::Finished => VerdictSpec::Finished,
                    Verdict::Superseded => unreachable!("returned before"),
                },
                counts: attachment.counts(),
            }
        );
        verdict
    }

    /// How many changes `exchange`, just decoded on the connection attached at `epoch`, waits for: for a change, those still running from earlier connections, and those the client gave up on; none for a connection that is no longer current itself, whose changes will not run, and none for any other request. It is held while there are any ([`SessionState::drain`]), and ready otherwise.
    fn fencing(&self, epoch: u64, exchange: &Exchange) -> usize {
        if !exchange.ordered {
            spec_trace!(self.recorder.as_ref(), {
                let (key, op) = *exchange
                    .traced
                    .get()
                    .expect("an exchange is keyed when it is decoded");
                EventSpec::Decoded {
                    key,
                    op,
                    change: false,
                    held: false,
                }
            });
            return 0;
        }
        let change = exchange;
        let attachment = self.attachment.lock();
        let fence = if attachment.epoch == epoch {
            attachment.running_older + attachment.abandoned
        } else {
            0
        };
        if fence > 0 {
            *change.phase.lock() = PhaseExchange::Held;
        }
        spec_trace!(self.recorder.as_ref(), {
            let (key, op) = *change
                .traced
                .get()
                .expect("an exchange is keyed when it is decoded");
            EventSpec::Decoded {
                key,
                op,
                change: true,
                held: fence > 0,
            }
        });
        #[cfg(not(feature = "spec-trace"))]
        let _ = change;
        fence
    }

    /// Whether the held `change`, from the connection attached at `epoch`, goes on: `Some(true)` once it waits for nothing ([`SessionState::fencing`]), when it is ready; `Some(false)` when that connection stopped being current meanwhile, and it will not run; `None` while it is still held.
    fn drained(&self, epoch: u64, change: &Exchange) -> Option<bool> {
        let attachment = self.attachment.lock();
        let mut phase = change.phase.lock();
        assert_eq!(*phase, PhaseExchange::Held, "only a held change drains");
        let current = if attachment.epoch != epoch {
            change.end(&mut phase, PhaseExchange::Superseded);
            false
        } else if attachment.running_older + attachment.abandoned == 0 {
            *phase = PhaseExchange::Ready;
            true
        } else {
            return None;
        };
        spec_trace!(
            self.recorder.as_ref(),
            EventSpec::HeldEnded {
                key: change.key(),
                end: if current {
                    EndHeld::Drained
                } else {
                    EndHeld::Superseded
                }
            }
        );
        Some(current)
    }

    /// Wait until the held `change` goes on ([`SessionState::drained`]).
    async fn drain(&self, epoch: u64, change: &Exchange) -> bool {
        loop {
            // Enabled before the look, so a wake between the two is not lost.
            let notified = self.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(current) = self.drained(epoch, change) {
                return current;
            }
            notified.await;
        }
    }

    /// The held `change`'s stream ended before it drained: the client stopped reading its reply (`lost` false), or its connection went. It will not run.
    fn stopped(&self, change: &Exchange, lost: bool) {
        let _attachment = self.attachment.lock();
        let mut phase = change.phase.lock();
        assert_eq!(*phase, PhaseExchange::Held, "only a held change is stopped");
        change.end(&mut phase, PhaseExchange::Dropped);
        spec_trace!(
            self.recorder.as_ref(),
            EventSpec::HeldEnded {
                key: change.key(),
                end: if lost {
                    EndHeld::Lost
                } else {
                    EndHeld::Stopped
                }
            }
        );
        #[cfg(not(feature = "spec-trace"))]
        let _ = lost;
    }
}

#[cfg(feature = "spec-trace")]
impl Drop for SessionState {
    fn drop(&mut self) {
        spec_trace!(
            self.recorder.as_ref(),
            EventSpec::SessionClosed { session: self.id }
        );
    }
}

/// An exchange running from [`SessionState::begin`] until dropped; a change counted as running all that time.
struct GuardExchange {
    session: Arc<SessionState>,
    epoch: u64,
    exchange: Arc<Exchange>,
    /// Whether the exchange's work ended in an errno, for the event of its end.
    #[cfg(feature = "spec-trace")]
    errno: bool,
}

impl Drop for GuardExchange {
    fn drop(&mut self) {
        if !self.exchange.ordered {
            self.exchange
                .end(&mut self.exchange.phase.lock(), PhaseExchange::Finished);
            spec_trace!(
                self.session.recorder.as_ref(),
                EventSpec::Finished {
                    key: self.exchange.key(),
                    errno: self.errno,
                    counts: None,
                }
            );
            return;
        }
        let mut attachment = self.session.attachment.lock();
        let abandoned = {
            let mut phase = self.exchange.phase.lock();
            let abandoned = *phase == PhaseExchange::Abandoned;
            self.exchange.end(&mut phase, PhaseExchange::Finished);
            abandoned
        };
        let current = attachment.epoch == self.epoch;
        if current {
            attachment.running -= 1;
            if abandoned {
                attachment.abandoned -= 1;
            }
        } else {
            attachment.running_older -= 1;
        }
        spec_trace!(
            self.session.recorder.as_ref(),
            EventSpec::Finished {
                key: self.exchange.key(),
                errno: self.errno,
                counts: Some(attachment.counts()),
            }
        );
        let waited_for = if current {
            if !abandoned {
                return;
            }
            attachment.abandoned
        } else {
            attachment.running_older
        };
        if waited_for == 0 {
            drop(attachment);
            self.session.drained.notify_waiters();
        }
    }
}

/// A connection's hold on its session, from `handle_connection` taking it up to the connection's end, when the session's grace period starts unless a newer connection has taken it over ([`Sessions::detach`]).
pub(crate) struct AttachmentConn {
    sessions: Arc<Sessions>,
    epoch: u64,
    holder: Holder,
}

impl Drop for AttachmentConn {
    fn drop(&mut self) {
        self.sessions.detach(self.holder.session.id, self.epoch);
    }
}

pub struct Sessions {
    map: Mutex<HashMap<u64, Arc<SessionState>>>,
    /// Sessions dropped from `map` (grace run out, or evicted), for as long as anything holds them. A client that names one gets it back while something of it is under way ([`Sessions::resume`], [`Holder`]), so a change of it still queued or running stays ordered before the client's next ones; one with nothing under way has nothing left to order, and the client starts a new session, even while a task of the old one finishes. Locked only under `map`'s lock.
    dropped: Mutex<HashMap<u64, Weak<SessionState>>>,
    next_id: AtomicU64,
    /// The handles a session holds before it is reported.
    handle_share: usize,
    /// The handles every session draws on.
    pool: Arc<HandlePool>,
    /// Where the sessions' events in the model's terms go, set by a trace-validation test before any connection.
    #[cfg(feature = "spec-trace")]
    recorder: OnceLock<Arc<Recorder>>,
}

impl Sessions {
    pub fn new(handle_share: usize, pool: Arc<HandlePool>) -> Sessions {
        Sessions {
            map: Mutex::new(HashMap::new()),
            dropped: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            handle_share,
            pool,
            #[cfg(feature = "spec-trace")]
            recorder: OnceLock::new(),
        }
    }

    #[cfg(feature = "spec-trace")]
    pub fn set_recorder(&self, recorder: Arc<Recorder>) {
        assert!(
            self.recorder.set(recorder).is_ok(),
            "the sessions record for one test"
        );
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
            handles: Handles::new(self.handle_share, self.pool.clone()),
            attachment: Mutex::new(Attachment {
                epoch: 1,
                ..Attachment::default()
            }),
            drained: tokio::sync::Notify::new(),
            holders: AtomicUsize::new(0),
            #[cfg(feature = "spec-trace")]
            recorder: self.recorder.get().cloned(),
        });
        #[cfg(feature = "spec-trace")]
        if let Some(recorder) = self.recorder.get() {
            state.handles.trace(recorder.clone(), id);
        }
        // Declared before the guard, so what was retired is dropped after the lock is released.
        let mut retired = Vec::new();
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
                retired.extend(self.retire(&mut map, *old));
            }
        }
        map.insert(id, state.clone());
        spec_trace!(self.recorder.get(), EventSpec::Created { session: id });
        (state, 1)
    }

    /// Reattach `id` if the token matches; a session still attached elsewhere is taken over, since the client evidently lost that connection. A session dropped from the table comes back while something of it is under way ([`Holder`]). Done under the table's lock, so no drop comes between finding the session and attaching it.
    pub fn resume(&self, id: u64, token: &[u8; 16]) -> Option<(Arc<SessionState>, u64)> {
        let mut map = self.map.lock();
        let (state, dropped) = match map.get(&id) {
            Some(state) => (state.clone(), false),
            None => {
                let state = self.dropped.lock().get(&id)?.upgrade()?;
                if state.holders.load(Ordering::SeqCst) == 0 {
                    // Nothing of it is under way, only tasks finishing. Its last reference may be this one: not under the table's lock.
                    drop(map);
                    return None;
                }
                (state, true)
            }
        };
        if !bool::from(state.resume_token.ct_eq(token)) {
            // A dropped session's last reference may be this one, and dropping it closes its handles: not under the table's lock.
            drop(map);
            return None;
        }
        if dropped {
            tracing::info!(
                session = id,
                "resuming a dropped session whose requests still run"
            );
            self.dropped.lock().remove(&id);
            map.insert(id, state.clone());
        }
        let mut attachment = state.attachment.lock();
        attachment.epoch += 1;
        attachment.detached_at = None;
        attachment.running_older += attachment.running;
        attachment.running = 0;
        attachment.abandoned = 0;
        spec_trace!(
            self.recorder.get(),
            EventSpec::Resumed {
                session: id,
                counts: attachment.counts(),
                dropped
            }
        );
        let epoch = attachment.epoch;
        drop(attachment);
        drop(map);
        // A change held on the connection just superseded will not run now; let it go.
        state.drained.notify_waiters();
        Some((state, epoch))
    }

    /// Move `id` from the table to the dropped sessions, forgetting those of them with nothing left. The session is returned for the caller to drop once the table's lock is released: it is often the last reference, and its drop closes every handle the session holds.
    fn retire(
        &self,
        map: &mut HashMap<u64, Arc<SessionState>>,
        id: u64,
    ) -> Option<Arc<SessionState>> {
        let state = map.remove(&id)?;
        let mut dropped = self.dropped.lock();
        dropped.retain(|_, state| state.strong_count() > 0);
        dropped.insert(id, Arc::downgrade(&state));
        spec_trace!(
            self.recorder.get(),
            EventSpec::SessionDropped { session: id }
        );
        Some(state)
    }

    /// Drop a session no client can resume: one whose Ack, with its id and token, never reached the client.
    fn forget(&self, id: u64) {
        self.map.lock().remove(&id);
    }

    /// The connection attached at `epoch` takes `state` up ([`AttachmentConn`]).
    pub(crate) fn attach(
        self: &Arc<Self>,
        state: &Arc<SessionState>,
        epoch: u64,
    ) -> AttachmentConn {
        AttachmentConn {
            sessions: self.clone(),
            epoch,
            holder: state.hold(),
        }
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

    /// Drop sessions detached for longer than `grace`, closing their handles once nothing of theirs runs.
    pub fn reap(&self, grace: Duration) -> usize {
        let now = Instant::now();
        // Declared before the guard, so what was retired is dropped after the lock is released.
        let mut retired = Vec::new();
        let mut map = self.map.lock();
        let expired: Vec<u64> = map
            .iter()
            .filter(|(_, state)| {
                state
                    .attachment
                    .lock()
                    .detached_at
                    .is_some_and(|at| now.duration_since(at) >= grace)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            retired.extend(self.retire(&mut map, *id));
        }
        expired.len()
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

    /// Every session that holds handles: those in the table, and the dropped ones something still holds, with whether each was dropped. Returned rather than used under the table's lock, since the snapshot may hold a dropped session's last reference, whose drop closes its handles.
    fn snapshot(&self) -> Vec<(Arc<SessionState>, bool)> {
        let map = self.map.lock();
        let mut sessions: Vec<_> = map.values().map(|s| (s.clone(), false)).collect();
        sessions.extend(
            self.dropped
                .lock()
                .values()
                .filter_map(Weak::upgrade)
                .map(|s| (s, true)),
        );
        sessions
    }

    /// Every session's handles by kind, its client's last address and where it stands, in id order; a dropped session is listed while something of it still runs, since its handles stay open until then.
    pub fn handle_rows(&self) -> Vec<HandlesSession> {
        let mut rows: Vec<HandlesSession> = self
            .snapshot()
            .iter()
            .map(|(s, dropped)| {
                let totals = s.handles.totals();
                let attachment = s.attachment.lock();
                HandlesSession {
                    session: s.id,
                    remote: attachment
                        .remote
                        .map_or_else(String::new, |remote| remote.to_string()),
                    state: if *dropped {
                        StateSession::Dropped
                    } else if attachment.detached_at.is_some() {
                        StateSession::Detached
                    } else {
                        StateSession::Attached
                    },
                    files: totals.files,
                    dirs: totals.dirs,
                }
            })
            .collect();
        rows.sort_unstable_by_key(|row| row.session);
        rows
    }

    /// The handles every session holds, by kind, the dropped sessions' still open included.
    pub fn handle_totals(&self) -> HandlesTotals {
        self.snapshot()
            .iter()
            .map(|(s, _)| s.handles.totals())
            .fold(HandlesTotals::default(), |sum, t| HandlesTotals {
                files: sum.files + t.files,
                dirs: sum.dirs + t.dirs,
            })
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
            tracing::info!(target: TRACE_TARGET, "perf handles session={} open={} files={} dirs={} state={} remote={}", row.session, row.files + row.dirs, row.files, row.dirs, row.state.as_str(), row.remote);
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
    spec_trace!(
        session.recorder.as_ref(),
        EventSpec::Attached {
            session: session.id,
            epoch,
            conn: conn_key.unwrap_or(0)
        }
    );
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
            spec_trace!(
                session.recorder.as_ref(),
                EventSpec::ConnEnded {
                    conn: conn_key.unwrap_or(0)
                }
            );
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
        attachment: Some(server.sessions.attach(&session, epoch)),
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
        session: session.clone(),
        epoch,
        conn: conn.clone(),
    });
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                // The request holds its session from here, before its task first runs.
                tokio::spawn(handle_request(
                    serving.clone(),
                    serving.session.hold(),
                    send,
                    recv,
                ));
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
    attachment: Option<AttachmentConn>,
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
        drop(self.attachment.take());
        spec_trace!(
            self.session.recorder.as_ref(),
            EventSpec::ConnEnded {
                conn: jackalopefs_perf::conn_key(&self.conn).unwrap_or(0)
            }
        );
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

/// Undoes the handshake's attaching of a session unless its Ack was written, should the handshake fail after that (the Ack could not be written, or the handshake timed out writing it): a resumed session starts its grace period, since the client still holds its token, and a new one is dropped, since no client ever learned it. It covers the handshake only; `handle_connection` has its own `DetachOnDrop` in place before it next awaits.
struct DetachUnlessAcked<'a> {
    sessions: &'a Sessions,
    id: u64,
    epoch: u64,
    resumed: bool,
    acked: bool,
}

impl Drop for DetachUnlessAcked<'_> {
    fn drop(&mut self) {
        if self.acked {
            return;
        }
        spec_trace!(
            self.sessions.recorder.get(),
            EventSpec::HandshakeFailed {
                session: self.id,
                resumed: self.resumed
            }
        );
        if self.resumed {
            tracing::info!(
                session = self.id,
                "the handshake failed after resuming the session; detached"
            );
            self.sessions.detach(self.id, self.epoch);
        } else {
            tracing::info!(
                session = self.id,
                "the handshake failed before the new session's Ack; dropped"
            );
            self.sessions.forget(self.id);
        }
    }
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
            let mut unacked = DetachUnlessAcked {
                sessions: &server.sessions,
                id: state.id,
                epoch,
                resumed,
                acked: false,
            };
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
            unacked.acked = true;
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
    session: Arc<SessionState>,
    /// The session's attachment epoch this connection holds.
    epoch: u64,
    conn: Connection,
}

/// A request that ran on its blocking thread.
struct Ran {
    started: Instant,
    finished: Instant,
    resp: Response,
    armed: Vec<crate::watch::Armed>,
}

/// The code the client reset its side of a request stream with, once it has: it gave up on the request. Never, for a stream it finished or that failed with its connection.
async fn cancel_asked(recv: &mut RecvStream) -> quinn::VarInt {
    match recv.received_reset().await {
        Ok(Some(code)) => code,
        Ok(None) | Err(_) => std::future::pending().await,
    }
}

async fn handle_request(
    serving: Arc<Serving>,
    holder: Holder,
    mut send: SendStream,
    mut recv: RecvStream,
) {
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
    #[cfg(feature = "spec-trace")]
    let (recorder, key) = (
        serving.session.recorder.clone(),
        KeyExchange {
            conn: ops.conn.unwrap_or(0),
            stream,
        },
    );
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
            spec_trace!(
                recorder.as_ref(),
                EventSpec::Undecoded {
                    key,
                    cause: CauseUndecoded::Other
                }
            );
            return;
        }
        // The client finishes a stream early or resets it when it gives up on a call.
        Ok(Err(e))
            if e.is_eof()
                || matches!(&e, jackalopefs_proto::ErrorCodec::Io(io) if io.kind() == std::io::ErrorKind::ConnectionReset) =>
        {
            spec_trace!(
                recorder.as_ref(),
                EventSpec::Undecoded {
                    key,
                    cause: CauseUndecoded::Reset
                }
            );
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
            spec_trace!(
                recorder.as_ref(),
                EventSpec::Undecoded {
                    key,
                    cause: CauseUndecoded::Lost
                }
            );
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
            spec_trace!(
                recorder.as_ref(),
                EventSpec::Undecoded {
                    key,
                    cause: CauseUndecoded::Other
                }
            );
            return;
        }
        Err(_) => {
            spec_trace!(
                recorder.as_ref(),
                EventSpec::Undecoded {
                    key,
                    cause: CauseUndecoded::Other
                }
            );
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
    let exchange = Exchange::new(req.changes(), holder);
    #[cfg(feature = "spec-trace")]
    exchange.traced.set((key, op)).expect("keyed once");
    let fence = serving.session.fencing(serving.epoch, &exchange);
    let mut superseded = false;
    if fence > 0 {
        inflight.held();
        let held_since = Instant::now();
        let held = &exchange;
        let current = tokio::select! {
            current = serving.session.drain(serving.epoch, held) => current,
            code = cancel_asked(&mut recv) => {
                let verdict = serving.session.abandon(serving.epoch, held);
                debug_assert_eq!(verdict, Verdict::Unrun, "a held change has not begun");
                event!(
                    target: EVENT_TARGET,
                    perf.events,
                    Slowpath::RequestCancelled,
                    IdsEvent {
                        op: Some(op),
                        ..ids.clone()
                    },
                    format!(
                        "{}: the client gave up on it ({code}) while it was held behind {fence} changes; dropped unrun",
                        inflight.subject().unwrap_or_default()
                    )
                );
                if let Some(sampled) = sampled.as_mut() {
                    sampled.outcome("unrun");
                }
                if let Err(e) = send.reset(code_reset::UNRUN.into()) {
                    tracing::debug!(op, "reset of a request dropped unrun: {e}");
                }
                return;
            }
            stopped = send.stopped() => {
                serving.session.stopped(held, stopped.is_err());
                let why = match stopped {
                    Ok(code) => format!("the client gave up on it ({code:?})"),
                    Err(e) => format!("its stream ended ({e})"),
                };
                event!(
                    target: EVENT_TARGET,
                    perf.events,
                    Slowpath::RequestCancelled,
                    IdsEvent {
                        op: Some(op),
                        ..ids.clone()
                    },
                    format!(
                        "{}: {why} while it was held behind {fence} changes; dropped unrun",
                        inflight.subject().unwrap_or_default()
                    )
                );
                return;
            }
        };
        inflight.waiting();
        phases.held = held_since.elapsed();
        superseded = !current;
        if current {
            event!(
                target: EVENT_TARGET,
                perf.events,
                Slowpath::RequestHeld,
                IdsEvent {
                    op: Some(op),
                    ..ids.clone()
                },
                format!(
                    "{}: held {} behind {fence} changes given up on or still running from the session's earlier connections",
                    inflight.subject().unwrap_or_default(),
                    fmt_duration(phases.held)
                )
            );
        }
    }
    let queued = Instant::now();
    // A client that gives up on a change resets its side of the stream and waits to hear what became of it.
    let mut fenced = false;
    let joined = if superseded {
        // `drain` let it go: the session resumed on a newer connection, and `begin` would refuse it.
        Ok(None)
    } else {
        let running = inflight.clone();
        let session = serving.session.clone();
        let epoch = serving.epoch;
        let begun = exchange.clone();
        let mut blocking = tokio::task::spawn_blocking(move || {
            let mut hooked = hook.and_then(|hook| hook(&req));
            // Running from here to the end of the closure, hook included, so a test can hold a change that has begun.
            #[cfg_attr(not(feature = "spec-trace"), allow(unused_mut))]
            let mut running_guard = session.begin(epoch, &begun)?;
            let reserved = ops.reserve(&req);
            if let Some(hooked) = hooked.as_mut() {
                hooked(PhaseDispatch::Running);
            }
            let tid = nix::unistd::gettid().as_raw();
            let started = Instant::now();
            running.arming(tid);
            let armed = ops.watches.arm_request(&req);
            running.running(tid);
            let resp = ops::dispatch(&ops, req, reserved);
            let finished = Instant::now();
            #[cfg(feature = "spec-trace")]
            {
                running_guard.errno = matches!(resp, Response::Err(_));
            }
            if let Some(mut hooked) = hooked {
                hooked(PhaseDispatch::Done(&resp));
            }
            drop(running_guard);
            Some(Ran {
                started,
                finished,
                resp,
                armed,
            })
        });
        match exchange.ordered {
            false => blocking.await,
            true => tokio::select! {
                joined = &mut blocking => joined,
                code = cancel_asked(&mut recv) => match serving.session.abandon(serving.epoch, &exchange) {
                    Verdict::Unrun => {
                        event!(
                            target: EVENT_TARGET,
                            perf.events,
                            Slowpath::RequestCancelled,
                            IdsEvent {
                                op: Some(op),
                                ..ids.clone()
                            },
                            format!(
                                "{}: the client gave up on it ({code}) before it began; dropped unrun",
                                inflight.subject().unwrap_or_default()
                            )
                        );
                        if let Some(sampled) = sampled.as_mut() {
                            sampled.outcome("unrun");
                        }
                        if let Err(e) = send.reset(code_reset::UNRUN.into()) {
                            tracing::debug!(op, "reset of a request dropped unrun: {e}");
                        }
                        return;
                    }
                    Verdict::Fenced => {
                        event!(
                            target: EVENT_TARGET,
                            perf.events,
                            Slowpath::RequestAbandoned,
                            IdsEvent {
                                op: Some(op),
                                ..ids.clone()
                            },
                            format!(
                                "{}: the client gave up on it ({code}) while it ran; the session's later changes wait for it",
                                inflight.subject().unwrap_or_default()
                            )
                        );
                        if let Err(e) = send.reset(code_reset::FENCED.into()) {
                            tracing::debug!(op, "reset of an abandoned request: {e}");
                        }
                        fenced = true;
                        blocking.await
                    }
                    Verdict::Finished | Verdict::Superseded => blocking.await,
                },
            },
        }
    };
    let resp = match joined {
        Ok(Some(Ran {
            started,
            finished,
            resp,
            armed,
        })) => {
            phases.wait = started - queued;
            phases.op = finished - started;
            (resp, armed)
        }
        // Its session resumed on a newer connection before it could run.
        Ok(None) => {
            if let Some(sampled) = sampled.as_mut() {
                sampled.outcome("superseded");
            }
            event!(
                target: EVENT_TARGET,
                perf.events,
                Slowpath::RequestSuperseded,
                IdsEvent {
                    op: Some(op),
                    ..ids.clone()
                },
                format!(
                    "{}: the session has resumed on a newer connection; dropped unrun, and this connection closed",
                    inflight.subject().unwrap_or_default()
                )
            );
            if let Err(e) = send.reset(code_reset::SUPERSEDED.into()) {
                tracing::debug!(op, "reset of a superseded request: {e}");
            }
            serving
                .conn
                .close(close_code::SUPERSEDED.into(), b"session resumed elsewhere");
            return;
        }
        Err(e) => {
            tracing::error!(op, "operation panicked: {e}");
            phases.wait = queued.elapsed();
            (Response::Err(nix::errno::Errno::EIO as i32), Vec::new())
        }
    };
    // The directories the request named stay watched until its reply is out: a notice that they were dropped must not reach the client ahead of the reply it would cache.
    let (resp, armed) = resp;
    let outcome = outcome_of(&resp);
    if fenced {
        if let Some(sampled) = sampled.as_mut() {
            sampled.outcome("fenced");
        }
    } else {
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
                if let Err(e) = send.reset(code_reset::STALLED.into()) {
                    tracing::debug!(op, "reset after stalled reply: {e}");
                }
            }
        }
        phases.send = sending.elapsed();
    }
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
            held_us = phases.held.as_micros() as u64,
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
                    ("held".into(), ns(phases.held)),
                    ("wait".into(), ns(phases.wait)),
                    ("op".into(), ns(phases.op)),
                    ("send".into(), ns(phases.send)),
                ],
                total_ns: ns(total),
                ..Summary::default()
            }
        });
    }
    drop(armed);
    drop(inflight);
    // Read the request stream to its end, so that dropping it sends nothing: a change's client finishes its side once it has the reply, and a read's has already.
    match timeout(REQUEST_FIN_TIMEOUT, recv.read(&mut [0u8; 1])).await {
        Ok(Ok(None)) => {}
        Ok(Ok(Some(_))) => tracing::debug!(op, "data after the request on its stream"),
        Ok(Err(e)) => tracing::trace!(op, "request stream ended without finishing: {e}"),
        Err(_) => tracing::trace!(
            op,
            "the client did not finish the request stream within {}",
            fmt_duration(REQUEST_FIN_TIMEOUT)
        ),
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
        assert_eq!(sessions.handle_totals().files, 1);
        sessions.detach(state.id, epoch);
        assert_eq!(sessions.handle_rows()[0].state, StateSession::Detached);
        assert_eq!(sessions.reap(Duration::ZERO), 1);
        assert_eq!(
            sessions.pool().used(),
            1,
            "the request holding it still runs"
        );
        assert_eq!(
            sessions.handle_totals().files,
            1,
            "a dropped session's handles are still open and counted"
        );
        let rows = sessions.handle_rows();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].session, state.id);
        assert_eq!(rows[0].state, StateSession::Dropped);
        assert_eq!(rows[0].files, 1);
        drop(state);
        assert_eq!(sessions.pool().used(), 0);
        assert_eq!(sessions.handle_totals().files, 0);
        assert!(sessions.handle_rows().is_empty());
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

    /// A session whose grace ran out while one of its changes still ran comes back to a client that names it: its changes stay ordered by M1, and its handles are the ones the client holds.
    #[tokio::test]
    async fn a_dropped_session_with_a_change_running_is_resumed() {
        let sessions = sessions_unlimited();
        let (state, first) = sessions.create();
        let running = state
            .begin(first, &Exchange::new(true, state.hold()))
            .unwrap();
        sessions.detach(state.id, first);
        assert_eq!(sessions.reap(Duration::ZERO), 1);
        assert!(sessions.get(state.id).is_none(), "dropped");
        assert!(
            sessions.resume(state.id, &[0u8; 16]).is_none(),
            "a wrong token resumes nothing"
        );
        let (again, second) = sessions
            .resume(state.id, &state.resume_token)
            .expect("its change still runs, so the session is resumed");
        assert!(Arc::ptr_eq(&state, &again));
        assert!(
            sessions.get(state.id).is_some(),
            "back in the table, to be detached and reaped as before"
        );
        let rows = sessions.handle_rows();
        assert_eq!(rows.len(), 1, "listed once: {rows:?}");
        assert_eq!(rows[0].state, StateSession::Attached);
        let next = held(&state, second);
        assert!(
            pending(state.drain(second, &next)).await,
            "the change still running is waited for"
        );
        drop(running);
        assert!(timeout(Duration::from_secs(1), state.drain(second, &next))
            .await
            .unwrap());
    }

    #[test]
    fn a_dropped_session_with_nothing_left_is_not_resumed() {
        let sessions = sessions_unlimited();
        let (state, epoch) = sessions.create();
        let (id, token) = (state.id, state.resume_token);
        sessions.detach(id, epoch);
        assert_eq!(sessions.reap(Duration::ZERO), 1);
        drop(state);
        assert!(sessions.resume(id, &token).is_none());
    }

    /// What still holds a dropped session's `Arc` once nothing of it is under way (a request task writing its reply, a blocking thread yet to see that its request was given up on, a report listing the session) does not keep it resumable: the model's sessions resume only while something of them is under way.
    #[test]
    fn a_dropped_session_with_nothing_under_way_is_not_resumed_while_its_tasks_finish() {
        let sessions = sessions_unlimited();
        let (state, epoch) = sessions.create();
        let finished = Exchange::new(true, state.hold());
        drop(state.begin(epoch, &finished).unwrap());
        let given_up = Exchange::new(true, state.hold());
        assert_eq!(state.abandon(epoch, &given_up), Verdict::Unrun);
        sessions.detach(state.id, epoch);
        assert_eq!(sessions.reap(Duration::ZERO), 1);
        assert!(
            sessions.resume(state.id, &state.resume_token).is_none(),
            "only tasks finishing hold it"
        );
        drop((finished, given_up));
    }

    #[test]
    fn a_session_evicted_while_its_change_runs_is_resumed() {
        let sessions = sessions_unlimited();
        let (state, epoch) = sessions.create();
        let running = state
            .begin(epoch, &Exchange::new(true, state.hold()))
            .unwrap();
        sessions.detach(state.id, epoch);
        for _ in 0..MAX_DETACHED_SESSIONS {
            let (other, other_epoch) = sessions.create();
            sessions.detach(other.id, other_epoch);
        }
        assert!(sessions.get(state.id).is_none(), "evicted as the oldest");
        assert!(sessions.resume(state.id, &state.resume_token).is_some());
        drop(running);
    }

    /// Whether `future` is still pending after a moment, which is as long as the tests below give anything to happen.
    async fn pending<F: std::future::Future>(future: F) -> bool {
        timeout(Duration::from_millis(50), future).await.is_err()
    }

    /// A change just decoded on the connection attached at `epoch`, which must be held.
    fn held(state: &Arc<SessionState>, epoch: u64) -> Arc<Exchange> {
        let change = Exchange::new(true, state.hold());
        assert!(state.fencing(epoch, &change) > 0, "nothing fences it");
        change
    }

    #[test]
    fn a_change_from_a_superseded_connection_is_refused() {
        let sessions = sessions_unlimited();
        let (state, first) = sessions.create();
        let running = state
            .begin(first, &Exchange::new(true, state.hold()))
            .expect("the current connection's change runs");
        let (_, second) = sessions.resume(state.id, &state.resume_token).unwrap();
        assert!(
            state
                .begin(first, &Exchange::new(true, state.hold()))
                .is_none(),
            "the session has resumed on a newer connection"
        );
        assert!(state
            .begin(second, &Exchange::new(true, state.hold()))
            .is_some());
        drop(running);
    }

    #[tokio::test]
    async fn a_resumed_connection_waits_for_the_older_ones_changes_only() {
        let sessions = sessions_unlimited();
        let (state, first) = sessions.create();
        let old = state
            .begin(first, &Exchange::new(true, state.hold()))
            .unwrap();
        assert_eq!(
            state.fencing(first, &Exchange::new(true, state.hold())),
            0,
            "nothing is older than the first connection"
        );
        let (_, second) = sessions.resume(state.id, &state.resume_token).unwrap();
        let own = state
            .begin(second, &Exchange::new(true, state.hold()))
            .unwrap();
        let next = Exchange::new(true, state.hold());
        assert_eq!(state.fencing(second, &next), 1);
        assert!(
            pending(state.drain(second, &next)).await,
            "an older change is still running"
        );
        drop(old);
        assert!(timeout(Duration::from_secs(1), state.drain(second, &next))
            .await
            .unwrap());
        assert!(state.begin(second, &next).is_some(), "drained, it is ready");
        drop(own);

        let (_, third) = sessions.resume(state.id, &state.resume_token).unwrap();
        let older = state
            .begin(third, &Exchange::new(true, state.hold()))
            .unwrap();
        let (_, fourth) = sessions.resume(state.id, &state.resume_token).unwrap();
        let drained = tokio::spawn({
            let state = state.clone();
            let next = held(&state, fourth);
            async move { state.drain(fourth, &next).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!drained.is_finished());
        drop(older);
        assert!(drained.await.unwrap());
    }

    #[tokio::test]
    async fn a_held_change_whose_connection_is_superseded_waits_no_longer() {
        let sessions = sessions_unlimited();
        let (state, first) = sessions.create();
        let old = state
            .begin(first, &Exchange::new(true, state.hold()))
            .unwrap();
        let (_, second) = sessions.resume(state.id, &state.resume_token).unwrap();
        let next = held(&state, second);
        let waiting = tokio::spawn({
            let state = state.clone();
            let next = next.clone();
            async move { state.drain(second, &next).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !waiting.is_finished(),
            "held behind the first connection's change"
        );
        let (_, third) = sessions.resume(state.id, &state.resume_token).unwrap();
        assert!(
            !timeout(Duration::from_secs(1), waiting)
                .await
                .unwrap()
                .unwrap(),
            "its change will not run"
        );
        assert_eq!(*next.phase.lock(), PhaseExchange::Superseded);
        assert_eq!(
            state.fencing(second, &Exchange::new(true, state.hold())),
            0,
            "a superseded connection's change is not held"
        );
        assert!(
            pending(state.drain(third, &held(&state, third))).await,
            "the first connection's change still runs"
        );
        assert!(
            state
                .begin(first, &Exchange::new(true, state.hold()))
                .is_none()
                && state
                    .begin(second, &Exchange::new(true, state.hold()))
                    .is_none()
        );
        drop(old);
    }

    #[test]
    fn a_change_given_up_on_before_it_began_never_runs() {
        let sessions = sessions_unlimited();
        let (state, epoch) = sessions.create();
        let change = Exchange::new(true, state.hold());
        assert_eq!(state.abandon(epoch, &change), Verdict::Unrun);
        assert!(state.begin(epoch, &change).is_none());
        assert_eq!(
            state.fencing(epoch, &Exchange::new(true, state.hold())),
            0,
            "nothing ran, so nothing waits"
        );
    }

    #[tokio::test]
    async fn a_change_given_up_on_while_it_ran_holds_the_later_ones() {
        let sessions = sessions_unlimited();
        let (state, epoch) = sessions.create();
        let change = Exchange::new(true, state.hold());
        let running = state.begin(epoch, &change).unwrap();
        let other = state
            .begin(epoch, &Exchange::new(true, state.hold()))
            .unwrap();
        assert_eq!(
            state.fencing(epoch, &Exchange::new(true, state.hold())),
            0,
            "changes in flight hold nothing"
        );
        assert_eq!(state.abandon(epoch, &change), Verdict::Fenced);
        let next = held(&state, epoch);
        drop(other);
        assert!(pending(state.drain(epoch, &next)).await, "it still runs");
        drop(running);
        assert!(timeout(Duration::from_secs(1), state.drain(epoch, &next))
            .await
            .unwrap());
        assert_eq!(state.fencing(epoch, &Exchange::new(true, state.hold())), 0);
    }

    #[test]
    fn a_change_given_up_on_once_it_has_run_holds_nothing() {
        let sessions = sessions_unlimited();
        let (state, epoch) = sessions.create();
        let change = Exchange::new(true, state.hold());
        drop(state.begin(epoch, &change).unwrap());
        assert_eq!(state.abandon(epoch, &change), Verdict::Finished);
        assert_eq!(state.fencing(epoch, &Exchange::new(true, state.hold())), 0);
    }

    #[tokio::test]
    async fn a_change_given_up_on_and_then_resumed_past_is_waited_for_once() {
        let sessions = sessions_unlimited();
        let (state, first) = sessions.create();
        let change = Exchange::new(true, state.hold());
        let running = state.begin(first, &change).unwrap();
        assert_eq!(state.abandon(first, &change), Verdict::Fenced);
        let (_, second) = sessions.resume(state.id, &state.resume_token).unwrap();
        let next = Exchange::new(true, state.hold());
        assert_eq!(
            state.fencing(second, &next),
            1,
            "an earlier connection's change, counted once"
        );
        assert!(pending(state.drain(second, &next)).await);
        drop(running);
        assert!(timeout(Duration::from_secs(1), state.drain(second, &next))
            .await
            .unwrap());
        let attachment = state.attachment.lock();
        assert_eq!(
            (
                attachment.running,
                attachment.abandoned,
                attachment.running_older
            ),
            (0, 0, 0)
        );
    }

    #[test]
    fn a_superseded_connections_change_given_up_on_is_counted_once() {
        let sessions = sessions_unlimited();
        let (state, first) = sessions.create();
        let change = Exchange::new(true, state.hold());
        let running = state.begin(first, &change).unwrap();
        let (_, second) = sessions.resume(state.id, &state.resume_token).unwrap();
        assert_eq!(state.abandon(first, &change), Verdict::Fenced);
        assert_eq!(state.fencing(second, &Exchange::new(true, state.hold())), 1);
        drop(running);
        assert_eq!(state.fencing(second, &Exchange::new(true, state.hold())), 0);
        let attachment = state.attachment.lock();
        assert_eq!(
            (
                attachment.running,
                attachment.abandoned,
                attachment.running_older
            ),
            (0, 0, 0)
        );
    }

    #[test]
    fn a_held_change_drains_once_nothing_fences_it() {
        let sessions = sessions_unlimited();
        let (state, epoch) = sessions.create();
        let running = state
            .begin(epoch, &Exchange::new(true, state.hold()))
            .unwrap();
        let fenced = Exchange::new(true, state.hold());
        drop(state.begin(epoch, &fenced).map(|guard| {
            assert_eq!(state.abandon(epoch, &fenced), Verdict::Fenced);
            (guard, running)
        }));
        let next = Exchange::new(true, state.hold());
        assert_eq!(state.fencing(epoch, &next), 0, "everything has finished");
        assert_eq!(*next.phase.lock(), PhaseExchange::Ready);

        let first = state
            .begin(epoch, &Exchange::new(true, state.hold()))
            .unwrap();
        assert_eq!(
            state.abandon(epoch, &Exchange::new(true, state.hold())),
            Verdict::Unrun
        );
        let given_up = Exchange::new(true, state.hold());
        let guard = state.begin(epoch, &given_up).unwrap();
        assert_eq!(state.abandon(epoch, &given_up), Verdict::Fenced);
        let next = held(&state, epoch);
        assert_eq!(state.drained(epoch, &next), None, "still fenced");
        assert_eq!(*next.phase.lock(), PhaseExchange::Held);
        drop(guard);
        assert_eq!(state.drained(epoch, &next), Some(true));
        assert_eq!(*next.phase.lock(), PhaseExchange::Ready);
        drop(first);
    }

    #[test]
    fn a_held_change_given_up_on_or_stopped_never_runs() {
        let sessions = sessions_unlimited();
        let (state, epoch) = sessions.create();
        let given_up = Exchange::new(true, state.hold());
        let guard = state.begin(epoch, &given_up).unwrap();
        assert_eq!(state.abandon(epoch, &given_up), Verdict::Fenced);
        let cancelled = held(&state, epoch);
        assert_eq!(state.abandon(epoch, &cancelled), Verdict::Unrun);
        assert_eq!(*cancelled.phase.lock(), PhaseExchange::Cancelled);
        let stopped = held(&state, epoch);
        state.stopped(&stopped, false);
        assert_eq!(*stopped.phase.lock(), PhaseExchange::Dropped);
        drop(guard);
        assert!(
            state.begin(epoch, &cancelled).is_none(),
            "a change given up on is never counted"
        );
        let attachment = state.attachment.lock();
        assert_eq!((attachment.running, attachment.abandoned), (0, 0));
    }

    #[test]
    fn a_change_superseded_as_it_began_is_answered_as_superseded() {
        let sessions = sessions_unlimited();
        let (state, first) = sessions.create();
        let change = Exchange::new(true, state.hold());
        sessions.resume(state.id, &state.resume_token).unwrap();
        assert!(state.begin(first, &change).is_none());
        assert_eq!(*change.phase.lock(), PhaseExchange::Superseded);
        assert_eq!(state.abandon(first, &change), Verdict::Superseded);
    }

    #[tokio::test]
    async fn a_held_change_whose_session_resumes_is_let_go_as_superseded() {
        let sessions = sessions_unlimited();
        let (state, first) = sessions.create();
        let running = state
            .begin(first, &Exchange::new(true, state.hold()))
            .unwrap();
        let (_, second) = sessions.resume(state.id, &state.resume_token).unwrap();
        let next = held(&state, second);
        assert_eq!(state.drained(second, &next), None);
        sessions.resume(state.id, &state.resume_token).unwrap();
        assert!(!timeout(Duration::from_secs(1), state.drain(second, &next))
            .await
            .unwrap());
        assert_eq!(*next.phase.lock(), PhaseExchange::Superseded);
        drop(running);
    }

    #[test]
    fn a_request_that_is_no_change_runs_whatever_the_epoch_and_counts_nowhere() {
        let sessions = sessions_unlimited();
        let (state, first) = sessions.create();
        let running = state
            .begin(first, &Exchange::new(true, state.hold()))
            .unwrap();
        sessions.resume(state.id, &state.resume_token).unwrap();
        let read = Exchange::new(false, state.hold());
        assert_eq!(state.fencing(first, &read), 0, "never held");
        let guard = state
            .begin(first, &read)
            .expect("a stale epoch refuses only changes");
        assert_eq!(*read.phase.lock(), PhaseExchange::Running);
        let counts = |state: &SessionState| {
            let attachment = state.attachment.lock();
            (
                attachment.running,
                attachment.abandoned,
                attachment.running_older,
            )
        };
        assert_eq!(counts(&state), (0, 0, 1));
        drop(guard);
        assert_eq!(*read.phase.lock(), PhaseExchange::Finished);
        assert_eq!(counts(&state), (0, 0, 1));
        drop(running);
    }

    fn holders(state: &SessionState) -> usize {
        state.holders.load(Ordering::SeqCst)
    }

    #[test]
    fn a_request_holds_its_session_until_it_ends() {
        let sessions = sessions_unlimited();
        let (state, epoch) = sessions.create();
        let unread = state.hold();
        assert_eq!(holders(&state), 1, "from the stream's acceptance");
        drop(unread);
        assert_eq!(holders(&state), 0, "a request never decoded lets go");

        let given_up = Exchange::new(true, state.hold());
        assert_eq!(state.abandon(epoch, &given_up), Verdict::Unrun);
        assert_eq!(holders(&state), 0, "cancelled");

        let change = Exchange::new(true, state.hold());
        let guard = state.begin(epoch, &change).unwrap();
        assert_eq!(state.abandon(epoch, &change), Verdict::Fenced);
        assert_eq!(holders(&state), 1, "running, given up on or not");
        let next = held(&state, epoch);
        let stopped = held(&state, epoch);
        assert_eq!(holders(&state), 3);
        state.stopped(&stopped, true);
        assert_eq!(holders(&state), 2, "dropped while held");
        drop(guard);
        assert_eq!(holders(&state), 1, "finished");
        assert_eq!(state.drained(epoch, &next), Some(true));
        assert_eq!(holders(&state), 1, "ready");
        let read = Exchange::new(false, state.hold());
        drop(state.begin(epoch, &read).unwrap());
        drop(state.begin(epoch, &next).unwrap());
        assert_eq!(holders(&state), 0);

        let running = state
            .begin(epoch, &Exchange::new(true, state.hold()))
            .unwrap();
        let (_, second) = sessions.resume(state.id, &state.resume_token).unwrap();
        let superseded = Exchange::new(true, state.hold());
        assert!(state.begin(epoch, &superseded).is_none());
        assert_eq!(holders(&state), 1, "superseded as it began");
        let let_go = held(&state, second);
        sessions.resume(state.id, &state.resume_token).unwrap();
        assert_eq!(state.drained(second, &let_go), Some(false));
        assert_eq!(holders(&state), 1, "superseded as it was held");
        drop(running);
        assert_eq!(holders(&state), 0);
        drop(Exchange::new(true, state.hold()));
        assert_eq!(holders(&state), 0, "dropped unended, at shutdown");
    }

    #[test]
    fn an_attached_connection_holds_its_session_and_detaches_it_as_it_ends() {
        let sessions = Arc::new(sessions_unlimited());
        let (state, first) = sessions.create();
        let attached = sessions.attach(&state, first);
        assert_eq!(holders(&state), 1);
        let (_, second) = sessions.resume(state.id, &state.resume_token).unwrap();
        let taken_over = sessions.attach(&state, second);
        drop(attached);
        assert_eq!(holders(&state), 1);
        assert_eq!(
            sessions.reap(Duration::ZERO),
            0,
            "the connection taken over leaves the session attached"
        );
        drop(taken_over);
        assert_eq!(holders(&state), 0);
        assert_eq!(sessions.reap(Duration::ZERO), 1, "detached");
    }
}

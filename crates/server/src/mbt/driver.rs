//! The server's session machine taking the model's steps, with the driver as the client and the network.
//!
//! The driver reads from the model only what the client and the network did: which requests were written, by which call and on which connection, which answers the client read, and which end of a connection went (each listed in `spec/README.md`, "Model-based testing"). Everything the server decides comes from the code: a request's session and epoch are what `Sessions::resume` or `Sessions::create` gave its connection, never the model's.

use super::model::{Answer, Kind, Model, Origin, Phase, Slot, View, ViewReq, ViewSession};
use crate::export::Export;
use crate::handles::{Handle, HandlePool, Reserved, SHARE_MAX};
use crate::ids::{IdMap, ModeIds};
use crate::ops::{self, Ops, Refusals, Reservation};
use crate::session::{
    AttachmentConn, DetachUnlessAcked, Exchange, GuardExchange, Holder, PhaseExchange,
    SessionState, Sessions, Verdict,
};
use crate::watch::{ChangeLog, Watches};
use jackalopefs_proto::{Name, Path, Request, Response};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

/// A model step the server takes, inferred from what it changed ([`infer`]); the client's and the network's steps are all `Environment`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Arrive(u64),
    DropCut(u64),
    Drain(u64),
    Begin(u64),
    SeeCancel(u64),
    Finish(u64),
    LoseServer(u64),
    Reconnect,
    NewSession,
    HandshakeLost,
    DropSession(u64),
    CloseSession(u64),
    Environment,
}

impl Step {
    /// The names of the model's actions (its `step`'s, as `mbt::actionTaken` gives them) this step can be.
    pub fn actions(self) -> &'static [&'static str] {
        match self {
            Step::Arrive(_) => &["stepArrive"],
            Step::DropCut(_) => &["stepDropCut"],
            Step::Drain(_) => &["stepDrain"],
            Step::Begin(_) => &["stepBegin"],
            Step::SeeCancel(_) => &["stepSeeCancel"],
            Step::Finish(_) => &["stepFinish"],
            Step::LoseServer(_) => &["stepLoseServer"],
            Step::Reconnect => &["reconnect"],
            Step::NewSession => &["newSession"],
            Step::HandshakeLost => &["handshakeLost"],
            Step::DropSession(_) => &["stepDropSession"],
            Step::CloseSession(_) => &["stepCloseSession"],
            Step::Environment => &[
                "stepStart",
                "stepSend",
                "stepGiveUp",
                "stepLoseClient",
                "stepReceive",
                "stepReopenSend",
                "stepReopenGiveUp",
                "publish",
                "stepOwedSend",
                "stepOrphanSend",
                "stepOrphanGiveUp",
                "stepOrphanSentGiveUp",
            ],
        }
    }
}

/// Which server step took the model from `pre` to `post`: each changes something no other step does (a request's phase moving the way only it moves it, the generation, a connection's server end, a session leaving the table, its epoch, its handles closing). A change none of them explains, or more than one, is an error.
pub fn infer(pre: &Model, post: &Model) -> Result<Step, String> {
    use Phase::*;
    let mut found = Vec::new();
    let mut environment = false;
    for (r, q) in &post.reqs {
        let before = pre.req(*r).phase;
        let step = match (before, q.phase) {
            (a, b) if a == b => continue,
            (Absent, Transit | Dropped) | (Transit, Absent) => {
                environment = true;
                continue;
            }
            (Transit, Held | Ready) => Step::Arrive(*r),
            (Transit | Held, Dropped) => Step::DropCut(*r),
            (Held, Ready | Superseded) => Step::Drain(*r),
            (Ready, Running | Superseded) => Step::Begin(*r),
            (Transit | Held | Ready, Cancelled) | (Running, Abandoned) => Step::SeeCancel(*r),
            (Running | Abandoned, Finished) => Step::Finish(*r),
            (a, b) => {
                return Err(format!(
                    "request {r} went from {a:?} to {b:?}, which no step does"
                ))
            }
        };
        found.push(step);
    }
    if post.gen != pre.gen {
        found.push(if post.sid == pre.sid {
            Step::Reconnect
        } else {
            Step::NewSession
        });
    } else {
        for (g, k) in &post.conns {
            if pre.conns[g].server_alive && !k.server_alive {
                found.push(Step::LoseServer(*g));
            }
        }
        for (s, ses) in &post.sessions {
            let was = &pre.sessions[s];
            if was.live && !ses.live {
                found.push(Step::DropSession(*s));
            }
            if was.epoch != 0 && was.epoch != ses.epoch {
                found.push(Step::HandshakeLost);
            }
        }
    }
    if found.is_empty() {
        for (s, ses) in &post.sessions {
            let held = |handles: &BTreeMap<u64, super::model::Entry>| {
                handles.values().filter(|e| e.by != 0).count()
            };
            if held(&pre.sessions[s].handles) > 0 && held(&ses.handles) == 0 {
                found.push(Step::CloseSession(*s));
            }
        }
    }
    match found.as_slice() {
        [] => {
            // A client's step may end what keeps a session alive (a request erased unsent), and nothing else of the server's.
            let server = |model: &Model| {
                let mut sessions = model.view().sessions;
                sessions.values_mut().for_each(|s| s.alive = false);
                sessions
            };
            if post.pool != pre.pool || server(post) != server(pre) {
                return Err("the server's state changed in a step of the client's".into());
            }
            Ok(Step::Environment)
        }
        [step] if !environment => Ok(*step),
        steps => Err(format!(
            "more than one step: {steps:?}{}",
            if environment { " and the client's" } else { "" }
        )),
    }
}

/// What the server and the network hold of one of the model's connections.
struct ConnServer {
    session: u64,
    epoch: u64,
    /// Up at the server's end.
    alive: bool,
    attachment: Option<AttachmentConn>,
    /// What the connection's tasks hold of the session until its last reference goes, the model's `closeSession`.
    state: Option<Arc<SessionState>>,
    ops: Option<Arc<Ops>>,
}

/// What the server and the network hold of one of the model's requests.
struct ReqServer {
    conn: u64,
    session: u64,
    epoch: u64,
    request: Request,
    /// The hold its accepted stream has on the session until it is decoded.
    holder: Option<Holder>,
    exchange: Option<Arc<Exchange>>,
    guard: Option<GuardExchange>,
    reserved: Option<Reservation>,
    /// Its phase while the server has no exchange of it: written, or ended before it was decoded.
    phase: Phase,
    slot: Slot,
    /// What the server sent back and the client has not read.
    answer: Answer,
    /// The answer the client read, after which nothing more may come.
    read: Option<Answer>,
}

/// Each server step and outcome a run took, so a batch of runs can be seen to reach them all.
pub type Coverage = BTreeMap<&'static str, usize>;

/// What the model's session ids name in the code: the session (for as long as it lives) and its token.
struct Known {
    weak: Weak<SessionState>,
    token: [u8; 16],
    /// What was last seen of it, for the comparisons after its last reference has gone: nothing of it changes in the model from then on but its handles, which have closed.
    last: Option<ViewSession>,
}

pub struct Driver {
    /// The export's directory; `None` once a failed replay has let it go ([`Driver::abandon`]).
    dir: Option<tempfile::TempDir>,
    export: Arc<Export>,
    sessions: Arc<Sessions>,
    known: BTreeMap<u64, Known>,
    conns: BTreeMap<u64, ConnServer>,
    reqs: BTreeMap<u64, ReqServer>,
    calls: Vec<u64>,
    pub coverage: Coverage,
}

impl Driver {
    /// The server as the model's `init` has it: one session, attached by the first connection.
    pub fn new(init: &Model) -> Result<Driver, String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let export = Arc::new(Export::open(dir.path()).map_err(|e| e.to_string())?);
        let mut driver = Driver {
            dir: Some(dir),
            export,
            sessions: Arc::new(Sessions::new(
                SHARE_MAX,
                Arc::new(HandlePool::new(usize::MAX)),
            )),
            known: BTreeMap::new(),
            conns: BTreeMap::new(),
            reqs: BTreeMap::new(),
            calls: init.calls.keys().copied().collect(),
            coverage: Coverage::new(),
        };
        let (state, epoch) = driver.sessions.create();
        driver.connect(init.gen, state, epoch, init.sid)?;
        Ok(driver)
    }

    /// Give up on a replay that parted from the model: the scratch directory goes, and the rest is forgotten, since its guards and exchanges are where the code parted, and their drops may panic over counts the model never had.
    pub fn abandon(mut self) {
        drop(self.dir.take());
        std::mem::forget(self);
    }

    fn covered(&mut self, what: &'static str) {
        *self.coverage.entry(what).or_default() += 1;
    }

    /// A connection of generation `g` attaches `state` at `epoch`, which the model calls session `sid`.
    fn connect(
        &mut self,
        g: u64,
        state: Arc<SessionState>,
        epoch: u64,
        sid: u64,
    ) -> Result<(), String> {
        if state.id != sid {
            return Err(format!(
                "the code's session is {}, the model's {sid}",
                state.id
            ));
        }
        self.known.entry(sid).or_insert_with(|| Known {
            weak: Arc::downgrade(&state),
            token: state.resume_token,
            last: None,
        });
        let ops = Arc::new(Ops {
            export: self.export.clone(),
            handles: state.handles.clone(),
            session_id: state.id,
            conn: Some(g),
            changes: Arc::new(ChangeLog::default()),
            watches: Watches::disabled(),
            ids: IdMap::of_process(ModeIds::Direct)?,
            remote: SocketAddr::from(([127, 0, 0, 1], 4433)),
            events: crate::perf::Perf::default().events.clone(),
            refusals: Mutex::new(Refusals::default()),
        });
        self.conns.insert(
            g,
            ConnServer {
                session: sid,
                epoch,
                alive: true,
                attachment: Some(self.sessions.attach(&state, epoch)),
                state: Some(state),
                ops: Some(ops),
            },
        );
        Ok(())
    }

    /// The server's end of connection `g` goes: its task ends, and what its requests had sent and the client had not read is lost.
    fn lose_server(&mut self, g: u64) {
        let conn = self.conns.get_mut(&g).expect("a connection of the model's");
        conn.alive = false;
        drop(conn.attachment.take());
        for req in self.reqs.values_mut().filter(|q| q.conn == g) {
            if req.answer != Answer::NoAnswer {
                req.answer = Answer::Lost;
            }
        }
    }

    fn state_of(&self, g: u64) -> Arc<SessionState> {
        self.conns[&g]
            .state
            .clone()
            .expect("a connection whose session has not closed")
    }

    fn req(&mut self, r: u64) -> &mut ReqServer {
        self.reqs.get_mut(&r).expect("a request the server has")
    }

    /// The real request standing for the model's request `r`: a change is a mkdir, an open opens a file of its own, so a handle names the request that opened it.
    fn request(post: &Model, r: u64) -> Request {
        let open = |fh| Request::Open {
            fh,
            path: path_of('f', r),
            flags: libc::O_RDONLY,
        };
        match post.req(r).origin {
            Origin::OfCall(c) => match post.calls[&c].kind {
                Kind::Change => Request::Mkdir {
                    parent: Path::root(),
                    name: name_of('d', r),
                    mode: 0o755,
                },
                Kind::Open => open(c),
                Kind::Release(fh) => Request::Release { fh, ordered: false },
            },
            Origin::Reopen(fh) => open(fh),
            Origin::OrphanRelease(fh) | Origin::OwedRelease(fh) => {
                Request::Release { fh, ordered: true }
            }
            Origin::NoOrigin => unreachable!("a request written has an origin"),
        }
    }

    /// Take the step from `pre` to `post`.
    pub fn apply(&mut self, pre: &Model, post: &Model, step: Step) -> Result<(), String> {
        match step {
            Step::Environment => self.environment(pre, post)?,
            Step::Arrive(r) => {
                let g = self.reqs[&r].conn;
                let state = self.state_of(g);
                let req = self.req(r);
                let exchange = Exchange::new(
                    req.request.changes(),
                    req.holder.take().expect("an accepted stream"),
                );
                let held = state.fencing(req.epoch, &exchange) > 0;
                req.exchange = Some(exchange);
                self.covered(if held { "arrive held" } else { "arrive ready" });
            }
            Step::DropCut(r) => {
                let g = self.reqs[&r].conn;
                let state = self.state_of(g);
                let req = self.req(r);
                match &req.exchange {
                    Some(exchange) => {
                        state.stopped(exchange, true);
                        self.covered("dropCut held");
                    }
                    None => {
                        req.holder = None;
                        req.phase = Phase::Dropped;
                        self.covered("dropCut undecoded");
                    }
                }
            }
            Step::Drain(r) => {
                let g = self.reqs[&r].conn;
                let state = self.state_of(g);
                let req = self.req(r);
                let exchange = req.exchange.as_ref().expect("a decoded request");
                match state.drained(req.epoch, exchange) {
                    None => {
                        return Err(
                            "the model lets a held change go; the code still holds it".into()
                        )
                    }
                    Some(true) => self.covered("drain ready"),
                    Some(false) => self.covered("drain superseded"),
                }
            }
            Step::Begin(r) => {
                let g = self.reqs[&r].conn;
                let state = self.state_of(g);
                let ops = self.conns[&g]
                    .ops
                    .clone()
                    .expect("a connection whose session has not closed");
                let req = self.req(r);
                let exchange = req.exchange.clone().expect("a decoded request");
                req.guard = state.begin(req.epoch, &exchange);
                if req.guard.is_some() {
                    let reserved = ops.reserve(&req.request);
                    req.slot = match &reserved {
                        Ok(None) => Slot::NoSlot,
                        Ok(Some(Reserved::Slot(_))) => Slot::Taken,
                        Ok(Some(Reserved::Held(_))) => Slot::Kept,
                        Err(e) => return Err(format!("the reserve failed: {e:?}")),
                    };
                    req.reserved = Some(reserved);
                    let slot = req.slot;
                    self.covered(match slot {
                        Slot::NoSlot => "begin running",
                        Slot::Taken => "begin running, a slot taken",
                        Slot::Kept => "begin running, the handle kept",
                    });
                } else {
                    self.covered("begin superseded");
                }
            }
            Step::SeeCancel(r) => {
                let (g, epoch) = (self.reqs[&r].conn, self.reqs[&r].epoch);
                let state = self.state_of(g);
                match self.reqs[&r].exchange.clone() {
                    Some(exchange) => {
                        let verdict = state.abandon(epoch, &exchange);
                        let answer = match verdict {
                            Verdict::Unrun => Answer::Unrun,
                            Verdict::Fenced => Answer::Fenced,
                            Verdict::Finished | Verdict::Superseded => {
                                return Err(format!("the code answers the cancel {verdict:?}"));
                            }
                        };
                        self.answer(r, answer)?;
                        self.covered(if answer == Answer::Fenced {
                            "seeCancel fenced"
                        } else {
                            "seeCancel unrun"
                        });
                    }
                    None => {
                        let req = self.req(r);
                        req.holder = None;
                        req.phase = Phase::Cancelled;
                        self.answer(r, Answer::Unrun)?;
                        self.covered("seeCancel undecoded");
                    }
                }
            }
            Step::Finish(r) => self.finish(post, r)?,
            Step::LoseServer(g) => {
                self.lose_server(g);
                self.covered("loseServer");
            }
            Step::Reconnect => {
                let sid = pre.sid;
                let token = self.known[&sid].token;
                let (state, epoch) = self
                    .sessions
                    .resume(sid, &token)
                    .ok_or("the model resumes the session; the code does not")?;
                if self.conns[&pre.gen].alive {
                    self.lose_server(pre.gen);
                    self.covered("reconnect, taking over");
                } else {
                    self.covered("reconnect");
                }
                self.connect(post.gen, state, epoch, sid)?;
            }
            Step::NewSession => {
                let old = pre.sid;
                if self.sessions.resume(old, &self.known[&old].token).is_some() {
                    return Err(
                        "the model starts a new session; the code resumes the old one".into(),
                    );
                }
                let (state, epoch) = self.sessions.create();
                self.connect(post.gen, state, epoch, post.sid)?;
                self.covered("newSession");
            }
            Step::HandshakeLost => {
                let sid = pre.sid;
                let (_, epoch) = self
                    .sessions
                    .resume(sid, &self.known[&sid].token)
                    .ok_or("the model resumes the session; the code does not")?;
                drop(DetachUnlessAcked {
                    sessions: &self.sessions,
                    id: sid,
                    epoch,
                    resumed: true,
                    acked: false,
                });
                self.covered("handshakeLost");
            }
            Step::DropSession(s) => {
                let reaped = self.sessions.reap(Duration::ZERO);
                if reaped != 1 || self.sessions.get(s).is_some() {
                    return Err(format!(
                        "the model drops session {s}; the code dropped {reaped}"
                    ));
                }
                self.covered("dropSession");
            }
            Step::CloseSession(s) => {
                for conn in self.conns.values_mut().filter(|k| k.session == s) {
                    conn.state = None;
                    conn.ops = None;
                }
                if self.known[&s].weak.upgrade().is_some() {
                    return Err(format!(
                        "the model closes session {s}; something of it still holds it in the code"
                    ));
                }
                self.covered("closeSession");
            }
        }
        Ok(())
    }

    /// What the client and the network did: requests written (accepted at once by a server whose end is up) or taken back with a connection the client lost before writing them whole, and answers read.
    fn environment(&mut self, pre: &Model, post: &Model) -> Result<(), String> {
        for (r, q) in &post.reqs {
            let before = pre.req(*r);
            match (before.phase, q.phase) {
                (Phase::Absent, Phase::Absent) => {}
                (Phase::Absent, phase) => {
                    let conn = &self.conns[&q.conn];
                    if conn.alive != (phase == Phase::Transit) {
                        return Err(format!(
                            "request {r} written on connection {} whose server end is {}",
                            q.conn,
                            if conn.alive { "up" } else { "gone" }
                        ));
                    }
                    let holder = conn.alive.then(|| {
                        conn.state
                            .as_ref()
                            .expect("a live connection's session")
                            .hold()
                    });
                    self.reqs.insert(
                        *r,
                        ReqServer {
                            conn: q.conn,
                            session: conn.session,
                            epoch: conn.epoch,
                            request: Self::request(post, *r),
                            holder,
                            exchange: None,
                            guard: None,
                            reserved: None,
                            phase,
                            slot: Slot::NoSlot,
                            answer: Answer::NoAnswer,
                            read: None,
                        },
                    );
                }
                (_, Phase::Absent) => {
                    self.reqs.remove(r);
                }
                _ if before.answer != Answer::NoAnswer && q.answer == Answer::NoAnswer => {
                    let req = self.req(*r);
                    req.read = Some(req.answer);
                    req.answer = Answer::NoAnswer;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// The server sends `answer` for request `r`, or loses it with a connection its end of which has gone; once the client has read an answer, nothing more may come.
    fn answer(&mut self, r: u64, answer: Answer) -> Result<(), String> {
        let alive = self.conns[&self.reqs[&r].conn].alive;
        let req = self.req(r);
        if let Some(read) = req.read {
            return Err(format!(
                "request {r} answered {answer:?} after the client read {read:?}"
            ));
        }
        req.answer = if alive { answer } else { Answer::Lost };
        Ok(())
    }

    /// `finish(r, errno)`: the request's work, on a filesystem made to give the model's outcome where the code does not decide it, then its guard's end.
    fn finish(&mut self, post: &Model, r: u64) -> Result<(), String> {
        let q = post.req(r);
        let g = self.reqs[&r].conn;
        let ops = self.conns[&g]
            .ops
            .clone()
            .expect("a connection whose session has not closed");
        let root = self
            .dir
            .as_ref()
            .expect("a driver in use")
            .path()
            .to_path_buf();
        let req = self.req(r);
        let abandoned = req
            .exchange
            .as_ref()
            .expect("a decoded request")
            .phase_now()
            == PhaseExchange::Abandoned;
        // An open whose id the code already holds is refused by `Slot::insert`, whatever the filesystem says: the open itself goes through, so the refusal is the code's. Otherwise the model's choice, where the trace records it, or what its answer shows; an answer lost or not sent shows nothing, and the open is taken to succeed.
        let refused = match &req.request {
            Request::Open { fh, .. } => req.slot == Slot::Taken && ops.handles.get(*fh).is_ok(),
            _ => false,
        };
        let errno = !refused && post.pick("errno").unwrap_or(q.answer == Answer::ErrnoReply);
        let prepared = match &req.request {
            Request::Mkdir { name, .. } => {
                let dir = root.join(name.as_os_str());
                match (errno, dir.exists()) {
                    (true, false) => std::fs::create_dir(&dir),
                    (false, true) => std::fs::remove_dir(&dir),
                    _ => Ok(()),
                }
            }
            Request::Open { path, .. } => {
                let file = root.join(path.to_os_string());
                match (errno, file.exists()) {
                    (true, true) => std::fs::remove_file(&file),
                    (false, false) => std::fs::write(&file, b""),
                    _ => Ok(()),
                }
            }
            _ => Ok(()),
        };
        prepared.map_err(|e| format!("preparing the filesystem: {e}"))?;
        let reserved = req.reserved.take().expect("begun");
        let resp = ops::dispatch(&ops, req.request.clone(), reserved);
        let failed = matches!(resp, Response::Err(_));
        let mut guard = req.guard.take().expect("begun");
        #[cfg(feature = "spec-trace")]
        {
            guard.errno = failed;
        }
        #[cfg(not(feature = "spec-trace"))]
        let _ = &mut guard;
        drop(guard);
        if abandoned {
            self.covered("finish abandoned");
            return Ok(());
        }
        self.covered(if failed {
            "finish errno"
        } else {
            "finish reply"
        });
        self.answer(
            r,
            if failed {
                Answer::ErrnoReply
            } else {
                Answer::Reply
            },
        )
    }

    /// The code's state, in the model's terms.
    pub fn view(&mut self) -> View {
        let fhs = self.calls.clone();
        let mut sessions = BTreeMap::new();
        for (id, known) in self.known.iter_mut() {
            let seen = match known.weak.upgrade() {
                Some(state) => {
                    let (epoch, running, abandoned, running_older, detached) =
                        state.attachment_now();
                    let handles = fhs
                        .iter()
                        .filter_map(|fh| match state.handles.get(*fh) {
                            Ok(Handle::File { path, .. }) => Some((*fh, request_of(&path))),
                            Ok(Handle::Dir { .. }) => Some((*fh, 0)),
                            Err(_) => None,
                        })
                        .collect();
                    let seen = ViewSession {
                        epoch,
                        running,
                        abandoned,
                        running_older,
                        live: self.sessions.get(*id).is_some(),
                        detached,
                        alive: state.held_now(),
                        handles,
                    };
                    known.last = Some(seen.clone());
                    seen
                }
                None => ViewSession {
                    handles: BTreeMap::new(),
                    ..known.last.clone().expect("a session seen before it closed")
                },
            };
            sessions.insert(*id, seen);
        }
        View {
            sessions,
            conns: self
                .conns
                .iter()
                .map(|(g, k)| (*g, (k.session, k.epoch)))
                .collect(),
            pool: self.sessions.pool().used(),
            reqs: self
                .reqs
                .iter()
                .map(|(r, q)| {
                    (
                        *r,
                        ViewReq {
                            phase: q
                                .exchange
                                .as_ref()
                                .map_or(q.phase, |e| phase_of(e.phase_now())),
                            session: q.session,
                            epoch: q.epoch,
                            slot: q.slot,
                            answer: q.answer,
                        },
                    )
                })
                .collect(),
        }
    }
}

fn phase_of(phase: PhaseExchange) -> Phase {
    match phase {
        PhaseExchange::Held => Phase::Held,
        PhaseExchange::Ready => Phase::Ready,
        PhaseExchange::Cancelled => Phase::Cancelled,
        PhaseExchange::Superseded => Phase::Superseded,
        PhaseExchange::Dropped => Phase::Dropped,
        PhaseExchange::Running => Phase::Running,
        PhaseExchange::Abandoned => Phase::Abandoned,
        PhaseExchange::Finished => Phase::Finished,
    }
}

fn name_of(prefix: char, r: u64) -> Name {
    Name::new(format!("{prefix}{r}")).expect("a short name")
}

fn path_of(prefix: char, r: u64) -> Path {
    Path::root().join(name_of(prefix, r)).expect("a short path")
}

/// The request whose file a handle has open ([`Driver::request`]).
fn request_of(path: &Path) -> u64 {
    let name = path.names().last().expect("a file below the root");
    std::str::from_utf8(&name.as_bytes()[1..])
        .ok()
        .and_then(|r| r.parse().ok())
        .expect("a file the driver named")
}

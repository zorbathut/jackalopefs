//! The client's session machine taking the model's steps, with the driver as the server, the network and the kernel.
//!
//! The driver reads from the model only what those did: which calls the kernel started, with what kind, and gave up on; which answers the network delivered, and what each said; which connection's client end went, and whether a frame went with it before it was carried whole; whether a handshake resumed the session. Everything the client decides comes from the code: whether a call is resent, counted, owed or kept, what a reopen leaves, which releases are owed, and when each step may be taken.

use super::view::{view_client, ViewCall, ViewClient};
use crate::client::{release_request, retry_safe, Error};
use crate::handles::tests::attr;
use crate::handles::{HandleKind, HandleTable};
use crate::inodes::KeyNode;
use crate::machine::{
    counts_give_up, open_settled, owed_sendable, release_begins, release_owed, AttachedState,
    CallState, CancelPending, LossExchange, ReopenRound, Sendable, SettleOpen, StatusCall,
};
use jackalopefs_mbt::model::{Answer, Guards, Kind, Model, Origin, Phase, StatusCall as Status};
use jackalopefs_mbt::{Coverage, Drive};
use jackalopefs_proto::{Name, Path, Request, Response, SetAttr};
use std::collections::{BTreeMap, BTreeSet};

/// A model step the client takes, inferred from what it changed ([`infer`]); the server's steps are all `Environment`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Start(u64),
    Send(u64),
    GiveUp(u64),
    LoseClient(u64),
    Receive(u64),
    ReopenSend(u64),
    ReopenGiveUp(u64),
    ReopenUnsentGiveUp(u64),
    Publish,
    OwedSend(u64),
    Reconnect,
    NewSession,
    Environment,
}

impl Step {
    fn actions(self) -> &'static [&'static str] {
        match self {
            Step::Start(_) => &["stepStart"],
            Step::Send(_) => &["stepSend"],
            Step::GiveUp(_) => &["stepGiveUp"],
            Step::LoseClient(_) => &["stepLoseClient"],
            Step::Receive(_) => &["stepReceive"],
            Step::ReopenSend(_) => &["stepReopenSend"],
            Step::ReopenGiveUp(_) => &["stepReopenGiveUp"],
            Step::ReopenUnsentGiveUp(_) => &["stepReopenUnsentGiveUp"],
            Step::Publish => &["publish"],
            Step::OwedSend(_) => &["stepOwedSend"],
            Step::Reconnect => &["reconnect"],
            Step::NewSession => &["newSession"],
            Step::Environment => &[
                "stepLoseServer",
                "handshakeLost",
                "stepDropSession",
                "stepCloseSession",
                "stepArrive",
                "stepDropCut",
                "stepDrain",
                "stepBegin",
                "stepFinish",
                "stepSeeCancel",
            ],
        }
    }
}

/// Which client step took the model from `pre` to `post`: each changes something no other step does (a call's status, a request written, an answer read, a connection's client end or its publication, the generation, the round of reopens). A change none of them explains, or more than one, is an error.
fn infer(pre: &Model, post: &Model) -> Result<Step, String> {
    if post.gen != pre.gen {
        return Ok(if post.sid == pre.sid {
            Step::Reconnect
        } else {
            Step::NewSession
        });
    }
    let lost: Vec<u64> = post
        .conns
        .iter()
        .filter(|(g, k)| pre.conns[*g].client_alive && !k.client_alive)
        .map(|(g, _)| *g)
        .collect();
    if let [g] = lost.as_slice() {
        return Ok(Step::LoseClient(*g));
    }
    let mut found = Vec::new();
    for (g, k) in &post.conns {
        if !pre.conns[g].published && k.published {
            found.push(Step::Publish);
        }
    }
    for (c, call) in &post.calls {
        let was = &pre.calls[c];
        match (was.status, call.status) {
            (Status::Idle, Status::Waiting) => found.push(Step::Start(*c)),
            (Status::Waiting, Status::InFlight) => found.push(Step::Send(*c)),
            (Status::Waiting | Status::InFlight, Status::Ended)
                if call.outcome == jackalopefs_mbt::model::Outcome::GaveUp =>
            {
                found.push(Step::GiveUp(*c))
            }
            _ => {}
        }
    }
    for (r, q) in &post.reqs {
        let was = pre.req(*r);
        if was.phase == Phase::Absent && q.phase != Phase::Absent {
            match q.origin {
                Origin::Reopen(fh) => found.push(Step::ReopenSend(fh)),
                Origin::OwedRelease(fh) => found.push(Step::OwedSend(fh)),
                _ => {}
            }
        }
        if !matches!(was.answer, Answer::NoAnswer | Answer::Lost) && q.answer == Answer::NoAnswer {
            found.push(Step::Receive(*r));
        }
        if matches!(q.origin, Origin::Reopen(_)) && !was.cancel_sent && q.cancel_sent {
            found.push(Step::ReopenGiveUp(*r));
        }
    }
    for fh in pre.client.to_reopen.difference(&post.client.to_reopen) {
        if !found.contains(&Step::ReopenSend(*fh)) {
            found.push(Step::ReopenUnsentGiveUp(*fh));
        }
    }
    match found.as_slice() {
        [] => Ok(Step::Environment),
        [step] => Ok(*step),
        steps => Err(format!("more than one step: {steps:?}")),
    }
}

/// What the kernel's call is, as the code has it.
struct CallClient {
    kind: Kind,
    state: CallState,
    request: Request,
    /// The request of the attempt in flight, the model's.
    req: Option<u64>,
}

/// What a request the client wrote was for.
#[derive(Clone, Copy, Debug)]
enum ForReq {
    Call(u64),
    Reopen(u64),
    Owed { fh: u64 },
}

struct ReqClient {
    what: ForReq,
    conn: u64,
    /// The client's count of it on its connection's pending cancels, until the answer is read.
    counted: Option<CancelPending>,
}

pub struct Driver {
    handles: HandleTable,
    /// Each connection's state, by generation, and whether its client end is up (the network's).
    attached: BTreeMap<u64, AttachedState>,
    alive: BTreeMap<u64, bool>,
    gen: u64,
    calls: BTreeMap<u64, CallClient>,
    reqs: BTreeMap<u64, ReqClient>,
    round: Option<ReopenRound>,
    coverage: Coverage,
}

fn path_of(c: u64) -> Path {
    Path::root().join(name_of(c)).expect("a short name")
}

fn name_of(c: u64) -> Name {
    Name::new(format!("f{c}").into_bytes()).expect("a valid name")
}

impl Driver {
    fn covered(&mut self, what: &'static str) {
        *self.coverage.entry(what).or_default() += 1;
    }

    fn current(&self) -> &AttachedState {
        &self.attached[&self.gen]
    }

    fn pending(attached: &AttachedState) -> usize {
        *attached.cancels.borrow()
    }

    /// What the code would do now, in the model's terms: which calls it would send, which owed releases, which reopens, and whether it would publish. A connection whose client end is down is the network's, so it allows nothing.
    fn guards(&self) -> Guards {
        let attached = self.current();
        let up = self.alive[&self.gen];
        let pending = Self::pending(attached);
        Guards {
            send: self
                .calls
                .iter()
                .filter(|(_, call)| up && call.state.sendable(attached, pending) == Sendable::Now)
                .map(|(c, _)| *c)
                .collect(),
            owed: if up {
                owed_sendable(&self.handles, attached, pending)
                    .into_iter()
                    .collect()
            } else {
                BTreeSet::new()
            },
            reopen: match &self.round {
                Some(round) if up && !attached.published() => round.unsent().into_iter().collect(),
                _ => BTreeSet::new(),
            },
            publish: up
                && !attached.published()
                && self.round.as_ref().is_none_or(ReopenRound::publishable),
        }
    }

    /// The request the model wrote for a step: the one absent before and present after, with `origin`.
    fn written(pre: &Model, post: &Model, origin: Origin) -> Result<u64, String> {
        post.reqs
            .iter()
            .find(|(r, q)| {
                pre.req(**r).phase == Phase::Absent
                    && q.phase != Phase::Absent
                    && q.origin == origin
            })
            .map(|(r, _)| *r)
            .ok_or_else(|| format!("no request written for {origin:?}"))
    }

    /// What the end of an open or a release given up on, or failed with its connection, leaves owed.
    fn settle_unknown(&mut self, c: u64, e: Error) -> Result<(), String> {
        let call = &self.calls[&c];
        let ended = Err(e);
        match call.kind {
            Kind::Open => match open_settled(&ended) {
                SettleOpen::Owe => {
                    self.handles
                        .owe_release(release_request(HandleKind::File, c));
                    self.covered("open of unknown outcome owed");
                }
                other => return Err(format!("an open of unknown outcome settled as {other:?}")),
            },
            Kind::Release(_) => {
                if !release_owed(&ended) {
                    return Err("a release of unknown outcome is not owed".into());
                }
                self.handles.owe_release(call.request.clone());
                self.covered("release of unknown outcome owed");
            }
            Kind::Change => {}
        }
        Ok(())
    }

    fn step(&mut self, pre: &Model, post: &Model, step: Step) -> Result<(), String> {
        let code = self.guards();
        // The client's own steps the model takes, the code must be able to take, in every run.
        let allowed = match step {
            Step::Send(c) => code.send.contains(&c),
            Step::OwedSend(fh) => code.owed.contains(&fh),
            Step::ReopenSend(fh) => code.reopen.contains(&fh),
            Step::Publish => code.publish,
            _ => true,
        };
        if !allowed {
            return Err(format!(
                "the code would not take the step: it would {code:?}"
            ));
        }
        // And in a run that records what the model allowed, it must allow nothing else.
        if let Some(guards) = &post.guards {
            if guards.send != code.send
                || guards.owed != code.owed
                || guards.reopen != code.reopen
                || guards.publish != code.publish
            {
                return Err(format!(
                    "the code would act otherwise than the model may, in the state before: the code {code:?}, the model {guards:?}"
                ));
            }
        }
        match step {
            Step::Environment => {}
            Step::Start(c) => {
                let call = &post.calls[&c];
                let request = match call.kind {
                    Kind::Change if call.resendable => Request::Setattr {
                        path: Some(path_of(c)),
                        fh: None,
                        set: SetAttr::default(),
                    },
                    Kind::Change => Request::Mkdir {
                        parent: Path::root(),
                        name: name_of(c),
                        mode: 0o755,
                    },
                    Kind::Open => Request::Open {
                        fh: c,
                        path: path_of(c),
                        flags: if call.resendable {
                            libc::O_RDONLY
                        } else {
                            libc::O_RDWR | libc::O_TRUNC
                        },
                    },
                    Kind::Release(fh) => {
                        if !release_begins(&self.handles, fh) {
                            return Err(format!(
                                "the code sends no release of {fh}, which the model holds"
                            ));
                        }
                        Request::Release { fh, ordered: false }
                    }
                };
                let handles = request
                    .fhs()
                    .map(|fh| fh.and_then(|fh| self.handles.get(fh)));
                let resendable = retry_safe(&request, &handles);
                if resendable != call.resendable {
                    return Err(format!(
                        "the code takes {request:?} as resendable: {resendable}"
                    ));
                }
                let ordered = !matches!(call.kind, Kind::Release(_));
                if request.changes() != ordered {
                    return Err(format!(
                        "the code orders {request:?}: {}",
                        request.changes()
                    ));
                }
                let state = CallState::new(request.changes(), resendable);
                self.calls.insert(
                    c,
                    CallClient {
                        kind: call.kind.clone(),
                        state,
                        request,
                        req: None,
                    },
                );
                self.covered("start");
            }
            Step::Send(c) => {
                let r = Self::written(pre, post, Origin::OfCall(c))?;
                let generation = self.gen;
                let call = self.calls.get_mut(&c).ok_or("a call never started")?;
                call.state.sent(generation);
                call.req = Some(r);
                self.reqs.insert(
                    r,
                    ReqClient {
                        what: ForReq::Call(c),
                        conn: generation,
                        counted: None,
                    },
                );
                self.covered(if post.calls[&c].attempt > 1 {
                    "send again"
                } else {
                    "send"
                });
            }
            Step::GiveUp(c) => {
                let call = self.calls.get_mut(&c).ok_or("a call never started")?;
                let req = call.req.take();
                let written = matches!(call.state.status(), StatusCall::InFlight { .. });
                let counted = call.state.gave_up(written);
                if counted {
                    let r = req.expect("a call in flight has its request");
                    let q = self.reqs.get_mut(&r).expect("a request written");
                    q.counted = Some(CancelPending::count(&self.attached[&q.conn].cancels));
                    self.covered("give up, counted");
                } else {
                    self.covered(if written {
                        "give up, in flight, not counted"
                    } else {
                        "give up, waiting"
                    });
                }
                self.settle_unknown(c, Error::Timeout)?;
            }
            Step::LoseClient(g) => {
                self.alive.insert(g, false);
                let inflight: Vec<(u64, u64)> = self
                    .calls
                    .iter()
                    .filter_map(|(c, call)| match (call.state.status(), call.req) {
                        (StatusCall::InFlight { generation }, Some(r)) if generation == g => {
                            Some((*c, r))
                        }
                        _ => None,
                    })
                    .collect();
                for (c, r) in inflight {
                    let not_sent = post.req(r).phase == Phase::Absent;
                    let call = self.calls.get_mut(&c).expect("a call in flight");
                    call.req = None;
                    let lost = call.state.lost(if not_sent {
                        LossExchange::NotSent
                    } else {
                        LossExchange::Lost
                    });
                    if not_sent {
                        self.reqs.remove(&r);
                    }
                    match lost {
                        Ok(()) => self.covered(if not_sent {
                            "lose, not sent"
                        } else {
                            "lose, resent"
                        }),
                        Err(e) => {
                            self.covered("lose, failed");
                            self.settle_unknown(c, e)?;
                        }
                    }
                }
                for q in self.reqs.values_mut().filter(|q| q.conn == g) {
                    q.counted = None;
                }
                if g == self.gen {
                    if let Some(round) = self.round.as_mut() {
                        for fh in round.unsent().into_iter().chain(round.sending()) {
                            round.ended(&self.handles, fh, Err(Error::Disconnected));
                            *self.coverage.entry("reopen lost").or_default() += 1;
                        }
                    }
                }
                self.handles.owed_connection_ended(g);
            }
            Step::Receive(r) => {
                let answer = pre.req(r).answer;
                let q = self
                    .reqs
                    .get_mut(&r)
                    .ok_or("an answer to a request never written")?;
                if q.counted.take().is_some() {
                    self.covered("receive the answer to a cancel");
                    return Ok(());
                }
                let errno = match answer {
                    Answer::Reply => false,
                    Answer::ErrnoReply => true,
                    other => return Err(format!("an uncounted request answered {other:?}")),
                };
                match q.what {
                    ForReq::Call(c) => {
                        let call = self.calls.get_mut(&c).expect("a call written");
                        if call.req != Some(r) {
                            // A call given up on that the code did not count: its stream was dropped, so its answer is never read.
                            self.covered("answer to a call given up on, unread");
                            return Ok(());
                        }
                        call.req = None;
                        call.state.answered(errno);
                        if call.kind == Kind::Open {
                            let opened = if errno {
                                Err(Error::Remote(libc::ENOENT))
                            } else {
                                Ok(Response::Opened { attr: attr(c) })
                            };
                            match open_settled(&opened) {
                                SettleOpen::Keep => {
                                    let flags = match &call.request {
                                        Request::Open { flags, .. } => *flags,
                                        other => unreachable!("an open is an open: {other:?}"),
                                    };
                                    self.handles.insert(
                                        c,
                                        c,
                                        KeyNode::of(&attr(c)),
                                        path_of(c),
                                        flags,
                                        HandleKind::File,
                                        None,
                                    );
                                    self.covered("open kept");
                                }
                                SettleOpen::Nothing => self.covered("open refused"),
                                SettleOpen::Owe => {
                                    return Err("an answered open owed its release".into())
                                }
                            }
                        } else {
                            self.covered(if errno {
                                "receive errno"
                            } else {
                                "receive reply"
                            });
                        }
                    }
                    ForReq::Reopen(fh) => {
                        let round = self.round.as_mut().ok_or("a reopen with no round")?;
                        let held = self.handles.get(fh).is_some();
                        let outcome = if errno {
                            Err(Error::Remote(libc::ENOENT))
                        } else {
                            Ok(Response::Opened { attr: attr(fh) })
                        };
                        round.ended(&self.handles, fh, outcome);
                        self.covered(match (errno, held) {
                            (true, _) => "reopen killed",
                            (false, true) => "reopen kept",
                            (false, false) => "reopen of a handle released meanwhile",
                        });
                    }
                    ForReq::Owed { fh } => {
                        if errno {
                            return Err("a release answered with an errno".into());
                        }
                        self.handles.owed_delivered(fh, q.conn);
                        self.covered("owed release delivered");
                    }
                }
            }
            Step::ReopenSend(fh) => {
                let r = Self::written(pre, post, Origin::Reopen(fh))?;
                let round = self.round.as_mut().ok_or("a reopen with no round")?;
                match round.send(fh) {
                    Request::Open { fh: sent, .. } if sent == fh => {}
                    other => return Err(format!("the reopen of {fh} is {other:?}")),
                }
                self.reqs.insert(
                    r,
                    ReqClient {
                        what: ForReq::Reopen(fh),
                        conn: self.gen,
                        counted: None,
                    },
                );
                self.covered("reopen sent");
            }
            Step::ReopenGiveUp(r) => {
                let q = self.reqs.get_mut(&r).ok_or("a reopen never written")?;
                let ForReq::Reopen(fh) = q.what else {
                    return Err(format!("{:?} given up on as a reopen", q.what));
                };
                if !counts_give_up(true, true, true) {
                    return Err("a reopen given up on once written is not counted".into());
                }
                q.counted = Some(CancelPending::count(&self.attached[&q.conn].cancels));
                self.round.as_mut().ok_or("a reopen with no round")?.ended(
                    &self.handles,
                    fh,
                    Err(Error::Timeout),
                );
                self.covered("reopen given up on");
            }
            Step::ReopenUnsentGiveUp(fh) => {
                if counts_give_up(true, false, true) {
                    return Err("a reopen given up on before it was written is counted".into());
                }
                self.round.as_mut().ok_or("a reopen with no round")?.ended(
                    &self.handles,
                    fh,
                    Err(Error::Timeout),
                );
                self.covered("reopen given up on unsent");
            }
            Step::Publish => {
                self.current().publish();
                self.covered("publish");
            }
            Step::OwedSend(fh) => {
                let r = Self::written(pre, post, Origin::OwedRelease(fh))?;
                match self.handles.owed_send(fh, self.gen) {
                    Request::Release {
                        fh: sent,
                        ordered: true,
                    }
                    | Request::Releasedir {
                        fh: sent,
                        ordered: true,
                    } if sent == fh => {}
                    other => return Err(format!("the owed release of {fh} is {other:?}")),
                }
                self.reqs.insert(
                    r,
                    ReqClient {
                        what: ForReq::Owed { fh },
                        conn: self.gen,
                        counted: None,
                    },
                );
                self.covered("owed release sent");
            }
            Step::Reconnect => {
                self.connect();
                self.current().publish();
                self.covered("reconnect");
            }
            Step::NewSession => {
                self.connect();
                if !self.handles.owed_now().is_empty() {
                    self.covered("owed releases moot");
                }
                self.handles.owed_moot();
                let round = ReopenRound::new(&self.handles);
                if round.publishable() {
                    self.current().publish();
                    self.covered("new session");
                } else {
                    self.covered("new session, reopening");
                }
                self.round = Some(round);
            }
        }
        Ok(())
    }

    fn connect(&mut self) {
        self.gen += 1;
        self.attached.insert(self.gen, AttachedState::new(self.gen));
        self.alive.insert(self.gen, true);
    }

    fn view(&self) -> ViewClient {
        let fhs: Vec<u64> = self.calls.keys().copied().collect();
        ViewClient {
            calls: self
                .calls
                .iter()
                .map(|(c, call)| {
                    (
                        *c,
                        ViewCall {
                            status: match call.state.status() {
                                StatusCall::Waiting => "Waiting".into(),
                                StatusCall::InFlight { .. } => "InFlight".into(),
                                StatusCall::Ended(end) => format!("{end:?}"),
                            },
                            attempt: call.state.attempt(),
                            min_gen: call.state.min_generation().max(1),
                            lost_once: call.state.lost_once(),
                        },
                    )
                })
                .collect(),
            conns: self
                .attached
                .iter()
                .map(|(g, a)| (*g, (a.published(), Self::pending(a))))
                .collect(),
            held: fhs
                .iter()
                .copied()
                .filter(|fh| self.handles.get(*fh).is_some_and(|rec| !rec.is_dead()))
                .collect(),
            dead: fhs
                .iter()
                .copied()
                .filter(|fh| self.handles.get(*fh).is_some_and(|rec| rec.is_dead()))
                .collect(),
            owed: self.handles.owed_now(),
            to_reopen: self
                .round
                .as_ref()
                .map(|r| r.unsent().into_iter().collect())
                .unwrap_or_default(),
            reopening: self
                .round
                .as_ref()
                .map(|r| r.sending().into_iter().collect())
                .unwrap_or_default(),
            reopened: self
                .round
                .as_ref()
                .map(|r| r.reopened().clone())
                .unwrap_or_default(),
        }
    }
}

impl Drive for Driver {
    type Step = Step;

    fn new(init: &Model) -> Result<Driver, String> {
        if init.gen != 1 || init.calls.values().any(|c| c.status != Status::Idle) {
            return Err("a run that does not start from the model's init".into());
        }
        let mut driver = Driver {
            handles: HandleTable::default(),
            attached: BTreeMap::new(),
            alive: BTreeMap::new(),
            gen: 0,
            calls: BTreeMap::new(),
            reqs: BTreeMap::new(),
            round: None,
            coverage: Coverage::new(),
        };
        driver.connect();
        driver.current().publish();
        Ok(driver)
    }

    fn infer(pre: &Model, post: &Model) -> Result<Step, String> {
        infer(pre, post)
    }

    fn actions(step: &Step) -> &'static [&'static str] {
        step.actions()
    }

    fn apply(&mut self, pre: &Model, post: &Model, step: Step) -> Result<(), String> {
        self.step(pre, post, step)
    }

    fn compared(&mut self, model: &Model) -> (String, String) {
        (
            format!("{:#?}", self.view()),
            format!("{:#?}", view_client(model)),
        )
    }

    fn abandon(self) {}

    fn coverage(&mut self) -> Coverage {
        std::mem::take(&mut self.coverage)
    }
}

//! The session model's state as an ITF trace carries it (`spec/session.qnt`, its `var`s), and the part of it the server's code is compared on.

use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "tag", content = "value")]
pub enum Kind {
    Change,
    Open,
    Release(u64),
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "tag", content = "value")]
#[allow(clippy::enum_variant_names)] // the model's names
pub enum Origin {
    NoOrigin,
    OfCall(u64),
    Reopen(u64),
    OrphanRelease(u64),
    OwedRelease(u64),
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "tag", content = "value")]
pub enum Phase {
    Absent,
    Transit,
    Held,
    Ready,
    Cancelled,
    Superseded,
    Dropped,
    Running,
    Abandoned,
    Finished,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "tag", content = "value")]
#[allow(clippy::enum_variant_names)] // the model's names
pub enum Answer {
    NoAnswer,
    Reply,
    ErrnoReply,
    Unrun,
    Fenced,
    Lost,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "tag", content = "value")]
#[allow(clippy::enum_variant_names)] // the model's names
pub enum Slot {
    NoSlot,
    Taken,
    Kept,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Call {
    pub kind: Kind,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Req {
    pub origin: Origin,
    pub phase: Phase,
    pub conn: u64,
    pub epoch: u64,
    pub session: u64,
    pub answer: Answer,
    pub slot: Slot,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conn {
    pub session: u64,
    pub epoch: u64,
    pub server_alive: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Entry {
    pub by: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub epoch: u64,
    pub running: usize,
    pub abandoned: usize,
    pub running_older: usize,
    pub live: bool,
    pub detached: bool,
    pub handles: BTreeMap<u64, Entry>,
}

/// One state of a trace: the model's variables, with the module path taken off their names, and, in a trace `quint run --mbt` wrote, the action that led to it.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Model {
    pub calls: BTreeMap<u64, Call>,
    pub reqs: BTreeMap<u64, Req>,
    pub conns: BTreeMap<u64, Conn>,
    pub gen: u64,
    pub sessions: BTreeMap<u64, Session>,
    pub sid: u64,
    pub pool: usize,
    #[serde(default)]
    pub action_taken: Option<String>,
    /// The choices the action made, each `Some` or `None`, in a trace `quint run --mbt` wrote.
    #[serde(default)]
    pub nondet_picks: Option<serde_json::Value>,
}

impl Model {
    pub fn req(&self, r: u64) -> &Req {
        &self.reqs[&r]
    }

    /// The model's `alive`: a request of session `s` not ended, or a connection of it up at the server.
    fn alive(&self, s: u64) -> bool {
        use Phase::*;
        self.reqs.values().any(|q| {
            q.session == s
                && !matches!(
                    q.phase,
                    Absent | Cancelled | Superseded | Dropped | Finished
                )
        }) || self
            .conns
            .values()
            .any(|k| k.session == s && k.server_alive)
    }

    /// The boolean the action chose for `name`, in a trace that records its choices.
    pub fn pick(&self, name: &str) -> Option<bool> {
        let pick = self.nondet_picks.as_ref()?.get(name)?;
        match pick["tag"].as_str()? {
            "Some" => pick["value"].as_bool(),
            _ => None,
        }
    }

    /// What the server's code is compared on: every session's attachment and handles, the connections' epochs, the pool, and each request the server has, as the model has them.
    pub fn view(&self) -> View {
        View {
            sessions: self
                .sessions
                .iter()
                .filter(|(_, s)| s.epoch > 0)
                .map(|(id, s)| {
                    (
                        *id,
                        ViewSession {
                            epoch: s.epoch,
                            running: s.running,
                            abandoned: s.abandoned,
                            running_older: s.running_older,
                            live: s.live,
                            detached: s.detached,
                            alive: self.alive(*id),
                            handles: s
                                .handles
                                .iter()
                                .filter(|(_, e)| e.by != 0)
                                .map(|(fh, e)| (*fh, e.by))
                                .collect(),
                        },
                    )
                })
                .collect(),
            conns: self
                .conns
                .iter()
                .filter(|(_, k)| k.session != 0)
                .map(|(g, k)| (*g, (k.session, k.epoch)))
                .collect(),
            pool: self.pool,
            reqs: self
                .reqs
                .iter()
                .filter(|(_, q)| q.phase != Phase::Absent)
                .map(|(r, q)| {
                    (
                        *r,
                        ViewReq {
                            phase: q.phase,
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

/// The state model and code are compared on after every step.
#[derive(Debug, PartialEq, Eq)]
pub struct View {
    pub sessions: BTreeMap<u64, ViewSession>,
    /// Each connection's session and epoch.
    pub conns: BTreeMap<u64, (u64, u64)>,
    pub pool: usize,
    pub reqs: BTreeMap<u64, ViewReq>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewSession {
    pub epoch: u64,
    pub running: usize,
    pub abandoned: usize,
    pub running_older: usize,
    pub live: bool,
    pub detached: bool,
    /// Whether anything of it is under way at the server, which keeps it resumable once it is no longer live.
    pub alive: bool,
    /// Each handle held, by the request that opened it.
    pub handles: BTreeMap<u64, u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ViewReq {
    pub phase: Phase,
    pub session: u64,
    pub epoch: u64,
    pub slot: Slot,
    pub answer: Answer,
}

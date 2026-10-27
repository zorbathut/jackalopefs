//! The session model's state as an ITF trace carries it (`spec/session.qnt`, its `var`s).

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

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

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "tag", content = "value")]
pub enum StatusCall {
    Idle,
    Waiting,
    InFlight,
    Ended,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "tag", content = "value")]
pub enum Outcome {
    NoOutcome,
    Replied,
    Errno,
    GaveUp,
    Failed,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Call {
    pub kind: Kind,
    pub status: StatusCall,
    pub resendable: bool,
    pub attempt: u32,
    pub min_gen: u64,
    pub lost_once: bool,
    pub req: u64,
    pub outcome: Outcome,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Req {
    pub origin: Origin,
    pub attempt: u32,
    pub phase: Phase,
    pub conn: u64,
    pub epoch: u64,
    pub session: u64,
    pub cancel_sent: bool,
    pub counted: bool,
    pub answer: Answer,
    pub slot: Slot,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conn {
    pub session: u64,
    pub epoch: u64,
    pub client_alive: bool,
    pub server_alive: bool,
    pub published: bool,
    pub cancels: usize,
}

/// The client's handle table and its round of reopens.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Client {
    /// For each id, the request whose reply the client accepted, or the reopen it expects; 0 for none held.
    pub held: BTreeMap<u64, u64>,
    pub dead: BTreeSet<u64>,
    pub owed: BTreeSet<u64>,
    pub to_reopen: BTreeSet<u64>,
    pub reopened: BTreeSet<u64>,
    pub reopening: BTreeSet<u64>,
}

/// What the client could do in the state before, in a run of `spec/session_mbt.qnt`, but for the model's bound on requests.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Guards {
    pub send: BTreeSet<u64>,
    pub owed: BTreeSet<u64>,
    pub reopen: BTreeSet<u64>,
    pub publish: bool,
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
    pub client: Client,
    pub pool: usize,
    /// In a run of `spec/session_mbt.qnt`: what the client could do in the state before this one.
    #[serde(default)]
    pub guards: Option<Guards>,
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
    pub fn alive(&self, s: u64) -> bool {
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
}

//! The part of the model's state the server's code is compared on.

use jackalopefs_mbt::model::{Answer, Model, Phase, Slot};
use std::collections::BTreeMap;

/// What the server's code is compared on: every session's attachment and handles, the connections' epochs, the pool, and each request the server has, as the model has them.
pub fn view(model: &Model) -> View {
    View {
        sessions: model
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
                        alive: model.alive(*id),
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
        conns: model
            .conns
            .iter()
            .filter(|(_, k)| k.session != 0)
            .map(|(g, k)| (*g, (k.session, k.epoch)))
            .collect(),
        pool: model.pool,
        reqs: model
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

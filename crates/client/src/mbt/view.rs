//! The part of the model's state the client's code is compared on.

use jackalopefs_mbt::model::{Model, Origin, StatusCall};
use std::collections::{BTreeMap, BTreeSet};

/// The state model and code are compared on after every step.
#[derive(Debug, PartialEq, Eq)]
pub struct ViewClient {
    /// Every call the kernel started.
    pub calls: BTreeMap<u64, ViewCall>,
    /// Each connection's publication and pending cancels, by generation.
    pub conns: BTreeMap<u64, (bool, usize)>,
    /// The handles held, and those dead, that the kernel has not released.
    pub held: BTreeSet<u64>,
    pub dead: BTreeSet<u64>,
    pub owed: BTreeSet<u64>,
    /// The round of reopens after the latest new session: the handles not yet reopened, those whose reopen waits for its answer, and those reopened.
    pub to_reopen: BTreeSet<u64>,
    pub reopening: BTreeSet<u64>,
    pub reopened: BTreeSet<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ViewCall {
    /// Waiting, in flight, or how it ended.
    pub status: String,
    pub attempt: u32,
    pub min_gen: u64,
    pub lost_once: bool,
}

/// What the client's code is compared on, as the model has it.
pub fn view_client(model: &Model) -> ViewClient {
    ViewClient {
        calls: model
            .calls
            .iter()
            .filter(|(_, call)| call.status != StatusCall::Idle)
            .map(|(c, call)| {
                (
                    *c,
                    ViewCall {
                        status: match call.status {
                            StatusCall::Ended => format!("{:?}", call.outcome),
                            other => format!("{other:?}"),
                        },
                        attempt: call.attempt,
                        min_gen: call.min_gen,
                        lost_once: call.lost_once,
                    },
                )
            })
            .collect(),
        conns: model
            .conns
            .iter()
            .filter(|(_, k)| k.session != 0)
            .map(|(g, k)| (*g, (k.published, k.cancels)))
            .collect(),
        held: model
            .client
            .held
            .iter()
            .filter(|(_, by)| **by != 0)
            .map(|(fh, _)| *fh)
            .collect(),
        dead: model.client.dead.clone(),
        owed: model.client.owed.clone(),
        to_reopen: model.client.to_reopen.clone(),
        reopening: model
            .client
            .reopening
            .iter()
            .map(|r| match model.req(*r).origin {
                Origin::Reopen(fh) => fh,
                other => panic!("a reopen from {other:?}"),
            })
            .collect(),
        reopened: model.client.reopened.clone(),
    }
}

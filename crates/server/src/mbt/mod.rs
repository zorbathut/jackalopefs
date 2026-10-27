//! Model-based testing of the server's session machine against `spec/session.qnt`: runs of the model, as ITF traces, are replayed step by step with the real `Sessions`, exchanges and handles taking the server's steps ([`driver`]), and the code's state is compared with the model's after every one (`jackalopefs_mbt`). `spec/README.md`, "Model-based testing", says what is driven, read and compared.

mod driver;
mod view;

use driver::Driver;
use jackalopefs_mbt::model::Phase;
use jackalopefs_mbt::{corpus, random_runs, replay, replay_all, states, Coverage};

#[test]
fn the_corpus_replays_reaching_every_server_step() {
    let coverage = replay_all::<Driver>(corpus());
    let missing: Vec<&str> = [
        "arrive held",
        "arrive ready",
        "dropCut held",
        "drain ready",
        "drain superseded",
        "begin running",
        "begin running, a slot taken",
        "begin running, the handle kept",
        "begin superseded",
        "seeCancel unrun",
        "seeCancel fenced",
        "finish reply",
        "finish errno",
        "finish abandoned",
        "loseServer",
        "reconnect",
        "reconnect, taking over",
        "newSession",
        "handshakeLost",
        "dropSession",
        "closeSession",
    ]
    .into_iter()
    .filter(|what| !coverage.contains_key(what))
    .collect();
    assert!(
        missing.is_empty(),
        "never reached: {missing:?}; reached: {coverage:?}"
    );
}

/// A run whose server held a change the code lets through stops at that step: the comparison is not vacuous.
#[test]
fn a_run_the_code_does_not_take_stops_where_it_parts() {
    let (name, trace) = corpus()
        .into_iter()
        .find(|(name, _)| name == "cancelledRunningTest")
        .expect("the scenario is in the corpus");
    let mut states = states(&trace).unwrap();
    let held = (1..states.len())
        .find(|&i| {
            states[i].reqs.iter().any(|(r, q)| {
                q.phase == Phase::Held && states[i - 1].req(*r).phase == Phase::Transit
            })
        })
        .expect("a change held as it arrives");
    for q in states[held]
        .reqs
        .values_mut()
        .filter(|q| q.phase == Phase::Held)
    {
        q.phase = Phase::Ready;
    }
    let stopped = replay::<Driver>(&states, &mut Coverage::new())
        .expect_err(&format!("{name} replayed with a held change made ready"));
    assert!(stopped.starts_with(&format!("step {held} ")), "{stopped}");
}

/// Random runs of the model's small instance ([`random_runs`]); `scripts/spec/mbt.sh` runs it.
#[test]
#[ignore = "needs Quint: scripts/spec/mbt.sh"]
fn random_runs_replay() {
    let coverage = replay_all::<Driver>(random_runs());
    eprintln!("{coverage:#?}");
}

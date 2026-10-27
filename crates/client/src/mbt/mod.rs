//! Model-based testing of the client's session machine against `spec/session.qnt`: runs of the model, as ITF traces, are replayed step by step with the real `HandleTable`, each call's `CallState`, each connection's `AttachedState` and the `ReopenRound` taking the client's steps ([`driver`]), and the code's state is compared with the model's after every one (`jackalopefs_mbt`). In a run that records what the client could do in each state (`spec/session_mbt.qnt`), the code must allow exactly that too. `spec/README.md`, "Model-based testing", says what is driven, read and compared.

mod driver;
mod view;

use driver::Driver;
use jackalopefs_mbt::model::Outcome;
use jackalopefs_mbt::{corpus, random_runs, replay, replay_all, states, Coverage};

#[test]
fn the_corpus_replays_reaching_every_client_step() {
    let coverage = replay_all::<Driver>(corpus());
    let missing: Vec<&str> = [
        "start",
        "send",
        "send again",
        "give up, waiting",
        "give up, counted",
        "give up, in flight, not counted",
        "open of unknown outcome owed",
        "release of unknown outcome owed",
        "lose, not sent",
        "lose, resent",
        "lose, failed",
        "receive reply",
        "receive errno",
        "receive the answer to a cancel",
        "open kept",
        "open refused",
        "reopen sent",
        "reopen kept",
        "reopen killed",
        "reopen of a handle released meanwhile",
        "reopen given up on",
        "reopen given up on unsent",
        "reopen lost",
        "publish",
        "owed release sent",
        "owed release delivered",
        "owed releases moot",
        "reconnect",
        "new session",
        "new session, reopening",
    ]
    .into_iter()
    .filter(|what| !coverage.contains_key(what))
    .collect();
    assert!(
        missing.is_empty(),
        "never reached: {missing:?}; reached: {coverage:?}"
    );
}

/// A run whose client was given up on as an unknown outcome where the code knows the reply stops at that step: the comparison is not vacuous.
#[test]
fn a_run_the_code_does_not_take_stops_where_it_parts() {
    let (name, trace) = corpus()
        .into_iter()
        .find(|(name, _)| name == "replyLostTest")
        .expect("the scenario is in the corpus");
    let mut states = states(&trace).unwrap();
    let resent = (1..states.len())
        .find(|&i| states[i].calls[&1].lost_once && !states[i - 1].calls[&1].lost_once)
        .expect("a reply lost and asked for again");
    for state in &mut states[resent..] {
        let call = state.calls.get_mut(&1).unwrap();
        if call.outcome == Outcome::NoOutcome {
            call.lost_once = false;
        }
    }
    let stopped = replay::<Driver>(&states, &mut Coverage::new())
        .expect_err(&format!("{name} replayed with a resend not marked as one"));
    assert!(stopped.starts_with(&format!("step {resent} ")), "{stopped}");
}

/// Random runs of the model's small instance ([`random_runs`]); `scripts/spec/mbt.sh` runs it.
#[test]
#[ignore = "needs Quint: scripts/spec/mbt.sh"]
fn random_runs_replay() {
    let coverage = replay_all::<Driver>(random_runs());
    eprintln!("{coverage:#?}");
}

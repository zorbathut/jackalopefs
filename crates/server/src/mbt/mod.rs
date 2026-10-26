//! Model-based testing of the server's session machine against `spec/session.qnt`: runs of the model, as ITF traces, are replayed step by step with the real `Sessions`, exchanges and handles taking the server's steps ([`driver`]), and the code's state is compared with the model's after every one. `spec/README.md`, "Model-based testing", says what is driven, read and compared.
//!
//! The corpus (`spec/mbt/corpus.json.gz`: the scenario runs of `spec/session_small.qnt` and a run reaching each of the model's witnesses, made by `scripts/spec/mbt.sh corpus`) is replayed by every `cargo test`; `scripts/spec/mbt.sh` replays as many random runs as asked, which needs Quint.

mod driver;
mod model;

use driver::{infer, Coverage, Driver};
use model::{Model, Phase};
use std::io::BufRead;
use std::path::{Path, PathBuf};

/// A trace's states, the module path taken off each variable's name.
fn states(trace: &serde_json::Value) -> Result<Vec<Model>, String> {
    let states = trace["states"].as_array().ok_or("a trace without states")?;
    states
        .iter()
        .map(|state| {
            let vars: serde_json::Map<String, serde_json::Value> = state
                .as_object()
                .ok_or("a state that is no record")?
                .iter()
                .filter(|(name, _)| !name.starts_with('#'))
                .map(|(name, value)| {
                    (
                        name.rsplit("::").next().unwrap_or(name).to_string(),
                        value.clone(),
                    )
                })
                .collect();
            serde_json::from_value(plain(serde_json::Value::Object(vars)))
                .map_err(|e| e.to_string())
        })
        .collect()
}

/// An ITF value as plain JSON: an integer as a number, a map as an object keyed by its keys' text, a set or a tuple as an array, the empty tuple (a sum type's unit value) as null.
fn plain(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(fields) => {
            let mut fields: Vec<(String, Value)> = fields.into_iter().collect();
            match fields.as_mut_slice() {
                [(key, Value::String(n))] if key == "#bigint" => {
                    Value::Number(n.parse().expect("an ITF integer"))
                }
                [(key, Value::Array(pairs))] if key == "#map" => Value::Object(
                    std::mem::take(pairs)
                        .into_iter()
                        .map(|pair| match plain(pair) {
                            Value::Array(kv) => match <[Value; 2]>::try_from(kv) {
                                Ok([k, v]) => (k.to_string(), v),
                                Err(kv) => panic!("an ITF map entry: {kv:?}"),
                            },
                            other => panic!("an ITF map entry: {other}"),
                        })
                        .collect(),
                ),
                [(key, Value::Array(items))] if key == "#tup" && items.is_empty() => Value::Null,
                [(key, Value::Array(items))] if key == "#set" || key == "#tup" => {
                    Value::Array(std::mem::take(items).into_iter().map(plain).collect())
                }
                _ => Value::Object(fields.into_iter().map(|(k, v)| (k, plain(v))).collect()),
            }
        }
        Value::Array(items) => Value::Array(items.into_iter().map(plain).collect()),
        other => other,
    }
}

/// Replay `states` against a fresh server: every step must be one the code can take, and leave the code where the model is. The error names the step it stopped at.
fn replay(states: &[Model], coverage: &mut Coverage) -> Result<(), String> {
    let mut driver = Driver::new(&states[0])?;
    let replayed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        replay_with(&mut driver, states)
    }))
    .unwrap_or_else(|panic| {
        Err(format!(
            "panicked: {}",
            panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or(panic.downcast_ref::<&str>().copied())
                .unwrap_or("?")
        ))
    });
    if replayed.is_err() {
        driver.abandon();
        return replayed;
    }
    for (what, n) in std::mem::take(&mut driver.coverage) {
        *coverage.entry(what).or_default() += n;
    }
    Ok(())
}

fn replay_with(driver: &mut Driver, states: &[Model]) -> Result<(), String> {
    let compared = |driver: &mut Driver, model: &Model| {
        let (code, model) = (
            format!("{:#?}", driver.view()),
            format!("{:#?}", model.view()),
        );
        if code == model {
            return Ok(());
        }
        let diff = similar::TextDiff::from_lines(&model, &code)
            .unified_diff()
            .header("model", "code")
            .to_string();
        Err(format!("the code's state is not the model's:\n{diff}"))
    };
    compared(driver, &states[0]).map_err(|e| format!("init: {e}"))?;
    for (i, pair) in states.windows(2).enumerate() {
        let (pre, post) = (&pair[0], &pair[1]);
        let at = |step: &dyn std::fmt::Debug, e: String| {
            format!(
                "step {} ({step:?}, the model's {}): {e}",
                i + 1,
                post.action_taken.as_deref().unwrap_or("action unrecorded")
            )
        };
        let step = infer(pre, post).map_err(|e| at(&"?", e))?;
        if let Some(action) = &post.action_taken {
            if !step.actions().contains(&action.as_str()) {
                return Err(at(
                    &step,
                    format!("inferred as {step:?}, which {action} is not"),
                ));
            }
        }
        driver.apply(pre, post, step).map_err(|e| at(&step, e))?;
        compared(driver, post).map_err(|e| at(&step, e))?;
    }
    Ok(())
}

fn spec_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec")
}

/// The corpus, by trace name.
fn corpus() -> Vec<(String, serde_json::Value)> {
    let file = std::fs::File::open(spec_dir().join("mbt/corpus.json.gz"))
        .expect("spec/mbt/corpus.json.gz (scripts/spec/mbt.sh corpus makes it)");
    let lines = std::io::BufReader::new(flate2::read::GzDecoder::new(file)).lines();
    lines
        .skip(1)
        .map(|line| {
            let mut entry: serde_json::Value =
                serde_json::from_str(&line.expect("the corpus reads"))
                    .expect("a corpus line is JSON");
            let name = entry["name"].as_str().expect("a named trace").to_string();
            (name, entry["trace"].take())
        })
        .collect()
}

/// Replay every trace, failing with each one that stops.
fn replay_all(traces: impl IntoIterator<Item = (String, serde_json::Value)>) -> Coverage {
    let mut coverage = Coverage::new();
    let mut failed = Vec::new();
    let mut replayed = 0;
    for (name, trace) in traces {
        replayed += 1;
        if let Err(e) = states(&trace).and_then(|states| replay(&states, &mut coverage)) {
            failed.push(format!("{name}: {e}"));
        }
    }
    assert!(replayed > 0, "no traces");
    assert!(
        failed.is_empty(),
        "{} of {replayed} traces stopped:\n\n{}",
        failed.len(),
        failed.join("\n\n")
    );
    coverage
}

#[test]
fn the_corpus_replays_reaching_every_server_step() {
    let coverage = replay_all(corpus());
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
    let stopped = replay(&states, &mut Coverage::new())
        .expect_err(&format!("{name} replayed with a held change made ready"));
    assert!(stopped.starts_with(&format!("step {held} ")), "{stopped}");
}

/// Random runs of the model's small instance (`JACKALOPEFS_MBT_TRACES` of them, from `JACKALOPEFS_MBT_SEED`), as many steps long as `JACKALOPEFS_MBT_STEPS`; `scripts/spec/mbt.sh` runs it.
#[test]
#[ignore = "needs Quint: scripts/spec/mbt.sh"]
fn random_runs_replay() {
    let var =
        |name: &str, default: &str| std::env::var(name).unwrap_or_else(|_| default.to_string());
    let traces: usize = var("JACKALOPEFS_MBT_TRACES", "200")
        .parse()
        .expect("a number of traces");
    let seed = var("JACKALOPEFS_MBT_SEED", &format!("{}", std::process::id()));
    let steps = var("JACKALOPEFS_MBT_STEPS", "40");
    let quint = spec_dir().join("node_modules/.bin/quint");
    assert!(
        quint.exists(),
        "{} is missing: scripts/spec/check.sh installs it",
        quint.display()
    );
    let out = tempfile::tempdir().unwrap();
    let ran = std::process::Command::new(&quint)
        .current_dir(spec_dir())
        .args([
            "run",
            "session_small.qnt",
            "--main",
            "session_small",
            "--mbt",
            "--verbosity",
            "0",
        ])
        .args([
            "--max-samples",
            &traces.to_string(),
            "--n-traces",
            &traces.to_string(),
            "--max-steps",
            &steps,
            "--seed",
            &seed,
        ])
        .arg("--out-itf")
        .arg(out.path().join("run{seq}.itf.json"))
        .output()
        .expect("quint runs");
    assert!(
        ran.status.success(),
        "quint run: {}{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    let mut files: Vec<PathBuf> = std::fs::read_dir(out.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    eprintln!("replaying {} runs of seed {seed}", files.len());
    let coverage = replay_all(files.into_iter().map(|file| {
        let trace = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        (
            format!(
                "seed {seed}, {}",
                file.file_name().unwrap().to_string_lossy()
            ),
            trace,
        )
    }));
    eprintln!("{coverage:#?}");
}

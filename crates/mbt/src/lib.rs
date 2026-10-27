//! Runs of the session model (`spec/session.qnt`), read from ITF traces, and their replay against a driver of the code: the model-based tests of the server and the client (`spec/README.md`, "Model-based testing"). A driver takes each step of a run with the code and says what the code's state is; the replay compares it with the model's after every step.
//!
//! The corpus (`spec/mbt/corpus.json.gz`: the scenario runs of `spec/session_small.qnt` and a run reaching each of the model's witnesses, made by `scripts/spec/mbt.sh corpus`) is replayed by every `cargo test`; [`random_runs`] has Quint make as many random runs as asked.

pub mod model;

use model::Model;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::BufRead;
use std::path::{Path, PathBuf};

/// Each step and outcome a batch of runs took, so it can be seen to reach them all.
pub type Coverage = BTreeMap<&'static str, usize>;

/// The code taking the model's steps.
pub trait Drive: Sized {
    type Step: Debug;

    /// The code as the model's `init` has it.
    fn new(init: &Model) -> Result<Self, String>;

    /// Which step took the model from `pre` to `post`.
    fn infer(pre: &Model, post: &Model) -> Result<Self::Step, String>;

    /// The names of the model's actions (its `step`'s, as `mbt::actionTaken` gives them) `step` can be.
    fn actions(step: &Self::Step) -> &'static [&'static str];

    /// Take `step` with the code.
    fn apply(&mut self, pre: &Model, post: &Model, step: Self::Step) -> Result<(), String>;

    /// What the code's state is and what the model's is, in the same terms, for the comparison after every step.
    fn compared(&mut self, model: &Model) -> (String, String);

    /// Let go of a driver whose replay failed, without the checks its drop would make.
    fn abandon(self);

    /// The steps and outcomes this driver's run took.
    fn coverage(&mut self) -> Coverage;
}

/// A trace's states, the module path taken off each variable's name.
pub fn states(trace: &serde_json::Value) -> Result<Vec<Model>, String> {
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

/// Replay `states` with a fresh driver: every step must be one the code can take, and leave the code where the model is. The error names the step it stopped at.
pub fn replay<D: Drive>(states: &[Model], coverage: &mut Coverage) -> Result<(), String> {
    let mut driver = D::new(&states[0])?;
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
    for (what, n) in driver.coverage() {
        *coverage.entry(what).or_default() += n;
    }
    Ok(())
}

fn replay_with<D: Drive>(driver: &mut D, states: &[Model]) -> Result<(), String> {
    let compared = |driver: &mut D, model: &Model| {
        let (code, model) = driver.compared(model);
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
        let at = |step: &dyn Debug, e: String| {
            format!(
                "step {} ({step:?}, the model's {}): {e}",
                i + 1,
                post.action_taken.as_deref().unwrap_or("action unrecorded")
            )
        };
        let step = D::infer(pre, post).map_err(|e| at(&"?", e))?;
        if let Some(action) = &post.action_taken {
            if !D::actions(&step).contains(&action.as_str()) {
                return Err(at(
                    &step,
                    format!("inferred as {step:?}, which {action} is not"),
                ));
            }
        }
        let shown = format!("{step:?}");
        driver.apply(pre, post, step).map_err(|e| at(&shown, e))?;
        compared(driver, post).map_err(|e| at(&shown, e))?;
    }
    Ok(())
}

/// Replay every trace, failing with each one that stops.
pub fn replay_all<D: Drive>(
    traces: impl IntoIterator<Item = (String, serde_json::Value)>,
) -> Coverage {
    let mut coverage = Coverage::new();
    let mut failed = Vec::new();
    let mut replayed = 0;
    for (name, trace) in traces {
        replayed += 1;
        if let Err(e) = states(&trace).and_then(|states| replay::<D>(&states, &mut coverage)) {
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

fn spec_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec")
}

/// The corpus, by trace name.
pub fn corpus() -> Vec<(String, serde_json::Value)> {
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

/// Random runs of the model's small instance, by name, each state after the first carrying what the client could do in the one before (`spec/session_mbt.qnt`): `JACKALOPEFS_MBT_TRACES` of them (default 200), from `JACKALOPEFS_MBT_SEED`, each up to `JACKALOPEFS_MBT_STEPS` steps (default 40). Needs Quint, which `scripts/spec/check.sh` installs; `scripts/spec/mbt.sh` runs the tests that use this.
pub fn random_runs() -> Vec<(String, serde_json::Value)> {
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
            "session_mbt.qnt",
            "--main",
            "session_mbt",
            "--init",
            "mbtInit",
            "--step",
            "mbtStep",
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
    files
        .into_iter()
        .map(|file| {
            let trace = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
            (
                format!(
                    "seed {seed}, {}",
                    file.file_name().unwrap().to_string_lossy()
                ),
                trace,
            )
        })
        .collect()
}

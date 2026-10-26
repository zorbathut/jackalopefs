//! A test's client and server recording what they do in the session model's terms, for `spec/replay.qnt` to replay: only when the test is built with the `spec-trace` feature and `JACKALOPEFS_SPEC_TRACES` names a directory (`scripts/spec/traces.sh` sets both). Otherwise [`Traced`] makes a plain client and writes nothing.

use super::TestServer;
use jackalopefs_client::{Client, Config};

/// One test run's recording, named after the test (its thread's name) and `run`, which tells apart the runs one test makes.
pub struct Traced {
    #[cfg(feature = "spec-trace")]
    recorded: Option<(
        std::sync::Arc<jackalopefs_perf::spec_trace::Recorder>,
        String,
    )>,
}

impl Traced {
    /// Starts recording `server`'s sessions, before any client connects.
    pub fn start(server: &TestServer, run: &str) -> Traced {
        #[cfg(feature = "spec-trace")]
        {
            let recorded = std::env::var_os("JACKALOPEFS_SPEC_TRACES").map(|_| {
                let recorder =
                    std::sync::Arc::new(jackalopefs_perf::spec_trace::Recorder::default());
                server.server.sessions.set_recorder(recorder.clone());
                let test = std::thread::current().name().unwrap_or("test").to_owned();
                (
                    recorder,
                    if run.is_empty() {
                        test
                    } else {
                        format!("{test}_{run}")
                    },
                )
            });
            Traced { recorded }
        }
        #[cfg(not(feature = "spec-trace"))]
        {
            let _ = (server, run);
            Traced {}
        }
    }

    /// The test's client, recording into the same trace as the server when there is one.
    pub async fn client(&self, config: Config) -> Client {
        #[cfg(feature = "spec-trace")]
        if let Some((recorder, _)) = &self.recorded {
            return Client::connect_recorded(config, recorder.clone())
                .await
                .unwrap();
        }
        Client::connect(config).await.unwrap()
    }

    /// Writes the trace, once the client and the server have shut down, so every event of theirs is in it.
    pub fn finish(self) {
        #[cfg(feature = "spec-trace")]
        if let Some((recorder, name)) = self.recorded {
            let dir = std::path::PathBuf::from(
                std::env::var_os("JACKALOPEFS_SPEC_TRACES").expect("set when recording"),
            );
            std::fs::create_dir_all(&dir).unwrap();
            let events = recorder.events();
            let name = jackalopefs_perf::spec_trace::quint::ident(&name);
            std::fs::write(
                dir.join(format!("{name}.qnt.part")),
                jackalopefs_perf::spec_trace::quint::fragment(&name, &events),
            )
            .unwrap();
            std::fs::write(
                dir.join(format!("{name}.log")),
                events
                    .iter()
                    .enumerate()
                    .map(|(i, e)| format!("{i}: {e:?}\n"))
                    .collect::<String>(),
            )
            .unwrap();
        }
    }
}

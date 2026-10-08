//! The log subscriber both binaries install: `RUST_LOG` (or `info`) as the filter, which a signal can widen to a side's trace directives and narrow back while the process runs.

use std::io::IsTerminal;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{reload, EnvFilter, Registry};

/// The installed filter and what it can be switched between.
pub struct Logging {
    handle: reload::Handle<EnvFilter, Registry>,
    base: String,
    trace: &'static str,
    tracing: bool,
}

/// Install the process's subscriber, logging to stdout. `trace` is the directives [`Logging::toggle_trace`] adds to the startup filter.
pub fn init(trace: &'static str) -> Logging {
    let (base, invalid) = base_of(std::env::var("RUST_LOG"));
    let (subscriber, logging) = build(
        base,
        trace,
        std::io::stdout,
        std::io::stdout().is_terminal(),
    );
    subscriber.init();
    if let Some((given, e)) = invalid {
        tracing::warn!("RUST_LOG={given:?} does not parse ({e}); logging at info");
    }
    logging
}

/// The startup filter for `RUST_LOG` as read: the variable when it is set and parses, else `info` and, when it was set, what it said and why it was refused.
fn base_of(var: Result<String, std::env::VarError>) -> (String, Option<(String, String)>) {
    match var {
        Ok(given) => match EnvFilter::try_new(&given) {
            Ok(_) => (given, None),
            Err(e) => ("info".into(), Some((given, e.to_string()))),
        },
        Err(std::env::VarError::NotPresent) => ("info".into(), None),
        Err(e @ std::env::VarError::NotUnicode(_)) => {
            ("info".into(), Some(("(not unicode)".into(), e.to_string())))
        }
    }
}

fn build<W>(
    base: String,
    trace: &'static str,
    writer: W,
    ansi: bool,
) -> (impl tracing::Subscriber + Send + Sync, Logging)
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let (filter, handle) =
        reload::Layer::new(EnvFilter::try_new(&base).expect("the base filter was parsed before"));
    let subscriber = tracing_subscriber::registry().with(filter).with(
        tracing_subscriber::fmt::layer()
            .with_ansi(ansi)
            .with_writer(writer),
    );
    let logging = Logging {
        handle,
        base,
        trace,
        tracing: false,
    };
    (subscriber, logging)
}

impl Logging {
    /// Switch between the startup filter and the startup filter plus the trace directives.
    pub fn toggle_trace(&mut self) {
        let on = !self.tracing;
        let directives = if on {
            [self.base.as_str(), self.trace]
                .into_iter()
                .filter(|d| !d.is_empty())
                .collect::<Vec<_>>()
                .join(",")
        } else {
            self.base.clone()
        };
        let filter = match EnvFilter::try_new(&directives) {
            Ok(filter) => filter,
            Err(e) => {
                tracing::warn!("cannot build the log filter {directives:?}: {e}");
                return;
            }
        };
        match self.handle.reload(filter) {
            Ok(()) => {
                self.tracing = on;
                if on {
                    tracing::info!("trace logging on ({directives}); SIGUSR2 again turns it off");
                } else {
                    tracing::info!("trace logging off ({directives})");
                }
            }
            Err(e) => tracing::warn!("cannot change the log filter: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'w> MakeWriter<'w> for Buffer {
        type Writer = Buffer;

        fn make_writer(&'w self) -> Buffer {
            self.clone()
        }
    }

    impl Buffer {
        fn take(&self) -> String {
            String::from_utf8(std::mem::take(&mut *self.0.lock().unwrap())).unwrap()
        }
    }

    const TARGET: &str = "jackalopefs_perf_test::perf";

    #[test]
    fn rust_log_is_taken_when_it_parses_and_reported_when_it_does_not() {
        assert_eq!(
            base_of(Err(std::env::VarError::NotPresent)),
            ("info".into(), None)
        );
        assert_eq!(
            base_of(Ok("debug,quinn=warn".into())),
            ("debug,quinn=warn".into(), None)
        );
        let (base, invalid) = base_of(Ok("jackalopefs=loud".into()));
        assert_eq!(base, "info");
        let (given, _) = invalid.expect("an unparseable RUST_LOG is reported");
        assert_eq!(given, "jackalopefs=loud");
    }

    #[test]
    fn trace_mode_comes_and_goes() {
        let buffer = Buffer::default();
        let (subscriber, mut logging) = build(
            "info".into(),
            "jackalopefs_perf_test=trace",
            buffer.clone(),
            false,
        );
        tracing::subscriber::with_default(subscriber, || {
            let emit = || tracing::trace!(target: TARGET, unique = 7, "request");
            assert!(!tracing::enabled!(target: TARGET, tracing::Level::TRACE));
            emit();
            tracing::info!(target: TARGET, "info line");
            let before = buffer.take();
            assert!(!before.contains("unique=7"), "{before}");
            assert!(before.contains("info line"), "{before}");

            logging.toggle_trace();
            assert!(tracing::enabled!(target: TARGET, tracing::Level::TRACE));
            emit();
            let during = buffer.take();
            assert!(during.contains("unique=7"), "{during}");

            logging.toggle_trace();
            emit();
            let after = buffer.take();
            assert!(!after.contains("unique=7"), "{after}");
            assert!(!tracing::enabled!(target: TARGET, tracing::Level::TRACE));
        });
    }

    #[test]
    fn an_empty_base_still_turns_tracing_on() {
        let buffer = Buffer::default();
        let (subscriber, mut logging) = build(
            String::new(),
            "jackalopefs_perf_test=trace",
            buffer.clone(),
            false,
        );
        tracing::subscriber::with_default(subscriber, || {
            logging.toggle_trace();
            tracing::trace!(target: TARGET, unique = 8, "request");
            assert!(buffer.take().contains("unique=8"));
        });
    }
}

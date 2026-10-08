//! The log subscriber both binaries install.

use std::io::IsTerminal;
use tracing_subscriber::EnvFilter;

/// Install the process's subscriber, logging to stdout at `RUST_LOG`, or `info` when it is unset or does not parse; one that does not parse is reported.
pub fn init() {
    let (base, invalid) = base_of(std::env::var("RUST_LOG"));
    tracing_subscriber::fmt()
        .with_ansi(std::io::stdout().is_terminal())
        .with_env_filter(EnvFilter::try_new(&base).expect("the base filter was parsed before"))
        .init();
    if let Some((given, e)) = invalid {
        tracing::warn!("RUST_LOG={given:?} does not parse ({e}); logging at info");
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
}

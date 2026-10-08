//! The log subscriber both binaries install.

use std::io::IsTerminal;
use tracing_subscriber::EnvFilter;

/// Install the process's subscriber, logging to stdout at `RUST_LOG`, or `info` when it is unset or does not parse.
pub fn init() {
    tracing_subscriber::fmt()
        .with_ansi(std::io::stdout().is_terminal())
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

//! jackalopefs client: a reconnecting QUIC session to one server, a typed request API with a deadline on every call, and (in [`mount`]) the FUSE backend that presents it as a filesystem.

pub mod transport;

pub use transport::ServerTrust;

use std::time::Duration;

/// A connection with no traffic for this long is dead. Negotiated as the minimum of both peers, so the server sets the same value.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Ping cadence that keeps an idle connection alive and detects a vanished server within [`IDLE_TIMEOUT`].
pub const KEEP_ALIVE: Duration = Duration::from_secs(3);

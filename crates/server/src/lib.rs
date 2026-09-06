//! jackalopefs server: exports one directory over QUIC to unprivileged clients.
//!
//! Every client path is resolved by `openat2` confined to the export root ([`export`]); filesystem work runs on the blocking pool ([`ops`]); each QUIC bidi stream carries exactly one request ([`session`]).

pub mod export;

use std::sync::Arc;
use std::time::Duration;

/// A connection with no traffic for this long is dead; the client keeps it alive with pings well inside this.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a detached session keeps its open handles for a reconnecting client.
pub const SESSION_GRACE: Duration = Duration::from_secs(60);

/// Per-stream receive window; must exceed [`jackalopefs_proto::MAX_FRAME`] so a maximal frame never stalls on flow control.
const STREAM_RECEIVE_WINDOW: u32 = 2 * 1024 * 1024;

/// Whole-connection receive/send windows; quinn's default receive window is unbounded, which an anonymous peer could turn into memory exhaustion.
const CONNECTION_WINDOW: u32 = 64 * 1024 * 1024;

/// Request streams a client may have open at once.
const MAX_REQUEST_STREAMS: u32 = 1024;

/// Simultaneous client connections; beyond this new connections are refused.
pub const MAX_CONNECTIONS: usize = 64;

/// QUIC transport parameters for the server side of a jackalopefs connection.
pub fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            IDLE_TIMEOUT.try_into().expect("idle timeout fits a VarInt"),
        ))
        .keep_alive_interval(None)
        .stream_receive_window(STREAM_RECEIVE_WINDOW.into())
        .receive_window(CONNECTION_WINDOW.into())
        .send_window(CONNECTION_WINDOW as u64)
        .max_concurrent_bidi_streams(MAX_REQUEST_STREAMS.into())
        .max_concurrent_uni_streams(8u32.into());
    Arc::new(transport)
}

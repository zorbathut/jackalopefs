//! What the client's and the server's performance reports share: the number formatting and the QUIC statistics line. Each side logs the lines under its own target, so the functions here return text rather than logging it.

use std::time::Duration;

pub fn fmt_duration(d: Duration) -> String {
    let us = d.as_micros();
    if us < 1_000 {
        format!("{us}us")
    } else if us < 1_000_000 {
        format!("{:.2}ms", us as f64 / 1_000.0)
    } else {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    }
}

pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n}B")
    } else {
        format!("{value:.1}{}", UNITS[unit])
    }
}

/// A connection's QUIC statistics: round-trip time, congestion window and MTU as they stand, and losses, congestion events and bytes each way since it was made. `head` names the connection the way each side does (the generation on the client, the session and remote address on the server).
pub fn line_quic(head: &str, stats: &quinn::ConnectionStats) -> String {
    format!(
        "perf quic {head} rtt={} cwnd={} mtu={} since connect: lost_packets={} congestion_events={} tx={}/{} datagrams rx={}/{} datagrams",
        fmt_duration(stats.path.rtt),
        fmt_bytes(stats.path.cwnd),
        stats.path.current_mtu,
        stats.path.lost_packets,
        stats.path.congestion_events,
        fmt_bytes(stats.udp_tx.bytes),
        stats.udp_tx.datagrams,
        fmt_bytes(stats.udp_rx.bytes),
        stats.udp_rx.datagrams,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting_helpers() {
        assert_eq!(fmt_duration(Duration::from_micros(999)), "999us");
        assert_eq!(fmt_duration(Duration::from_millis(1)), "1.00ms");
        assert_eq!(fmt_duration(Duration::from_millis(1500)), "1.50s");
        assert_eq!(fmt_bytes(512), "512B");
        assert_eq!(fmt_bytes(1536), "1.5KiB");
        assert_eq!(fmt_bytes(200 * 1024 * 1024), "200.0MiB");
        assert_eq!(fmt_bytes(3 * 1024 * 1024 * 1024), "3.0GiB");
    }
}

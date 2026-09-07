use anyhow::Context;
use clap::Parser;
use jackalopefs_client::mount::{Mount, MountOptions};
use jackalopefs_client::{Client, Config, ServerTrust};
use jackalopefs_proto::Auth;
use jackalopefs_proto::DEFAULT_PORT;
use std::io::IsTerminal;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

/// Mount a jackalopefs export.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Server: `host`, `host:port`, or an IP address; the port defaults to 1933. An IPv6 address with a port goes in brackets, `[::1]:1933`.
    server: String,
    /// Empty directory to mount on.
    mountpoint: PathBuf,
    /// Expected server certificate fingerprint, `sha256:...`, as printed by the server at startup.
    #[arg(long, conflicts_with = "insecure")]
    fingerprint: Option<String>,
    /// Accept any server certificate. Encrypted, but you have no idea who you're talking to.
    #[arg(long)]
    insecure: bool,
    /// Token the server requires.
    #[arg(long)]
    token: Option<String>,
    /// Longest a single filesystem operation may take before it fails with ETIMEDOUT.
    #[arg(long, default_value = "30s", value_parser = humantime::parse_duration)]
    op_timeout: Duration,
    /// Longest one connection attempt may take. Each address the server name resolves to gets its own attempt.
    #[arg(long, default_value = "10s", value_parser = humantime::parse_duration)]
    connect_timeout: Duration,
    /// How long the kernel may trust a cached directory entry.
    #[arg(long, default_value = "1s", value_parser = humantime::parse_duration)]
    entry_timeout: Duration,
    /// How long the kernel may trust cached file attributes.
    #[arg(long, default_value = "1s", value_parser = humantime::parse_duration)]
    attr_timeout: Duration,
    /// Let other local users use the mount (they all act as the server user).
    #[arg(long)]
    allow_other: bool,
    /// Unmount automatically if this process dies; requires --allow-other.
    #[arg(long, requires = "allow_other")]
    auto_unmount: bool,
    /// Have the kernel enforce mode bits against the attributes the server reports. Without it every request is forwarded and only the server's own access rights apply, so a mount shared through --allow-other enforces nothing.
    #[arg(long)]
    default_permissions: bool,
    /// Log a per-operation performance summary this often (e.g. `5s`); SIGUSR1 logs one at any time.
    #[arg(long, value_parser = humantime::parse_duration)]
    perf_interval: Option<Duration>,
}

/// The signals the client answers, subscribed before anything that takes time so none is missed (and so SIGUSR1, whose default disposition is to terminate, cannot kill a client that is still connecting).
struct Signals {
    term: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
    usr1: tokio::signal::unix::Signal,
}

impl Signals {
    fn subscribe() -> anyhow::Result<Signals> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Signals {
            term: signal(SignalKind::terminate()).context("listening for SIGTERM")?,
            int: signal(SignalKind::interrupt()).context("listening for SIGINT")?,
            usr1: signal(SignalKind::user_defined1()).context("listening for SIGUSR1")?,
        })
    }
}

/// Waits for the next signal; a stream that ends (which tokio documents as not happening in practice) waits forever rather than spinning.
async fn next_signal(signal: &mut tokio::signal::unix::Signal) {
    if signal.recv().await.is_none() {
        tracing::warn!("signal stream ended; no longer listening for it");
        std::future::pending::<()>().await;
    }
}

/// Waits for the next report tick, or forever when no interval was asked for.
async fn next_tick(interval: &mut Option<tokio::time::Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(std::io::stdout().is_terminal())
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    if args.allow_other && !args.default_permissions {
        tracing::warn!("--allow-other without --default-permissions: every local user gets the server user's access to the export");
    }
    let trust = match (&args.fingerprint, args.insecure) {
        (Some(fp), _) => ServerTrust::Fingerprint(
            jackalopefs_proto::parse_fingerprint(fp).context("--fingerprint")?,
        ),
        (None, true) => ServerTrust::Insecure,
        (None, false) => anyhow::bail!(
            "pass --fingerprint sha256:... (the server prints it at startup) or --insecure"
        ),
    };
    let runtime = tokio::runtime::Runtime::new().context("tokio runtime")?;
    runtime.block_on(async move {
        let mut signals = Signals::subscribe()?;
        let (host, port) = server_target(&args.server)?;
        let server_addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .with_context(|| format!("resolving {host} port {port}"))?
            .collect();
        anyhow::ensure!(!server_addrs.is_empty(), "{host} resolves to nothing");
        tracing::info!(
            "{} resolves to {}",
            args.server,
            server_addrs
                .iter()
                .map(|addr| addr.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        let server_name = host;
        let config = Config {
            server_addrs,
            server_name,
            trust,
            auth: args
                .token
                .map(|t| Auth::Token(t.into_bytes()))
                .unwrap_or(Auth::Anonymous),
            connect_timeout: args.connect_timeout,
            op_timeout: args.op_timeout,
        };
        tracing::info!(
            "protocol revision {:016x}",
            jackalopefs_proto::PROTO_REVISION
        );
        let client = Client::connect(config)
            .await
            .with_context(|| format!("connecting to {}", args.server))?;
        let mount = Mount::start(
            client,
            &args.mountpoint,
            MountOptions {
                entry_ttl: args.entry_timeout,
                attr_ttl: args.attr_timeout,
                allow_other: args.allow_other,
                auto_unmount: args.auto_unmount,
                default_permissions: args.default_permissions,
            },
        )
        .await?;
        tracing::info!("mounted {} at {}", args.server, args.mountpoint.display());
        // The first tick of an interval is immediate; the first report is due one period from now. A tick delayed by a stalled process is taken late rather than as a burst of near-empty windows.
        let mut ticks = args.perf_interval.map(|every| {
            let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticks
        });
        loop {
            tokio::select! {
                _ = next_signal(&mut signals.term) => break,
                _ = next_signal(&mut signals.int) => break,
                _ = next_signal(&mut signals.usr1) => mount.report(),
                _ = next_tick(&mut ticks) => mount.report(),
            }
        }
        tracing::info!("unmounting");
        mount.unmount().await
    })
}

/// The server as typed: `host`, `host:port`, an IPv4 or IPv6 address, or `[v6]:port`; a missing port is [`DEFAULT_PORT`]. A bare IPv6 address is taken whole, so one with a port needs the brackets.
fn server_target(input: &str) -> anyhow::Result<(String, u16)> {
    let usage = || {
        anyhow::anyhow!(
            "server must be `host`, `host:port`, or an IP address, with an IPv6 address and port in brackets (`[::1]:{DEFAULT_PORT}`); got `{input}`"
        )
    };
    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok((ip.to_string(), DEFAULT_PORT));
    }
    let (host, port) = match input.strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((host, "")) => (host, None),
            Some((host, port)) => (host, Some(port.strip_prefix(':').ok_or_else(usage)?)),
            None => return Err(usage()),
        },
        None => match input.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (input, None),
        },
    };
    if host.is_empty() {
        return Err(usage());
    }
    let port = match port {
        Some(port) => port.parse::<u16>().map_err(|_| usage())?,
        None => DEFAULT_PORT,
    };
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_target_shapes() {
        let ok = |s: &str| server_target(s).unwrap();
        assert_eq!(ok("nas"), ("nas".into(), DEFAULT_PORT));
        assert_eq!(ok("nas:5"), ("nas".into(), 5));
        assert_eq!(ok("10.0.0.2"), ("10.0.0.2".into(), DEFAULT_PORT));
        assert_eq!(ok("10.0.0.2:5"), ("10.0.0.2".into(), 5));
        assert_eq!(ok("::1"), ("::1".into(), DEFAULT_PORT));
        assert_eq!(ok("[::1]"), ("::1".into(), DEFAULT_PORT));
        assert_eq!(
            ok("[2001:db8::1234]"),
            ("2001:db8::1234".into(), DEFAULT_PORT)
        );
        assert_eq!(ok("[::1]:5"), ("::1".into(), 5));
        // A bare IPv6 address is taken whole; a port needs the brackets.
        assert_eq!(ok("::1:5"), ("::1:5".into(), DEFAULT_PORT));
        for bad in ["", ":5", "nas:", "nas:x", "nas:70000", "[::1", "[::1]5"] {
            assert!(server_target(bad).is_err(), "{bad}");
        }
    }
}

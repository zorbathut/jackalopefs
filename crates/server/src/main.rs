use anyhow::Context;
use clap::Parser;
use jackalopefs_server::export::Export;
use jackalopefs_server::session::{self, Server};
use jackalopefs_server::tls::{self, Identity};
use jackalopefs_server::watch::{self, ChangeLog, EventBatch};
use jackalopefs_server::{transport_config, MAX_CONNECTIONS};
use nix::sys::resource::{getrlimit, setrlimit, Resource, RLIM_INFINITY};
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing_subscriber::EnvFilter;

/// Export a directory over QUIC for jackalopefs clients.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Directory to export.
    #[arg(long)]
    export: PathBuf,
    /// Address to listen on. Anything but loopback lets every host that can reach it read and write the export as this user unless --token is set.
    #[arg(long, default_value_t = SocketAddr::from(([127, 0, 0, 1], jackalopefs_proto::DEFAULT_PORT)))]
    listen: SocketAddr,
    /// Where the certificate and key live (default: $XDG_STATE_HOME/jackalopefs or ~/.local/state/jackalopefs).
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Require clients to present this token.
    #[arg(long)]
    token: Option<String>,
    /// Log a per-operation performance summary this often (e.g. `5s`); SIGUSR1 logs one at any time.
    #[arg(long, value_parser = humantime::parse_duration)]
    perf_interval: Option<Duration>,
}

/// The signals the server answers, subscribed before it starts serving so none is missed (and so SIGUSR1, whose default disposition is to terminate, never kills it).
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

/// Raise the soft open-file limit to the hard one: every file a client holds open is a descriptor here, and the default soft limit of 1024 is a few hundred open files away from failing every request that opens anything.
fn raise_open_file_limit() -> anyhow::Result<()> {
    let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).context("reading the open file limit")?;
    if soft >= hard {
        tracing::info!("open file limit {}", limit_text(soft));
        return Ok(());
    }
    match setrlimit(Resource::RLIMIT_NOFILE, hard, hard) {
        Ok(()) => tracing::info!("open file limit {} (raised from {soft})", limit_text(hard)),
        Err(e) => tracing::warn!(
            "open file limit {soft}; raising it to {} failed: {e}",
            limit_text(hard)
        ),
    }
    Ok(())
}

fn limit_text(limit: u64) -> String {
    if limit == RLIM_INFINITY {
        "unlimited".to_string()
    } else {
        limit.to_string()
    }
}

fn default_state_dir() -> anyhow::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(dir).join("jackalopefs"));
    }
    let home = std::env::var_os("HOME")
        .context("neither XDG_STATE_HOME nor HOME is set; pass --state-dir")?;
    Ok(PathBuf::from(home).join(".local/state/jackalopefs"))
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(std::io::stdout().is_terminal())
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    // The client kernel already applied the caller's umask to every mode it sends; applying ours too would mask modes twice.
    nix::sys::stat::umask(nix::sys::stat::Mode::empty());

    raise_open_file_limit()?;

    let state_dir = match args.state_dir {
        Some(dir) => dir,
        None => default_state_dir()?,
    };
    let identity = Identity::load_or_generate(&state_dir)?;
    tracing::info!("certificate fingerprint: {}", identity.fingerprint());
    let export = Arc::new(Export::open(&args.export)?);

    let runtime = tokio::runtime::Runtime::new().context("tokio runtime")?;
    runtime.block_on(async move {
        let mut signals = Signals::subscribe()?;
        let server_config = tls::server_config(identity, transport_config())?;
        let endpoint = quinn::Endpoint::server(server_config, args.listen)
            .with_context(|| format!("binding {}", args.listen))?;
        tracing::info!(
            "exporting {} on {} (protocol revision {:016x})",
            args.export.display(),
            endpoint.local_addr()?,
            jackalopefs_proto::PROTO_REVISION
        );
        let (events, _) = broadcast::channel::<Arc<EventBatch>>(256);
        let changes = Arc::new(ChangeLog::default());
        let _watcher = watch::spawn(&args.export, changes.clone(), events.clone());
        let server = Arc::new(Server::new(
            export,
            args.token,
            events,
            changes,
            MAX_CONNECTIONS,
        ));

        let closer = {
            let endpoint = endpoint.clone();
            let server = server.clone();
            // The first tick of an interval is immediate; the first report is due one period from now. A tick delayed by a stalled process is taken late rather than as a burst of near-empty windows.
            let mut ticks = args.perf_interval.map(|every| {
                let mut ticks =
                    tokio::time::interval_at(tokio::time::Instant::now() + every, every);
                ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticks
            });
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = next_signal(&mut signals.term) => break,
                        _ = next_signal(&mut signals.int) => break,
                        _ = next_signal(&mut signals.usr1) => server.report(),
                        _ = next_tick(&mut ticks) => server.report(),
                    }
                }
                tracing::info!("shutting down");
                endpoint.close(session::close_code::SHUTDOWN.into(), b"server shutdown");
            })
        };
        session::serve(endpoint.clone(), server.clone()).await;
        closer.abort();
        endpoint.wait_idle().await;
        server.report();
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listens_on_the_default_port() {
        let args = Args::parse_from(["jackalopefs-server", "--export", "/x"]);
        assert_eq!(
            args.listen,
            SocketAddr::from(([127, 0, 0, 1], jackalopefs_proto::DEFAULT_PORT))
        );
    }
}

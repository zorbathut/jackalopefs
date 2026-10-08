use anyhow::Context;
use clap::{Parser, ValueEnum};
use jackalopefs_perf::stall::{Watchdog, WATCH_PERIOD};
use jackalopefs_server::export::Export;
use jackalopefs_server::ids::{IdMap, ModeIds};
use jackalopefs_server::session::{self, Server};
use jackalopefs_server::tls::{self, Identity};
use jackalopefs_server::watch::{self, ChangeLog, EventBatch};
use jackalopefs_server::watchdog::WatchServer;
use jackalopefs_server::{handles, transport_config, Limits, MAX_CONNECTIONS};
use nix::sys::resource::{getrlimit, setrlimit, Resource, RLIM_INFINITY};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

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
    /// Which file owners clients see and may set. `flatten`: only this process's own uid and gid, every other owner shown as nobody and refused in chown and POSIX ACLs (every other `system.*` attribute, other ACL formats among them, is refused). `direct`: every owner as the filesystem has it, and any id a client asks for, as far as this process's privileges allow.
    #[arg(long, value_enum, default_value_t = ModeIds::Flatten)]
    ids: ModeIds,
    /// Log a per-operation performance summary this often (e.g. `5s`); SIGUSR1 logs one at any time.
    #[arg(long, value_parser = humantime::parse_duration)]
    perf_interval: Option<Duration>,
    /// Most directories to watch for changes at once, besides the export root; the least recently used are dropped as others are needed, and clients told to drop what they cached under them. Default: half of fs.inotify.max_user_watches, at most 65536.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    watch_limit: Option<u64>,
}

/// The signals the server answers, subscribed before it starts serving so none is missed (and so SIGUSR1 and SIGUSR2, whose default disposition is to terminate, never kill it).
struct Signals {
    term: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
    usr1: tokio::signal::unix::Signal,
    usr2: tokio::signal::unix::Signal,
}

impl Signals {
    fn subscribe() -> anyhow::Result<Signals> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Signals {
            term: signal(SignalKind::terminate()).context("listening for SIGTERM")?,
            int: signal(SignalKind::interrupt()).context("listening for SIGINT")?,
            usr1: signal(SignalKind::user_defined1()).context("listening for SIGUSR1")?,
            usr2: signal(SignalKind::user_defined2()).context("listening for SIGUSR2")?,
        })
    }
}

/// `SIGUSR2` once toggled trace logging. It stays subscribed, since its default action would end the process, and says where that went.
fn usr2_unused() {
    tracing::info!("SIGUSR2 does nothing; jackalopefs-ctl shows events and requests live");
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

/// Raise the soft open-file limit to the hard one, and return the soft and hard limits in force: every file a client holds open is a descriptor here, and the default soft limit of 1024 is a few hundred open files away from failing every request that opens anything.
fn raise_open_file_limit() -> anyhow::Result<(u64, u64)> {
    let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).context("reading the open file limit")?;
    if soft >= hard {
        tracing::info!("open file limit {}", limit_text(soft));
        return Ok((soft, hard));
    }
    match setrlimit(Resource::RLIMIT_NOFILE, hard, hard) {
        Ok(()) => {
            tracing::info!("open file limit {} (raised from {soft})", limit_text(hard));
            Ok((hard, hard))
        }
        Err(e) => {
            tracing::warn!(
                "open file limit {soft}; raising it to {} failed: {e}",
                limit_text(hard)
            );
            Ok((soft, hard))
        }
    }
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
    jackalopefs_perf::logging::init();
    let args = Args::parse();

    // The client kernel already applied the caller's umask to every mode it sends; applying ours too would mask modes twice.
    nix::sys::stat::umask(nix::sys::stat::Mode::empty());

    let (open_files, hard) = raise_open_file_limit()?;
    let limits = Limits {
        connections: MAX_CONNECTIONS,
        handles_per_session: handles::per_session(open_files),
    };
    if limits.handles_per_session == 0 {
        if open_files < hard {
            anyhow::bail!("open file limit {open_files} leaves no room for client handles; raise it with ulimit -n, up to the hard limit of {}", limit_text(hard));
        }
        anyhow::bail!("open file limit {open_files} leaves no room for client handles; raise the hard limit (LimitNOFILE= under systemd, ulimit -Hn as root)");
    }
    tracing::info!(
        "up to {} open handles per session",
        limits.handles_per_session
    );

    let ids = IdMap::of_process(args.ids).map_err(anyhow::Error::msg)?;
    tracing::info!(
        "owners: --ids {} as uid {} gid {}",
        args.ids
            .to_possible_value()
            .expect("every mode has a name")
            .get_name(),
        ids.uid,
        ids.gid
    );

    let state_dir = match args.state_dir {
        Some(dir) => dir,
        None => default_state_dir()?,
    };
    let identity = Identity::load_or_generate(&state_dir)?;
    tracing::info!("certificate fingerprint: {}", identity.fingerprint());
    let export = Arc::new(Export::open(&args.export)?);
    match export.handles_are_stable() {
        Ok(true) => {}
        Ok(false) => tracing::warn!("{} is on FUSE or overlayfs, whose file handles do not last as long as its files (a remount, a copy-up): clients will take such a file for a new one", args.export.display()),
        Err(e) => tracing::warn!("cannot tell what filesystem {} is on: {e}", args.export.display()),
    }

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
        let budget = args
            .watch_limit
            .map_or_else(watch::default_budget, |limit| {
                usize::try_from(limit).unwrap_or(usize::MAX)
            });
        let (watches, _watcher) = watch::spawn(
            export.clone(),
            &args.export,
            budget,
            changes.clone(),
            events.clone(),
        );
        let server = Arc::new(Server::new(
            export, args.token, events, changes, watches, limits, ids,
        ));
        let mut watch = WatchServer::new(server.perf.clone(), tokio::runtime::Handle::current());
        let watchdog = Watchdog::spawn("jfs-watchdog", WATCH_PERIOD, move || watch.tick())
            .context("starting the stall watchdog")?;

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
                        _ = next_signal(&mut signals.usr2) => usr2_unused(),
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
        tokio::task::spawn_blocking(move || watchdog.stop())
            .await
            .context("watchdog shutdown")?;
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

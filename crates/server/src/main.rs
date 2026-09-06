use anyhow::Context;
use clap::Parser;
use jackalopefs_server::export::Export;
use jackalopefs_server::session::{self, Server};
use jackalopefs_server::tls::{self, Identity};
use jackalopefs_server::watch::{self, ChangeLog, EventBatch};
use jackalopefs_server::{transport_config, MAX_CONNECTIONS};
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
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

    let state_dir = match args.state_dir {
        Some(dir) => dir,
        None => default_state_dir()?,
    };
    let identity = Identity::load_or_generate(&state_dir)?;
    tracing::info!("certificate fingerprint: {}", identity.fingerprint());
    let export = Arc::new(Export::open(&args.export)?);

    let runtime = tokio::runtime::Runtime::new().context("tokio runtime")?;
    runtime.block_on(async move {
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
            tokio::spawn(async move {
                wait_for_shutdown_signal().await;
                tracing::info!("shutting down");
                endpoint.close(session::close_code::SHUTDOWN.into(), b"server shutdown");
            })
        };
        session::serve(endpoint.clone(), server).await;
        closer.abort();
        endpoint.wait_idle().await;
        Ok(())
    })
}

async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(term) => term,
        Err(e) => {
            tracing::error!("cannot listen for SIGTERM: {e}");
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::error!("cannot listen for SIGINT: {e}");
                std::future::pending::<()>().await;
            }
            return;
        }
    };
    tokio::select! {
        result = tokio::signal::ctrl_c() => if let Err(e) = result { tracing::error!("cannot listen for SIGINT: {e}"); std::future::pending::<()>().await },
        _ = term.recv() => {},
    }
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

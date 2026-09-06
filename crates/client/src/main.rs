use anyhow::Context;
use clap::Parser;
use jackalopefs_client::mount::{Mount, MountOptions};
use jackalopefs_client::{Client, Config, ServerTrust};
use jackalopefs_proto::Auth;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

/// Mount a jackalopefs export.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Server address, `host:port`.
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
    /// Longest one connection attempt may take.
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
        let server_addr = tokio::net::lookup_host(&args.server)
            .await
            .with_context(|| format!("resolving {}", args.server))?
            .next()
            .with_context(|| format!("{} resolves to nothing", args.server))?;
        let server_name = args
            .server
            .rsplit_once(':')
            .map(|(host, _)| host.trim_matches(|c| c == '[' || c == ']').to_string())
            .unwrap_or_else(|| "jackalopefs".to_string());
        let config = Config {
            server_addr,
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
        let client = Client::connect(config).await.context("connecting")?;
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
        wait_for_shutdown_signal().await;
        tracing::info!("unmounting");
        mount.unmount().await
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

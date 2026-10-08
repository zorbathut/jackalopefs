use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use jackalopefs_ctl::{fmt_record, rates, render_top, selection, targets, Target};
use jackalopefs_proto::control::{
    Ask, ControlReply, ControlRequest, Counters, Happened, Selection,
};
use jackalopefs_proto::{read_frame, write_frame, CONTROL_REVISION};
use std::io::IsTerminal;
use std::os::linux::net::SocketAddrExt;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use tokio::signal::unix::{signal, Signal, SignalKind};

/// Longest to wait for a process to answer: it may be the stuck thing being looked at.
const PATIENCE: Duration = Duration::from_secs(5);

/// A running jackalopefs client's or server's counters, events and requests, live, through its control socket.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// The jackalopefs processes of this user that can be reached (of every user, for root).
    List,
    /// One process's counters, redrawn every interval: each operation's rate, bandwidth, mean latency and errors, and each event's rate.
    Top {
        /// The process; needed when there is more than one.
        #[arg(long)]
        pid: Option<u32>,
        /// How long between readings.
        #[arg(short = 'd', long, default_value = "1s", value_parser = humantime::parse_duration)]
        delay: Duration,
        /// Stop after this many screens.
        #[arg(short = 'n', long)]
        count: Option<u32>,
    },
    /// One process's events and requests as they happen. A SELECTOR is an event's name, `events` (all of them), `op:NAME` (every request of that operation) or `ops` (every request).
    Trace {
        /// The process; needed when there is more than one.
        #[arg(long)]
        pid: Option<u32>,
        /// Stop after this many records.
        #[arg(long)]
        limit: Option<u64>,
        selectors: Vec<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let ran = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?
        .block_on(run(args.command));
    // Output piped into something that stopped reading (`| head`) is the reader's choice to stop, not a failure.
    match ran {
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe) =>
        {
            Ok(())
        }
        ran => ran,
    }
}

/// Write one line to stdout; unlike `println!`, a reader that went away is an error to stop on rather than a panic.
fn say(line: &str) -> std::io::Result<()> {
    use std::io::Write;
    writeln!(std::io::stdout().lock(), "{line}")
}

async fn run(command: Command) -> anyhow::Result<()> {
    match command {
        Command::List => list().await,
        Command::Top { pid, delay, count } => top(pick(pid)?, delay, count).await,
        Command::Trace {
            pid,
            limit,
            selectors,
        } => {
            let selection = selection(&selectors).map_err(anyhow::Error::msg)?;
            trace(pick(pid)?, selection, limit).await
        }
    }
}

/// The processes serving a control socket that this user may use: its own, or every user's for root.
fn found() -> anyhow::Result<Vec<Target>> {
    let table = std::fs::read_to_string("/proc/net/unix").context("reading /proc/net/unix")?;
    let uid = nix::unistd::getuid().as_raw();
    Ok(targets(&table, (uid != 0).then_some(uid)))
}

/// The process to talk to: the one named, or the only one there is.
fn pick(pid: Option<u32>) -> anyhow::Result<Target> {
    let found = found()?;
    match pid {
        Some(pid) => found
            .into_iter()
            .find(|t| t.pid == pid)
            .with_context(|| format!("no jackalopefs process {pid} has a control socket")),
        None => match found.as_slice() {
            [] => bail!("no jackalopefs process has a control socket"),
            [only] => Ok(only.clone()),
            many => bail!(
                "more than one jackalopefs process; pick one with --pid: {}",
                many.iter()
                    .map(|t| format!("{} {}", t.side, t.pid))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        },
    }
}

/// Connect to `target`'s socket and check who answered: an abstract name is anyone's to take, so the listener must be the process the name says, running as this user or as root.
async fn connect(target: &Target) -> anyhow::Result<UnixStream> {
    let address = std::os::unix::net::SocketAddr::from_abstract_name(target.name.as_bytes())?;
    let stream = std::os::unix::net::UnixStream::connect_addr(&address)
        .with_context(|| format!("connecting to {} {}", target.side, target.pid))?;
    stream.set_nonblocking(true)?;
    let stream = UnixStream::from_std(stream)?;
    let peer = stream.peer_cred().context("asking who answered")?;
    let ours = nix::unistd::getuid().as_raw();
    if peer.uid() != ours && peer.uid() != 0 && ours != 0 {
        bail!(
            "{} answers as user {}, not this user: not a jackalopefs process of yours",
            target.name,
            peer.uid()
        );
    }
    if peer.pid() != Some(target.pid as i32) {
        bail!(
            "{} answers from process {:?}, not {}",
            target.name,
            peer.pid(),
            target.pid
        );
    }
    Ok(stream)
}

async fn send(stream: &mut UnixStream, ask: Ask) -> anyhow::Result<()> {
    let request = ControlRequest {
        revision: CONTROL_REVISION,
        ask,
    };
    write_frame(stream, &request).await.context("sending")?;
    Ok(())
}

async fn reply(stream: &mut UnixStream) -> anyhow::Result<ControlReply> {
    match read_frame(stream).await.context("reading the reply")? {
        ControlReply::Refused(why) => bail!("refused: {why}"),
        reply => Ok(reply),
    }
}

async fn counters(stream: &mut UnixStream) -> anyhow::Result<Counters> {
    let asked = async {
        send(stream, Ask::Counters).await?;
        match reply(stream).await? {
            ControlReply::Counters(counters) => Ok(counters),
            other => bail!("expected counters, got {other:?}"),
        }
    };
    tokio::time::timeout(PATIENCE, asked)
        .await
        .context("no answer within 5s")?
}

/// Ctrl-C, listened for once, so one pressed while output is being written is not missed.
fn interrupts() -> anyhow::Result<Signal> {
    signal(SignalKind::interrupt()).context("listening for Ctrl-C")
}

async fn list() -> anyhow::Result<()> {
    for target in found()? {
        let described = match connect(&target).await {
            Ok(mut stream) => match counters(&mut stream).await {
                Ok(c) => jackalopefs_ctl::clean(&c.describe),
                Err(e) => format!("(unresponsive: {e:#})"),
            },
            Err(e) => format!("(unreachable: {e:#})"),
        };
        say(&format!("{} {} {described}", target.side, target.pid))?;
    }
    Ok(())
}

async fn top(target: Target, delay: Duration, count: Option<u32>) -> anyhow::Result<()> {
    let mut interrupt = interrupts()?;
    let mut stream = connect(&target).await?;
    let redraw = std::io::stdout().is_terminal();
    let mut before = counters(&mut stream).await?;
    let mut then = Instant::now();
    let mut shown = 0;
    while count.is_none_or(|count| shown < count) {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = interrupt.recv() => return Ok(()),
        }
        let now = counters(&mut stream).await?;
        let seconds = then.elapsed().as_secs_f64();
        then = Instant::now();
        let (events, ops) = rates(&before, &now, seconds);
        let screen = render_top(&now, &events, &ops, seconds);
        if redraw {
            say(&format!("\x1b[H\x1b[2J{}", screen.trim_end()))?;
        } else {
            say(&screen)?;
        }
        before = now;
        shown += 1;
    }
    Ok(())
}

async fn trace(target: Target, selection: Selection, limit: Option<u64>) -> anyhow::Result<()> {
    let mut interrupt = interrupts()?;
    let mut stream = connect(&target).await?;
    send(&mut stream, Ask::Subscribe(selection)).await?;
    let mut seen = 0;
    while limit.is_none_or(|limit| seen < limit) {
        let reply = tokio::select! {
            reply = reply(&mut stream) => reply?,
            _ = interrupt.recv() => return Ok(()),
        };
        let ControlReply::Record(record) = reply else {
            bail!("expected records, got {reply:?}");
        };
        say(&fmt_record(&record))?;
        if !matches!(record.what, Happened::Dropped(_)) {
            seen += 1;
        }
    }
    Ok(())
}

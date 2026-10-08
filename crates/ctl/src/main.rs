use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use jackalopefs_ctl::{
    fmt_record, fmt_record_long, frame_selection, rates, read_preamble, read_record, render_top,
    selection, targets, write_preamble, write_record, Target,
};
use jackalopefs_proto::control::{
    Ask, CensusOp, ControlReply, ControlRequest, Counters, Happened, Header, Record, Selection,
};
use jackalopefs_proto::{read_frame, write_frame, CONTROL_REVISION, PROTO_REVISION};
use std::collections::BTreeMap;
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
        /// Show the exchanges themselves, decoded, instead of request summaries: one in `--every`, of the operations named (all when none is).
        #[arg(long)]
        frames: bool,
        /// With --frames: one exchange in this many, the same ones at both ends.
        #[arg(long)]
        every: Option<u32>,
        selectors: Vec<String>,
    },
    /// Write one process's frames to a file for `dump`: one exchange in `--every` of the operations named (all when none is), with any events named, and at the end a census of what the capture holds against what the process exchanged meanwhile.
    Capture {
        /// The process; needed when there is more than one.
        #[arg(long)]
        pid: Option<u32>,
        /// The file to write; created readable by this user alone.
        #[arg(short = 'o', long)]
        output: std::path::PathBuf,
        /// One exchange in this many, the same ones at both ends.
        #[arg(long, default_value_t = 1)]
        every: u32,
        /// Stop after this many exchanges.
        #[arg(long)]
        limit: Option<u64>,
        /// Stop after this long.
        #[arg(long, value_parser = humantime::parse_duration)]
        duration: Option<Duration>,
        /// Keep the data of reads and writes; without it, their contents are cut and only their lengths kept.
        #[arg(long)]
        payloads: bool,
        selectors: Vec<String>,
    },
    /// Print a capture, each exchange's frames decoded in full.
    Dump {
        file: std::path::PathBuf,
        /// Also write each frame body to its own file here, readable by this user alone, for `capnp convert`.
        #[arg(long)]
        frames_to: Option<std::path::PathBuf>,
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
            frames,
            every,
            selectors,
        } => {
            let selection = match (frames, every) {
                (true, every) => frame_selection(&selectors, every.unwrap_or(1), false),
                (false, Some(_)) => Err("--every chooses frames; add --frames".to_owned()),
                (false, None) => selection(&selectors),
            }
            .map_err(anyhow::Error::msg)?;
            trace(pick(pid)?, selection, limit).await
        }
        Command::Capture {
            pid,
            output,
            every,
            limit,
            duration,
            payloads,
            selectors,
        } => {
            let selection =
                frame_selection(&selectors, every, payloads).map_err(anyhow::Error::msg)?;
            capture(pick(pid)?, selection, &output, limit, duration).await
        }
        Command::Dump { file, frames_to } => dump(&file, frames_to.as_deref()).await,
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

fn record_now(what: Happened) -> Record {
    Record {
        at_ns: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos() as u64),
        what,
    }
}

/// What a capture holds, counted as it goes, for a census when the process cannot give one.
#[derive(Default)]
struct Tally {
    exchanges: u64,
    sampled: BTreeMap<String, u64>,
}

impl Tally {
    fn take(&mut self, record: &Record) {
        if let Happened::Exchange(x) = &record.what {
            self.exchanges += 1;
            *self
                .sampled
                .entry(x.ids.op.clone().unwrap_or_default())
                .or_default() += 1;
        }
    }
}

/// Why a capture stopped taking records.
enum Ended {
    /// It ran its course; the process is asked for its census.
    Asked,
    /// The process went away; the census is what the capture itself counted.
    Gone(String),
}

async fn capture(
    target: Target,
    selection: Selection,
    output: &std::path::Path,
    limit: Option<u64>,
    duration: Option<Duration>,
) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut interrupt = interrupts()?;
    let mut stream = connect(&target).await?;
    let about = counters(&mut stream).await?;
    send(&mut stream, Ask::Subscribe(selection.clone())).await?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .with_context(|| format!("creating {}", output.display()))?;
    let mut file = tokio::io::BufWriter::new(tokio::fs::File::from_std(file));
    write_preamble(&mut file).await?;
    let header = Header {
        proto_revision: PROTO_REVISION,
        control_revision: CONTROL_REVISION,
        side: about.side,
        pid: about.pid,
        describe: about.describe,
        selection,
    };
    write_record(&mut file, record_now(Happened::Header(header))).await?;
    let deadline = duration.map(|d| tokio::time::Instant::now() + d);
    let mut tally = Tally::default();
    let ended = loop {
        if limit.is_some_and(|limit| tally.exchanges >= limit) {
            break Ended::Asked;
        }
        let deadline_passed = async {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };
        let record = tokio::select! {
            reply = read_frame::<_, ControlReply>(&mut stream) => match reply {
                Ok(ControlReply::Record(record)) => record,
                Ok(other) => break Ended::Gone(format!("expected records, got {other:?}")),
                Err(e) => break Ended::Gone(e.to_string()),
            },
            _ = deadline_passed => break Ended::Asked,
            _ = interrupt.recv() => break Ended::Asked,
        };
        tally.take(&record);
        write_record(&mut file, record).await?;
    };
    // What was still queued in the process, then its census; or, the process gone, a census of what came.
    let gone = match ended {
        Ended::Asked => {
            let finished = async {
                send(&mut stream, Ask::Census).await?;
                loop {
                    let ControlReply::Record(record) = reply(&mut stream).await? else {
                        bail!("expected records");
                    };
                    let census = matches!(record.what, Happened::Census { .. });
                    tally.take(&record);
                    write_record(&mut file, record).await?;
                    if census {
                        return Ok(());
                    }
                }
            };
            match tokio::time::timeout(PATIENCE, finished).await {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(format!("{e:#}")),
                Err(_) => Some("no census within 5s".to_owned()),
            }
        }
        Ended::Gone(why) => Some(why),
    };
    if let Some(why) = &gone {
        let ops = tally
            .sampled
            .iter()
            .map(|(op, n)| CensusOp {
                op: op.clone(),
                sampled: *n,
                ..CensusOp::default()
            })
            .collect();
        write_record(&mut file, record_now(Happened::Census { ops, dropped: 0 })).await?;
        eprintln!(
            "the process stopped answering ({why}); the census counts only what the capture holds"
        );
    }
    tokio::io::AsyncWriteExt::flush(&mut file).await?;
    eprintln!(
        "{} exchanges written to {}",
        tally.exchanges,
        output.display()
    );
    Ok(())
}

async fn dump(file: &std::path::Path, frames_to: Option<&std::path::Path>) -> anyhow::Result<()> {
    let mut input = tokio::io::BufReader::new(
        tokio::fs::File::open(file)
            .await
            .with_context(|| format!("opening {}", file.display()))?,
    );
    if let Some(warning) = read_preamble(&mut input)
        .await
        .map_err(|e| anyhow::anyhow!("{}: {e}", file.display()))?
    {
        eprintln!("{}: {warning}", file.display());
    }
    if let Some(dir) = frames_to {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut n = 0u64;
    while let Some(record) = read_record(&mut input)
        .await
        .map_err(|e| anyhow::anyhow!("record {n} of {}: {e}", file.display()))?
    {
        say(&fmt_record_long(&record))?;
        if let Some(dir) = frames_to {
            let bodies: Vec<(&str, &[u8])> = match &record.what {
                Happened::Exchange(x) => vec![("request", &x.request), ("reply", &x.reply)],
                Happened::EventFrame { body, .. } => vec![("event", body)],
                Happened::Undecodable { body, .. } => vec![("undecodable", body)],
                _ => Vec::new(),
            };
            for (what, body) in bodies.into_iter().filter(|(_, b)| !b.is_empty()) {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let path = dir.join(format!("{n:06}-{what}.bin"));
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .and_then(|mut f| f.write_all(body))
                    .with_context(|| format!("writing {}", path.display()))?;
            }
        }
        n += 1;
    }
    Ok(())
}

//! What the client's and the server's performance reports share: the number formatting, the QUIC statistics line with its per-window delta, meters for the host's physical ports and UDP socket drop counters, and the verdict that names a link that is full and mostly not ours. Each side logs the lines under its own target, so the functions here return text rather than logging it.

pub mod control;
pub mod events;
pub mod histogram;
pub mod hub;
pub mod logging;
pub mod stall;

use histogram::Histogram;
use jackalopefs_proto::control::{Resources, TotalOp};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// A window shorter than this yields no rates: dividing a few bytes by a few milliseconds says nothing. A rate baseline is kept until a window this long has accumulated, so frequent reports still get rates every so often.
const MIN_WINDOW: Duration = Duration::from_secs(1);

/// A port this busy is treated as full.
const UTILIZATION_FULL: f64 = 0.8;

/// This connection's share of a full port below which the rest of the traffic is what starves it.
const SHARE_OURS: f64 = 0.5;

/// A connection cannot move more than its port does, so a share beyond this (link-layer framing and window skew allowed for) means the connection is not on that port and no verdict can be given.
const SHARE_IMPOSSIBLE: f64 = 1.1;

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

/// Every operation's totals since the process started, by level (`fuse`, `call`, `request`) and operation: what `jackalopefs-ctl top` turns into rates and, from the histograms, quantiles. Unlike the report's windows these never reset, so any number of readers can each take differences of their own.
#[derive(Default)]
pub struct Totals(BTreeMap<(&'static str, &'static str), TotalsOp>);

#[derive(Default)]
struct TotalsOp {
    count: u64,
    bytes: u64,
    items: u64,
    errors: u64,
    total_ns: u64,
    latency: Histogram,
    sizes: Histogram,
}

impl Totals {
    pub fn add(
        &mut self,
        level: &'static str,
        op: &'static str,
        bytes: u64,
        items: u64,
        errno: i32,
        took: Duration,
    ) {
        let total = self.0.entry((level, op)).or_default();
        let ns = took.as_nanos() as u64;
        total.count += 1;
        total.bytes += bytes;
        total.items += items;
        total.errors += u64::from(errno != 0);
        total.total_ns += ns;
        total.latency.record(ns);
        if bytes > 0 {
            total.sizes.record(bytes);
        }
    }

    /// The requests and bytes of every operation at `level`.
    pub fn at(&self, level: &str) -> (u64, u64) {
        self.0
            .iter()
            .filter(|((l, _), _)| *l == level)
            .fold((0, 0), |(n, b), (_, t)| (n + t.count, b + t.bytes))
    }

    pub fn list(&self) -> Vec<TotalOp> {
        self.0
            .iter()
            .map(|((level, op), t)| TotalOp {
                level: (*level).to_owned(),
                op: (*op).to_owned(),
                count: t.count,
                bytes: t.bytes,
                items: t.items,
                errors: t.errors,
                total_ns: t.total_ns,
                latency: t.latency.buckets(),
                sizes: t.sizes.buckets(),
            })
            .collect()
    }
}

/// The connection's key: 8 bytes of its TLS keying material, the same on both sides and different for every connection, so a client's line and the server's line about one request can be joined on `(conn, stream)` across reconnects and server restarts.
pub fn conn_key(conn: &quinn::Connection) -> Option<u64> {
    let mut key = [0u8; 8];
    match conn.export_keying_material(&mut key, b"jackalopefs conn id", b"") {
        Ok(()) => Some(u64::from_le_bytes(key)),
        Err(e) => {
            tracing::warn!("the connection has no keying material to name it by ({e:?}); its lines carry no connection key");
            None
        }
    }
}

fn fmt_rate(bytes_per_second: f64) -> String {
    format!("{}/s", fmt_bytes(bytes_per_second as u64))
}

/// What a connection did over the window between two samples.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DeltaQuic {
    pub window: Duration,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub lost_packets: u64,
    pub sent_packets: u64,
}

impl DeltaQuic {
    pub fn rx_rate(&self) -> f64 {
        self.rx_bytes as f64 / self.window.as_secs_f64()
    }

    pub fn tx_rate(&self) -> f64 {
        self.tx_bytes as f64 / self.window.as_secs_f64()
    }
}

/// A connection's statistics as they stand, and the window since the baseline sample once that is at least [`MIN_WINDOW`] old.
#[derive(Clone, Copy, Debug)]
pub struct SampleQuic {
    pub stats: quinn::ConnectionStats,
    pub delta: Option<DeltaQuic>,
}

/// Remembers a connection's baseline sample so a later one can report the window between them.
#[derive(Default)]
pub struct TrackerQuic {
    baseline: Option<(Instant, quinn::ConnectionStats)>,
}

impl TrackerQuic {
    pub fn sample(&mut self, stats: quinn::ConnectionStats) -> SampleQuic {
        self.sample_at(Instant::now(), stats)
    }

    /// The baseline moves only when a window of at least [`MIN_WINDOW`] is reported, so reports closer together than that still get a window every so often.
    pub fn sample_at(&mut self, now: Instant, stats: quinn::ConnectionStats) -> SampleQuic {
        let delta = match self.baseline {
            Some((then, last)) if now.duration_since(then) >= MIN_WINDOW => Some(DeltaQuic {
                window: now.duration_since(then),
                rx_bytes: stats.udp_rx.bytes.saturating_sub(last.udp_rx.bytes),
                tx_bytes: stats.udp_tx.bytes.saturating_sub(last.udp_tx.bytes),
                lost_packets: stats
                    .path
                    .lost_packets
                    .saturating_sub(last.path.lost_packets),
                sent_packets: stats
                    .path
                    .sent_packets
                    .saturating_sub(last.path.sent_packets),
            }),
            _ => None,
        };
        if delta.is_some() || self.baseline.is_none() {
            self.baseline = Some((now, stats));
        }
        SampleQuic { stats, delta }
    }
}

/// A connection's QUIC statistics: round-trip time, congestion window and MTU as they stand; losses, congestion events, black holes and bytes each way since it was made; and, when there is a window, its rates and losses over that window. `head` names the connection the way each side does (the generation on the client, the session and remote address on the server).
pub fn line_quic(head: &str, sample: &SampleQuic) -> String {
    let stats = &sample.stats;
    let mut line = format!(
        "perf quic {head} rtt={} cwnd={} mtu={} since connect: lost_packets={} congestion_events={} black_holes={} tx={}/{} datagrams rx={}/{} datagrams",
        fmt_duration(stats.path.rtt),
        fmt_bytes(stats.path.cwnd),
        stats.path.current_mtu,
        stats.path.lost_packets,
        stats.path.congestion_events,
        stats.path.black_holes_detected,
        fmt_bytes(stats.udp_tx.bytes),
        stats.udp_tx.datagrams,
        fmt_bytes(stats.udp_rx.bytes),
        stats.udp_rx.datagrams,
    );
    if let Some(delta) = &sample.delta {
        line.push_str(&format!(
            " window={}: tx={} rx={} lost=+{} of +{} sent",
            fmt_duration(delta.window),
            fmt_rate(delta.tx_rate()),
            fmt_rate(delta.rx_rate()),
            delta.lost_packets,
            delta.sent_packets,
        ));
    }
    line
}

/// The counters read from a port's `statistics` directory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CountersLink {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_dropped: u64,
    rx_missed: u64,
    rx_fifo: u64,
    rx_errors: u64,
    tx_dropped: u64,
    tx_errors: u64,
}

const COUNTERS_LINK: [&str; 8] = [
    "rx_bytes",
    "tx_bytes",
    "rx_dropped",
    "rx_missed_errors",
    "rx_fifo_errors",
    "rx_errors",
    "tx_dropped",
    "tx_errors",
];

impl CountersLink {
    fn read(dir: &Path) -> Result<CountersLink, String> {
        let mut values = [0u64; 8];
        for (value, name) in values.iter_mut().zip(COUNTERS_LINK) {
            *value = read_number(&dir.join("statistics").join(name))?;
        }
        let [rx_bytes, tx_bytes, rx_dropped, rx_missed, rx_fifo, rx_errors, tx_dropped, tx_errors] =
            values;
        Ok(CountersLink {
            rx_bytes,
            tx_bytes,
            rx_dropped,
            rx_missed,
            rx_fifo,
            rx_errors,
            tx_dropped,
            tx_errors,
        })
    }
}

fn read_number(path: &Path) -> Result<u64, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    text.trim()
        .parse()
        .map_err(|e| format!("{}: unreadable value {text:?}: {e}", path.display()))
}

/// A port's speed in Mb/s. A down or virtual port answers `EINVAL` or `-1`, which is the normal way of having no speed and not worth a warning; a value that is not a number is.
fn read_speed(dir: &Path) -> Option<u64> {
    let path = dir.join("speed");
    let text = std::fs::read_to_string(&path).ok()?;
    match text.trim().parse::<i64>() {
        Ok(speed) if speed > 0 => Some(speed as u64),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!("{}: unreadable value {text:?}: {e}", path.display());
            None
        }
    }
}

/// Packets a port lost on the way in or out over the window, by where they died.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DropsLink {
    pub rx_dropped: u64,
    pub rx_missed: u64,
    pub rx_fifo: u64,
    pub rx_errors: u64,
    pub tx_dropped: u64,
    pub tx_errors: u64,
}

/// Bytes per second each way over the window.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RatesLink {
    pub window: Duration,
    pub rx: f64,
    pub tx: f64,
}

/// One physical port's load over the window since the previous sample.
#[derive(Clone, Debug, PartialEq)]
pub struct SampleLink {
    pub name: String,
    /// A wireless port's `speed` is the negotiated PHY rate, not a capacity, so it never qualifies for a verdict.
    pub wireless: bool,
    /// Megabits per second as sysfs reports it, when it reports one.
    pub speed_mbps: Option<u64>,
    /// None until a window of at least [`MIN_WINDOW`] has accumulated since the rate baseline.
    pub rates: Option<RatesLink>,
    /// Since the previous sample, whatever its length.
    pub drops: DropsLink,
}

impl SampleLink {
    /// The fraction of the port's speed in use in each direction, when both the rate and the speed are known and the port is wired.
    fn utilization(&self) -> Option<(f64, f64)> {
        if self.wireless {
            return None;
        }
        let rates = self.rates?;
        let capacity = self.speed_mbps? as f64 * 1_000_000.0 / 8.0;
        Some((rates.rx / capacity, rates.tx / capacity))
    }
}

/// What was last read from one port: the counters at the previous sample, and the byte counters at the rate baseline.
struct BaselineLink {
    drops: CountersLink,
    rates_since: Instant,
    rx_bytes: u64,
    tx_bytes: u64,
}

/// Meters the host's physical ports: the interfaces under `/sys/class/net` backed by a bus device, which leaves out bridges, bonds, VLANs, veths and loopback, whose counters and speeds describe nothing physical. The ports are enumerated on every sample, so one that appears, disappears or comes back is metered from its next sample on.
pub struct MeterLink {
    root: PathBuf,
    baselines: HashMap<String, BaselineLink>,
}

impl MeterLink {
    pub fn system() -> MeterLink {
        MeterLink::new(Path::new("/sys/class/net"))
    }

    /// Takes the baseline sample so the first report has a window.
    fn new(root: &Path) -> MeterLink {
        MeterLink::new_at(Instant::now(), root)
    }

    fn new_at(now: Instant, root: &Path) -> MeterLink {
        let mut meter = MeterLink {
            root: root.to_path_buf(),
            baselines: HashMap::new(),
        };
        meter.sample_at(now);
        meter
    }

    /// The ports under the root with a `device` entry, with their counters; one whose counters cannot be read is logged and left out of this sample.
    fn ports(&self) -> Vec<(String, PathBuf, CountersLink)> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!("{}: {e}; no port can be metered", self.root.display());
                return Vec::new();
            }
        };
        let mut ports = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    tracing::warn!("{}: {e}", self.root.display());
                    continue;
                }
            };
            let dir = entry.path();
            if !dir.join("device").exists() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            match CountersLink::read(&dir) {
                Ok(counters) => ports.push((name, dir, counters)),
                Err(e) => tracing::warn!("port {name} cannot be metered: {e}"),
            }
        }
        ports.sort_by(|a, b| a.0.cmp(&b.0));
        ports
    }

    pub fn sample(&mut self) -> Vec<SampleLink> {
        self.sample_at(Instant::now())
    }

    /// Every physical port's load: drops since the previous sample, and rates once at least [`MIN_WINDOW`] has passed since the rate baseline, which then moves to this sample.
    fn sample_at(&mut self, now: Instant) -> Vec<SampleLink> {
        let mut samples = Vec::new();
        let mut baselines = HashMap::new();
        for (name, dir, counters) in self.ports() {
            let (drops, rates, rates_baseline) = match self.baselines.remove(&name) {
                Some(before) => {
                    let drops = DropsLink {
                        rx_dropped: counters.rx_dropped.saturating_sub(before.drops.rx_dropped),
                        rx_missed: counters.rx_missed.saturating_sub(before.drops.rx_missed),
                        rx_fifo: counters.rx_fifo.saturating_sub(before.drops.rx_fifo),
                        rx_errors: counters.rx_errors.saturating_sub(before.drops.rx_errors),
                        tx_dropped: counters.tx_dropped.saturating_sub(before.drops.tx_dropped),
                        tx_errors: counters.tx_errors.saturating_sub(before.drops.tx_errors),
                    };
                    let window = now.duration_since(before.rates_since);
                    if window >= MIN_WINDOW {
                        let rates = RatesLink {
                            window,
                            rx: counters.rx_bytes.saturating_sub(before.rx_bytes) as f64
                                / window.as_secs_f64(),
                            tx: counters.tx_bytes.saturating_sub(before.tx_bytes) as f64
                                / window.as_secs_f64(),
                        };
                        (
                            drops,
                            Some(rates),
                            (now, counters.rx_bytes, counters.tx_bytes),
                        )
                    } else {
                        (
                            drops,
                            None,
                            (before.rates_since, before.rx_bytes, before.tx_bytes),
                        )
                    }
                }
                None => (
                    DropsLink::default(),
                    None,
                    (now, counters.rx_bytes, counters.tx_bytes),
                ),
            };
            baselines.insert(
                name.clone(),
                BaselineLink {
                    drops: counters,
                    rates_since: rates_baseline.0,
                    rx_bytes: rates_baseline.1,
                    tx_bytes: rates_baseline.2,
                },
            );
            samples.push(SampleLink {
                wireless: dir.join("wireless").exists() || dir.join("phy80211").exists(),
                speed_mbps: read_speed(&dir),
                name,
                rates,
                drops,
            });
        }
        // A port that has gone is forgotten; if it comes back it starts a fresh baseline.
        self.baselines = baselines;
        samples
    }
}

/// One line per port: its rates, speed and utilization when known, and what it dropped over the window; one line saying so when the host has no physical port at all.
pub fn lines_link(samples: &[SampleLink]) -> Vec<String> {
    if samples.is_empty() {
        return vec!["perf link: no physical ports".to_string()];
    }
    samples
        .iter()
        .map(|sample| {
            let mut line = format!("perf link {}", sample.name);
            match sample.rates {
                Some(rates) => line.push_str(&format!(
                    " window={} rx={} tx={}",
                    fmt_duration(rates.window),
                    fmt_rate(rates.rx),
                    fmt_rate(rates.tx)
                )),
                None => line.push_str(" (rates need a longer window)"),
            }
            match sample.speed_mbps {
                Some(speed) => line.push_str(&format!(" speed={speed}Mb/s")),
                None => line.push_str(" speed=unknown"),
            }
            if sample.wireless {
                line.push_str(" wireless");
            }
            if let Some((rx, tx)) = sample.utilization() {
                line.push_str(&format!(
                    " utilization=rx {:.0}% tx {:.0}%",
                    rx * 100.0,
                    tx * 100.0
                ));
            }
            let d = &sample.drops;
            line.push_str(&format!(
                " drops: rx_dropped=+{} rx_missed=+{} rx_fifo=+{} rx_errors=+{} tx_dropped=+{} tx_errors=+{}",
                d.rx_dropped, d.rx_missed, d.rx_fifo, d.rx_errors, d.tx_dropped, d.tx_errors
            ));
            line
        })
        .collect()
}

/// The host-wide UDP error counters from `/proc/net/snmp`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CountersUdp {
    pub in_errors: u64,
    pub rcvbuf_errors: u64,
    pub sndbuf_errors: u64,
}

/// The two `Udp:` rows of `/proc/net/snmp` are a header of names and a row of values in the same order.
fn parse_udp(snmp: &str) -> Option<CountersUdp> {
    let mut rows = snmp.lines().filter_map(|line| line.strip_prefix("Udp:"));
    let names: Vec<&str> = rows.next()?.split_whitespace().collect();
    let values: Vec<&str> = rows.next()?.split_whitespace().collect();
    let column = |name: &str| -> Option<u64> {
        let i = names.iter().position(|n| *n == name)?;
        values.get(i)?.parse().ok()
    };
    Some(CountersUdp {
        in_errors: column("InErrors")?,
        rcvbuf_errors: column("RcvbufErrors")?,
        sndbuf_errors: column("SndbufErrors")?,
    })
}

/// UDP datagrams the host dropped over the window, host-wide: a socket whose receive buffer overflows is where a receiver that cannot keep up loses packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleUdp {
    pub window: Duration,
    pub delta: CountersUdp,
}

pub struct MeterUdp {
    path: PathBuf,
    last: Option<(Instant, CountersUdp)>,
}

impl MeterUdp {
    pub fn system() -> MeterUdp {
        MeterUdp::new(Path::new("/proc/net/snmp"))
    }

    /// Takes the baseline sample so the first report has a window.
    fn new(path: &Path) -> MeterUdp {
        let mut meter = MeterUdp {
            path: path.to_path_buf(),
            last: None,
        };
        meter.sample();
        meter
    }

    fn read(&self) -> Option<CountersUdp> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => {
                let counters = parse_udp(&text);
                if counters.is_none() {
                    tracing::warn!("{}: no Udp rows to read", self.path.display());
                }
                counters
            }
            Err(e) => {
                tracing::warn!("{}: {e}", self.path.display());
                None
            }
        }
    }

    pub fn sample(&mut self) -> Option<SampleUdp> {
        self.sample_at(Instant::now())
    }

    fn sample_at(&mut self, now: Instant) -> Option<SampleUdp> {
        let counters = self.read()?;
        let sample = self.last.map(|(then, last)| SampleUdp {
            window: now.duration_since(then),
            delta: CountersUdp {
                in_errors: counters.in_errors.saturating_sub(last.in_errors),
                rcvbuf_errors: counters.rcvbuf_errors.saturating_sub(last.rcvbuf_errors),
                sndbuf_errors: counters.sndbuf_errors.saturating_sub(last.sndbuf_errors),
            },
        });
        self.last = Some((now, counters));
        sample
    }
}

pub fn line_udp(sample: &SampleUdp) -> String {
    format!(
        "perf udp window={} host-wide: rcvbuf_errors=+{} sndbuf_errors=+{} in_errors=+{}",
        fmt_duration(sample.window),
        sample.delta.rcvbuf_errors,
        sample.delta.sndbuf_errors,
        sample.delta.in_errors
    )
}

/// The process's main runtime: one worker, unless `TOKIO_WORKER_THREADS` names a number. A connection's streams all lock quinn's state for that connection to move their data, so more workers serving one connection only contend for that lock and wake each other to steal work: measured on loopback, one worker cuts each request's CPU by about a third on the server and nearly half on the client, for higher throughput, and the filesystem work still runs on the blocking pool beside it. One worker serves every connection, though; the variable is the way past one core of networking until connections get runtimes of their own (`docs/design.md`, "Known limitations").
pub fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if std::env::var_os("TOKIO_WORKER_THREADS").is_none() {
        builder.worker_threads(1);
    }
    builder.enable_all().build()
}

/// What a UDP socket asks the kernel to buffer of what arrives before the runtime reads it. One worker reads the socket only between the tasks it runs, so a burst (a client's writeback, a run of readahead replies) waits there, and the kernel's default of about 200 KiB overflows: measured on loopback with one worker, the sockets dropped about a thousand datagrams a run, packet loss and congestion events roughly doubled and the sender's window fell from about 2 MiB to 200 KiB; with 4 MiB they drop next to none.
pub const UDP_RECEIVE_BUFFER: usize = 4 << 20;

/// Ask for [`UDP_RECEIVE_BUFFER`] on `socket`, and say so when the kernel grants less: it caps the request at `net.core.rmem_max` without failing it.
pub fn udp_receive_buffer(socket: &std::net::UdpSocket) {
    let socket = socket2::SockRef::from(socket);
    if let Err(e) = socket.set_recv_buffer_size(UDP_RECEIVE_BUFFER) {
        tracing::warn!("cannot size the UDP receive buffer: {e}; bursts may be dropped");
        return;
    }
    // The kernel reports twice what it grants, the other half being its own bookkeeping.
    match socket.recv_buffer_size() {
        Ok(granted) if granted / 2 < UDP_RECEIVE_BUFFER => tracing::warn!(
            "the UDP receive buffer is {} rather than {}: net.core.rmem_max caps it, and bursts beyond it are dropped (raise it with sysctl net.core.rmem_max={UDP_RECEIVE_BUFFER})",
            fmt_bytes((granted / 2) as u64),
            fmt_bytes(UDP_RECEIVE_BUFFER as u64)
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!("cannot read back the UDP receive buffer size: {e}"),
    }
}

/// The process's resource use so far: its CPU time and context switches from `getrusage`, which counts every thread, exited ones included, and `runtime`'s workers with their busy time and parks.
pub fn resources(runtime: &tokio::runtime::Handle) -> Resources {
    let metrics = runtime.metrics();
    let workers = metrics.num_workers();
    let mut resources = Resources {
        workers: workers as u32,
        busy_ns: (0..workers)
            .map(|w| metrics.worker_total_busy_duration(w).as_nanos() as u64)
            .sum(),
        parks: (0..workers).map(|w| metrics.worker_park_count(w)).sum(),
        ..Resources::default()
    };
    match nix::sys::resource::getrusage(nix::sys::resource::UsageWho::RUSAGE_SELF) {
        Ok(usage) => {
            let ns = |t: nix::sys::time::TimeVal| {
                t.tv_sec() as u64 * 1_000_000_000 + t.tv_usec() as u64 * 1_000
            };
            resources.user_ns = ns(usage.user_time());
            resources.sys_ns = ns(usage.system_time());
            resources.voluntary_switches = usage.voluntary_context_switches() as u64;
            resources.involuntary_switches = usage.involuntary_context_switches() as u64;
        }
        Err(e) => tracing::warn!("getrusage: {e}; CPU time and context switches read as zero"),
    }
    resources
}

/// A process's resource use between two readings, against what it served meanwhile: the requests at its outermost level ([`level_outermost`]) and the bytes they moved.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RateResources {
    pub seconds: f64,
    /// CPU time per second of the interval, so 1.0 is one core kept busy.
    pub user_cores: f64,
    pub sys_cores: f64,
    pub switches_per_second: f64,
    pub workers: u32,
    /// The main runtime's workers' busy time per second: wall time spent running tasks, which counts a task blocked in a syscall or on a lock as busy, so it is not CPU and can exceed it. With one worker, how close the network thread is to saturation. Tokio publishes a worker's busy time when it parks or does its periodic maintenance, so a worker that never rests reads behind.
    pub busy_cores: f64,
    pub parks_per_second: f64,
    pub requests_per_second: f64,
    pub cpu_ns_per_request: Option<f64>,
    pub switches_per_request: Option<f64>,
    pub cpu_ns_per_mib: Option<f64>,
}

impl RateResources {
    /// The rates from `before` to `now`, `seconds` apart, while `requests` were answered and `bytes` moved; `None` for an interval that is not positive.
    pub fn between(
        before: &Resources,
        now: &Resources,
        seconds: f64,
        requests: u64,
        bytes: u64,
    ) -> Option<RateResources> {
        if seconds <= 0.0 {
            return None;
        }
        let user = now.user_ns.saturating_sub(before.user_ns) as f64;
        let sys = now.sys_ns.saturating_sub(before.sys_ns) as f64;
        let switches = (now.voluntary_switches + now.involuntary_switches)
            .saturating_sub(before.voluntary_switches + before.involuntary_switches)
            as f64;
        let per = |amount: f64, of: u64| (of > 0).then(|| amount / of as f64);
        Some(RateResources {
            seconds,
            user_cores: user / 1e9 / seconds,
            sys_cores: sys / 1e9 / seconds,
            switches_per_second: switches / seconds,
            workers: now.workers,
            busy_cores: now.busy_ns.saturating_sub(before.busy_ns) as f64 / 1e9 / seconds,
            parks_per_second: now.parks.saturating_sub(before.parks) as f64 / seconds,
            requests_per_second: requests as f64 / seconds,
            cpu_ns_per_request: per(user + sys, requests),
            switches_per_request: per(switches, requests),
            cpu_ns_per_mib: (bytes > 0)
                .then(|| (user + sys) / (bytes as f64 / (1u64 << 20) as f64)),
        })
    }
}

/// The level whose requests a process of `side` answers for someone outside it: the kernel's on a client, the clients' on a server.
pub fn level_outermost(side: &str) -> &'static str {
    match side {
        "client" => "fuse",
        _ => "request",
    }
}

/// The requests and bytes of every operation at `level`.
pub fn totals_at(ops: &[TotalOp], level: &str) -> (u64, u64) {
    ops.iter()
        .filter(|t| t.level == level)
        .fold((0, 0), |(n, b), t| (n + t.count, b + t.bytes))
}

/// The process's resource use per report window, against the requests it served and the bytes they moved.
pub struct MeterProcess {
    runtime: tokio::runtime::Handle,
    last: (Instant, Resources, u64, u64),
}

impl MeterProcess {
    /// The first window starts here, with what the process has used and served so far.
    pub fn new(runtime: tokio::runtime::Handle, requests: u64, bytes: u64) -> MeterProcess {
        let last = (Instant::now(), resources(&runtime), requests, bytes);
        MeterProcess { runtime, last }
    }

    /// The rates since the last sample, given the totals of requests served and bytes moved so far.
    pub fn sample(&mut self, requests: u64, bytes: u64) -> Option<RateResources> {
        let now = (Instant::now(), resources(&self.runtime), requests, bytes);
        let (then, before, requests_before, bytes_before) = std::mem::replace(&mut self.last, now);
        RateResources::between(
            &before,
            &now.1,
            now.0.duration_since(then).as_secs_f64(),
            requests.saturating_sub(requests_before),
            bytes.saturating_sub(bytes_before),
        )
    }
}

/// A count per second, short: `56.1k`.
pub fn fmt_count(n: f64) -> String {
    if n >= 1e6 {
        format!("{:.1}M", n / 1e6)
    } else if n >= 1e3 {
        format!("{:.1}k", n / 1e3)
    } else {
        format!("{n:.1}")
    }
}

pub fn line_process(rate: &RateResources) -> String {
    let ns = |n: Option<f64>| {
        n.map_or_else(
            || "-".to_owned(),
            |n| fmt_duration(Duration::from_nanos(n as u64)),
        )
    };
    format!(
        "perf process window={} cpu={:.2} user={:.2} sys={:.2} switches={}/s workers={} busy={:.2} parks={}/s requests={}/s per_request: cpu={} switches={} per_mib: cpu={}",
        fmt_duration(Duration::from_secs_f64(rate.seconds)),
        rate.user_cores + rate.sys_cores,
        rate.user_cores,
        rate.sys_cores,
        fmt_count(rate.switches_per_second),
        rate.workers,
        rate.busy_cores,
        fmt_count(rate.parks_per_second),
        fmt_count(rate.requests_per_second),
        ns(rate.cpu_ns_per_request),
        rate.switches_per_request.map_or_else(|| "-".to_owned(), |n| format!("{n:.1}")),
        ns(rate.cpu_ns_per_mib),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Rx,
    Tx,
}

impl Direction {
    fn name(self) -> &'static str {
        match self {
            Direction::Rx => "rx",
            Direction::Tx => "tx",
        }
    }
}

/// Whether the traffic filling a port is this connection's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filling {
    /// This connection is a minority of what fills the port: starved by the rest.
    Others,
    /// This connection is most of what fills the port.
    Ours,
}

/// What the busiest wired port says about this connection.
#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    pub port: String,
    pub direction: Direction,
    pub utilization: f64,
    pub share: f64,
    pub filling: Filling,
}

impl Verdict {
    pub fn describe(&self) -> String {
        let tail = match self.filling {
            Filling::Others => "bandwidth-starved by other traffic on the link",
            Filling::Ours => "the link is full with this connection's own traffic",
        };
        format!(
            "perf verdict: {} {} is at {:.0}% of its speed and this connection is {:.0}% of that: {tail}",
            self.port,
            self.direction.name(),
            self.utilization * 100.0,
            self.share * 100.0
        )
    }
}

/// The verdict for one connection against the host's ports: the wired port and direction with the highest utilization, when that is at least [`UTILIZATION_FULL`], compared with this connection's rate in the same direction. The connection is assumed to run over that port; a share it could not have on it means it does not, and there is no verdict. Share reads a few percent low because the port counts link-layer bytes and the connection counts UDP payload.
pub fn verdict(ports: &[SampleLink], this: &SampleQuic) -> Option<Verdict> {
    let delta = this.delta?;
    let busiest = ports
        .iter()
        .filter_map(|port| {
            let (rx, tx) = port.utilization()?;
            let rates = port.rates?;
            let (direction, utilization, port_rate, ours) = if rx >= tx {
                (Direction::Rx, rx, rates.rx, delta.rx_rate())
            } else {
                (Direction::Tx, tx, rates.tx, delta.tx_rate())
            };
            Some((port, direction, utilization, port_rate, ours))
        })
        .max_by(|a, b| a.2.total_cmp(&b.2))?;
    let (port, direction, utilization, port_rate, ours) = busiest;
    if utilization < UTILIZATION_FULL {
        return None;
    }
    let share = ours / port_rate;
    if share > SHARE_IMPOSSIBLE {
        return None;
    }
    Some(Verdict {
        port: port.name.clone(),
        direction,
        utilization,
        share: share.min(1.0),
        filling: if share < SHARE_OURS {
            Filling::Others
        } else {
            Filling::Ours
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn resource_rates_are_per_second_per_request_and_per_mib() {
        let before = Resources {
            user_ns: 1_000_000_000,
            sys_ns: 500_000_000,
            voluntary_switches: 100,
            involuntary_switches: 10,
            workers: 1,
            busy_ns: 0,
            parks: 50,
        };
        let now = Resources {
            user_ns: 2_000_000_000,
            sys_ns: 1_500_000_000,
            voluntary_switches: 2_100,
            involuntary_switches: 10,
            workers: 1,
            busy_ns: 1_500_000_000,
            parks: 250,
        };
        let r = RateResources::between(&before, &now, 2.0, 1_000, 4 << 20).unwrap();
        assert_eq!(r.user_cores, 0.5);
        assert_eq!(r.sys_cores, 0.5);
        assert_eq!(r.switches_per_second, 1_000.0);
        assert_eq!(r.busy_cores, 0.75);
        assert_eq!(r.parks_per_second, 100.0);
        assert_eq!(r.requests_per_second, 500.0);
        assert_eq!(r.cpu_ns_per_request, Some(2_000_000.0));
        assert_eq!(r.switches_per_request, Some(2.0));
        assert_eq!(r.cpu_ns_per_mib, Some(500_000_000.0));
        let idle = RateResources::between(&before, &now, 2.0, 0, 0).unwrap();
        assert_eq!(idle.cpu_ns_per_request, None);
        assert_eq!(idle.switches_per_request, None);
        assert_eq!(idle.cpu_ns_per_mib, None);
        assert_eq!(RateResources::between(&before, &now, 0.0, 1, 1), None);
    }

    #[test]
    fn the_outermost_level_counts_what_a_process_serves() {
        let op = |level: &str, count, bytes| TotalOp {
            level: level.into(),
            op: "read".into(),
            count,
            bytes,
            ..TotalOp::default()
        };
        let ops = [op("fuse", 3, 30), op("call", 5, 50), op("fuse", 1, 10)];
        assert_eq!(totals_at(&ops, level_outermost("client")), (4, 40));
        assert_eq!(totals_at(&ops, level_outermost("server")), (0, 0));
    }

    #[test]
    fn totals_list_every_request_once_in_its_latency_and_only_data_in_its_sizes() {
        let mut totals = Totals::default();
        totals.add("request", "read", 4096, 0, 0, Duration::from_micros(20));
        totals.add("request", "read", 0, 0, 0, Duration::from_micros(30));
        totals.add("request", "read", 131072, 0, 5, Duration::from_millis(2));
        totals.add("request", "getattr", 0, 0, 0, Duration::from_micros(10));
        totals.add("call", "read", 4096, 0, 0, Duration::from_micros(90));
        let list = totals.list();
        let read = list
            .iter()
            .find(|t| t.level == "request" && t.op == "read")
            .unwrap();
        assert_eq!(read.count, 3);
        assert_eq!(read.errors, 1);
        assert_eq!(
            read.latency.iter().map(|b| b.count).sum::<u64>(),
            read.count
        );
        for (ns, b) in [20_000u64, 30_000, 2_000_000].iter().zip(&read.latency) {
            assert_eq!(b.upper, histogram::upper(histogram::bucket(*ns)));
        }
        assert_eq!(
            read.sizes
                .iter()
                .map(|b| (b.upper, b.count))
                .collect::<Vec<_>>(),
            vec![(4096, 1), (131072, 1)],
            "the read that moved nothing is in no size bucket"
        );
        let getattr = list.iter().find(|t| t.op == "getattr").unwrap();
        assert!(getattr.sizes.is_empty());
        assert_eq!(totals.at("request"), (4, 4096 + 131072));
        assert_eq!(totals.at("call"), (1, 4096));
    }

    #[tokio::test]
    async fn the_process_meter_reports_each_window_against_what_was_served() {
        let mut meter = MeterProcess::new(tokio::runtime::Handle::current(), 5, 1 << 20);
        // CPU of its own in the first window, and requests served in it.
        let spun: u64 = (0..20_000_000u64).map(std::hint::black_box).sum();
        assert!(spun > 0);
        let busy = meter.sample(15, 11 << 20).unwrap();
        assert!(busy.seconds > 0.0);
        assert_eq!(busy.workers, 1);
        assert!(busy.user_cores + busy.sys_cores > 0.0);
        let per_request = busy.cpu_ns_per_request.unwrap();
        let per_mib = busy.cpu_ns_per_mib.unwrap();
        assert!(per_request > 0.0);
        assert!(
            (per_mib - per_request).abs() < 1e-6 * per_request,
            "10 requests and 10 MiB since the baseline, not since the start"
        );
        let idle = meter.sample(15, 11 << 20).unwrap();
        assert_eq!(
            idle.cpu_ns_per_request, None,
            "nothing served in the second window"
        );
        assert_eq!(idle.cpu_ns_per_mib, None);
        assert!(!line_process(&busy).is_empty());
    }

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

    fn stats(rx: u64, tx: u64, lost: u64, sent: u64) -> quinn::ConnectionStats {
        let mut stats = quinn::ConnectionStats::default();
        stats.udp_rx.bytes = rx;
        stats.udp_tx.bytes = tx;
        stats.path.lost_packets = lost;
        stats.path.sent_packets = sent;
        stats
    }

    #[test]
    fn quic_tracker_keeps_its_baseline_until_the_window_is_long_enough() {
        let start = Instant::now();
        let mut tracker = TrackerQuic::default();
        let first = tracker.sample_at(start, stats(100, 10, 0, 5));
        assert!(first.delta.is_none());
        let short = tracker.sample_at(start + Duration::from_millis(600), stats(300, 20, 1, 9));
        assert!(short.delta.is_none(), "too short a window");
        let sample = tracker.sample_at(start + Duration::from_millis(1200), stats(2300, 30, 3, 20));
        let delta = sample.delta.unwrap();
        assert_eq!(
            delta.window,
            Duration::from_millis(1200),
            "measured from the baseline, not the short sample"
        );
        assert_eq!((delta.rx_bytes, delta.tx_bytes), (2200, 20));
        assert_eq!((delta.lost_packets, delta.sent_packets), (3, 15));
        let again = tracker.sample_at(start + Duration::from_millis(3200), stats(2300, 30, 3, 20));
        assert_eq!(again.delta.unwrap().rx_bytes, 0, "the baseline moved");
        assert!(
            line_quic("generation=1", &sample).len() > line_quic("generation=1", &first).len(),
            "a window adds to the line"
        );
    }

    /// A fake `/sys/class/net`: a wired port, a wireless port, a down port, a port with no speed file, a bridge without a device, and a port with a missing counter.
    fn fake_sysfs(root: &Path) {
        let port = |name: &str, device: bool, speed: Option<&str>, counters: &[(&str, u64)]| {
            let dir = root.join(name);
            fs::create_dir_all(dir.join("statistics")).unwrap();
            if device {
                fs::create_dir(dir.join("device")).unwrap();
            }
            if let Some(speed) = speed {
                fs::write(dir.join("speed"), speed).unwrap();
            }
            for name in COUNTERS_LINK {
                fs::write(dir.join("statistics").join(name), "0\n").unwrap();
            }
            for (name, value) in counters {
                fs::write(dir.join("statistics").join(name), format!("{value}\n")).unwrap();
            }
        };
        port(
            "eno1",
            true,
            Some("1000\n"),
            &[("rx_bytes", 1000), ("rx_missed_errors", 7)],
        );
        port("wlan0", true, Some("866\n"), &[]);
        fs::create_dir(root.join("wlan0").join("wireless")).unwrap();
        port("down0", true, Some("-1\n"), &[]);
        port("nospeed0", true, None, &[]);
        port("br0", false, Some("10000\n"), &[("rx_bytes", 5000)]);
        port("broken", true, Some("1000\n"), &[]);
        fs::remove_file(root.join("broken/statistics/tx_errors")).unwrap();
    }

    fn set(root: &Path, port: &str, counter: &str, value: u64) {
        fs::write(
            root.join(port).join("statistics").join(counter),
            format!("{value}\n"),
        )
        .unwrap();
    }

    fn by_name<'a>(samples: &'a [SampleLink], name: &str) -> &'a SampleLink {
        samples.iter().find(|s| s.name == name).unwrap()
    }

    #[test]
    fn link_meter_reads_physical_ports_only_and_rates_their_windows() {
        let dir = tempfile::tempdir().unwrap();
        fake_sysfs(dir.path());
        let start = Instant::now();
        let mut meter = MeterLink::new_at(start, dir.path());

        set(dir.path(), "eno1", "rx_bytes", 1000 + 100_000_000);
        set(dir.path(), "eno1", "tx_bytes", 1_000);
        set(dir.path(), "eno1", "rx_missed_errors", 12);
        let short = meter.sample_at(start + Duration::from_millis(500));
        let names: Vec<&str> = short.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            ["down0", "eno1", "nospeed0", "wlan0"],
            "no bridge, no broken port"
        );
        let eno1 = by_name(&short, "eno1");
        assert!(eno1.rates.is_none(), "too short a window for rates");
        assert_eq!(eno1.drops.rx_missed, 5, "drops count per sample");

        set(dir.path(), "eno1", "rx_bytes", 1000 + 2 * 100_000_000);
        set(dir.path(), "eno1", "tx_bytes", 2 * 1_000);
        let samples = meter.sample_at(start + Duration::from_millis(2000));
        let eno1 = by_name(&samples, "eno1");
        let rates = eno1.rates.unwrap();
        assert_eq!(
            rates.window,
            Duration::from_secs(2),
            "rated from the baseline, not the short sample"
        );
        assert_eq!((rates.rx, rates.tx), (100_000_000.0, 1_000.0));
        assert_eq!(eno1.speed_mbps, Some(1000));
        assert!(!eno1.wireless);
        let (rx, tx) = eno1.utilization().unwrap();
        assert!((rx - 0.8).abs() < 1e-9, "{rx}");
        assert!(tx < 0.001);
        assert_eq!(eno1.drops.rx_missed, 0, "counted in the previous sample");
        let wlan0 = by_name(&samples, "wlan0");
        assert!(wlan0.wireless);
        assert_eq!(wlan0.speed_mbps, Some(866));
        assert!(
            wlan0.utilization().is_none(),
            "a PHY rate is not a capacity"
        );
        for name in ["down0", "nospeed0"] {
            let port = by_name(&samples, name);
            assert_eq!(port.speed_mbps, None, "{name}");
            assert!(port.utilization().is_none(), "{name}");
        }
        assert_eq!(lines_link(&samples).len(), 4);

        fs::remove_file(dir.path().join("wlan0/statistics/rx_bytes")).unwrap();
        fs::create_dir_all(dir.path().join("eno2/statistics")).unwrap();
        fs::create_dir(dir.path().join("eno2/device")).unwrap();
        for name in COUNTERS_LINK {
            fs::write(dir.path().join("eno2/statistics").join(name), "0\n").unwrap();
        }
        let samples = meter.sample_at(start + Duration::from_millis(4000));
        let names: Vec<&str> = samples.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            ["down0", "eno1", "eno2", "nospeed0"],
            "a port that lost its counters is left out and a new one is picked up"
        );
        assert!(
            by_name(&samples, "eno2").rates.is_none(),
            "a new port starts its own baseline"
        );
        assert_eq!(lines_link(&[]).len(), 1, "an empty host still says so");
    }

    #[test]
    fn udp_rows_parse_and_delta() {
        let snmp = "Ip: Forwarding DefaultTTL\nIp: 1 64\nUdp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors\nUdp: 10 2 70 20 70 5 0\n";
        assert_eq!(
            parse_udp(snmp),
            Some(CountersUdp {
                in_errors: 70,
                rcvbuf_errors: 70,
                sndbuf_errors: 5
            })
        );
        assert_eq!(
            parse_udp("Udp: InErrors\n"),
            None,
            "a header without values"
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snmp");
        fs::write(&path, snmp).unwrap();
        let mut meter = MeterUdp::new(&path);
        fs::write(
            &path,
            snmp.replace("Udp: 10 2 70 20 70 5 0", "Udp: 10 2 73 20 72 5 0"),
        )
        .unwrap();
        let sample = meter.sample().unwrap();
        assert_eq!(
            sample.delta,
            CountersUdp {
                in_errors: 3,
                rcvbuf_errors: 2,
                sndbuf_errors: 0
            }
        );
        assert!(!line_udp(&sample).is_empty());
    }

    fn port(name: &str, wireless: bool, speed: Option<u64>, rx: f64, tx: f64) -> SampleLink {
        SampleLink {
            name: name.into(),
            wireless,
            speed_mbps: speed,
            rates: Some(RatesLink {
                window: Duration::from_secs(1),
                rx,
                tx,
            }),
            drops: DropsLink::default(),
        }
    }

    fn connection(rx_rate: u64, tx_rate: u64) -> SampleQuic {
        SampleQuic {
            stats: quinn::ConnectionStats::default(),
            delta: Some(DeltaQuic {
                window: Duration::from_secs(1),
                rx_bytes: rx_rate,
                tx_bytes: tx_rate,
                lost_packets: 0,
                sent_packets: 0,
            }),
        }
    }

    #[test]
    fn verdicts() {
        let gbit = 125_000_000.0;
        let full_rx = port("eno1", false, Some(1000), 0.94 * gbit, 0.02 * gbit);
        let starved = verdict(
            std::slice::from_ref(&full_rx),
            &connection(20_000_000, 100_000),
        )
        .unwrap();
        assert_eq!(
            (starved.port.as_str(), starved.direction, starved.filling),
            ("eno1", Direction::Rx, Filling::Others)
        );
        let own = verdict(
            std::slice::from_ref(&full_rx),
            &connection(110_000_000, 100_000),
        )
        .unwrap();
        assert_eq!(own.filling, Filling::Ours);
        assert_ne!(starved.describe(), own.describe());

        let full_tx = port("eno1", false, Some(1000), 0.02 * gbit, 0.9 * gbit);
        let uplink = verdict(&[full_tx], &connection(100_000, 10_000_000)).unwrap();
        assert_eq!(
            (uplink.direction, uplink.filling),
            (Direction::Tx, Filling::Others)
        );

        let quiet = port("eno1", false, Some(1000), 0.3 * gbit, 0.01 * gbit);
        assert_eq!(verdict(&[quiet], &connection(1_000_000, 0)), None);
        let wireless = port("wlan0", true, Some(866), 100_000_000.0, 0.0);
        assert_eq!(verdict(&[wireless], &connection(1_000_000, 0)), None);
        let unknown = port("eth9", false, None, gbit, 0.0);
        assert_eq!(verdict(&[unknown], &connection(1_000_000, 0)), None);
        let mut no_window = full_rx.clone();
        no_window.rates = None;
        assert_eq!(verdict(&[no_window], &connection(1_000_000, 0)), None);
        let mut this_no_window = connection(1_000_000, 0);
        this_no_window.delta = None;
        assert_eq!(
            verdict(std::slice::from_ref(&full_rx), &this_no_window),
            None
        );
        // A connection moving more than the busiest port is not on that port, so nothing can be said about it.
        let elsewhere = port("eno1", false, Some(1000), 0.9 * gbit, 0.0);
        assert_eq!(verdict(&[elsewhere], &connection(200_000_000, 0)), None);
    }
}

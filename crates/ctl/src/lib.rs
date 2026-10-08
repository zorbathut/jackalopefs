//! What `jackalopefs-ctl` works out without a process to talk to: which processes there are, what a selector asks for, rates between two readings of the counters, and how a record reads.

use jackalopefs_perf::{fmt_count, level_outermost, totals_at, RateResources};
use jackalopefs_proto::control::{
    Bucket, ControlReply, Counters, Exchange, Happened, Ids, Names, Record, Selection, Summary,
};
use jackalopefs_proto::{
    decode, read_frame, write_frame, Event, Request, Response, CONTROL_REVISION, PROTO_REVISION,
};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A process serving a control socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub side: String,
    pub pid: u32,
    /// The socket's abstract name.
    pub name: String,
}

/// Listening sockets in the `__SO_ACCEPTCON` sense, the `Flags` column of `/proc/net/unix`.
const SO_ACCEPTCON: u32 = 0x10000;

/// The control sockets listening in `proc_net_unix` (the contents of `/proc/net/unix`), each once, by pid: those of user `uid`, or of every user for `None` (root, which every process admits).
pub fn targets(proc_net_unix: &str, uid: Option<u32>) -> Vec<Target> {
    let mut found = BTreeMap::new();
    for line in proc_net_unix.lines().skip(1) {
        let columns: Vec<&str> = line.split_whitespace().collect();
        let (Some(flags), Some(path)) = (columns.get(3), columns.get(7)) else {
            continue;
        };
        if u32::from_str_radix(flags, 16).is_ok_and(|f| f & SO_ACCEPTCON == 0) {
            continue;
        }
        let Some(rest) = path.strip_prefix("@jackalopefs/") else {
            continue;
        };
        let Some((owner, rest)) = rest.split_once('/') else {
            continue;
        };
        if uid.is_some_and(|uid| owner != uid.to_string()) {
            continue;
        }
        let Some((side, pid)) = rest.rsplit_once('-') else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        found.insert(
            pid,
            Target {
                side: side.to_owned(),
                pid,
                name: path[1..].to_owned(),
            },
        );
    }
    found.into_values().collect()
}

/// `text` from a process or a file with its control characters escaped, so a file name holding a terminal's escape sequences shows as text instead of acting on the terminal.
pub fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// What `trace` selectors ask for: `events` (every event), `ops` (every request summary), `op:NAME` (one operation's summaries) or an event's name.
pub fn selection(selectors: &[String]) -> Result<Selection, String> {
    let mut selection = Selection::default();
    let add = |names: &mut Names, name: &str| match names {
        Names::All => {}
        Names::Some(list) => list.push(name.to_owned()),
        Names::None => *names = Names::Some(vec![name.to_owned()]),
    };
    for selector in selectors {
        match selector.as_str() {
            "events" => selection.events = Names::All,
            "ops" => selection.ops = Names::All,
            "" => return Err("an empty selector".into()),
            other => match other.strip_prefix("op:") {
                Some("") => return Err("op: needs an operation name".into()),
                Some(op) => add(&mut selection.ops, op),
                None => add(&mut selection.events, other),
            },
        }
    }
    if selection.events.is_none() && selection.ops.is_none() {
        return Err("nothing selected: name events, `events`, `ops` or `op:NAME`".into());
    }
    Ok(selection)
}

/// What `capture` or `trace --frames` asks for: the frames of the operations the selectors name (of every operation when they name none), one exchange in `every`, and the events they name.
pub fn frame_selection(
    selectors: &[String],
    every: u32,
    payloads: bool,
) -> Result<Selection, String> {
    let mut chosen = if selectors.is_empty() {
        Selection::default()
    } else {
        selection(selectors)?
    };
    chosen.frames = true;
    chosen.every = every.max(1);
    chosen.payloads = payloads;
    Ok(chosen)
}

/// An event's rate between two readings.
#[derive(Clone, Debug, PartialEq)]
pub struct RateEvent {
    pub name: String,
    pub per_second: f64,
    pub total: u64,
}

/// An operation's rates between two readings.
#[derive(Clone, Debug, PartialEq)]
pub struct RateOp {
    pub level: String,
    pub op: String,
    pub per_second: f64,
    pub bytes_per_second: f64,
    /// Mean time per request over the interval; `None` when none completed in it.
    pub mean_ns: Option<u64>,
    /// The interval's median and 99th-percentile latency, as the bound of the bucket each falls in (at most a quarter above the true value).
    pub p50_ns: Option<u64>,
    pub p99_ns: Option<u64>,
    /// The interval's median bytes moved, among the requests that moved any.
    pub size_p50: Option<u64>,
    pub errors_per_second: f64,
    pub total: u64,
}

/// The `q` quantile (0 to 1) of what was added to a histogram between readings `before` and `now`, as the upper bound of the bucket it falls in; `None` when nothing was added.
pub fn quantile(before: &[Bucket], now: &[Bucket], q: f64) -> Option<u64> {
    let earlier: BTreeMap<u64, u64> = before.iter().map(|b| (b.upper, b.count)).collect();
    let mut added: Vec<(u64, u64)> = now
        .iter()
        .map(|b| {
            (
                b.upper,
                b.count
                    .saturating_sub(earlier.get(&b.upper).copied().unwrap_or(0)),
            )
        })
        .filter(|(_, n)| *n > 0)
        .collect();
    added.sort_unstable();
    let total: u64 = added.iter().map(|(_, n)| n).sum();
    if total == 0 {
        return None;
    }
    // The rank of the value wanted, from 1: the smallest that has at least q of the values at or below it.
    let rank = ((q * total as f64).ceil() as u64).clamp(1, total);
    let mut seen = 0;
    added.into_iter().find_map(|(upper, n)| {
        seen += n;
        (seen >= rank).then_some(upper)
    })
}

/// What changed between readings `before` and `now`, `seconds` apart: every event and operation that has happened at all, busiest first.
pub fn rates(before: &Counters, now: &Counters, seconds: f64) -> (Vec<RateEvent>, Vec<RateOp>) {
    let seconds = seconds.max(f64::MIN_POSITIVE);
    let earlier: BTreeMap<&str, u64> = before
        .events
        .iter()
        .map(|(name, n)| (name.as_str(), *n))
        .collect();
    let mut events: Vec<RateEvent> = now
        .events
        .iter()
        .filter(|(_, total)| *total > 0)
        .map(|(name, total)| RateEvent {
            name: name.clone(),
            per_second: total.saturating_sub(earlier.get(name.as_str()).copied().unwrap_or(0))
                as f64
                / seconds,
            total: *total,
        })
        .collect();
    events.sort_by(|a, b| {
        b.per_second
            .total_cmp(&a.per_second)
            .then(b.total.cmp(&a.total))
    });
    let earlier: BTreeMap<(&str, &str), _> = before
        .ops
        .iter()
        .map(|t| ((t.level.as_str(), t.op.as_str()), t))
        .collect();
    let mut ops: Vec<RateOp> = now
        .ops
        .iter()
        .map(|t| {
            let was = earlier.get(&(t.level.as_str(), t.op.as_str()));
            let delta = |now: u64, then: fn(&&jackalopefs_proto::control::TotalOp) -> u64| {
                now.saturating_sub(was.map_or(0, then))
            };
            let count = delta(t.count, |w| w.count);
            let total_ns = delta(t.total_ns, |w| w.total_ns);
            RateOp {
                level: t.level.clone(),
                op: t.op.clone(),
                per_second: count as f64 / seconds,
                bytes_per_second: delta(t.bytes, |w| w.bytes) as f64 / seconds,
                mean_ns: (count > 0).then(|| total_ns / count),
                p50_ns: quantile(was.map_or(&[], |w| &w.latency), &t.latency, 0.5),
                p99_ns: quantile(was.map_or(&[], |w| &w.latency), &t.latency, 0.99),
                size_p50: quantile(was.map_or(&[], |w| &w.sizes), &t.sizes, 0.5),
                errors_per_second: delta(t.errors, |w| w.errors) as f64 / seconds,
                total: t.count,
            }
        })
        .collect();
    ops.sort_by(|a, b| {
        b.per_second
            .total_cmp(&a.per_second)
            .then(b.total.cmp(&a.total))
    });
    (events, ops)
}

/// The process's resource use between two readings of its counters, timed by the process's own uptime in each (not when the readings arrived), against the requests it served at its outermost level.
pub fn resources_between(before: &Counters, now: &Counters) -> Option<RateResources> {
    let level = level_outermost(&now.side);
    let (served_before, moved_before) = totals_at(&before.ops, level);
    let (served, moved) = totals_at(&now.ops, level);
    RateResources::between(
        &before.resources,
        &now.resources,
        now.uptime_ns.saturating_sub(before.uptime_ns) as f64 / 1e9,
        served.saturating_sub(served_before),
        moved.saturating_sub(moved_before),
    )
}

/// The resources line of `top`: what the process spends, in all and per request served.
pub fn fmt_resources(r: &RateResources) -> String {
    let per_request = match (r.cpu_ns_per_request, r.switches_per_request) {
        (Some(cpu), Some(switches)) => {
            format!(
                "{} CPU and {switches:.1} switches per request",
                fmt_ns(cpu as u64)
            )
        }
        _ => "no requests".to_owned(),
    };
    let per_mib = r.cpu_ns_per_mib.map_or_else(String::new, |cpu| {
        format!(", {} CPU per MiB", fmt_ns(cpu as u64))
    });
    format!(
        "CPU {:.2} cores (user {:.2}, sys {:.2}), {} switches/s; {} worker{} {:.0}% busy, {} parks/s; {per_request}{per_mib}",
        r.user_cores + r.sys_cores,
        r.user_cores,
        r.sys_cores,
        fmt_count(r.switches_per_second),
        r.workers,
        if r.workers == 1 { "" } else { "s" },
        100.0 * r.busy_cores / f64::from(r.workers.max(1)),
        fmt_count(r.parks_per_second),
    )
}

/// The counters as `key value` lines, one figure each, for scripts: names are stable, values raw.
pub fn counter_lines(c: &Counters) -> String {
    let mut out = String::new();
    let mut put = |key: &str, value: &dyn std::fmt::Display| {
        writeln!(out, "{key} {value}").expect("a String takes any write");
    };
    put("side", &clean(&c.side));
    put("pid", &c.pid);
    put("uptime_ns", &c.uptime_ns);
    put("inflight", &c.inflight);
    let r = &c.resources;
    put("resources.user_ns", &r.user_ns);
    put("resources.sys_ns", &r.sys_ns);
    put("resources.voluntary_switches", &r.voluntary_switches);
    put("resources.involuntary_switches", &r.involuntary_switches);
    put("resources.workers", &r.workers);
    put("resources.busy_ns", &r.busy_ns);
    put("resources.parks", &r.parks);
    for (name, value) in &c.events {
        put(&format!("event.{}", clean(name)), value);
    }
    for t in &c.ops {
        let key = format!("op.{}.{}", clean(&t.level), clean(&t.op));
        put(&format!("{key}.count"), &t.count);
        put(&format!("{key}.bytes"), &t.bytes);
        put(&format!("{key}.items"), &t.items);
        put(&format!("{key}.errors"), &t.errors);
        put(&format!("{key}.total_ns"), &t.total_ns);
        for b in &t.latency {
            put(&format!("{key}.latency_ns_le.{}", b.upper), &b.count);
        }
        for b in &t.sizes {
            put(&format!("{key}.bytes_le.{}", b.upper), &b.count);
        }
    }
    out
}

/// A duration in nanoseconds, as a person reads it.
pub fn fmt_ns(ns: u64) -> String {
    match ns {
        n if n < 1_000 => format!("{n}ns"),
        n if n < 1_000_000 => format!("{:.1}us", n as f64 / 1e3),
        n if n < 1_000_000_000 => format!("{:.2}ms", n as f64 / 1e6),
        n => format!("{:.2}s", n as f64 / 1e9),
    }
}

/// A byte count, as a person reads it.
pub fn fmt_bytes(bytes: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0}{}", UNITS[unit])
    } else {
        format!("{value:.1}{}", UNITS[unit])
    }
}

/// The `top` screen for reading `now` and the rates since the last.
pub fn render_top(
    now: &Counters,
    resources: Option<&RateResources>,
    events: &[RateEvent],
    ops: &[RateOp],
    seconds: f64,
) -> String {
    let mut out = String::new();
    writeln!(
        out,
        "{} {} — {} — up {}, {} in flight, every {seconds:.1}s",
        clean(&now.side),
        now.pid,
        clean(&now.describe),
        fmt_ns(now.uptime_ns),
        now.inflight
    )
    .expect("a String takes any write");
    if let Some(resources) = resources {
        writeln!(out, "{}", fmt_resources(resources)).expect("a String takes any write");
    }
    writeln!(
        out,
        "\n{:<8} {:<16} {:>9} {:>11} {:>9} {:>10} {:>10} {:>10} {:>8} {:>10}",
        "level", "op", "per sec", "bytes/s", "size p50", "mean", "p50", "p99", "err/s", "total"
    )
    .expect("a String takes any write");
    let or_dash = |v: Option<u64>, f: fn(u64) -> String| v.map_or_else(|| "-".to_owned(), f);
    for op in ops {
        writeln!(
            out,
            "{:<8} {:<16} {:>9.1} {:>11} {:>9} {:>10} {:>10} {:>10} {:>8.1} {:>10}",
            clean(&op.level),
            clean(&op.op),
            op.per_second,
            fmt_bytes(op.bytes_per_second),
            or_dash(op.size_p50, |b| fmt_bytes(b as f64)),
            or_dash(op.mean_ns, fmt_ns),
            or_dash(op.p50_ns, fmt_ns),
            or_dash(op.p99_ns, fmt_ns),
            op.errors_per_second,
            op.total
        )
        .expect("a String takes any write");
    }
    writeln!(out, "\n{:<26} {:>9} {:>10}", "event", "per sec", "total")
        .expect("a String takes any write");
    for event in events {
        writeln!(
            out,
            "{:<26} {:>9.1} {:>10}",
            clean(&event.name),
            event.per_second,
            event.total
        )
        .expect("a String takes any write");
    }
    out
}

/// A Unix time in nanoseconds as the UTC time of day, to the millisecond.
fn time_of_day(at_ns: u64) -> String {
    let ms = at_ns / 1_000_000;
    let day_ms = ms % 86_400_000;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        day_ms / 3_600_000,
        day_ms / 60_000 % 60,
        day_ms / 1000 % 60,
        day_ms % 1000
    )
}

fn fmt_ids(ids: &Ids) -> String {
    let mut out = String::new();
    if let Some(op) = &ids.op {
        write!(out, " op={op}").expect("a String takes any write");
    }
    for (name, value) in [
        ("session", ids.session),
        ("conn", ids.conn),
        ("stream", ids.stream),
        ("unique", ids.unique),
    ] {
        if let Some(value) = value {
            write!(out, " {name}={value}").expect("a String takes any write");
        }
    }
    out
}

fn fmt_summary(s: &Summary) -> String {
    let mut out = format!(
        "{} {}{}",
        s.level,
        s.ids.op.as_deref().unwrap_or("?"),
        fmt_ids(&s.ids)
    );
    for (name, value) in [
        ("ino", s.ino),
        ("fh", s.fh),
        ("offset", s.offset),
        ("size", s.size),
        ("pid", s.pid.map(u64::from)),
    ] {
        if let Some(value) = value {
            write!(out, " {name}={value}").expect("a String takes any write");
        }
    }
    if s.bytes > 0 {
        write!(out, " bytes={}", s.bytes).expect("a String takes any write");
    }
    if s.items > 0 {
        write!(out, " items={}", s.items).expect("a String takes any write");
    }
    if s.errno != 0 {
        write!(out, " errno={}", s.errno).expect("a String takes any write");
    }
    write!(out, " total={}", fmt_ns(s.total_ns)).expect("a String takes any write");
    for (name, ns) in &s.phases {
        write!(out, " {name}={}", fmt_ns(*ns)).expect("a String takes any write");
    }
    out
}

/// One line for a record, its control characters escaped.
pub fn fmt_record(record: &Record) -> String {
    clean(&line_of(record))
}

fn line_of(record: &Record) -> String {
    let at = time_of_day(record.at_ns);
    match &record.what {
        Happened::Event { name, ids, detail } => {
            format!("{at} {name}{}: {detail}", fmt_ids(ids))
        }
        Happened::Request(summary) => format!("{at} {}", fmt_summary(summary)),
        Happened::Dropped(n) => format!("{at} ({n} records dropped: this reader fell behind)"),
        Happened::Exchange(x) => format!("{at} {}", fmt_exchange(x)),
        Happened::Undecodable {
            side,
            ids,
            error,
            body,
        } => format!(
            "{at} {side} undecodable frame of {} bytes{}: {error}",
            body.len(),
            fmt_ids(ids)
        ),
        Happened::EventFrame {
            side,
            ids,
            every,
            seq,
            body,
        } => {
            let items = match decode::<Event>(body) {
                Ok(event) => format!("{} change events", event.items.len()),
                Err(e) => format!("undecodable events ({e})"),
            };
            format!(
                "{at} {side} {items}{} seq={seq} (1 in {every})",
                fmt_ids(ids)
            )
        }
        Happened::Header(h) => format!(
            "{at} capture of {} {} ({}), protocol {:016x}, control {:016x}",
            h.side, h.pid, h.describe, h.proto_revision, h.control_revision
        ),
        Happened::Census { ops, dropped } => {
            let mut out = format!("{at} census:");
            for op in ops {
                // A census the capture made itself, its process gone, knows only what it holds.
                if op.seen == 0 && op.sampled > 0 {
                    out.push_str(&format!(" {}={}/?", op.op, op.sampled));
                } else {
                    out.push_str(&format!(" {}={}/{}", op.op, op.sampled, op.seen));
                }
                if op.dropped > 0 {
                    out.push_str(&format!(" ({} dropped)", op.dropped));
                }
            }
            if *dropped > 0 {
                out.push_str(&format!(", {dropped} records dropped"));
            }
            out
        }
    }
}

/// What a reply says, in a few words.
fn fmt_response(resp: &Response) -> String {
    match resp {
        Response::Err(errno) => format!("errno {errno}"),
        Response::Read(data) => format!("{} bytes", data.len()),
        Response::Written(n) => format!("{n} written"),
        Response::Readdir { entries, end } => {
            format!(
                "{} entries{}",
                entries.len(),
                if *end { ", end" } else { "" }
            )
        }
        other => other.kind_name().to_owned(),
    }
}

/// One line for a captured exchange: what was asked, what came back, and how long it took.
pub fn fmt_exchange(x: &Exchange) -> String {
    let asked = match decode::<Request>(&x.request) {
        Ok(req) => format!("{} {}", req.op_name(), req.subject()),
        Err(e) => format!("(request undecodable: {e})"),
    };
    let mut out = format!(
        "{} exchange {asked}{} (1 in {})",
        x.side,
        fmt_ids(&x.ids),
        x.every
    );
    if x.request_elided > 0 {
        out.push_str(&format!(" with {} bytes (cut)", x.request_elided));
    }
    if x.outcome == "replied" {
        let answer = match decode::<Response>(&x.reply) {
            Ok(Response::Read(_)) if x.reply_elided > 0 => {
                format!("{} bytes (cut)", x.reply_elided)
            }
            Ok(resp) => fmt_response(&resp),
            Err(e) => format!("undecodable ({e})"),
        };
        out.push_str(&format!(" -> {answer} in {}", fmt_ns(x.elapsed_ns)));
    } else {
        out.push_str(&format!(
            " -> no reply: {} after {}",
            x.outcome,
            fmt_ns(x.elapsed_ns)
        ));
    }
    out
}

/// What a capture's debug form shows of a frame body: the message decoded in full, or why it does not decode.
fn decoded<T: jackalopefs_proto::Message + std::fmt::Debug>(body: &[u8]) -> String {
    match decode::<T>(body) {
        Ok(message) => format!("{message:#?}"),
        Err(e) => format!("(does not decode: {e})"),
    }
}

/// A record as `dump` shows it: its line, then each frame it holds decoded in full, indented; control characters escaped throughout.
pub fn fmt_record_long(record: &Record) -> String {
    let mut out = line_of(record);
    let mut frame = |what: &str, text: String| {
        out.push_str(&format!("\n  {what}:"));
        for line in text.lines() {
            out.push_str("\n    ");
            out.push_str(line);
        }
    };
    match &record.what {
        Happened::Exchange(x) => {
            frame("request", decoded::<Request>(&x.request));
            if !x.reply.is_empty() {
                frame("reply", decoded::<Response>(&x.reply));
            }
        }
        Happened::EventFrame { body, .. } => frame("events", decoded::<Event>(body)),
        _ => {}
    }
    clean_keeping_lines(&out)
}

fn clean_keeping_lines(text: &str) -> String {
    text.lines().map(clean).collect::<Vec<_>>().join("\n")
}

/// What a capture file starts with, before any record: the file's kind and the revisions its records and frames were written in, readable before decoding anything.
const CAPTURE_MAGIC: &[u8; 8] = b"jfscap\0\x01";

/// The bytes a capture file starts with.
pub fn capture_preamble() -> Vec<u8> {
    let mut preamble = CAPTURE_MAGIC.to_vec();
    preamble.extend_from_slice(&CONTROL_REVISION.to_le_bytes());
    preamble.extend_from_slice(&PROTO_REVISION.to_le_bytes());
    preamble
}

/// Check a capture file's first bytes: an error when it is not a capture or holds records of another control revision, which would read as garbage; a warning when its frames are of another protocol revision, which may decode wrongly.
pub fn check_preamble(preamble: &[u8; 24]) -> Result<Option<String>, String> {
    if preamble[..8] != CAPTURE_MAGIC[..] {
        return Err("not a jackalopefs capture".into());
    }
    let revision =
        |at: usize| u64::from_le_bytes(preamble[at..at + 8].try_into().expect("8 bytes"));
    let (control, proto) = (revision(8), revision(16));
    if control != CONTROL_REVISION {
        return Err(format!(
            "written with control revision {control:016x}; this jackalopefs-ctl reads {CONTROL_REVISION:016x}"
        ));
    }
    Ok((proto != PROTO_REVISION).then(|| {
        format!(
            "its frames are of protocol revision {proto:016x}, not this build's {PROTO_REVISION:016x}, and may decode wrongly; --frames-to keeps their bytes"
        )
    }))
}

/// Write the preamble of a capture file.
pub async fn write_preamble<W: AsyncWrite + Unpin>(out: &mut W) -> std::io::Result<()> {
    out.write_all(&capture_preamble()).await
}

/// Read and check the preamble of a capture file: the warning to give, if any.
pub async fn read_preamble<R: AsyncRead + Unpin>(input: &mut R) -> Result<Option<String>, String> {
    let mut preamble = [0u8; 24];
    input
        .read_exact(&mut preamble)
        .await
        .map_err(|e| format!("too short for a capture ({e})"))?;
    check_preamble(&preamble)
}

/// Write one record of a capture file.
pub async fn write_record<W: AsyncWrite + Unpin>(
    out: &mut W,
    record: Record,
) -> Result<(), jackalopefs_proto::ErrorCodec> {
    write_frame(out, &ControlReply::Record(record)).await
}

/// The next record of a capture file; `None` at its end.
pub async fn read_record<R: AsyncRead + Unpin>(input: &mut R) -> Result<Option<Record>, String> {
    match read_frame::<_, ControlReply>(input).await {
        Ok(ControlReply::Record(record)) => Ok(Some(record)),
        Ok(other) => Err(format!("not a record: {other:?}")),
        Err(e) if e.is_eof() => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jackalopefs_proto::control::TotalOp;

    #[test]
    fn only_listening_control_sockets_of_this_user_are_targets() {
        let table = "Num       RefCount Protocol Flags    Type St Inode Path
0000000000000001: 00000002 00000000 00010000 0001 01 1 @jackalopefs/1000/client-42
0000000000000002: 00000003 00000000 00000000 0001 03 2 @jackalopefs/1000/client-42
0000000000000003: 00000002 00000000 00010000 0001 01 3 @jackalopefs/1001/server-7
0000000000000004: 00000002 00000000 00010000 0001 01 4 @jackalopefs/1000/server-9
0000000000000005: 00000002 00000000 00010000 0001 01 5 /run/user/1000/bus
0000000000000006: 00000002 00000000 00010000 0001 01 6
";
        let found = targets(table, Some(1000));
        assert_eq!(targets(table, None).len(), 3, "root sees every user's");
        assert_eq!(
            found
                .iter()
                .map(|t| (t.side.as_str(), t.pid))
                .collect::<Vec<_>>(),
            vec![("server", 9), ("client", 42)]
        );
        assert_eq!(found[1].name, "jackalopefs/1000/client-42");
    }

    #[test]
    fn selectors_name_events_and_operations() {
        let parse = |s: &[&str]| selection(&s.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let s = parse(&["call_lost_retried", "op:read", "op:write"]).unwrap();
        assert_eq!(s.events, Names::Some(vec!["call_lost_retried".into()]));
        assert_eq!(s.ops, Names::Some(vec!["read".into(), "write".into()]));
        let s = parse(&["events", "ops", "op:read"]).unwrap();
        assert_eq!((s.events, s.ops), (Names::All, Names::All));
        assert!(parse(&[]).is_err());
        assert!(parse(&["op:"]).is_err());
    }

    fn total(level: &str, op: &str, count: u64, bytes: u64, errors: u64, total_ns: u64) -> TotalOp {
        TotalOp {
            level: level.into(),
            op: op.into(),
            count,
            bytes,
            items: 0,
            errors,
            total_ns,
            ..TotalOp::default()
        }
    }

    #[test]
    fn rates_are_the_differences_over_the_interval_busiest_first() {
        let before = Counters {
            events: vec![("a".into(), 1), ("b".into(), 0)],
            ops: vec![total("call", "read", 10, 1000, 0, 10_000)],
            ..Counters::default()
        };
        let now = Counters {
            events: vec![("a".into(), 5), ("b".into(), 0)],
            ops: vec![
                total("call", "read", 30, 5000, 2, 50_000),
                total("call", "write", 4, 0, 0, 4_000),
            ],
            ..Counters::default()
        };
        let (events, ops) = rates(&before, &now, 2.0);
        assert_eq!(
            events,
            vec![RateEvent {
                name: "a".into(),
                per_second: 2.0,
                total: 5
            }],
            "an event that never happened is left out"
        );
        assert_eq!(ops[0].op, "read");
        assert_eq!(ops[0].per_second, 10.0);
        assert_eq!(ops[0].bytes_per_second, 2000.0);
        assert_eq!(ops[0].mean_ns, Some(2_000));
        assert_eq!(ops[0].errors_per_second, 1.0);
        assert_eq!(
            (ops[1].op.as_str(), ops[1].per_second),
            ("write", 2.0),
            "new since the last reading"
        );
        let (_, idle) = rates(&now, &now, 1.0);
        assert_eq!(idle[0].mean_ns, None);
    }

    fn buckets(pairs: &[(u64, u64)]) -> Vec<Bucket> {
        pairs
            .iter()
            .map(|&(upper, count)| Bucket { upper, count })
            .collect()
    }

    #[test]
    fn quantiles_come_from_what_the_interval_added() {
        let before = buckets(&[(4096, 100), (131072, 5)]);
        let now = buckets(&[(1024, 1), (4096, 100), (131072, 50)]);
        assert_eq!(
            quantile(&before, &now, 0.5),
            Some(131072),
            "the 100 old 4 KiB values are not the window's"
        );
        assert_eq!(quantile(&before, &now, 0.0), Some(1024));
        assert_eq!(quantile(&[], &now, 0.5), Some(4096));
        assert_eq!(quantile(&now, &now, 0.5), None);
        let wide = buckets(&[(10, 98), (20, 1), (30, 1)]);
        assert_eq!(quantile(&[], &wide, 0.99), Some(20));
        assert_eq!(quantile(&[], &wide, 1.0), Some(30));
    }

    #[test]
    fn rates_carry_the_windows_quantiles() {
        let mut before = total("call", "write", 10, 10 * 4096, 0, 10_000);
        before.latency = buckets(&[(1024, 10)]);
        before.sizes = buckets(&[(4096, 10)]);
        let mut now = total("call", "write", 30, 30 * 4096, 0, 50_000);
        now.latency = buckets(&[(1024, 10), (2048, 15), (8192, 5)]);
        now.sizes = buckets(&[(4096, 30)]);
        let (_, ops) = rates(
            &Counters {
                ops: vec![before],
                ..Counters::default()
            },
            &Counters {
                ops: vec![now],
                ..Counters::default()
            },
            1.0,
        );
        assert_eq!(ops[0].size_p50, Some(4096));
        assert_eq!(ops[0].p50_ns, Some(2048));
        assert!(ops[0].p99_ns >= ops[0].p50_ns);
    }

    #[test]
    fn resources_are_timed_by_the_process_and_counted_against_its_outermost_requests() {
        let reading = |uptime_s: u64, cpu_s: u64, fuse: u64, call: u64| Counters {
            side: "client".into(),
            uptime_ns: uptime_s * 1_000_000_000,
            ops: vec![
                total("fuse", "read", fuse, fuse * 4096, 0, 0),
                total("call", "read", call, call * 4096, 0, 0),
            ],
            resources: jackalopefs_proto::control::Resources {
                user_ns: cpu_s * 1_000_000_000,
                workers: 1,
                ..Default::default()
            },
            ..Counters::default()
        };
        let r = resources_between(&reading(10, 1, 100, 300), &reading(12, 3, 1100, 2300)).unwrap();
        assert_eq!(r.seconds, 2.0);
        assert_eq!(r.user_cores, 1.0);
        assert_eq!(
            r.requests_per_second, 500.0,
            "the kernel's requests, not the calls made for them"
        );
        assert_eq!(r.cpu_ns_per_request, Some(2_000_000.0));
        let busy = fmt_resources(&r);
        let idle = fmt_resources(
            &resources_between(&reading(12, 3, 1100, 2300), &reading(14, 3, 1100, 2300)).unwrap(),
        );
        assert!(!busy.is_empty());
        assert_ne!(
            busy, idle,
            "a process at work reads differently from one at rest"
        );
    }

    #[test]
    fn counter_lines_name_every_figure_once() {
        let c = Counters {
            side: "server".into(),
            pid: 7,
            events: vec![("reply_stalled".into(), 2)],
            ops: vec![TotalOp {
                sizes: buckets(&[(4096, 3)]),
                ..total("request", "read", 3, 12288, 0, 300)
            }],
            ..Counters::default()
        };
        let text = counter_lines(&c);
        let keys: Vec<&str> = text.lines().map(|l| l.split_once(' ').unwrap().0).collect();
        let mut unique = keys.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(keys.len(), unique.len());
        for (key, value) in [
            ("pid", "7"),
            ("resources.user_ns", "0"),
            ("event.reply_stalled", "2"),
            ("op.request.read.count", "3"),
            ("op.request.read.bytes", "12288"),
            ("op.request.read.bytes_le.4096", "3"),
        ] {
            assert!(
                text.lines().any(|l| l == format!("{key} {value}")),
                "{key} in {text}"
            );
        }
    }

    #[test]
    fn records_read_differently_and_carry_what_they_are_about() {
        let event = Record {
            at_ns: 1,
            what: Happened::Event {
                name: "reply_stalled".into(),
                ids: Ids {
                    stream: Some(8),
                    ..Ids::default()
                },
                detail: "the detail".into(),
            },
        };
        let request = Record {
            at_ns: 1,
            what: Happened::Request(Summary {
                level: "call".into(),
                ids: Ids {
                    op: Some("read".into()),
                    ..Ids::default()
                },
                errno: 5,
                ..Summary::default()
            }),
        };
        let dropped = Record {
            at_ns: 1,
            what: Happened::Dropped(3),
        };
        let lines: Vec<String> = [&event, &request, &dropped]
            .iter()
            .map(|r| fmt_record(r))
            .collect();
        assert!(lines[0].contains("the detail") && lines[0].contains('8'));
        assert!(lines[1].contains("read"));
        assert!(lines[2].contains('3'));
        assert_ne!(lines[0], lines[1]);
        assert_ne!(lines[1], lines[2]);
    }

    #[test]
    fn a_time_of_day_is_utc() {
        assert_eq!(
            time_of_day(((3600 + 61) * 1000 + 5) * 1_000_000),
            "01:01:01.005"
        );
    }

    #[test]
    fn a_capture_selects_frames_of_everything_unless_told_otherwise() {
        let all = frame_selection(&[], 0, false).unwrap();
        assert!(all.frames && all.ops.is_none() && all.every == 1);
        let some = frame_selection(
            &["op:read".to_string(), "reply_stalled".to_string()],
            8,
            true,
        )
        .unwrap();
        assert_eq!(some.ops, Names::Some(vec!["read".into()]));
        assert_eq!(some.events, Names::Some(vec!["reply_stalled".into()]));
        assert!(some.payloads && some.every == 8);
    }

    #[test]
    fn an_exchange_reads_as_what_was_asked_and_answered() {
        let body = |frame: Vec<u8>| frame[4..].to_vec();
        let request = body(jackalopefs_proto::encode(&Request::Release { fh: 5 }).unwrap());
        let replied = Exchange {
            side: "client".into(),
            every: 1,
            request: request.clone(),
            reply: body(jackalopefs_proto::encode(&Response::Err(2)).unwrap()),
            outcome: "replied".into(),
            ..Exchange::default()
        };
        let abandoned = Exchange {
            reply: Vec::new(),
            outcome: "abandoned".into(),
            ..replied.clone()
        };
        let (a, b) = (fmt_exchange(&replied), fmt_exchange(&abandoned));
        assert!(a.contains("release") && b.contains("release"));
        assert!(a.contains('2'));
        assert!(b.contains("abandoned"));
        assert_ne!(a, b);
    }

    #[test]
    fn control_characters_from_a_process_are_shown_not_obeyed() {
        let line = clean("name\x1b[2Jwith\nescapes");
        assert!(!line.chars().any(char::is_control), "{line:?}");
        assert!(line.contains("name") && line.contains("escapes"));
        assert_eq!(clean("plain"), "plain");
        let record = Record {
            at_ns: 0,
            what: Happened::Event {
                name: "e".into(),
                ids: Ids::default(),
                detail: "\x1b]0;title\x07".into(),
            },
        };
        assert!(!fmt_record(&record).chars().any(char::is_control));
    }

    #[tokio::test]
    async fn a_capture_file_reads_back_as_written_and_refuses_another_revision() {
        let records = vec![
            Record {
                at_ns: 1,
                what: Happened::Dropped(2),
            },
            Record {
                at_ns: 3,
                what: Happened::Event {
                    name: "e".into(),
                    ids: Ids::default(),
                    detail: "d".into(),
                },
            },
        ];
        let mut file = Vec::new();
        write_preamble(&mut file).await.unwrap();
        for record in &records {
            write_record(&mut file, record.clone()).await.unwrap();
        }
        let mut input = file.as_slice();
        assert_eq!(read_preamble(&mut input).await, Ok(None));
        let mut back = Vec::new();
        while let Some(record) = read_record(&mut input).await.unwrap() {
            back.push(record);
        }
        assert_eq!(back, records);

        let mut other = capture_preamble();
        other[8] ^= 1;
        assert!(read_preamble(&mut other.as_slice()).await.is_err());
        let mut newer_frames = capture_preamble();
        newer_frames[16] ^= 1;
        assert!(matches!(
            read_preamble(&mut newer_frames.as_slice()).await,
            Ok(Some(_))
        ));
        assert!(read_preamble(&mut &b"not a capture at all...."[..])
            .await
            .is_err());
    }

    #[test]
    fn a_dumped_exchange_shows_its_frames_decoded() {
        let body = |frame: Vec<u8>| frame[4..].to_vec();
        let record = Record {
            at_ns: 0,
            what: Happened::Exchange(Exchange {
                side: "server".into(),
                every: 1,
                request: body(jackalopefs_proto::encode(&Request::Release { fh: 41 }).unwrap()),
                reply: body(jackalopefs_proto::encode(&Response::Ok).unwrap()),
                outcome: "replied".into(),
                ..Exchange::default()
            }),
        };
        let long = fmt_record_long(&record);
        assert!(long.lines().count() > fmt_record(&record).lines().count());
        assert!(long.contains("41"));
    }
}

//! What `jackalopefs-ctl` works out without a process to talk to: which processes there are, what a selector asks for, rates between two readings of the counters, and how a record reads.

use jackalopefs_proto::control::{Counters, Happened, Ids, Names, Record, Selection, Summary};
use std::collections::BTreeMap;
use std::fmt::Write as _;

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
    pub errors_per_second: f64,
    pub total: u64,
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
pub fn render_top(now: &Counters, events: &[RateEvent], ops: &[RateOp], seconds: f64) -> String {
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
    writeln!(
        out,
        "\n{:<8} {:<16} {:>9} {:>11} {:>10} {:>8} {:>10}",
        "level", "op", "per sec", "bytes/s", "mean", "err/s", "total"
    )
    .expect("a String takes any write");
    for op in ops {
        writeln!(
            out,
            "{:<8} {:<16} {:>9.1} {:>11} {:>10} {:>8.1} {:>10}",
            clean(&op.level),
            clean(&op.op),
            op.per_second,
            fmt_bytes(op.bytes_per_second),
            op.mean_ns.map_or_else(|| "-".to_owned(), fmt_ns),
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
}

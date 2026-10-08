//! The control protocol (`schema/control.capnp`): what `jackalopefs-ctl` asks a process over its local socket, and what comes back. The peer is the same user on the same host, so parsing checks the shape of what it reads and nothing more.

use crate::control_capnp as schema;
use crate::wire::{ErrorDecode, Message};
use capnp::message::{self, HeapAllocator, ReaderSegments};

/// Which names a subscriber wants.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Names {
    #[default]
    None,
    All,
    Some(Vec<String>),
}

impl Names {
    pub fn has(&self, name: &str) -> bool {
        match self {
            Names::None => false,
            Names::All => true,
            Names::Some(names) => names.iter().any(|n| n == name),
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Names::None)
    }
}

/// What a subscriber wants: event details by event name, request summaries by operation name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    pub events: Names,
    pub ops: Names,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ask {
    Counters,
    Subscribe(Selection),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlRequest {
    /// [`CONTROL_REVISION`](crate::CONTROL_REVISION) of the asker.
    pub revision: u64,
    pub ask: Ask,
}

/// One operation's totals since the process started, at one level: `fuse`, `call` or `request`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TotalOp {
    pub level: String,
    pub op: String,
    pub count: u64,
    pub bytes: u64,
    pub items: u64,
    pub errors: u64,
    pub total_ns: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub side: String,
    pub pid: u32,
    pub describe: String,
    pub uptime_ns: u64,
    pub inflight: u64,
    pub events: Vec<(String, u64)>,
    pub ops: Vec<TotalOp>,
}

/// The identifiers that join a record to the log lines and to the other side's records.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ids {
    pub session: Option<u64>,
    pub conn: Option<u64>,
    pub stream: Option<u64>,
    pub unique: Option<u64>,
    pub op: Option<String>,
}

/// One request answered, at its level.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub level: String,
    pub ids: Ids,
    pub fh: Option<u64>,
    pub offset: Option<u64>,
    pub size: Option<u64>,
    /// The kernel's inode and the process that asked, at the `fuse` level.
    pub ino: Option<u64>,
    pub pid: Option<u32>,
    pub bytes: u64,
    pub items: u64,
    pub errno: i32,
    pub phases: Vec<(String, u64)>,
    pub total_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Happened {
    Event {
        name: String,
        ids: Ids,
        detail: String,
    },
    Request(Summary),
    /// Records the process could not hold for this subscriber, since it last said.
    Dropped(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Unix time, in nanoseconds.
    pub at_ns: u64,
    pub what: Happened,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlReply {
    Counters(Counters),
    Record(Record),
    Refused(String),
}

/// Bits of a `present` field, for optional numbers.
fn present(values: &[Option<u64>]) -> u8 {
    values
        .iter()
        .enumerate()
        .filter(|(_, v)| v.is_some())
        .fold(0, |bits, (i, _)| bits | (1 << i))
}

fn optional(present: u8, bit: u8, value: u64) -> Option<u64> {
    (present & (1 << bit) != 0).then_some(value)
}

fn text(reader: capnp::text::Reader<'_>) -> Result<String, ErrorDecode> {
    reader
        .to_string()
        .map_err(|e| ErrorDecode::Invalid(format!("text is not UTF-8: {e}")))
}

fn build_names(mut b: schema::names::Builder<'_>, names: &Names) {
    match names {
        Names::None => b.set_none(()),
        Names::All => b.set_all(()),
        Names::Some(list) => {
            let mut out = b.init_some(list.len() as u32);
            for (i, name) in list.iter().enumerate() {
                out.set(i as u32, name.as_str());
            }
        }
    }
}

fn parse_names(r: schema::names::Reader<'_>) -> Result<Names, ErrorDecode> {
    Ok(match r.which()? {
        schema::names::None(()) => Names::None,
        schema::names::All(()) => Names::All,
        schema::names::Some(list) => Names::Some(
            list?
                .iter()
                .map(|name| text(name?))
                .collect::<Result<_, _>>()?,
        ),
    })
}

fn build_ids(mut b: schema::ids::Builder<'_>, ids: &Ids) {
    b.set_present(present(&[ids.session, ids.conn, ids.stream, ids.unique]));
    b.set_session(ids.session.unwrap_or(0));
    b.set_conn(ids.conn.unwrap_or(0));
    b.set_stream(ids.stream.unwrap_or(0));
    b.set_unique(ids.unique.unwrap_or(0));
    b.set_op(ids.op.as_deref().unwrap_or(""));
}

fn parse_ids(r: schema::ids::Reader<'_>) -> Result<Ids, ErrorDecode> {
    let p = r.get_present();
    let op = text(r.get_op()?)?;
    Ok(Ids {
        session: optional(p, 0, r.get_session()),
        conn: optional(p, 1, r.get_conn()),
        stream: optional(p, 2, r.get_stream()),
        unique: optional(p, 3, r.get_unique()),
        op: (!op.is_empty()).then_some(op),
    })
}

impl Message for ControlRequest {
    fn build(&self, message: &mut message::Builder<HeapAllocator>) {
        let mut b = message.init_root::<schema::control_request::Builder<'_>>();
        b.set_revision(self.revision);
        match &self.ask {
            Ask::Counters => b.set_counters(()),
            Ask::Subscribe(selection) => {
                let mut s = b.init_subscribe();
                build_names(s.reborrow().init_events(), &selection.events);
                build_names(s.init_ops(), &selection.ops);
            }
        }
    }

    fn parse<S: ReaderSegments>(message: &message::Reader<S>) -> Result<Self, ErrorDecode> {
        use schema::control_request::Which;
        let r = message.get_root::<schema::control_request::Reader<'_>>()?;
        let ask = match r.which()? {
            Which::Counters(()) => Ask::Counters,
            Which::Subscribe(s) => {
                let s = s?;
                Ask::Subscribe(Selection {
                    events: parse_names(s.get_events()?)?,
                    ops: parse_names(s.get_ops()?)?,
                })
            }
        };
        Ok(ControlRequest {
            revision: r.get_revision(),
            ask,
        })
    }

    fn size_hint(&self) -> u32 {
        64
    }
}

fn build_record(mut b: schema::record::Builder<'_>, record: &Record) {
    b.set_at_ns(record.at_ns);
    match &record.what {
        Happened::Event { name, ids, detail } => {
            let mut e = b.init_event();
            e.set_name(name.as_str());
            build_ids(e.reborrow().init_ids(), ids);
            e.set_detail(detail.as_str());
        }
        Happened::Request(s) => {
            let mut q = b.init_request();
            q.set_level(s.level.as_str());
            build_ids(q.reborrow().init_ids(), &s.ids);
            q.set_present(present(&[
                s.fh,
                s.offset,
                s.size,
                s.ino,
                s.pid.map(u64::from),
            ]));
            q.set_fh(s.fh.unwrap_or(0));
            q.set_offset(s.offset.unwrap_or(0));
            q.set_size(s.size.unwrap_or(0));
            q.set_ino(s.ino.unwrap_or(0));
            q.set_pid(s.pid.unwrap_or(0));
            q.set_bytes(s.bytes);
            q.set_items(s.items);
            q.set_errno(s.errno);
            let mut phases = q.reborrow().init_phases(s.phases.len() as u32);
            for (i, (name, ns)) in s.phases.iter().enumerate() {
                let mut p = phases.reborrow().get(i as u32);
                p.set_name(name.as_str());
                p.set_ns(*ns);
            }
            q.set_total_ns(s.total_ns);
        }
        Happened::Dropped(n) => b.set_dropped(*n),
    }
}

fn parse_record(r: schema::record::Reader<'_>) -> Result<Record, ErrorDecode> {
    use schema::record::Which;
    let what = match r.which()? {
        Which::Event(e) => Happened::Event {
            name: text(e.get_name()?)?,
            ids: parse_ids(e.get_ids()?)?,
            detail: text(e.get_detail()?)?,
        },
        Which::Request(q) => {
            let p = q.get_present();
            Happened::Request(Summary {
                level: text(q.get_level()?)?,
                ids: parse_ids(q.get_ids()?)?,
                fh: optional(p, 0, q.get_fh()),
                offset: optional(p, 1, q.get_offset()),
                size: optional(p, 2, q.get_size()),
                ino: optional(p, 3, q.get_ino()),
                pid: optional(p, 4, u64::from(q.get_pid())).map(|pid| pid as u32),
                bytes: q.get_bytes(),
                items: q.get_items(),
                errno: q.get_errno(),
                phases: q
                    .get_phases()?
                    .iter()
                    .map(|p| Ok((text(p.get_name()?)?, p.get_ns())))
                    .collect::<Result<_, ErrorDecode>>()?,
                total_ns: q.get_total_ns(),
            })
        }
        Which::Dropped(n) => Happened::Dropped(n),
    };
    Ok(Record {
        at_ns: r.get_at_ns(),
        what,
    })
}

impl Message for ControlReply {
    fn build(&self, message: &mut message::Builder<HeapAllocator>) {
        let mut b = message.init_root::<schema::control_reply::Builder<'_>>();
        match self {
            ControlReply::Counters(c) => {
                let mut o = b.init_counters();
                o.set_side(c.side.as_str());
                o.set_pid(c.pid);
                o.set_describe(c.describe.as_str());
                o.set_uptime_ns(c.uptime_ns);
                o.set_inflight(c.inflight);
                let mut events = o.reborrow().init_events(c.events.len() as u32);
                for (i, (name, value)) in c.events.iter().enumerate() {
                    let mut e = events.reborrow().get(i as u32);
                    e.set_name(name.as_str());
                    e.set_value(*value);
                }
                let mut ops = o.init_ops(c.ops.len() as u32);
                for (i, t) in c.ops.iter().enumerate() {
                    let mut o = ops.reborrow().get(i as u32);
                    o.set_level(t.level.as_str());
                    o.set_op(t.op.as_str());
                    o.set_count(t.count);
                    o.set_bytes(t.bytes);
                    o.set_items(t.items);
                    o.set_errors(t.errors);
                    o.set_total_ns(t.total_ns);
                }
            }
            ControlReply::Record(record) => build_record(b.init_record(), record),
            ControlReply::Refused(why) => b.set_refused(why.as_str()),
        }
    }

    fn parse<S: ReaderSegments>(message: &message::Reader<S>) -> Result<Self, ErrorDecode> {
        use schema::control_reply::Which;
        let r = message.get_root::<schema::control_reply::Reader<'_>>()?;
        Ok(match r.which()? {
            Which::Counters(c) => {
                let c = c?;
                ControlReply::Counters(Counters {
                    side: text(c.get_side()?)?,
                    pid: c.get_pid(),
                    describe: text(c.get_describe()?)?,
                    uptime_ns: c.get_uptime_ns(),
                    inflight: c.get_inflight(),
                    events: c
                        .get_events()?
                        .iter()
                        .map(|e| Ok((text(e.get_name()?)?, e.get_value())))
                        .collect::<Result<_, ErrorDecode>>()?,
                    ops: c
                        .get_ops()?
                        .iter()
                        .map(|o| {
                            Ok(TotalOp {
                                level: text(o.get_level()?)?,
                                op: text(o.get_op()?)?,
                                count: o.get_count(),
                                bytes: o.get_bytes(),
                                items: o.get_items(),
                                errors: o.get_errors(),
                                total_ns: o.get_total_ns(),
                            })
                        })
                        .collect::<Result<_, ErrorDecode>>()?,
                })
            }
            Which::Record(record) => ControlReply::Record(parse_record(record?)?),
            Which::Refused(why) => ControlReply::Refused(text(why?)?),
        })
    }

    fn size_hint(&self) -> u32 {
        match self {
            ControlReply::Counters(c) => 32 + 8 * (c.events.len() + 4 * c.ops.len()) as u32,
            ControlReply::Record(Record {
                what: Happened::Event { detail, .. },
                ..
            }) => 32 + (detail.len() / 8) as u32,
            _ => 64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode, encode};

    fn round_trip<T: Message + PartialEq + std::fmt::Debug>(msg: &T) {
        let frame = encode(msg).unwrap();
        assert_eq!(&decode::<T>(&frame[4..]).unwrap(), msg);
    }

    #[test]
    fn control_messages_round_trip() {
        round_trip(&ControlRequest {
            revision: 7,
            ask: Ask::Counters,
        });
        round_trip(&ControlRequest {
            revision: 7,
            ask: Ask::Subscribe(Selection {
                events: Names::Some(vec!["call_lost_retried".into()]),
                ops: Names::All,
            }),
        });
        round_trip(&ControlReply::Counters(Counters {
            side: "client".into(),
            pid: 42,
            describe: "/mnt from host".into(),
            uptime_ns: 5,
            inflight: 2,
            events: vec![("interrupt".into(), 3)],
            ops: vec![TotalOp {
                level: "call".into(),
                op: "read".into(),
                count: 9,
                bytes: 4096,
                items: 0,
                errors: 1,
                total_ns: 1000,
            }],
        }));
        round_trip(&ControlReply::Record(Record {
            at_ns: 11,
            what: Happened::Event {
                name: "reply_stalled".into(),
                ids: Ids {
                    session: Some(1),
                    conn: None,
                    stream: Some(0),
                    unique: None,
                    op: Some("read".into()),
                },
                detail: "detail".into(),
            },
        }));
        round_trip(&ControlReply::Record(Record {
            at_ns: 12,
            what: Happened::Request(Summary {
                level: "request".into(),
                ids: Ids::default(),
                fh: Some(3),
                offset: None,
                size: Some(0),
                ino: Some(5),
                pid: None,
                bytes: 10,
                items: 0,
                errno: 2,
                phases: vec![("read".into(), 5)],
                total_ns: 9,
            }),
        }));
        round_trip(&ControlReply::Record(Record {
            at_ns: 13,
            what: Happened::Dropped(4),
        }));
        round_trip(&ControlReply::Refused("no".into()));
    }
}

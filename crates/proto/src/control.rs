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

/// What a subscriber wants: event details by event name, request summaries by operation name, and with `frames` the frames themselves, one exchange in `every` (of the operations `ops` names, when it names any) and one event frame in `every`; without `payloads`, the data of reads and writes is cut from them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    pub events: Names,
    pub ops: Names,
    pub frames: bool,
    pub every: u32,
    pub payloads: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ask {
    Counters,
    Subscribe(Selection),
    /// During a subscription: what is still queued, a census, and the end.
    Census,
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

/// What a process has used since it started; see `Resources` in the schema.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Resources {
    pub user_ns: u64,
    pub sys_ns: u64,
    pub voluntary_switches: u64,
    pub involuntary_switches: u64,
    pub workers: u32,
    pub busy_ns: u64,
    pub parks: u64,
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
    pub resources: Resources,
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

/// One request and its reply as they crossed the wire.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exchange {
    /// `client` or `server`.
    pub side: String,
    pub ids: Ids,
    pub every: u32,
    /// The request's body as sent: the message without its length prefix.
    pub request: Vec<u8>,
    /// Bytes of data cut from the request; 0 when none were.
    pub request_elided: u64,
    /// The reply's body, empty when there was none.
    pub reply: Vec<u8>,
    pub reply_elided: u64,
    /// `replied`, or why there is no reply.
    pub outcome: String,
    pub elapsed_ns: u64,
}

/// One operation in a capture: exchanges there were while it lasted, those chosen, and those of them dropped because the reader fell behind.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CensusOp {
    pub op: String,
    pub seen: u64,
    pub sampled: u64,
    pub dropped: u64,
}

/// The first record of a capture file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub proto_revision: u64,
    pub control_revision: u64,
    pub side: String,
    pub pid: u32,
    pub describe: String,
    pub selection: Selection,
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
    Exchange(Exchange),
    /// A frame that did not decode, as it was read.
    Undecodable {
        side: String,
        ids: Ids,
        error: String,
        body: Vec<u8>,
    },
    /// A batch of change events, as it crossed the wire: the `seq`th the stream carried.
    EventFrame {
        side: String,
        ids: Ids,
        every: u32,
        seq: u64,
        body: Vec<u8>,
    },
    Header(Header),
    /// The last record of a capture: per operation, requests seen and exchanges held, and the records lost.
    Census {
        ops: Vec<CensusOp>,
        dropped: u64,
    },
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

fn build_selection(mut b: schema::selection::Builder<'_>, selection: &Selection) {
    build_names(b.reborrow().init_events(), &selection.events);
    build_names(b.reborrow().init_ops(), &selection.ops);
    b.set_frames(selection.frames);
    b.set_every(selection.every);
    b.set_payloads(selection.payloads);
}

fn parse_selection(r: schema::selection::Reader<'_>) -> Result<Selection, ErrorDecode> {
    Ok(Selection {
        events: parse_names(r.get_events()?)?,
        ops: parse_names(r.get_ops()?)?,
        frames: r.get_frames(),
        every: r.get_every(),
        payloads: r.get_payloads(),
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
            Ask::Subscribe(selection) => build_selection(b.init_subscribe(), selection),
            Ask::Census => b.set_census(()),
        }
    }

    fn parse<S: ReaderSegments>(message: &message::Reader<S>) -> Result<Self, ErrorDecode> {
        use schema::control_request::Which;
        let r = message.get_root::<schema::control_request::Reader<'_>>()?;
        let ask = match r.which()? {
            Which::Counters(()) => Ask::Counters,
            Which::Subscribe(s) => Ask::Subscribe(parse_selection(s?)?),
            Which::Census(()) => Ask::Census,
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
        Happened::Exchange(x) => {
            let mut e = b.init_exchange();
            e.set_side(x.side.as_str());
            build_ids(e.reborrow().init_ids(), &x.ids);
            e.set_every(x.every);
            e.set_request(&x.request);
            e.set_request_elided(x.request_elided);
            e.set_reply(&x.reply);
            e.set_reply_elided(x.reply_elided);
            e.set_outcome(x.outcome.as_str());
            e.set_elapsed_ns(x.elapsed_ns);
        }
        Happened::Undecodable {
            side,
            ids,
            error,
            body,
        } => {
            let mut u = b.init_undecodable();
            u.set_side(side.as_str());
            build_ids(u.reborrow().init_ids(), ids);
            u.set_error(error.as_str());
            u.set_body(body);
        }
        Happened::EventFrame {
            side,
            ids,
            every,
            seq,
            body,
        } => {
            let mut f = b.init_event_frame();
            f.set_side(side.as_str());
            build_ids(f.reborrow().init_ids(), ids);
            f.set_every(*every);
            f.set_seq(*seq);
            f.set_body(body);
        }
        Happened::Header(h) => {
            let mut o = b.init_header();
            o.set_proto_revision(h.proto_revision);
            o.set_control_revision(h.control_revision);
            o.set_side(h.side.as_str());
            o.set_pid(h.pid);
            o.set_describe(h.describe.as_str());
            build_selection(o.init_selection(), &h.selection);
        }
        Happened::Census { ops, dropped } => {
            let mut c = b.init_census();
            c.set_dropped(*dropped);
            let mut list = c.init_ops(ops.len() as u32);
            for (i, op) in ops.iter().enumerate() {
                let mut o = list.reborrow().get(i as u32);
                o.set_op(op.op.as_str());
                o.set_seen(op.seen);
                o.set_sampled(op.sampled);
                o.set_dropped(op.dropped);
            }
        }
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
        Which::Exchange(e) => Happened::Exchange(Exchange {
            side: text(e.get_side()?)?,
            ids: parse_ids(e.get_ids()?)?,
            every: e.get_every(),
            request: e.get_request()?.to_vec(),
            request_elided: e.get_request_elided(),
            reply: e.get_reply()?.to_vec(),
            reply_elided: e.get_reply_elided(),
            outcome: text(e.get_outcome()?)?,
            elapsed_ns: e.get_elapsed_ns(),
        }),
        Which::Undecodable(u) => Happened::Undecodable {
            side: text(u.get_side()?)?,
            ids: parse_ids(u.get_ids()?)?,
            error: text(u.get_error()?)?,
            body: u.get_body()?.to_vec(),
        },
        Which::EventFrame(f) => Happened::EventFrame {
            side: text(f.get_side()?)?,
            ids: parse_ids(f.get_ids()?)?,
            every: f.get_every(),
            seq: f.get_seq(),
            body: f.get_body()?.to_vec(),
        },
        Which::Header(h) => Happened::Header(Header {
            proto_revision: h.get_proto_revision(),
            control_revision: h.get_control_revision(),
            side: text(h.get_side()?)?,
            pid: h.get_pid(),
            describe: text(h.get_describe()?)?,
            selection: parse_selection(h.get_selection()?)?,
        }),
        Which::Census(c) => Happened::Census {
            ops: c
                .get_ops()?
                .iter()
                .map(|o| {
                    Ok(CensusOp {
                        op: text(o.get_op()?)?,
                        seen: o.get_seen(),
                        sampled: o.get_sampled(),
                        dropped: o.get_dropped(),
                    })
                })
                .collect::<Result<_, ErrorDecode>>()?,
            dropped: c.get_dropped(),
        },
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
                let mut r = o.reborrow().init_resources();
                r.set_user_ns(c.resources.user_ns);
                r.set_sys_ns(c.resources.sys_ns);
                r.set_voluntary_switches(c.resources.voluntary_switches);
                r.set_involuntary_switches(c.resources.involuntary_switches);
                r.set_workers(c.resources.workers);
                r.set_busy_ns(c.resources.busy_ns);
                r.set_parks(c.resources.parks);
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
                    resources: {
                        let r = c.get_resources()?;
                        Resources {
                            user_ns: r.get_user_ns(),
                            sys_ns: r.get_sys_ns(),
                            voluntary_switches: r.get_voluntary_switches(),
                            involuntary_switches: r.get_involuntary_switches(),
                            workers: r.get_workers(),
                            busy_ns: r.get_busy_ns(),
                            parks: r.get_parks(),
                        }
                    },
                })
            }
            Which::Record(record) => ControlReply::Record(parse_record(record?)?),
            Which::Refused(why) => ControlReply::Refused(text(why?)?),
        })
    }

    fn size_hint(&self) -> u32 {
        match self {
            ControlReply::Counters(c) => 48 + 8 * (c.events.len() + 4 * c.ops.len()) as u32,
            ControlReply::Record(Record {
                what: Happened::Event { detail, .. },
                ..
            }) => 32 + (detail.len() / 8) as u32,
            ControlReply::Record(Record {
                what: Happened::Exchange(x),
                ..
            }) => 48 + ((x.request.len() + x.reply.len()) / 8) as u32,
            ControlReply::Record(Record {
                what: Happened::Undecodable { body, .. } | Happened::EventFrame { body, .. },
                ..
            }) => 32 + (body.len() / 8) as u32,
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
            ask: Ask::Census,
        });
        round_trip(&ControlRequest {
            revision: 7,
            ask: Ask::Subscribe(Selection {
                events: Names::Some(vec!["call_lost_retried".into()]),
                ops: Names::All,
                frames: true,
                every: 4,
                payloads: false,
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
            resources: Resources {
                user_ns: 1,
                sys_ns: 2,
                voluntary_switches: 3,
                involuntary_switches: 4,
                workers: 5,
                busy_ns: 6,
                parks: 7,
            },
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
        round_trip(&ControlReply::Record(Record {
            at_ns: 14,
            what: Happened::Exchange(Exchange {
                side: "client".into(),
                ids: Ids {
                    conn: Some(9),
                    stream: Some(4),
                    ..Ids::default()
                },
                every: 4,
                request: vec![1, 2, 3],
                request_elided: 0,
                reply: vec![4, 5],
                reply_elided: 4096,
                outcome: "replied".into(),
                elapsed_ns: 77,
            }),
        }));
        round_trip(&ControlReply::Record(Record {
            at_ns: 15,
            what: Happened::Header(Header {
                proto_revision: 1,
                control_revision: 2,
                side: "server".into(),
                pid: 3,
                describe: "/srv".into(),
                selection: Selection {
                    frames: true,
                    every: 8,
                    ..Selection::default()
                },
            }),
        }));
        round_trip(&ControlReply::Record(Record {
            at_ns: 16,
            what: Happened::Census {
                ops: vec![CensusOp {
                    op: "read".into(),
                    seen: 100,
                    sampled: 12,
                    dropped: 2,
                }],
                dropped: 1,
            },
        }));
        round_trip(&ControlReply::Record(Record {
            at_ns: 17,
            what: Happened::Undecodable {
                side: "server".into(),
                ids: Ids::default(),
                error: "bad".into(),
                body: vec![0; 9],
            },
        }));
        round_trip(&ControlReply::Refused("no".into()));
    }

    #[test]
    fn the_largest_records_still_fit_a_frame() {
        let write = crate::codec::encode(&crate::Request::Write {
            fh: 1,
            offset: 0,
            data: vec![7; crate::MAX_IO],
        })
        .unwrap();
        let exchange = ControlReply::Record(Record {
            at_ns: 0,
            what: Happened::Exchange(Exchange {
                side: "client".into(),
                request: write[4..].to_vec(),
                reply: vec![0; 64],
                outcome: "replied".into(),
                ..Exchange::default()
            }),
        });
        assert!(encode(&exchange).is_ok());
        let undecodable = ControlReply::Record(Record {
            at_ns: 0,
            what: Happened::Undecodable {
                side: "server".into(),
                ids: Ids::default(),
                error: "bad".into(),
                body: vec![0; 1 << 20],
            },
        });
        assert!(encode(&undecodable).is_ok());
    }
}

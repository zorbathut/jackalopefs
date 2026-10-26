//! What the client and the server did, in the session model's terms (`spec/session.qnt`), recorded for a test to replay against the model (`spec/replay.qnt`). The client and server record only when built with their `spec-trace` feature, which nothing but the trace-validation tests turns on.
//!
//! What each event means is modelled in `spec/session.qnt`, through `spec/replay.qnt`'s mapping of it; a change to them updates the replay, or its commit says why not (`spec/README.md`, "Keeping it in sync").
//!
//! One [`Recorder`] is shared by a test's client and server, so its events form one order. Each is recorded where it takes effect: under the lock that orders it against the others where there is one (the server's attachment lock for the fence, `begin`, a cancel's verdict and a change's end; the client's count of pending cancels for a send), else on the task that did it, right after, where events of different tasks are ordered only by when they were recorded (`spec/README.md`, "Trace validation", says how replay allows for that).

use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// A connection, by the key both ends derive from it (`conn_key`), and a stream on it: one exchange, as both ends name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyExchange {
    pub conn: u64,
    pub stream: u64,
}

/// What the client sends an exchange for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// A call, by the number [`Recorder::call`] gave it.
    Call(u64),
    /// The reopen of a handle after a new session.
    Reopen(u64),
    /// A release sent by the connection's release task: owed, or of a handle a reopen lost.
    Owed(u64),
}

/// What a call asks for, as the model tells calls apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KindCall {
    /// A request that takes part in the ordering and keeps no handle.
    Change,
    /// An open, a create or an opendir, under handle `fh`.
    Open { fh: u64 },
    /// A release of handle `fh`: the kernel's when not `ordered`, else one the client sends on its own.
    Release { fh: u64, ordered: bool },
    /// Anything the model leaves out (reads, `fsync`).
    Other,
}

/// How a call's attempt ended short of an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Given up on (interrupt, `--op-timeout`, the offline deadline); `counted` when the exchange counted a cancel on the connection.
    GaveUp { written: bool, counted: bool },
    /// The frame did not reach the stream whole; the call waits for a newer connection.
    NotSent,
    /// The stream failed after the frame was written: the connection went.
    Lost,
    /// A handle the request names is dead; nothing was sent.
    Stale,
    /// Anything else the call failed with.
    Other,
}

/// The counts of a session's attachment, after an event changed them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub epoch: u64,
    pub running: usize,
    pub abandoned: usize,
    pub running_older: usize,
}

/// How a request the server decoded and held left the hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndHeld {
    Drained,
    /// Its connection stopped being the session's current one.
    Superseded,
    /// The client stopped reading its reply.
    Stopped,
    /// Its connection went.
    Lost,
}

/// Why a request's frame was never decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CauseUndecoded {
    /// The client reset its stream or ended it early: it gave up.
    Reset,
    /// The stream failed: its connection went.
    Lost,
    /// The frame was malformed, or did not come whole in time.
    Other,
}

/// How the server's `SessionState::begin` took a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Begun {
    Running,
    Superseded,
    /// The client's cancel got there first.
    Cancelled,
}

/// What the server answered a cancel with (`SessionState::abandon`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Unrun,
    Fenced,
    Finished,
}

/// An event; an `op` is the request's operation, for the trace's log, which replay does not read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventSpec {
    // The client.
    /// A connection is up (`generation`), attached to `session`, resumed or new.
    Connected {
        generation: u64,
        conn: u64,
        session: u64,
        resumed: bool,
    },
    /// The connection is published: calls may use it.
    Published { conn: u64 },
    /// The connection manager saw the connection end.
    ConnLost { conn: u64 },
    /// A call starts.
    CallStarted {
        call: u64,
        op: &'static str,
        kind: KindCall,
        resendable: bool,
    },
    /// A call has its connection and, for a change, has seen the connection's pending cancels answered: it is about to send.
    CallReady { call: u64, conn: u64 },
    /// The connection's release task is about to send the release of handle `fh`, its pending cancels answered.
    ReleaseReady { fh: u64, conn: u64 },
    /// An exchange opened its stream and is about to write its frame, so the server cannot decode it before this is recorded; a give-up before the frame is written whole says so (`Failure::GaveUp`'s `written`).
    Stream { origin: Origin, key: KeyExchange },
    /// An exchange's reply came: `errno` when it was one.
    Answered {
        origin: Origin,
        key: KeyExchange,
        errno: bool,
    },
    /// An attempt ended without an answer: on connection `conn` once it had one, on stream `stream` once it had opened one.
    Failed {
        origin: Origin,
        conn: Option<u64>,
        stream: Option<u64>,
        failure: Failure,
    },
    /// The server's answer to a change given up on came, read in the background: `verdict` as `client::verdict_of` names it.
    CancelAnswered {
        key: KeyExchange,
        verdict: &'static str,
    },
    /// A release is owed.
    Owed { fh: u64 },

    // The server.
    /// `Sessions::create` made a session.
    Created { session: u64 },
    /// `Sessions::resume` attached the session again; `dropped` when it came back from the dropped ones.
    Resumed {
        session: u64,
        counts: Counts,
        dropped: bool,
    },
    /// The handshake failed after the session was attached, before its Ack was written (`DetachUnlessAcked`).
    HandshakeFailed { session: u64, resumed: bool },
    /// The handshake's Ack was written: the connection carries the session at `epoch`.
    Attached { session: u64, epoch: u64, conn: u64 },
    /// The server's task for the connection ended.
    ConnEnded { conn: u64 },
    /// The session left the table (grace run out, or evicted).
    SessionDropped { session: u64 },
    /// The session's last reference went; its handles closed.
    SessionClosed { session: u64 },
    /// A request was decoded; a change was `held` if the fence was above zero.
    Decoded {
        key: KeyExchange,
        op: &'static str,
        change: bool,
        held: bool,
    },
    /// A request ended before it was decoded.
    Undecoded {
        key: KeyExchange,
        cause: CauseUndecoded,
    },
    /// A held request left the hold.
    HeldEnded { key: KeyExchange, end: EndHeld },
    /// A request began on its blocking thread; for a change, `counts` after.
    Began {
        key: KeyExchange,
        begun: Begun,
        counts: Option<Counts>,
    },
    /// `Handles::reserve` found the open's id held (`kept`) or took a slot.
    Reserved { session: u64, fh: u64, kept: bool },
    /// A cancel reached a decoded request; for a change, `counts` after.
    Abandoned {
        key: KeyExchange,
        verdict: Verdict,
        counts: Counts,
    },
    /// A request's work ended, with an errno or not; for a change, `counts` after it was uncounted.
    Finished {
        key: KeyExchange,
        errno: bool,
        counts: Option<Counts>,
    },
}

/// The events of one test, in the order they took effect.
#[derive(Default)]
pub struct Recorder {
    events: Mutex<Vec<EventSpec>>,
    calls: AtomicU64,
}

impl Recorder {
    pub fn record(&self, event: EventSpec) {
        self.events.lock().push(event);
    }

    /// A number for a new call, from 1.
    pub fn call(&self) -> u64 {
        self.calls.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn events(&self) -> Vec<EventSpec> {
        self.events.lock().clone()
    }
}

pub mod quint {
    //! The recorded events as `spec/replay.qnt`'s `Ev` records. Connections become the client's generations, which the client's `Connected` events name; a connection the client never had (a handshake that failed before its Ack reached it) is generation 0, which replay passes over.

    use super::{
        Begun, CauseUndecoded, Counts, EndHeld, EventSpec, Failure, KeyExchange, KindCall, Origin,
        Verdict,
    };
    use std::collections::HashMap;
    use std::fmt::Write;

    /// `name` as a Quint identifier.
    pub fn ident(name: &str) -> String {
        name.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect()
    }
    /// One field of an `Ev`, written as `.with(...)`.
    #[derive(Clone)]
    enum Field {
        Int(&'static str, u64),
        Bool(&'static str, bool),
        Str(&'static str, &'static str),
    }

    /// A Quint fragment: the trace as `pure val T_<name>`, and the run replaying it.
    pub fn fragment(name: &str, events: &[EventSpec]) -> String {
        let generations: HashMap<u64, u64> = events
            .iter()
            .filter_map(|e| match e {
                EventSpec::Connected {
                    generation, conn, ..
                } => Some((*conn, *generation)),
                _ => None,
            })
            .collect();
        let mut out = format!("  pure val T_{name}: List[Ev] = [\n");
        for (i, event) in events.iter().enumerate() {
            let (kind, fields) =
                fields(event, &|conn| generations.get(&conn).copied().unwrap_or(0));
            write!(out, "    ev(\"{kind}\")").unwrap();
            for field in fields {
                match field {
                    Field::Int(name, value) => write!(out, ".with(\"{name}\", {value})"),
                    Field::Bool(name, value) => write!(out, ".with(\"{name}\", {value})"),
                    Field::Str(name, value) => write!(out, ".with(\"{name}\", \"{value}\")"),
                }
                .unwrap();
            }
            writeln!(out, ", // {i}").unwrap();
        }
        writeln!(out, "  ]").unwrap();
        writeln!(out, "  run {name}Test = replayInit.then((3 * T_{name}.length()).reps(i => replayStep(T_{name}))).expect(replayed(T_{name}))").unwrap();
        out
    }

    fn origin(origin: Origin) -> Vec<Field> {
        match origin {
            Origin::Call(call) => vec![Field::Str("origin", "call"), Field::Int("call", call)],
            Origin::Reopen(fh) => vec![Field::Str("origin", "reopen"), Field::Int("fh", fh)],
            Origin::Owed(fh) => vec![Field::Str("origin", "owed"), Field::Int("fh", fh)],
        }
    }

    fn counts(counts: Option<Counts>) -> Vec<Field> {
        match counts {
            None => Vec::new(),
            Some(c) => vec![
                Field::Bool("counts", true),
                Field::Int("epoch", c.epoch),
                Field::Int("running", c.running as u64),
                Field::Int("abandoned", c.abandoned as u64),
                Field::Int("older", c.running_older as u64),
            ],
        }
    }

    fn fields(event: &EventSpec, gen_of: &dyn Fn(u64) -> u64) -> (&'static str, Vec<Field>) {
        let key = |k: &KeyExchange| {
            vec![
                Field::Int("gen", gen_of(k.conn)),
                Field::Int("stream", k.stream),
            ]
        };
        match event {
            EventSpec::Connected {
                generation,
                session,
                resumed,
                ..
            } => (
                "connected",
                vec![
                    Field::Int("gen", *generation),
                    Field::Int("session", *session),
                    Field::Bool("resumed", *resumed),
                ],
            ),
            EventSpec::Published { conn } => ("published", vec![Field::Int("gen", gen_of(*conn))]),
            EventSpec::ConnLost { conn } => ("connlost", vec![Field::Int("gen", gen_of(*conn))]),
            EventSpec::CallStarted {
                call,
                kind,
                resendable,
                ..
            } => {
                let mut f = vec![
                    Field::Str("origin", "call"),
                    Field::Int("call", *call),
                    Field::Bool("resendable", *resendable),
                ];
                f.extend(match kind {
                    KindCall::Change => vec![Field::Str("ckind", "change")],
                    KindCall::Open { fh } => {
                        vec![Field::Str("ckind", "open"), Field::Int("fh", *fh)]
                    }
                    KindCall::Release { fh, ordered } => vec![
                        Field::Str("ckind", "release"),
                        Field::Int("fh", *fh),
                        Field::Bool("ordered", *ordered),
                    ],
                    KindCall::Other => vec![Field::Str("ckind", "other")],
                });
                ("callstarted", f)
            }
            EventSpec::CallReady { call, conn } => (
                "callready",
                vec![
                    Field::Str("origin", "call"),
                    Field::Int("call", *call),
                    Field::Int("gen", gen_of(*conn)),
                ],
            ),
            EventSpec::Stream { origin: o, key: k } => ("stream", [origin(*o), key(k)].concat()),
            EventSpec::Answered {
                origin: o,
                key: k,
                errno,
            } => (
                "answered",
                [origin(*o), key(k), vec![Field::Bool("errno", *errno)]].concat(),
            ),
            EventSpec::Failed {
                origin: o,
                conn,
                stream,
                failure,
            } => {
                let mut f = origin(*o);
                f.push(Field::Int("gen", conn.map_or(0, gen_of)));
                f.push(Field::Int("stream", stream.unwrap_or(0)));
                f.extend(match failure {
                    Failure::GaveUp { written, counted } => vec![
                        Field::Str("failure", "gaveup"),
                        Field::Bool("written", *written),
                        Field::Bool("counted", *counted),
                    ],
                    Failure::NotSent => vec![Field::Str("failure", "notsent")],
                    Failure::Lost => vec![Field::Str("failure", "lost")],
                    Failure::Stale => vec![Field::Str("failure", "stale")],
                    Failure::Other => vec![Field::Str("failure", "other")],
                });
                ("failed", f)
            }
            EventSpec::ReleaseReady { fh, conn } => (
                "releaseready",
                vec![
                    Field::Str("origin", "owed"),
                    Field::Int("fh", *fh),
                    Field::Int("gen", gen_of(*conn)),
                ],
            ),
            EventSpec::CancelAnswered { key: k, verdict } => (
                "cancelanswered",
                [key(k), vec![Field::Str("verdict", verdict)]].concat(),
            ),
            EventSpec::Owed { fh } => ("owed", vec![Field::Int("fh", *fh)]),
            EventSpec::Created { session } => ("created", vec![Field::Int("session", *session)]),
            EventSpec::Resumed {
                session,
                counts: c,
                dropped,
            } => (
                "resumed",
                [
                    vec![
                        Field::Int("session", *session),
                        Field::Bool("dropped", *dropped),
                    ],
                    counts(Some(*c)),
                ]
                .concat(),
            ),
            EventSpec::HandshakeFailed { session, resumed } => (
                "handshakefailed",
                vec![
                    Field::Int("session", *session),
                    Field::Bool("resumed", *resumed),
                ],
            ),
            EventSpec::Attached {
                session,
                epoch,
                conn,
            } => (
                "attached",
                vec![
                    Field::Int("session", *session),
                    Field::Int("epoch", *epoch),
                    Field::Int("gen", gen_of(*conn)),
                ],
            ),
            EventSpec::ConnEnded { conn } => ("connended", vec![Field::Int("gen", gen_of(*conn))]),
            EventSpec::SessionDropped { session } => {
                ("sessiondropped", vec![Field::Int("session", *session)])
            }
            EventSpec::SessionClosed { session } => {
                ("sessionclosed", vec![Field::Int("session", *session)])
            }
            EventSpec::Decoded {
                key: k,
                change,
                held,
                ..
            } => (
                "decoded",
                [
                    key(k),
                    vec![Field::Bool("change", *change), Field::Bool("held", *held)],
                ]
                .concat(),
            ),
            EventSpec::Undecoded { key: k, cause } => {
                let cause = match cause {
                    CauseUndecoded::Reset => "reset",
                    CauseUndecoded::Lost => "lost",
                    CauseUndecoded::Other => "other",
                };
                (
                    "undecoded",
                    [key(k), vec![Field::Str("cause", cause)]].concat(),
                )
            }
            EventSpec::HeldEnded { key: k, end } => {
                let end = match end {
                    EndHeld::Drained => "drained",
                    EndHeld::Superseded => "superseded",
                    EndHeld::Stopped => "stopped",
                    EndHeld::Lost => "lost",
                };
                ("heldended", [key(k), vec![Field::Str("end", end)]].concat())
            }
            EventSpec::Began {
                key: k,
                begun,
                counts: c,
            } => {
                let begun = match begun {
                    Begun::Running => "running",
                    Begun::Superseded => "superseded",
                    Begun::Cancelled => "cancelled",
                };
                (
                    "began",
                    [key(k), vec![Field::Str("begun", begun)], counts(*c)].concat(),
                )
            }
            EventSpec::Reserved { session, fh, kept } => (
                "reserved",
                vec![
                    Field::Int("session", *session),
                    Field::Int("fh", *fh),
                    Field::Bool("kept", *kept),
                ],
            ),
            EventSpec::Abandoned {
                key: k,
                verdict,
                counts: c,
            } => {
                let verdict = match verdict {
                    Verdict::Unrun => "unrun",
                    Verdict::Fenced => "fenced",
                    Verdict::Finished => "finished",
                };
                (
                    "abandoned",
                    [
                        key(k),
                        vec![Field::Str("verdict", verdict)],
                        counts(Some(*c)),
                    ]
                    .concat(),
                )
            }
            EventSpec::Finished {
                key: k,
                errno,
                counts: c,
            } => (
                "finished",
                [key(k), vec![Field::Bool("errno", *errno)], counts(*c)].concat(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trace_is_written_as_replay_events_with_connections_by_generation() {
        let key = KeyExchange {
            conn: 0xdead_beef_0000_0001,
            stream: 4,
        };
        let events = [
            EventSpec::Connected {
                generation: 1,
                conn: key.conn,
                session: 1,
                resumed: false,
            },
            EventSpec::CallStarted {
                call: 1,
                op: "mkdir",
                kind: KindCall::Change,
                resendable: false,
            },
            EventSpec::Stream {
                origin: Origin::Call(1),
                key,
            },
            EventSpec::Decoded {
                key,
                op: "mkdir",
                change: true,
                held: false,
            },
            EventSpec::Finished {
                key,
                errno: true,
                counts: Some(Counts {
                    epoch: 1,
                    running: 0,
                    abandoned: 0,
                    running_older: 0,
                }),
            },
            EventSpec::ConnEnded { conn: 7 },
        ];
        assert_eq!(
            quint::fragment("t", &events),
            r#"  pure val T_t: List[Ev] = [
    ev("connected").with("gen", 1).with("session", 1).with("resumed", false), // 0
    ev("callstarted").with("origin", "call").with("call", 1).with("resendable", false).with("ckind", "change"), // 1
    ev("stream").with("origin", "call").with("call", 1).with("gen", 1).with("stream", 4), // 2
    ev("decoded").with("gen", 1).with("stream", 4).with("change", true).with("held", false), // 3
    ev("finished").with("gen", 1).with("stream", 4).with("errno", true).with("counts", true).with("epoch", 1).with("running", 0).with("abandoned", 0).with("older", 0), // 4
    ev("connended").with("gen", 0), // 5
  ]
  run tTest = replayInit.then((3 * T_t.length()).reps(i => replayStep(T_t))).expect(replayed(T_t))
"#
        );
    }

    #[test]
    fn a_test_name_becomes_an_identifier() {
        assert_eq!(
            quint::ident("Write_Faulted(ReplyLost)"),
            "write_faulted_replylost_"
        );
    }
}

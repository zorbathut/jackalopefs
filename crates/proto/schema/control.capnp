@0x804f2961addfb047;

# The control protocol between a jackalopefs process and jackalopefs-ctl, over
# the process's local socket (docs/design.md, "Control socket"). It is not the
# wire protocol: this file has its own revision (CONTROL_REVISION in
# crates/proto/src/lib.rs, the hash of this file), which every request carries
# and the process checks. Frames are the wire protocol's: a little-endian u32
# length, then one single-segment message.

# A name selection: nothing, everything, or the names listed.
struct Names {
  union {
    none @0 :Void;
    all @1 :Void;
    some @2 :List(Text);
  }
}

# What a subscriber wants: event details by event name, request summaries by
# operation name, and, with `frames`, the frames themselves: one exchange in
# `every`, chosen by its connection and stream so that both ends choose the
# same ones (of the selected operations, when `ops` names any), and one event
# frame in `every`. Without `payloads`, the data of reads and writes is cut
# from the frames and its length kept.
struct Selection {
  events @0 :Names;
  ops @1 :Names;
  frames @2 :Bool;
  every @3 :UInt32;
  payloads @4 :Bool;
}

# One operation in a capture: exchanges the process made or answered while
# the subscription lasted, those it chose, and those of them dropped because
# the reader fell behind. Event frames count as the operation `event`.
struct CensusOp {
  op @0 :Text;
  seen @1 :UInt64;
  sampled @2 :UInt64;
  dropped @3 :UInt64;
}

struct ControlRequest {
  revision @0 :UInt64;
  union {
    # One Counters reply; a connection may ask again.
    counters @1 :Void;
    # Records as they happen, until the subscriber closes the connection or,
    # on the same connection, asks for the census.
    subscribe @2 :Selection;
    # Sent during a subscription: the records still queued, then a census
    # record, and the subscription ends.
    census @3 :Void;
  }
}

struct Count {
  name @0 :Text;
  value @1 :UInt64;
}

# One bucket of a histogram: how many values were at most `upper` and above the bucket below's bound.
struct Bucket {
  upper @0 :UInt64;
  count @1 :UInt64;
}

# One operation's totals since the process started, at one level: `fuse` (what
# the kernel asked the client), `call` (what the client asked the server) or
# `request` (what the server answered).
struct TotalOp {
  level @0 :Text;
  op @1 :Text;
  count @2 :UInt64;
  bytes @3 :UInt64;
  items @4 :UInt64;
  errors @5 :UInt64;
  totalNs @6 :UInt64;
  # Every request's latency in nanoseconds, and the bytes of those that moved any, since the process started, as the buckets that have counts; differences between two readings give an interval's quantiles.
  latency @7 :List(Bucket);
  sizes @8 :List(Bucket);
}

# What the process has used since it started: its CPU time and context switches (every thread's, exited ones included), and its main runtime's workers, the time they spent busy (summed) and how often they parked.
struct Resources {
  userNs @0 :UInt64;
  sysNs @1 :UInt64;
  voluntarySwitches @2 :UInt64;
  involuntarySwitches @3 :UInt64;
  workers @4 :UInt32;
  busyNs @5 :UInt64;
  parks @6 :UInt64;
}

struct Counters {
  # `client` or `server`.
  side @0 :Text;
  pid @1 :UInt32;
  # The mount and its server, or the export and its address.
  describe @2 :Text;
  uptimeNs @3 :UInt64;
  inflight @4 :UInt64;
  events @5 :List(Count);
  ops @6 :List(TotalOp);
  resources @7 :Resources;
}

# The identifiers that join a record to the log lines and to the other side's
# records. `present` has bit 0 for session, 1 for conn, 2 for stream, 3 for
# unique; `op` is empty when unknown.
struct Ids {
  present @0 :UInt8;
  session @1 :UInt64;
  conn @2 :UInt64;
  stream @3 :UInt64;
  unique @4 :UInt64;
  op @5 :Text;
}

struct Phase {
  name @0 :Text;
  ns @1 :UInt64;
}

struct Record {
  # Unix time, in nanoseconds.
  atNs @0 :UInt64;
  union {
    event :group {
      name @1 :Text;
      ids @2 :Ids;
      detail @3 :Text;
    }
    # One request answered, at its `level` (as in TotalOp); `fh`, `offset`,
    # `size`, `ino` and `pid` follow `present` in Ids' manner: bits 0 to 4.
    request :group {
      level @4 :Text;
      ids @5 :Ids;
      present @6 :UInt8;
      fh @7 :UInt64;
      offset @8 :UInt64;
      size @9 :UInt64;
      bytes @10 :UInt64;
      items @11 :UInt64;
      errno @12 :Int32;
      phases @13 :List(Phase);
      totalNs @14 :UInt64;
      ino @15 :UInt64;
      pid @16 :UInt32;
    }
    # Records the process could not hold for this subscriber, since it last said.
    dropped @17 :UInt64;
    # One request and its reply as they crossed the wire: each frame's body
    # (the message without its length prefix), as the client sent it and the
    # server received it, so the two ends' frames are the same bytes. A body
    # with data cut from it says how much (`requestElided`, `replyElided`).
    # `outcome` is `replied`; `undecodable`, with the reply's body as it was
    # read; or why there is no reply: `abandoned`, `lost`, `not sent`,
    # `undelivered`, `stalled`.
    exchange :group {
      side @18 :Text;
      ids @19 :Ids;
      every @20 :UInt32;
      request @21 :Data;
      requestElided @22 :UInt64;
      reply @23 :Data;
      replyElided @24 :UInt64;
      outcome @25 :Text;
      elapsedNs @26 :UInt64;
    }
    # A frame that did not decode, as it was read (its first MiB).
    undecodable :group {
      side @27 :Text;
      ids @28 :Ids;
      error @29 :Text;
      body @30 :Data;
    }
    # A batch of change events, as it crossed the wire: the `seq`th the
    # stream carried, counted alike at both ends.
    eventFrame :group {
      side @31 :Text;
      ids @32 :Ids;
      every @33 :UInt32;
      body @34 :Data;
      seq @43 :UInt64;
    }
    # The first record of a capture file: what was captured, from whom, and
    # the revisions its frames and records were written in.
    header :group {
      protoRevision @35 :UInt64;
      controlRevision @36 :UInt64;
      side @37 :Text;
      pid @38 :UInt32;
      describe @39 :Text;
      selection @40 :Selection;
    }
    # The last record of a capture: per operation, the exchanges there were,
    # chosen and dropped, and every record dropped for the reader.
    census :group {
      ops @41 :List(CensusOp);
      dropped @42 :UInt64;
    }
  }
}

struct ControlReply {
  union {
    counters @0 :Counters;
    record @1 :Record;
    refused @2 :Text;
  }
}

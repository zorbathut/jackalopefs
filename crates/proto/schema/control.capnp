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

# What a subscriber wants: event details by event name, and request summaries
# by operation name.
struct Selection {
  events @0 :Names;
  ops @1 :Names;
}

struct ControlRequest {
  revision @0 :UInt64;
  union {
    # One Counters reply; a connection may ask again.
    counters @1 :Void;
    # Records as they happen, until the subscriber closes the connection.
    subscribe @2 :Selection;
  }
}

struct Count {
  name @0 :Text;
  value @1 :UInt64;
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
  }
}

struct ControlReply {
  union {
    counters @0 :Counters;
    record @1 :Record;
    refused @2 :Text;
  }
}

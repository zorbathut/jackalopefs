@0xfb77a64f10864f65;

# Every byte of this file, comments included, feeds the protocol revision the
# peers compare in Hello (PROTO_REVISION in crates/proto/src/lib.rs; docs/design.md,
# "Wire format"): any edit here is a new revision, and peers built from
# different revisions refuse each other.
#
# jackalopefs wire protocol. Every frame on a QUIC stream is a u32 little-endian
# length prefix followed by one standard Cap'n Proto message with exactly one
# segment; docs/design.md, "Wire format", is the normative description of the
# framing, the reader limits and the validation rules below.
#
# Evolution contract (checked against capnp 1.5): union discriminant values
# follow ordinal order, not declaration order, so reordering declarations keeps
# the wire format (though it is still a new revision, see above); a group's
# position in a union is its lowest member ordinal; out-of-order ordinals
# compile without complaint, so the compiler will not catch a renumber.
# Hello, HelloReply and every struct they reach (Resume, Identity) are frozen
# for ever: peers of different revisions must still decode them to refuse each
# other and say why, and a server decodes the whole Hello before it compares
# revisions. Every other struct is decoded only between peers of one revision,
# so a new revision may renumber it (ordinals must stay contiguous, which
# removing a field requires); a field added without removing any is appended
# with a fresh, higher ordinal, and a field grows into a group by keeping its
# own ordinal as the group's lowest member.
#
# Rules the schema cannot express (docs/design.md, "Wire format", is normative):
#
# Decoders reject:
# - a frame body longer than 2097152 bytes, before allocating it
# - a name that is empty, longer than 255 bytes, contains '/' or NUL, or is "." or ".."
# - a path longer than 4096 bytes when joined with '/' (the empty path, or an omitted path pointer, is the export root)
# - a resume token that is not exactly 16 bytes
# - a file handle longer than 128 bytes
# - a reason that is not UTF-8 (every other byte field, the auth token included, is arbitrary bytes)
# - an unknown union discriminant or enum value
#
# Senders guarantee (a receiver answers a violation with an ordinary error):
# - a write payload is at most 1048576 bytes (EINVAL beyond that) and a read asks for at most that many (a larger request is clamped)
# - a fallocate covers at most 67108864 bytes (EINVAL beyond that; a sender splits a longer range into consecutive requests), and its mode is a combination of FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE and FALLOC_FL_ZERO_RANGE (EOPNOTSUPP for any other bit)
# - a copyFileRange may be answered with fewer bytes than len, as copy_file_range(2) may: copied says how many, and the sender asks again for the rest
# - getattr and setattr carry a path, a handle, or both, never neither
# - fh values are chosen by the client and never reused within a client's lifetime
# - err is a Linux errno; flags, mode and mask are Linux values; nextOffset is a getdents64 cookie

using Path = List(Data);

struct TimeSpec {
  sec @0 :Int64;
  nsec @1 :UInt32;
}

enum FileKind {
  regular @0;
  directory @1;
  symlink @2;
  fifo @3;
  socket @4;
  charDevice @5;
  blockDevice @6;
}

# What an lseek looks for from its offset: the next data, or the next hole (the end of the file counts as one).
enum Whence {
  data @0;
  hole @1;
}

# What tells one file from another when inode numbers cannot: the file's handle as name_to_handle_at(2) returns it, its
# type and the first handle_bytes bytes of f_handle (the rest of the kernel's buffer is uninitialised and never sent).
# It is opaque and only ever compared for equality, within one export. It is equal for one file for as long as the file
# exists, by whatever name it is reached and across server restarts, and different for different files that share an
# inode number (a recycled number, a snapshot and its origin); the server takes both on trust from the export's
# filesystem, and one that sets no inode generation cannot tell a recycled number apart.
struct Identity {
  handleType @0 :Int32;
  handle @1 :Data;
}

struct Attr {
  ino @0 :UInt64;
  size @1 :UInt64;
  blocks @2 :UInt64;
  atime :group { sec @3 :Int64; nsec @4 :UInt32; }
  mtime :group { sec @5 :Int64; nsec @6 :UInt32; }
  ctime :group { sec @7 :Int64; nsec @8 :UInt32; }
  kind @9 :FileKind;
  perm @10 :UInt16;
  nlink @11 :UInt32;
  uid @12 :UInt32;
  gid @13 :UInt32;
  rdev @14 :UInt64;
  blksize @15 :UInt32;
  # The node's extended attribute names, as listxattr returns them, sent so a client can answer getxattr and listxattr
  # for what is *not* there without a round trip: `some` with an empty list states the node has no extended attributes.
  # `unknown` means the server did not look (or could not say: too many names, or a filesystem without xattr support,
  # whose errno the client must fetch) and obliges the client to ask. A client answers only absence from this list;
  # a name that is present is always fetched, and no value is ever cached.
  xattrNames :union {
    unknown @16 :Void;
    some @17 :List(Data);
  }
  identity @18 :Identity;
  # The file lies outside the export root's subvolume (in another btrfs or bcachefs subvolume or snapshot), where
  # inode numbers repeat the root subvolume's. ino is always the filesystem's own number, the export root's included.
  foreign @19 :Bool;
}

struct Statfs {
  blocks @0 :UInt64;
  bfree @1 :UInt64;
  bavail @2 :UInt64;
  files @3 :UInt64;
  ffree @4 :UInt64;
  bsize @5 :UInt32;
  namelen @6 :UInt32;
  frsize @7 :UInt32;
}

# One entry of a listing. attr is absent only for "." and "..", which are directories and which a client numbers itself; every other entry is described, or left out.
struct DirEntry {
  nextOffset @0 :UInt64;
  name @1 :Data;
  attr :union { none @2 :Void; some @3 :Attr; }
}

struct TimeOrNow {
  union {
    time @0 :TimeSpec;
    now @1 :Void;
  }
}

# Every field is independent; none means leave alone.
struct SetAttr {
  mode :union { none @0 :Void; some @1 :UInt32; }
  uid :union { none @2 :Void; some @3 :UInt32; }
  gid :union { none @4 :Void; some @5 :UInt32; }
  size :union { none @6 :Void; some @7 :UInt64; }
  atime :union { none @8 :Void; some @9 :TimeOrNow; }
  mtime :union { none @10 :Void; some @11 :TimeOrNow; }
}

struct Resume {
  sessionId @0 :UInt64;
  token @1 :Data;
}

# First message on the control stream, client to server.
struct Hello {
  # PROTO_REVISION of the client's build; the server refuses any other.
  revision @0 :UInt64;
  auth :union { anonymous @1 :Void; token @2 :Data; }
  resume :union { none @3 :Void; some @4 :Resume; }
}

struct HelloReply {
  union {
    ack :group {
      sessionId @0 :UInt64;
      resumeToken @1 :Data;
      resumed @2 :Bool;
      # The export root: its inode number and identity, by which a client knows on every connection that this is
      # still the directory it mounted.
      rootIno @5 :UInt64;
      rootIdentity @6 :Identity;
      # The server process's effective uid and gid: they own everything it creates and are whom its access checks run as.
      uid @7 :UInt32;
      gid @8 :UInt32;
    }
    reject :group {
      reason @3 :Text;
    }
    # The server speaks another revision; it closes the connection once this has been read.
    revisionMismatch :group {
      revision @4 :UInt64;
    }
  }
}

# One request per bidi stream. Paths are relative to the export root.
struct Request {
  union {
    lookup :group { parent @0 :Path; name @1 :Data; }
    getattr :group {
      path :union { none @2 :Void; some @3 :Path; }
      fh :union { none @4 :Void; some @5 :UInt64; }
    }
    setattr :group {
      path :union { none @6 :Void; some @7 :Path; }
      fh :union { none @8 :Void; some @9 :UInt64; }
      set @10 :SetAttr;
    }
    readlink :group { path @11 :Path; }
    mknod :group { parent @12 :Path; name @13 :Data; mode @14 :UInt32; rdev @15 :UInt64; }
    mkdir :group { parent @16 :Path; name @17 :Data; mode @18 :UInt32; }
    unlink :group { parent @19 :Path; name @20 :Data; }
    rmdir :group { parent @21 :Path; name @22 :Data; }
    symlink :group { parent @23 :Path; name @24 :Data; target @25 :Data; }
    rename :group { parent @26 :Path; name @27 :Data; newParent @28 :Path; newName @29 :Data; flags @30 :UInt32; }
    link :group { path @31 :Path; newParent @32 :Path; newName @33 :Data; }
    open :group { fh @34 :UInt64; path @35 :Path; flags @36 :Int32; }
    create :group { fh @37 :UInt64; parent @38 :Path; name @39 :Data; mode @40 :UInt32; flags @41 :Int32; }
    read :group { fh @42 :UInt64; offset @43 :UInt64; size @44 :UInt32; }
    write :group { fh @45 :UInt64; offset @46 :UInt64; data @47 :Data; }
    release :group { fh @48 :UInt64; }
    fsync :group { fh @49 :UInt64; datasync @50 :Bool; }
    opendir :group { fh @51 :UInt64; path @52 :Path; }
    readdir :group { fh @53 :UInt64; offset @54 :UInt64; maxBytes @55 :UInt32; }
    releasedir :group { fh @56 :UInt64; }
    statfs :group { path @57 :Path; }
    setxattr :group { path @58 :Path; name @59 :Data; value @60 :Data; flags @61 :Int32; }
    getxattr :group { path @62 :Path; name @63 :Data; }
    listxattr :group { path @64 :Path; }
    removexattr :group { path @65 :Path; name @66 :Data; }
    access :group { path @67 :Path; mask @68 :Int32; }
    copyFileRange :group { fhIn @69 :UInt64; offsetIn @70 :UInt64; fhOut @71 :UInt64; offsetOut @72 :UInt64; len @73 :UInt64; }
    fallocate :group { fh @74 :UInt64; offset @75 :UInt64; len @76 :UInt64; mode @77 :Int32; }
    lseek :group { fh @78 :UInt64; offset @79 :UInt64; whence @80 :Whence; }
  }
}

# Reply to a Request. err is first so that an all-zero message reads as an error.
struct Response {
  union {
    err @0 :Int32;
    entry :group { attr @1 :Attr; }
    attr @2 :Attr;
    readlink @3 :Data;
    ok @4 :Void;
    opened :group { attr @5 :Attr; }
    read :group { data @6 :Data; }
    written @7 :UInt32;
    # end: no entry follows the last one in entries, so a client may answer a
    # further read at that entry's nextOffset itself; says nothing when
    # entries is empty.
    readdir :group { entries @8 :List(DirEntry); end @11 :Bool; }
    statfs @9 :Statfs;
    xattr @10 :Data;
    copied @12 :UInt32;
    seeked @13 :UInt64;
  }
}

# One invalidation. entry: the directory entry changed; data: contents or
# attributes changed; overflow: events were lost, distrust everything cached.
struct EventItem {
  union {
    entry :group { dir @0 :Path; name @1 :Data; }
    data @2 :Path;
    overflow @3 :Void;
  }
}

# One debounce window of events, in order, on the server-to-client stream.
struct Event {
  items @0 :List(EventItem);
}

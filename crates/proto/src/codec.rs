//! Framing: a `u32` little-endian length prefix followed by one single-segment Cap'n Proto message.
//!
//! The length prefix is load-bearing for cancellation: a request stream that is cut off mid-write (client timed out) arrives as a clean early EOF, which [`read_frame`] reports as [`ErrorCodec::Io`] with `UnexpectedEof`, never as a shorter valid message. The single-segment rule is what keeps a decoder in another language (or in a kernel) simple: no far pointers, no segment lookups.

use crate::wire::{ErrorDecode, Message};
use capnp::message::{self, HeapAllocator, ReaderOptions};
use capnp::serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest frame body either side will encode or accept.
pub const MAX_FRAME: usize = 2 * 1024 * 1024;

/// Largest single read or write payload; the FUSE `max_write`/`max_readahead` on the client match it.
pub const MAX_IO: usize = 1024 * 1024;

/// Bytes read per step while filling a frame body, so memory tracks what has actually arrived rather than what the peer declared.
const READ_CHUNK: usize = 64 * 1024;

/// Words a decoder may traverse per frame. Four times the largest frame: pointer aliasing stays bounded, but a legitimately maximal message never trips it even though the reader charges every getter call and double-counts re-reads. Changing it is a protocol change: edit the schema so the revision moves.
const TRAVERSAL_LIMIT_WORDS: usize = 4 * MAX_FRAME / 8;

/// The deepest real message is six pointer levels (Response → List(DirEntryPlus) → DirEntryPlus → Attr → List(Data) → Data); sixteen leaves room without inviting recursion abuse. Changing it is a protocol change: edit the schema so the revision moves.
const NESTING_LIMIT: i32 = 16;

#[derive(Debug, thiserror::Error)]
pub enum ErrorCodec {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame of {0} bytes exceeds the {MAX_FRAME} byte limit")]
    TooLarge(usize),
    #[error("encode: {0}")]
    Encode(String),
    #[error("decode: {0}")]
    Decode(#[from] ErrorDecode),
}

impl ErrorCodec {
    /// True when the peer closed the stream before a complete frame arrived: the routine shape of a cancelled request.
    pub fn is_eof(&self) -> bool {
        matches!(self, ErrorCodec::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof)
    }
}

fn reader_options() -> ReaderOptions {
    let mut options = ReaderOptions::default();
    options.traversal_limit_in_words(Some(TRAVERSAL_LIMIT_WORDS));
    options.nesting_limit(NESTING_LIMIT);
    options
}

/// Encode `msg` as a complete frame: length prefix plus a single-segment message. The first segment is sized from the message's own estimate; if that was short and the builder spilled into a second segment, the message is canonicalized into one.
pub fn encode<T: Message>(msg: &T) -> Result<Vec<u8>, ErrorCodec> {
    let mut builder =
        message::Builder::new(HeapAllocator::new().first_segment_words(msg.size_hint()));
    msg.build(&mut builder);
    if builder.get_segments_for_output().len() > 1 {
        let canonical = builder
            .into_reader()
            .canonicalize()
            .map_err(|e| ErrorCodec::Encode(e.to_string()))?;
        return frame_one_segment(capnp::Word::words_to_bytes(&canonical));
    }
    let words = serialize::compute_serialized_size_in_words(&builder);
    let len = words * 8;
    if len > MAX_FRAME {
        return Err(ErrorCodec::TooLarge(len));
    }
    let mut frame = Vec::with_capacity(4 + len);
    frame.extend_from_slice(&(len as u32).to_le_bytes());
    serialize::write_message(&mut frame, &builder)
        .map_err(|e| ErrorCodec::Encode(e.to_string()))?;
    debug_assert_eq!(frame.len(), 4 + len);
    Ok(frame)
}

/// Frame an already-serialized single segment: the segment table is eight bytes, so the size is known before anything is copied.
fn frame_one_segment(segment: &[u8]) -> Result<Vec<u8>, ErrorCodec> {
    let len = 8 + segment.len();
    if len > MAX_FRAME {
        return Err(ErrorCodec::TooLarge(len));
    }
    let mut frame = Vec::with_capacity(4 + len);
    frame.extend_from_slice(&(len as u32).to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&((segment.len() / 8) as u32).to_le_bytes());
    frame.extend_from_slice(segment);
    Ok(frame)
}

/// Decode one frame body (without its length prefix).
pub fn decode<T: Message>(body: &[u8]) -> Result<T, ErrorCodec> {
    if body.len() < 8 {
        return Err(ErrorDecode::Frame(format!(
            "{} bytes is shorter than a segment table",
            body.len()
        ))
        .into());
    }
    // The table's first word is the segment count minus one, as a u32 that could be u32::MAX.
    let segments = u32::from_le_bytes(body[0..4].try_into().expect("four bytes")) as u64 + 1;
    if segments != 1 {
        return Err(ErrorDecode::Frame(format!(
            "{segments} segments; the protocol requires exactly one"
        ))
        .into());
    }
    let mut slice = body;
    let reader = serialize::read_message_from_flat_slice(&mut slice, reader_options())
        .map_err(ErrorDecode::Capnp)?;
    if !slice.is_empty() {
        return Err(
            ErrorDecode::Frame(format!("{} trailing bytes inside the frame", slice.len())).into(),
        );
    }
    Ok(T::parse(&reader)?)
}

/// Encode `msg` and write it as one frame with a single `write_all`.
pub async fn write_frame<W, T>(writer: &mut W, msg: &T) -> Result<(), ErrorCodec>
where
    W: AsyncWrite + Unpin,
    T: Message,
{
    let frame = encode(msg)?;
    writer.write_all(&frame).await?;
    Ok(())
}

/// Read exactly one frame and decode it; rejects oversize frames before allocating for them.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, ErrorCodec>
where
    R: AsyncRead + Unpin,
    T: Message,
{
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_FRAME {
        return Err(ErrorCodec::TooLarge(len));
    }
    let mut body = Vec::with_capacity(len.min(READ_CHUNK));
    while body.len() < len {
        let start = body.len();
        body.resize(start + (len - start).min(READ_CHUNK), 0);
        reader.read_exact(&mut body[start..]).await?;
    }
    decode(&body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use std::process::{Command, Stdio};

    const SCHEMA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/schema/jackalopefs.capnp");

    fn path(s: &str) -> Path {
        Path::from_names(
            s.split('/')
                .map(|n| Name::new(n.as_bytes()).unwrap())
                .collect(),
        )
        .unwrap()
    }

    fn name(s: &str) -> Name {
        Name::new(s.as_bytes()).unwrap()
    }

    fn sample_attr(ino: u64) -> Attr {
        Attr {
            ino,
            size: 42,
            blocks: 1,
            atime: TimeSpec { sec: 1, nsec: 2 },
            mtime: TimeSpec { sec: 3, nsec: 4 },
            ctime: TimeSpec { sec: -5, nsec: 6 },
            kind: FileKind::Regular,
            perm: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 4096,
            xattr_names: Some(vec![b"user.k".to_vec(), b"security.selinux".to_vec()]),
        }
    }

    /// One instance of every request variant; `variant_index` is exhaustive, so a variant without a sample fails `request_samples_cover_every_variant`.
    fn all_requests() -> Vec<Request> {
        vec![
            Request::Lookup {
                parent: path("a/b"),
                name: name("c"),
            },
            Request::Getattr {
                path: Some(Path::root()),
                fh: None,
            },
            Request::Getattr {
                path: None,
                fh: Some(7),
            },
            Request::Setattr {
                path: Some(path("x")),
                fh: Some(3),
                set: SetAttr {
                    mode: Some(0o600),
                    uid: None,
                    gid: Some(5),
                    size: Some(0),
                    atime: Some(TimeOrNow::Now),
                    mtime: Some(TimeOrNow::Time(TimeSpec { sec: 9, nsec: 8 })),
                },
            },
            Request::Setattr {
                path: None,
                fh: Some(3),
                set: SetAttr::default(),
            },
            Request::Readlink { path: path("l") },
            Request::Mknod {
                parent: Path::root(),
                name: name("fifo"),
                mode: 0o10644,
                rdev: 0,
            },
            Request::Mkdir {
                parent: Path::root(),
                name: name("d"),
                mode: 0o755,
            },
            Request::Unlink {
                parent: path("d"),
                name: name("f"),
            },
            Request::Rmdir {
                parent: Path::root(),
                name: name("d"),
            },
            Request::Symlink {
                parent: Path::root(),
                name: name("l"),
                target: b"../t".to_vec(),
            },
            Request::Rename {
                parent: path("a"),
                name: name("b"),
                newparent: path("c"),
                newname: name("d"),
                flags: 1,
            },
            Request::Link {
                path: path("a/b"),
                newparent: path("c"),
                newname: name("d"),
            },
            Request::Open {
                fh: 1,
                path: path("f"),
                flags: 2,
            },
            Request::Create {
                fh: 2,
                parent: Path::root(),
                name: name("f"),
                mode: 0o644,
                flags: 0o101,
            },
            Request::Read {
                fh: 1,
                offset: 4096,
                size: 65536,
            },
            Request::Write {
                fh: 1,
                offset: 0,
                data: vec![1u8; 1000],
            },
            Request::Release { fh: 1 },
            Request::Fsync {
                fh: 1,
                datasync: true,
            },
            Request::Opendir {
                fh: 3,
                path: path("d"),
            },
            Request::Readdir {
                fh: 3,
                offset: 0,
                max_bytes: 65536,
                plus: true,
            },
            Request::Releasedir { fh: 3 },
            Request::Statfs { path: Path::root() },
            Request::Setxattr {
                path: path("f"),
                name: b"user.k".to_vec(),
                value: b"v".to_vec(),
                flags: 0,
            },
            Request::Getxattr {
                path: path("f"),
                name: b"user.k".to_vec(),
            },
            Request::Listxattr { path: path("f") },
            Request::Removexattr {
                path: path("f"),
                name: b"user.k".to_vec(),
            },
            Request::Access {
                path: path("f"),
                mask: 4,
            },
        ]
    }

    const REQUEST_VARIANTS: usize = 26;

    fn variant_index(req: &Request) -> usize {
        match req {
            Request::Lookup { .. } => 0,
            Request::Getattr { .. } => 1,
            Request::Setattr { .. } => 2,
            Request::Readlink { .. } => 3,
            Request::Mknod { .. } => 4,
            Request::Mkdir { .. } => 5,
            Request::Unlink { .. } => 6,
            Request::Rmdir { .. } => 7,
            Request::Symlink { .. } => 8,
            Request::Rename { .. } => 9,
            Request::Link { .. } => 10,
            Request::Open { .. } => 11,
            Request::Create { .. } => 12,
            Request::Read { .. } => 13,
            Request::Write { .. } => 14,
            Request::Release { .. } => 15,
            Request::Fsync { .. } => 16,
            Request::Opendir { .. } => 17,
            Request::Readdir { .. } => 18,
            Request::Releasedir { .. } => 19,
            Request::Statfs { .. } => 20,
            Request::Setxattr { .. } => 21,
            Request::Getxattr { .. } => 22,
            Request::Listxattr { .. } => 23,
            Request::Removexattr { .. } => 24,
            Request::Access { .. } => 25,
        }
    }

    const RESPONSE_VARIANTS: usize = 12;

    fn response_index(resp: &Response) -> usize {
        match resp {
            Response::Err(_) => 0,
            Response::Entry(_) => 1,
            Response::Attr(_) => 2,
            Response::Readlink(_) => 3,
            Response::Ok => 4,
            Response::Opened { .. } => 5,
            Response::Read(_) => 6,
            Response::Written(_) => 7,
            Response::Readdir(_) => 8,
            Response::ReaddirPlus(_) => 9,
            Response::Statfs(_) => 10,
            Response::Xattr(_) => 11,
        }
    }

    fn all_responses() -> Vec<Response> {
        let entry = DirEntry {
            ino: 5,
            next_offset: 77,
            kind: FileKind::Directory,
            name: b"..".to_vec(),
        };
        vec![
            Response::Err(2),
            Response::Entry(sample_attr(9)),
            Response::Attr(sample_attr(10)),
            Response::Attr(Attr {
                xattr_names: None,
                ..sample_attr(11)
            }),
            Response::Readlink(b"target".to_vec()),
            Response::Ok,
            Response::Opened {
                attr: sample_attr(11),
            },
            Response::Read(vec![0u8; 100]),
            Response::Written(100),
            Response::Readdir(vec![entry.clone()]),
            Response::ReaddirPlus(vec![
                DirEntryPlus { entry, attr: None },
                DirEntryPlus {
                    entry: DirEntry {
                        ino: 6,
                        next_offset: 78,
                        kind: FileKind::Symlink,
                        name: b"x".to_vec(),
                    },
                    attr: Some(sample_attr(6)),
                },
            ]),
            Response::Statfs(Statfs {
                blocks: 1,
                bfree: 2,
                bavail: 3,
                files: 4,
                ffree: 5,
                bsize: 4096,
                namelen: 255,
                frsize: 4096,
            }),
            Response::Xattr(b"a\0b\0".to_vec()),
        ]
    }

    fn control_messages() -> (Vec<Hello>, Vec<HelloReply>, Event) {
        (
            vec![
                Hello {
                    revision: 0x0102030405060708,
                    auth: Auth::Anonymous,
                    resume: None,
                },
                Hello {
                    revision: 0x0102030405060708,
                    auth: Auth::Token(b"secret".to_vec()),
                    resume: Some(Resume {
                        session_id: 3,
                        token: [7u8; 16],
                    }),
                },
            ],
            vec![
                HelloReply::Ack {
                    session_id: 1,
                    resume_token: [1u8; 16],
                    resumed: true,
                },
                HelloReply::Reject {
                    reason: "no".into(),
                },
                HelloReply::RevisionMismatch {
                    revision: 0x0102030405060708,
                },
            ],
            Event {
                items: vec![
                    EventItem::Entry {
                        dir: Path::root(),
                        name: name("f"),
                    },
                    EventItem::Data { path: path("a/f") },
                    EventItem::Overflow,
                ],
            },
        )
    }

    fn frame_body<T: Message>(msg: &T) -> Vec<u8> {
        let frame = encode(msg).unwrap();
        assert_eq!(
            u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize,
            frame.len() - 4
        );
        frame[4..].to_vec()
    }

    fn round_trip<T: Message + PartialEq + std::fmt::Debug>(msg: &T) {
        let mut builder =
            message::Builder::new(HeapAllocator::new().first_segment_words(msg.size_hint()));
        msg.build(&mut builder);
        assert_eq!(
            builder.get_segments_for_output().len(),
            1,
            "size_hint under-estimates {msg:?}"
        );
        let body = frame_body(msg);
        assert_eq!(&body[0..4], &[0, 0, 0, 0], "single segment");
        let back: T = decode(&body).unwrap();
        assert_eq!(&back, msg);
    }

    #[test]
    fn samples_cover_every_variant() {
        let mut seen = vec![false; REQUEST_VARIANTS];
        for req in all_requests() {
            seen[variant_index(&req)] = true;
        }
        assert!(seen.iter().all(|s| *s), "missing request samples: {seen:?}");
        let mut seen = vec![false; RESPONSE_VARIANTS];
        for resp in all_responses() {
            seen[response_index(&resp)] = true;
        }
        assert!(
            seen.iter().all(|s| *s),
            "missing response samples: {seen:?}"
        );
    }

    #[test]
    fn everything_round_trips() {
        for req in all_requests() {
            round_trip(&req);
        }
        for resp in all_responses() {
            round_trip(&resp);
        }
        let (hellos, replies, event) = control_messages();
        for h in &hellos {
            round_trip(h);
        }
        for r in &replies {
            round_trip(r);
        }
        round_trip(&event);
    }

    #[tokio::test]
    async fn frames_round_trip_over_a_stream_in_chunks() {
        let big = Request::Write {
            fh: 1,
            offset: 0,
            data: (0..MAX_IO).map(|i| i as u8).collect(),
        };
        let (mut a, mut b) = tokio::io::duplex(8192);
        let writer = tokio::spawn(async move { write_frame(&mut a, &big).await.unwrap() });
        let back: Request = read_frame(&mut b).await.unwrap();
        writer.await.unwrap();
        assert!(
            matches!(back, Request::Write { data, .. } if data.len() == MAX_IO && data[MAX_IO - 1] == (MAX_IO - 1) as u8)
        );

        let big_read = Response::Read(vec![7u8; MAX_IO]);
        let (mut a, mut b) = tokio::io::duplex(8192);
        let writer = tokio::spawn(async move { write_frame(&mut a, &big_read).await.unwrap() });
        let back: Response = read_frame(&mut b).await.unwrap();
        writer.await.unwrap();
        assert!(matches!(back, Response::Read(data) if data.len() == MAX_IO));
    }

    #[test]
    fn oversize_frames_are_rejected() {
        let too_big = Request::Write {
            fh: 1,
            offset: 0,
            data: vec![0u8; MAX_FRAME + 1],
        };
        assert!(matches!(encode(&too_big), Err(ErrorCodec::TooLarge(_))));
    }

    #[tokio::test]
    async fn oversize_and_truncated_frames_on_a_stream() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&((MAX_FRAME as u32) + 1).to_le_bytes())
            .await
            .unwrap();
        assert!(matches!(
            read_frame::<_, Request>(&mut b).await,
            Err(ErrorCodec::TooLarge(_))
        ));

        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&100u32.to_le_bytes()).await.unwrap();
        a.write_all(&[0u8; 10]).await.unwrap();
        drop(a);
        let err = read_frame::<_, Request>(&mut b).await.unwrap_err();
        assert!(err.is_eof(), "{err}");

        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        assert!(read_frame::<_, Request>(&mut b).await.unwrap_err().is_eof());
    }

    #[test]
    fn trailing_bytes_inside_a_frame_are_rejected() {
        let mut body = frame_body(&Hello {
            revision: 0x0102030405060708,
            auth: Auth::Anonymous,
            resume: None,
        });
        body.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            decode::<Hello>(&body),
            Err(ErrorCodec::Decode(ErrorDecode::Frame(_)))
        ));
    }

    #[test]
    fn multi_segment_bodies_are_rejected_and_our_encoder_never_makes_them() {
        let mut builder = message::Builder::new(HeapAllocator::new().first_segment_words(1));
        Request::Write {
            fh: 1,
            offset: 0,
            data: vec![1u8; 100],
        }
        .build(&mut builder);
        assert!(
            builder.get_segments_for_output().len() > 1,
            "a one-word first segment must spill"
        );
        let two_segments = serialize::write_message_to_words(&builder);
        assert!(matches!(
            decode::<Request>(&two_segments),
            Err(ErrorCodec::Decode(ErrorDecode::Frame(_)))
        ));

        // A deliberately bad size hint spills in the builder, and the encoder canonicalizes it back to one segment.
        struct Underestimated(Request);
        impl Message for Underestimated {
            fn build(&self, message: &mut message::Builder<HeapAllocator>) {
                self.0.build(message)
            }
            fn parse<S: message::ReaderSegments>(
                message: &message::Reader<S>,
            ) -> Result<Self, ErrorDecode> {
                Request::parse(message).map(Underestimated)
            }
            fn size_hint(&self) -> u32 {
                1
            }
        }
        let big = Underestimated(Request::Write {
            fh: 1,
            offset: 0,
            data: vec![9u8; 100_000],
        });
        let frame = encode(&big).unwrap();
        assert_eq!(&frame[4..8], &[0, 0, 0, 0]);
        assert_eq!(decode::<Underestimated>(&frame[4..]).unwrap().0, big.0);
    }

    #[test]
    fn decoding_from_a_misaligned_buffer_works() {
        // The body is decoded wherever it lands in memory; the crate's `unaligned` feature is what makes this legal.
        let body = frame_body(&Request::Release { fh: 5 });
        let mut shifted = vec![0u8; 1];
        shifted.extend_from_slice(&body);
        assert_eq!(
            decode::<Request>(&shifted[1..]).unwrap(),
            Request::Release { fh: 5 }
        );
    }

    fn raw_lookup(parent: &[&[u8]], name: &[u8]) -> Vec<u8> {
        let mut builder = message::Builder::new_default();
        let mut lookup = builder
            .init_root::<jackalopefs_capnp::request::Builder<'_>>()
            .init_lookup();
        let mut list = lookup.reborrow().init_parent(parent.len() as u32);
        for (i, component) in parent.iter().enumerate() {
            list.set(i as u32, component);
        }
        lookup.set_name(name);
        serialize::write_message_to_words(&builder)
    }

    #[test]
    fn invalid_names_on_the_wire_are_decode_errors() {
        assert!(decode::<Request>(&raw_lookup(&[b"ok"], b"fine")).is_ok());
        for bad in [&b".."[..], b".", b"", b"a/b", b"a\0b", &[b'x'; 256]] {
            let err = decode::<Request>(&raw_lookup(&[b"ok"], bad)).unwrap_err();
            assert!(matches!(err, ErrorCodec::Decode(_)), "{bad:?}: {err}");
        }
        assert!(
            decode::<Request>(&raw_lookup(&[b"..", b"etc"], b"passwd")).is_err(),
            "path components are validated too"
        );
        let deep: Vec<&[u8]> = std::iter::repeat_n(&[b'x'; 255][..], 17).collect();
        assert!(
            decode::<Request>(&raw_lookup(&deep, b"f")).is_err(),
            "over PATH_MAX"
        );
    }

    #[test]
    fn resume_token_and_reason_are_validated() {
        let mut builder = message::Builder::new_default();
        let mut hello = builder.init_root::<jackalopefs_capnp::hello::Builder<'_>>();
        hello.set_revision(1);
        hello.reborrow().get_auth().set_anonymous(());
        let mut resume = hello.get_resume().init_some();
        resume.set_session_id(1);
        resume.set_token(&[0u8; 7]);
        let err = decode::<Hello>(&serialize::write_message_to_words(&builder)).unwrap_err();
        assert!(
            matches!(err, ErrorCodec::Decode(ErrorDecode::Invalid(ref m)) if m.contains("16")),
            "{err}"
        );

        let mut builder = message::Builder::new_default();
        let reject = builder
            .init_root::<jackalopefs_capnp::hello_reply::Builder<'_>>()
            .init_reject();
        reject
            .init_reason(2)
            .as_bytes_mut()
            .copy_from_slice(&[0xff, 0xfe]);
        let err = decode::<HelloReply>(&serialize::write_message_to_words(&builder)).unwrap_err();
        assert!(
            matches!(err, ErrorCodec::Decode(ErrorDecode::Invalid(ref m)) if m.contains("UTF-8")),
            "{err}"
        );
    }

    /// Byte layout of a frame body: segment table (8), root pointer (8), then the root struct's data section.
    const ROOT_DATA: usize = 16;

    #[test]
    fn unknown_discriminants_and_enum_values_are_errors_not_panics() {
        // Request's union tag is the first 16 bits of its data section; `release` is member 15.
        let mut body = frame_body(&Request::Release { fh: 5 });
        assert_eq!(
            &body[ROOT_DATA..ROOT_DATA + 2],
            &15u16.to_le_bytes(),
            "layout assumption"
        );
        body[ROOT_DATA..ROOT_DATA + 2].copy_from_slice(&26u16.to_le_bytes());
        assert!(matches!(
            decode::<Request>(&body),
            Err(ErrorCodec::Decode(ErrorDecode::NotInSchema(26)))
        ));

        // Response's union tag is at bits 32..48; `ok` is member 4.
        let mut body = frame_body(&Response::Ok);
        assert_eq!(
            &body[ROOT_DATA + 4..ROOT_DATA + 6],
            &4u16.to_le_bytes(),
            "layout assumption"
        );
        body[ROOT_DATA + 4..ROOT_DATA + 6].copy_from_slice(&12u16.to_le_bytes());
        assert!(matches!(
            decode::<Response>(&body),
            Err(ErrorCodec::Decode(ErrorDecode::NotInSchema(12)))
        ));

        // A readdir reply: root struct (8 data + 8 pointer), list tag word (8), then the first DirEntry whose kind is at bits 128..144.
        let entry = DirEntry {
            ino: 1,
            next_offset: 2,
            kind: FileKind::BlockDevice,
            name: b"n".to_vec(),
        };
        let mut body = frame_body(&Response::Readdir(vec![entry]));
        let kind_at = ROOT_DATA + 16 + 8 + 16;
        assert_eq!(
            &body[kind_at..kind_at + 2],
            &6u16.to_le_bytes(),
            "layout assumption"
        );
        body[kind_at..kind_at + 2].copy_from_slice(&99u16.to_le_bytes());
        assert!(matches!(
            decode::<Response>(&body),
            Err(ErrorCodec::Decode(ErrorDecode::NotInSchema(99)))
        ));
    }

    /// A composite list's tag word carries the element count and the element size; with a zero element size the count is limited only by the traversal budget, so a tiny frame could otherwise decode into a huge `Vec`.
    #[test]
    fn a_list_cannot_declare_more_elements_than_the_frame_has_words() {
        // Response { readdir = [] }: root data (8), root pointer to the list (8), then the list tag word at body offset 32 for a zero-length composite list.
        let mut body = frame_body(&Response::Readdir(Vec::new()));
        let list_ptr = ROOT_DATA + 8;
        // A composite list pointer: kind 1, element size 7 (composite), word count in the upper 29 bits; the tag word after it holds the element count.
        let tag_at = list_ptr + 8;
        assert!(body.len() >= tag_at + 8, "layout assumption");
        let pointer = u64::from_le_bytes(body[list_ptr..list_ptr + 8].try_into().unwrap());
        assert_eq!(pointer & 0b11, 1, "layout assumption: list pointer");
        assert_eq!(
            (pointer >> 32) & 0b111,
            7,
            "layout assumption: composite element size"
        );
        // Declare a million zero-word elements in a zero-word list.
        let tag = 1_000_000u64 << 2;
        body[tag_at..tag_at + 8].copy_from_slice(&tag.to_le_bytes());
        let err = decode::<Response>(&body).unwrap_err();
        assert!(
            matches!(
                err,
                ErrorCodec::Decode(ErrorDecode::Invalid(_))
                    | ErrorCodec::Decode(ErrorDecode::Capnp(_))
            ),
            "{err}"
        );
    }

    fn capnp_convert(direction: &str, type_name: &str, input: &[u8]) -> Vec<u8> {
        let mut child = Command::new("capnp")
            .args(["convert", direction, "--short", SCHEMA, type_name])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the capnp compiler is a build requirement, so it must be on PATH");
        std::io::Write::write_all(child.stdin.as_mut().unwrap(), input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "capnp convert {direction} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    #[test]
    fn frames_are_understood_by_the_reference_implementation_and_vice_versa() {
        let text = String::from_utf8(capnp_convert(
            "binary:text",
            "Request",
            &frame_body(&Request::Release { fh: 5 }),
        ))
        .unwrap();
        assert!(
            text.contains("release") && text.contains("fh = 5"),
            "{text}"
        );
        let text = String::from_utf8(capnp_convert(
            "binary:text",
            "Request",
            &frame_body(&Request::Lookup {
                parent: path("a/b"),
                name: name("c"),
            }),
        ))
        .unwrap();
        assert!(
            text.contains(r#"parent = ["a", "b"]"#) && text.contains(r#"name = "c""#),
            "{text}"
        );

        let bytes = capnp_convert(
            "text:binary",
            "Request",
            b"(lookup = (parent = [\"x\", \"y\"], name = \"z\"))",
        );
        assert_eq!(
            decode::<Request>(&bytes).unwrap(),
            Request::Lookup {
                parent: path("x/y"),
                name: name("z")
            }
        );
        let bytes = capnp_convert("text:binary", "Response", b"(opened = (attr = (ino = 42, kind = directory, perm = 493, nlink = 2, blksize = 4096)))");
        match decode::<Response>(&bytes).unwrap() {
            Response::Opened { attr } => {
                assert_eq!(attr.ino, 42);
                assert_eq!(attr.kind, FileKind::Directory);
                assert_eq!(attr.perm, 0o755);
            }
            other => panic!("{other:?}"),
        }

        let (hellos, replies, event) = control_messages();
        let text = String::from_utf8(capnp_convert(
            "binary:text",
            "Hello",
            &frame_body(&hellos[1]),
        ))
        .unwrap();
        assert!(
            text.contains("revision = 72623859790382856")
                && text.contains("token = \"secret\"")
                && text.contains("sessionId = 3"),
            "{text}"
        );
        let text = String::from_utf8(capnp_convert(
            "binary:text",
            "HelloReply",
            &frame_body(&replies[1]),
        ))
        .unwrap();
        assert!(
            text.contains("reject") && text.contains("reason = \"no\""),
            "{text}"
        );
        let text =
            String::from_utf8(capnp_convert("binary:text", "Event", &frame_body(&event))).unwrap();
        assert!(
            text.contains("overflow") && text.contains("data = [\"a\", \"f\"]"),
            "{text}"
        );
        let bytes = capnp_convert(
            "text:binary",
            "HelloReply",
            b"(ack = (sessionId = 9, resumeToken = \"0123456789abcdef\", resumed = true))",
        );
        assert_eq!(
            decode::<HelloReply>(&bytes).unwrap(),
            HelloReply::Ack {
                session_id: 9,
                resume_token: *b"0123456789abcdef",
                resumed: true
            }
        );
        let bytes = capnp_convert(
            "text:binary",
            "Event",
            b"(items = [(entry = (dir = [\"d\"], name = \"f\")), (overflow = void)])",
        );
        assert_eq!(
            decode::<Event>(&bytes).unwrap(),
            Event {
                items: vec![
                    EventItem::Entry {
                        dir: path("d"),
                        name: name("f")
                    },
                    EventItem::Overflow
                ]
            }
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Exact bytes for one instance of each top-level message. A round trip is self-consistent by construction and cannot notice an ordinal renumber or a union reorder; this can. Regenerate deliberately when the schema changes, and say so in the changelog.
    /// The framing limits are stated in the schema's comments so that they are part of the revision; this is what keeps the two copies equal.
    #[test]
    fn framing_limits_are_stated_in_the_schema() {
        let schema = include_str!("../schema/jackalopefs.capnp");
        assert!(schema.contains(&format!("frame body longer than {MAX_FRAME} bytes")));
        assert!(schema.contains(&format!("write payload is at most {MAX_IO} bytes")));
    }

    /// `dir_entry_bytes` is what the server budgets a page with, so it must be the true marginal cost of an entry.
    #[test]
    fn dir_entry_bytes_is_the_marginal_cost_of_an_entry() {
        let entry = |n: usize| DirEntry {
            ino: n as u64,
            next_offset: n as u64,
            kind: FileKind::Regular,
            name: format!("name{n}").into_bytes(),
        };
        let plain: Vec<DirEntry> = (0..8).map(entry).collect();
        let cost =
            |entries: &[DirEntry]| encode(&Response::Readdir(entries.to_vec())).unwrap().len();
        assert_eq!(
            cost(&plain[..8]) - cost(&plain[..7]),
            dir_entry_bytes(5, false, None)
        );
        for names in [
            None,
            Some(Vec::new()),
            Some(vec![b"user.k".to_vec(), b"security.selinux".to_vec()]),
        ] {
            let plus: Vec<DirEntryPlus> = (0..8)
                .map(|n| DirEntryPlus {
                    entry: entry(n),
                    attr: Some(Attr {
                        xattr_names: names.clone(),
                        ..sample_attr(n as u64)
                    }),
                })
                .collect();
            let cost = |entries: &[DirEntryPlus]| {
                encode(&Response::ReaddirPlus(entries.to_vec()))
                    .unwrap()
                    .len()
            };
            assert_eq!(
                cost(&plus[..8]) - cost(&plus[..7]),
                dir_entry_bytes(5, true, names.as_deref()),
                "{names:?}"
            );
        }
    }

    #[test]
    fn golden_bytes() {
        let (hellos, replies, event) = control_messages();
        let cases: [(&str, Vec<u8>, &str); 5] = [
            ("hello", frame_body(&hellos[1]), "000000000a0000000000000002000200080706050403020101000100000000000500000032000000040000000100010073656372657400000300000000000000010000008200000007070707070707070707070707070707"),
            ("reply", frame_body(&replies[0]), "0000000006000000000000000200010001000000000000000100000000000000010000008200000001010101010101010101010101010101"),
            ("request", frame_body(&Request::Rename { parent: path("a"), name: name("b"), newparent: path("c"), newname: name("d"), flags: 1 }), "000000000e00000000000000030004000900000000000000010000000000000000000000000000000d0000000e000000110000000a000000110000000e000000150000000a000000010000000a00000061000000000000006200000000000000010000000a00000063000000000000006400000000000000"),
            ("response", frame_body(&Response::Entry(sample_attr(9))), "000000001500000000000000010001000000000001000000000000000c00010009000000000000002a000000000000000100000000000000010000000000000002000000040000000300000000000000fbffffffffffffff060000000000a40101000000e8030000e80300000010000000000000000000000100000000000000010000001600000005000000320000000500000082000000757365722e6b000073656375726974792e73656c696e7578"),
            ("event", frame_body(&event), "00000000110000000000000000000100010000004f0000000c0000000100020000000000000000001d00000006000000190000000a0000000100000000000000150000001600000000000000000000000200000000000000000000000000000000000000000000006600000000000000050000000a000000050000000a00000061000000000000006600000000000000"),
        ];
        for (what, actual, expected) in cases {
            assert_eq!(hex(&actual), expected, "{what} encoding changed");
        }
    }
}

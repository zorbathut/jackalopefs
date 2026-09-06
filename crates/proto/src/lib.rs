//! Wire protocol for jackalopefs: the Cap'n Proto schema (`schema/jackalopefs.capnp`), the plain Rust message types, the conversions between the two, validation at the trust boundary, and framing.
//!
//! Every frame is one single-segment Cap'n Proto message prefixed by a little-endian `u32` length (see [`codec`]). Names and paths are validated as they are parsed, so a server never sees a path component it must not trust.

pub mod codec;
pub mod msg;
pub mod types;
pub mod wire;

/// Readers and builders generated from the schema. capnpc hardcodes `crate::jackalopefs_capnp::…` paths into what it generates, so this module must live at the crate root.
#[rustfmt::skip]
#[allow(clippy::all, dead_code, unused_imports, unused_qualifications)]
pub(crate) mod jackalopefs_capnp { include!(concat!(env!("OUT_DIR"), "/jackalopefs_capnp.rs")); }

pub use codec::{decode, encode, read_frame, write_frame, ErrorCodec, MAX_FRAME, MAX_IO};
pub use msg::*;
pub use types::*;
pub use wire::{dir_entry_bytes, ErrorDecode, Message};

use sha2::{Digest, Sha256};

/// 64-bit FNV-1a, offset basis 0xcbf29ce484222325, prime 0x100000001b3, one byte at a time. An accident detector, not a security control; another implementation only has to reproduce it exactly.
const fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        i += 1;
    }
    hash
}

/// The revision of the protocol this build speaks, carried in `Hello` and compared by the server: the hash of the schema file's exact bytes, comments included, so any edit to the file is a new revision and peers built from different ones refuse each other. Shown as 16 hex digits.
pub const PROTO_REVISION: u64 = fnv1a(include_bytes!("../schema/jackalopefs.capnp"));

/// UDP port the server listens on and the client connects to unless told otherwise.
pub const DEFAULT_PORT: u16 = 1933;

/// TLS ALPN identifier; the QUIC handshake refuses peers that don't offer it. Changing it is a protocol change: edit the schema so the revision moves.
pub const ALPN: &[u8] = b"jackalopefs/1";

/// SHA-256 of a DER-encoded certificate.
pub fn fingerprint_bytes(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// SHA-256 fingerprint of a DER-encoded certificate, formatted as `sha256:<64 lowercase hex digits>`.
pub fn fingerprint(der: &[u8]) -> String {
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for byte in fingerprint_bytes(der) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ErrorFingerprint {
    #[error("fingerprint must start with `sha256:`")]
    Prefix,
    #[error("fingerprint must be 64 hex digits after the prefix")]
    Hex,
}

/// Parse a fingerprint produced by [`fingerprint`]; hex digits are accepted in either case and `:` separators between bytes are tolerated.
pub fn parse_fingerprint(text: &str) -> Result<[u8; 32], ErrorFingerprint> {
    let hex = text
        .strip_prefix("sha256:")
        .ok_or(ErrorFingerprint::Prefix)?;
    let hex: String = hex.chars().filter(|c| *c != ':').collect();
    if hex.len() != 64 {
        return Err(ErrorFingerprint::Hex);
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| ErrorFingerprint::Hex)?;
        out[i] = u8::from_str_radix(pair, 16).map_err(|_| ErrorFingerprint::Hex)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_is_the_fnv1a_of_the_schema() {
        assert_eq!(fnv1a(b""), 0xcbf29ce484222325);
        assert_eq!(fnv1a(b"a"), 0xaf63dc4c8601ec8c);
        assert_ne!(PROTO_REVISION, 0);
        assert_ne!(PROTO_REVISION, fnv1a(b""));
    }

    #[test]
    fn fingerprint_round_trips() {
        let text = fingerprint(b"hello");
        assert!(text.starts_with("sha256:"));
        assert_eq!(text.len(), 7 + 64);
        let parsed = parse_fingerprint(&text).unwrap();
        assert_eq!(parsed, fingerprint_bytes(b"hello"));
        assert_eq!(
            parse_fingerprint(&text.to_uppercase().replace("SHA256", "sha256")).unwrap(),
            parsed
        );
    }

    #[test]
    fn fingerprint_rejects_garbage() {
        assert_eq!(parse_fingerprint("md5:abcd"), Err(ErrorFingerprint::Prefix));
        assert_eq!(parse_fingerprint("sha256:abcd"), Err(ErrorFingerprint::Hex));
        assert_eq!(
            parse_fingerprint(&format!("sha256:{}", "zz".repeat(32))),
            Err(ErrorFingerprint::Hex)
        );
    }
}

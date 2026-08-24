//! Compatibility shim that exposes bincode 1.x-shaped helpers backed by
//! `bincode-next` (3.0.0-rc.x) configured for the legacy v1 wire format.
//!
//! The on-disk IBS key format in `pg-pkg`, and the header/signature framing on
//! the wire, are byte-pinned to bincode v1's default encoding (little-endian,
//! fixed-int, no length limit). `bincode_next::config::legacy()` reproduces
//! that layout exactly, so existing serialized bytes round-trip unchanged.

use alloc::vec::Vec;
use bincode_next::error::{DecodeError, EncodeError};
use serde::{de::DeserializeOwned, Serialize};

/// Serialize `value` to a `Vec<u8>` using the bincode-1.x-compatible legacy config.
#[inline]
pub fn serialize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, EncodeError> {
    bincode_next::serde::encode_to_vec(value, bincode_next::config::legacy())
}

/// Deserialize `T` from a byte slice using the bincode-1.x-compatible legacy config.
#[inline]
pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    bincode_next::serde::decode_from_slice(bytes, bincode_next::config::legacy()).map(|(v, _)| v)
}

/// Deserialize `T` from a byte slice, also returning how many bytes it
/// consumed.
///
/// [`deserialize`] throws that count away, which makes it impossible to tell
/// where the first value ended and any appended value begins. Readers that have
/// to look past a decoded value — at bytes an older sealer did not write — need
/// the count.
#[inline]
pub fn deserialize_with_len<T: DeserializeOwned>(bytes: &[u8]) -> Result<(T, usize), DecodeError> {
    bincode_next::serde::decode_from_slice(bytes, bincode_next::config::legacy())
}

/// Serialize `value` and append the bytes to `out`. Replaces the
/// `bincode::serialize_into(&mut Vec<u8>, …)` pattern from bincode 1.x without
/// requiring `std::io::Write` (pg-core is `no_std + alloc`).
#[cfg(feature = "stream")]
#[inline]
pub fn serialize_into_vec<T: Serialize + ?Sized>(
    out: &mut Vec<u8>,
    value: &T,
) -> Result<(), EncodeError> {
    let bytes = bincode_next::serde::encode_to_vec(value, bincode_next::config::legacy())?;
    out.extend_from_slice(&bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Sample {
        a: u32,
        b: alloc::string::String,
        c: alloc::vec::Vec<u8>,
    }

    /// Locks the legacy config to bincode-1.x's default byte layout: fixed-int,
    /// little-endian, length-prefixed strings/vecs as u64. Any drift here is a
    /// silent wire-format break and must fail this test.
    #[test]
    fn legacy_config_matches_v1_default_bytes() {
        let s = Sample {
            a: 0x0102_0304,
            b: alloc::string::String::from("hi"),
            c: alloc::vec![0xAA, 0xBB],
        };
        let bytes = serialize(&s).unwrap();

        let expected: &[u8] = &[
            0x04, 0x03, 0x02, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, b'h', b'i',
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xBB,
        ];
        assert_eq!(bytes.as_slice(), expected);

        let round: Sample = deserialize(&bytes).unwrap();
        assert_eq!(round, s);
    }
}

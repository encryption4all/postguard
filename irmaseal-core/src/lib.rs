#![cfg_attr(docsrs, feature(doc_cfg))]

mod artifacts;
mod header;
mod identity;

#[cfg(test)]
mod test_common;

pub mod api;

#[doc(hidden)]
pub mod util;

#[doc(hidden)]
pub use ibe::{kem, Compress};

#[cfg_attr(docsrs, doc(cfg(any(feature = "stream", feature = "wasm_stream"))))]
#[cfg(any(feature = "stream", feature = "wasm_stream"))]
pub mod stream;

#[doc(inline)]
pub use artifacts::*;

#[doc(hidden)]
pub use constants::*;
pub use header::*;
pub use identity::*;

/// IRMAseal error enum type.
#[derive(Debug)]
pub enum Error {
    NotIRMASEAL,
    IncorrectVersion,
    ConstraintViolation,
    FormatViolation,
    KeyError,
    IncorrectTag,
    NotSupported,
    Kem(ibe::kem::Error),
    StdIO(std::io::Error),
    #[cfg(any(feature = "stream", feature = "wasm_stream"))]
    FuturesIO(futures::io::Error),
}

/// Constants used by IRMAseal.
#[allow(unused)]
pub mod constants {
    /// Version 1 (legacy).
    ///
    /// This version used the Kiltz-Vahlis-1 scheme.
    pub const VERSION_V1: u16 = 0;

    /// Version 2.
    ///
    /// This version uses the CGW anonymous IBE scheme to construct a KEM variant. This scheme can
    /// encapsulate the same shared secret for multiple recipients. This version also supports
    /// conjunctions. For this version we required the metadata to be dynamic.
    pub const VERSION_V2: u16 = 1;

    /// The size of the tag with which all IRMAseal bytestreams begin.
    pub const PRELUDE_SIZE: usize = 4;
    /// The tag bytes ith which all IRMAseal bytestreams begin.
    pub const PRELUDE: [u8; PRELUDE_SIZE] = [0x14, 0x8A, 0x8E, 0xA7];
    /// The size of the version identifier.
    pub const VERSION_SIZE: usize = std::mem::size_of::<u16>();
    /// The size of the metadata size.
    pub const METADATA_SIZE_SIZE: usize = std::mem::size_of::<u32>();

    /// The maximum size of the metadata (4 MiB).
    pub const MAX_METADATA_SIZE: usize = 1024 * 1024 * 4;

    /// The maximum size of symmetric segments (4 MiB).
    pub const MAX_SYMMETRIC_CHUNK_SIZE: u32 = 1024 * 1024 * 4;

    /// The preamble contains the following bytes:
    /// * Prelude: 4 bytes,
    /// * Version identifier: 2 bytes,
    /// * Size of metadata: 4 bytes,
    /// * Totalling: 4 + 2 + 4 = 10 bytes.
    pub const PREAMBLE_SIZE: usize = PRELUDE_SIZE + VERSION_SIZE + METADATA_SIZE_SIZE;

    /// Default size of symmetric encryption segments.
    ///
    /// A reasonable default is 1 MiB.
    pub const SYMMETRIC_CRYPTO_DEFAULT_CHUNK: u32 = 1024 * 1024;

    // Symmetric crypto constants.
    // This library uses AES128 because BLS12-381 is only secure up to around 120 bits.

    /// Identifier of the symmetric encryption scheme.
    pub const SYMMETRIC_CRYPTO_DEFAULT_ALGO: &str = "STREAM_32BE_AES128_GCM";

    /// Size of the symmetric key.
    pub const KEY_SIZE: usize = 16;

    /// Default size of the generated initialization vector (IV).
    ///
    /// We always generate 32 bytes of initialization vector.
    /// This should be enough for most use cases.
    pub const DEFAULT_IV_SIZE: usize = 32;

    // The STREAM construction needs only 12 bytes:
    // A 7-byte nonce, a 4-byte counter (u32) and an all-zero or all-one byte,
    // depending on if the segment is the final segment.

    /// Size of the IV used in the "STREAM" encryption construction.
    pub const STREAM_IV_SIZE: usize = 12;

    /// Size of the nonce in the "STREAM" encryption construction.
    pub const STREAM_NONCE_SIZE: usize = 7;

    /// Size of the authentication tag.
    /// The authentication tag is appended to each segment.
    pub const TAG_SIZE: usize = 16;
}

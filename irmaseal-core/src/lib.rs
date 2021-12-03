mod artifacts;
mod identity;
mod metadata;

#[cfg(test)]
mod test_common;

pub mod api;
pub mod util;

#[cfg(all(feature = "stream", feature = "wasm_stream"))]
compile_error!("Features \"stream\" and \"wasm_stream\" cannot be combined. Choose one, depending on your target.");

#[cfg(any(feature = "stream", feature = "wasm_stream"))]
pub mod stream;

pub use artifacts::*;
pub use constants::*;
pub use identity::*;
pub use metadata::*;

pub use ibe::*;

#[derive(Debug)]
pub enum Error {
    NotIRMASEAL,
    IncorrectVersion,
    ConstraintViolation,
    FormatViolation,
    KeyError,
    ReadError,
    WriteError,
    KemError(ibe::kem::Error),
}

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

    /// The tag 'IRMASEAL' with which all IRMAseal bytestreams start.
    pub const PRELUDE_SIZE: usize = 4;
    pub const PRELUDE: [u8; PRELUDE_SIZE] = [0x14, 0x8A, 0x8E, 0xA7];
    pub const VERSION_SIZE: usize = std::mem::size_of::<u16>();
    pub const METADATA_SIZE_SIZE: usize = std::mem::size_of::<u32>();

    // PREAMBLE contains the following:
    // * Prelude: 4 bytes,
    // * Version identifier: 2 bytes,
    // * Size of metadata: 4 bytes,
    // * Totalling: 4 + 2 + 4 = 12 bytes.
    pub const PREAMBLE_SIZE: usize = PRELUDE_SIZE + VERSION_SIZE + METADATA_SIZE_SIZE;

    // Default size of symmetric encryption chunks.
    // Should always be a multiple of the blocksize (16).
    // A reasonably default is 128 KiB.
    pub const SYMMETRIC_CRYPTO_DEFAULT_CHUNK: usize = 1024 * 128;

    // Symmetric crypto constants.
    // This library uses AES128 because BLS12-381 is only secure up to around 120 bits.
    // Furthermore, we construct an AEAD by combining the AES-CTR stream cipher with KMAC128 as an authenticator.
    // The counter is 64 bits wide and represented in big endian to generate blocks.
    // This effectively allows processing payload of at most 2^64 blocks.
    pub const SYMMETRIC_CRYPTO_IDENTIFIER: &str = "AES128-CTR64BE";
    pub const KEY_SIZE: usize = 16;
    pub const IV_SIZE: usize = 16;
    pub const NONCE_SIZE: usize = 8;
    pub const COUNTER_SIZE: usize = 8;

    // Which MAC algorithm is used.
    pub const MAC_IDENTIFIER: &str = "KMAC128";
    pub const TAG_SIZE: usize = 32;
}

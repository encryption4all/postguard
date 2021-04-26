#![no_std]

mod artifacts;
mod identity;
mod metadata;
mod metadata_reader;

pub mod api;
pub mod util;

#[cfg(feature = "stream")]
pub mod stream;

pub use artifacts::*;
pub use identity::*;
pub use metadata::*;
pub use metadata_reader::*;

use arrayvec::ArrayVec;
use core::mem;

#[derive(Debug, PartialEq)]
pub enum Error {
    NotIRMASEAL,
    IncorrectVersion,
    ConstraintViolation,
    FormatViolation,
}

// Version identifier
pub(crate) const VERSION_V1: u16 = 0;

/// The tag 'IRMASEAL' with which all IRMAseal bytestreams start.
pub(crate) const PRELUDE_SIZE: usize = 4;
pub(crate) const PRELUDE: [u8; PRELUDE_SIZE] = [0x14, 0x8A, 0x8E, 0xA7];

// PREAMBLE contains the following:
//
// * Prelude: 4 bytes
// * Version identifier: 2 bytes
// * Size of metadata: 4 bytes
// * Totalling: 4 + 2 + 4 = 8 bytes
pub(crate) const PREAMBLE_SIZE: usize =
    PRELUDE_SIZE + mem::size_of::<u16>() + mem::size_of::<u32>();

// According to calculations, this size can be a lot smaller:
//
// * ciphertext's length needs 2 bytes, ciphertext itself 144.
// * iv's length needs 1 byte, iv itself needs 16
// * identity's length needs 2 bytes, the buff itself needs 1024.
// * Totalling: 2 + 144 + 1 + 16 + 2 + 1024 = 1191
//
// But for now we will keep this size this large as it will grow in the future
// anyway. We use 8182 because together with the PREAMBLE it is 8192 bytes
// Which means the array trait is implemented and we can use it in
// fixed size structs.
pub(crate) const MAX_METADATA_SIZE: usize = 8182;

// Headerbuf is the preamble size plus the metadata
pub const MAX_HEADERBUF_SIZE: usize = PREAMBLE_SIZE + MAX_METADATA_SIZE;

type HeaderBuf = ArrayVec<[u8; MAX_HEADERBUF_SIZE]>;

// How large a block is that has to be encrypted using
// the symmetric crypto algorithm
pub(crate) const SYMMETRIC_CRYPTO_BLOCKSIZE: usize = 16384;

// Which symmetric crypto algorithm is used.
#[allow(dead_code)]
pub(crate) const SYMMETRIC_CRYPTO_IDENTIFIER: &str = "AES256-CTR";

// Which verification algorithm is used.
#[allow(dead_code)]
pub(crate) const VERIFIER_IDENTIFIER: &str = "SHA3-256";

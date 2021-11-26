//#![no_std]

mod artifacts;
mod identity;
mod metadata;
//mod metadata2;
//mod metadata_reader;

pub mod api;
pub mod util;

#[cfg(feature = "stream")]
pub mod stream;

pub use artifacts::*;
pub use identity::*;
pub use metadata::*;
//pub use metadata_reader::*;

use arrayvec::ArrayVec;
use core::mem;
pub use ibe::*;

extern crate alloc;

#[derive(Debug, PartialEq)]
pub enum Error {
    NotIRMASEAL,
    IncorrectVersion,
    ConstraintViolation,
    FormatViolation,
    DecapsulationError,
    VersionError,
}

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
pub(crate) const PRELUDE_SIZE: usize = 4;
pub(crate) const PRELUDE: [u8; PRELUDE_SIZE] = [0x14, 0x8A, 0x8E, 0xA7];
pub(crate) const VERSION_SIZE: usize = mem::size_of::<u16>();
pub(crate) const METADATA_SIZE_SIZE: usize = mem::size_of::<u32>();

// PREAMBLE contains the following:
//
// * Prelude: 4 bytes
// * Version identifier: 2 bytes
// * Size of metadata: 8 bytes
// * Totalling: 4 + 2 + 8 = 14 bytes
pub(crate) const PREAMBLE_SIZE: usize = PRELUDE_SIZE + VERSION_SIZE + METADATA_SIZE_SIZE;

// How large a block is that has to be encrypted using
// the symmetric crypto algorithm
// 128 KiB
pub const SYMMETRIC_CRYPTO_BLOCKSIZE: usize = 131072;

// Which symmetric crypto algorithm is used.
#[allow(dead_code)]
pub const SYMMETRIC_CRYPTO_IDENTIFIER: &str = "AES256-CTR64BE";

// Which verification algorithm is used.
#[allow(dead_code)]
pub const MAC_IDENTIFIER: &str = "SHA3-256";

#[allow(dead_code)]
pub const KEY_SIZE: usize = 32;
pub const IV_SIZE: usize = 16;
#[allow(dead_code)]
pub const MAC_SIZE: usize = 32;
pub const CIPHERTEXT_SIZE: usize = 144;

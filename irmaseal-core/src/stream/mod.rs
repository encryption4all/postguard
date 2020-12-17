//! Implementation of the IRMAseal stream format. Includes zero-allocation streaming encryption and decryption.

mod opener;
mod sealer;
pub(crate) mod util;

#[cfg(test)]
mod tests;

pub use futures::prelude::*;
pub use opener::*;
pub use sealer::*;

use crate::metadata::{IVSIZE, KEYSIZE};

#[cfg(feature = "wasm")]
mod aes_wasm;
#[cfg(feature = "wasm")]
pub(crate) use aes_wasm::SymCrypt;

#[cfg(not(feature = "wasm"))]
mod aes_lib;
#[cfg(not(feature = "wasm"))]
pub(crate) use aes_lib::SymCrypt;

pub(crate) type Verifier = hmac::Hmac<sha3::Sha3_256>;

/// The tag 'IRMASEAL' with which all IRMAseal bytestreams start.
pub(crate) const PRELUDE: [u8; 4] = [0x14, 0x8A, 0x8E, 0xA7];

/// The number of blocks that `opener` and `sealer` will cache to yield the plaintext and ciphertext.
/// TODO: In case of aes_wasm the buffer needs to be bigger to reduce cross-platform calls.
///       Make this a bit more nice, because in aes_lib scenarios this buffer can remain small.
pub const CHUNKS: usize = 2048;

/// The size of one block in AES
pub(crate) const BLOCKSIZE: usize = 16;

// According to calculations, this size can be a lot smaller:
//
// * Version is an enum with 1 option. If I understand correctly i
//   only serializes its discriminant, so it requires 1 byte.
// * ciphertext's length needs 2 bytes, ciphertext itself 144.
// * iv's length needs 1 byte, iv itself needs 16
// * identity's length needs 2 bytes, the buff itself needs 1024.
// * Totalling: 1 + 2 + 144 + 1 + 16 + 2 + 1024 = 1191
//
// But for now we will keep this size this large as it will grow in the future
// anyway.
pub const MAX_METADATA_SIZE: usize = 8192;

//! Implementation of the IRMAseal stream format. Includes zero-allocation streaming encryption and decryption.
use tiny_keccak::{Hasher, Kmac, Sha3};

mod sealer;
mod unsealer;

#[cfg(feature = "stream")]
mod aes_async;

#[cfg(feature = "wasm_stream")]
mod aes_wasm;

#[cfg(test)]
mod tests;

pub use sealer::*;
pub use unsealer::*;

use crate::Error;
use async_trait::async_trait;

/// Domain separation bytestring
pub const DOMAIN: &'static [u8] = b"IRMASeal";

pub trait NewMac {
    type Hasher: Hasher;
    fn new_with_key(key: &[u8]) -> Self::Hasher;
}

impl NewMac for Kmac {
    type Hasher = Self;

    fn new_with_key(key: &[u8]) -> Self::Hasher {
        Self::Hasher::v128(key, DOMAIN)
    }
}

impl NewMac for Sha3 {
    type Hasher = Self;

    fn new_with_key(key: &[u8]) -> Self::Hasher {
        let mut h = Sha3::v256();
        h.update(key);
        h.update(DOMAIN);
        h
    }
}

#[async_trait(?Send)]
pub trait AsyncNewCipher {
    type Cipher: AsyncStreamCipher;
    async fn new_from_slices(key: &[u8], nonce: &[u8]) -> Result<Self::Cipher, Error>;
}

#[async_trait(?Send)]
pub trait AsyncStreamCipher {
    async fn apply_keystream(&mut self, data: &mut [u8]);
}

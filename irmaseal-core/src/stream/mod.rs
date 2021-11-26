//! Implementation of the IRMAseal stream format. Includes zero-allocation streaming encryption and decryption.
use tiny_keccak::{Hasher, Kmac, Sha3};

mod sealer;
mod unsealer;

#[cfg(test)]
mod tests;

pub use sealer::*;
pub use unsealer::*;

#[derive(Debug, PartialEq)]
pub enum StreamError {
    IrmaSealError(crate::Error),
    UpstreamWritableError,
    EndOfStream,
    PrematureEndError,
}

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

// probably should'nt use SHA3_256 for a MAC, it's wasteful
// Kmac128 is much more suitable, because of it's higher rate
impl NewMac for Sha3 {
    type Hasher = Self;

    fn new_with_key(key: &[u8]) -> Self::Hasher {
        let mut h = Sha3::v256();
        h.update(key);
        h.update(DOMAIN);
        h
    }
}

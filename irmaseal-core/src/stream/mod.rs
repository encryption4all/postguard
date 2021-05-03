//! Implementation of the IRMAseal stream format. Includes zero-allocation streaming encryption and decryption.
mod sealer;
mod unsealer;
mod util;

#[cfg(test)]
mod tests;

pub use sealer::*;
pub use unsealer::*;
pub use util::*;

#[derive(Debug, PartialEq)]
pub enum StreamError {
    IrmaSealError(crate::Error),
    UpstreamWritableError,
    EndOfStream,
    PrematureEndError,
}

pub(crate) type SymCrypt = ctr::Ctr32BE<aes::Aes256>;
pub(crate) type Verifier = sha3::Sha3_256;

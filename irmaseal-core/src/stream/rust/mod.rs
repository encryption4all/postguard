//! This module uses the "stream" module from the AEAD crate to encrypt arbritrary large
//! bytestreams user-defined segments using [STREAM][1].
//!
//! [1]: https://eprint.iacr.org/2015/189.pdf
pub mod sealer;
pub mod unsealer;

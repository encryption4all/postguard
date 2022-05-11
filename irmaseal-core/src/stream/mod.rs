//! Implementation of the IRMAseal bytestream format.  We have two dedicated implementations:
//!
//! # Rust
//!
//! This module uses the "stream" module from the AEAD crate to encrypt arbritrary large is pure
//! rust and uses [`aead::stream`], the other one constructs the same `STREAM`.  bytestreams
//! user-defined segments using [STREAM][1].
//!
//! # Web
//!
//! This module implements [STREAM OAE2][1] encryption using primitives provided by WebCrypto.
//! This module becomes irrelevant when the AEAD crate will support async traits, since then it is
//! easy to construct this by implementing the traits bounds.
//!
//!
//! [1]: https://eprint.iacr.org/2015/189.pdf

#[cfg(feature = "stream")]
mod rust;

#[cfg(feature = "stream")]
pub use {rust::sealer::seal, rust::unsealer::Unsealer};

#[cfg(feature = "wasm_stream")]
mod web;

#[cfg(feature = "wasm_stream")]
pub use {web::sealer::seal as web_seal, web::unsealer::Unsealer as WebUnsealer};

#[cfg(test)]
mod tests;

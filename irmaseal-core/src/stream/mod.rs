//! This module provides an implementation of the IRMAseal bytestream format.
//!
//! The module implements a hybrid KEM+DEM approach:
//! * First, a shared secret is encapsulated for all recipients using [`ibe::kem::mr`].
//! * Then, the metadata is written to a stream. The metadata contains a ciphertext and the
//!   necessary information for decapsulation for all recipients while hiding the attribute values.
//! * Finally, the arbitrary-sized payload stream is chunked into user-defined segments and
//!   encrypted using the shared secret as symmetric key as described in  the paper [Online
//!   Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance][1].
//!
//! The header bytestream has the following layout:
//!
//! PRELUDE (4 bytes) || VERSION (2 bytes) || METASIZE (4 bytes) || METADATA (dynamic) || PAYLOAD_CT (dynamic)
//!
//! During decryption, each segment of the payload is seperately authenticated, this make the data safe for
//! consumers before the stream has been exhausted.
//!
//! This module offers two dedicated implementations, as listed below.
//!
//! # Rust
//!
//! This module implements the STREAM construction using [`aead::stream`] provided by [`Rust
//! Crypto`](https://github.com/RustCrypto). The module provides an interface to encrypt
//! data from an [AsyncRead][`futures::io::AsyncRead`] into an [AsyncWrite][`futures::io::AsyncWrite`].
//!
//! # Web
//!
//! This module implements the STREAM construction using primitives provided by [Web
//! Crypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). The module provides
//! an interface to encrypt data from a [`Stream<Item = Result<Uint8Array, JsValue>>`][`futures::stream::Stream`] into a
//! [`Sink<Uint8Array, Error = JsValue>`][`futures::sink::Sink`].
//!
//! This module is only available on the `target_arch = "wasm32-unknown-unknown"`.
//!
//! This module can largely be simplified when [the AEAD crate][`aead`] will support async, see
//! [the relevant issue](https://github.com/RustCrypto/traits/issues/304).
//!
//! [1]: https://eprint.iacr.org/2015/189.pdf

#[cfg(all(
    feature = "wasm_stream",
    target_arch = "wasm32-unknown-unknown",
    not(docsrs)
))]
compile_error!("feature \"wasm_stream\" can only be used for wasm targets");

#[cfg_attr(docsrs, doc(cfg(feature = "stream")))]
#[cfg(feature = "stream")]
pub mod rust;

#[cfg_attr(docsrs, doc(cfg(feature = "wasm_stream")))]
#[cfg(feature = "wasm_stream")]
pub mod web;

#[cfg(test)]
mod tests;

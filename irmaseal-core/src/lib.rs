//! # IRMAseal core library
//!
//! This library provides implementations of the IRMAseal protocol.
//!
//! IRMAseal is cryptographic protocol that utilizes identity-based encryption (IBE) to provide
//! confidentiality and integrity over messages.
//!
//! The library implements a hybrid KEM+DEM approach:
//! * First, a shared secret is encapsulated for all recipients using [Multi-recipient
//! Identity-Based Encryption][`ibe::kem::mkem`].
//!
//! * Then, the ciphertext and all information that is required for decryption is available in the
//! [header][`crate::header::Header`]. The header is publicly visible and therefore all sensitive
//! content is purged.
//!
//! * Finally, the arbitrary-sized payload stream is written either at once (using
//! [Mode::InMemory][`crate::header::Mode::InMemory`]) using an AEAD or in user-defined segments
//! ([Mode::Streaming][`crate::header::Mode::Streaming`]) and encrypted using the shared secret as
//! symmetric key as described in  the paper [Online Authenticated-Encryption and its Nonce-Reuse
//! Misuse-Resistance][1].
//!
//! The bytestream consists of the following segments, followed by their length in bytes:
//!
//! ```text
//!                  PREAMBLE (10)                ||
//! PRELUDE (4) || VERSION (2) || HEADER SIZE (4) || HEADER (*) || PAYLOAD (*)
//! ```
//!
//! This library offers two symmetric cryptography providers, as listed below.
//!
//! ## Symmetric crypto backends
//!
//! This library supports two symmetric encryption backends, depending on the compilation target
//! and selected features.
//!
//! ### Rust Crypto
//!
//! This module utilizes the symmetric primitives provided by [`Rust
//! Crypto`](https://github.com/RustCrypto). The streaming interface, enabled using the feature
//! `"rust_stream"` is a small wrapper around [`aead::stream`]. This feature enables an interface
//! to encrypt data using asynchronous byte streams, specifically from an
//! [AsyncRead][`futures::io::AsyncRead`] into an [AsyncWrite][`futures::io::AsyncWrite`].
//!
//! ### Web Crypto
//!
//! This module utilizes the symmetric primitives provided by [Web
//! Crypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). The streaming
//! interface, enabled using the feature `"web_stream"` enables an interface to encrypt data from a
//! [`Stream<Item = Result<Uint8Array, JsValue>>`][`futures::stream::Stream`] into a
//! [`Sink<Uint8Array, Error = JsValue>`][`futures::sink::Sink`]. These can easily interact with
//! [Web Streams](https://developer.mozilla.org/en-US/docs/Web/API/Streams_API) using the
//! [wasm-streams](https://docs.rs/wasm-streams/latest/wasm_streams/index.html) crate.
//!
//! This module is only available on the `target_arch = "wasm32-unknown-unknown"` and the output
//! _should_ be used in browser environments.
//!
//! This module can largely be simplified when [the AEAD crate][`aead`] will support async, see
//! [the relevant issue](https://github.com/RustCrypto/traits/issues/304).
//!
//! [1]: https://eprint.iacr.org/2015/189.pdf
//!
//! ## Streaming vs Memory
//!
//! For large or arbitrary sized data streams, enable either the `rust_stream` or `web_stream`
//! feature. In this mode, during decryption, each segment of the payload is seperately
//! authenticated, this makes the data safe for downstream consumers before the stream has been
//! exhausted. Note that it is up to the developer to choose which is suitable for their
//! application. Only use the in-memory variant if you are absolutely sure that you are
//! _exclusively_ encrypting small messages.
//!
//! ## Examples
//!
//! ### Setting up the encryption parameters.
//!
//! The public key should be retrieved from the Private Key Generator (PKG).
//! The encryption policy can be initialized as follows:
//!
//! ```
//! use std::collections::BTreeMap;
//! use std::time::SystemTime;
//! use irmaseal_core::identity::{Attribute, Policy};
//!
//! let timestamp = SystemTime::now()
//!     .duration_since(SystemTime::UNIX_EPOCH)
//!     .unwrap()
//!     .as_secs();
//!
//! let id1 = String::from("j.doe@example.com");
//! let id2 = String::from("john.doe@example.com");
//!
//! let p1 = Policy {
//!     timestamp,
//!     con: vec![Attribute::new(
//!         "pbdf.gemeente.personalData.bsn",
//!         Some("123456789"),
//!     )],
//! };
//!
//! let p2 = Policy {
//!     timestamp,
//!     con: vec![
//!         Attribute::new("pbdf.gemeente.personalData.name", Some("john")),
//!         Attribute::new("pbdf.sidn-pbdf.email.email", Some("john.doe@example.com")),
//!     ],
//! };
//!
//! let policies = BTreeMap::<String, Policy>::from([(id1, p1), (id2, p2)]);
//! ```
//!
//! This will specify two recipients who can decrypt, in this case identified by their e-mail
//! address, but this identifier can be anything which uniquely represents a receiver. The
//! recipients are only able to decrypt if they are able to prove the that they own the attributes
//! specified in the `con` field.
//!
//! ### Seal a slice using the Rust Crypto backend.
//!
//! ```
//! use irmaseal_core::error::Error;
//! use irmaseal_core::header::{Header};
//! use irmaseal_core::artifacts::{PublicKey, UserSecretKey};
//! use irmaseal_core::SealedPacket;
//! use irmaseal_core::test::TestSetup;
//!
//! # fn main() -> Result<(), Error> {
//! let mut rng = rand::thread_rng();
//! let setup = TestSetup::default();
//!
//! // Encryption & serialization.
//! let input = b"SECRET DATA";
//! let packet = SealedPacket::<Vec<u8>>::new(&setup.mpk, &setup.policies, &mut rng, &input)?;
//! let out_bin = packet.to_bin()?;
//!
//! println!("out: {:?}", &out_bin);
//!
//! // Deserialization & decryption.
//! let packet2 = SealedPacket::<Vec<u8>>::from_bin(&out_bin)?;
//! let id = "john.doe@example.com";
//! let usk = &setup.usks[id];
//! let original = packet2.unseal(&id, usk)?;
//!
//! assert_eq!(&input.to_vec(), &original);
//! # Ok(())
//! # }
//! ```
//!
//! ### Seal a stream using the Rust Crypto backend.
//!
//! ### Using the Web Crypto backend.
//!
//! See [`irmaseal-wasm-bindings`](../../irmaseal-wasm-bindings/tests/tests.rs).

//#![deny(missing_debug_implementations, rust_2018_idioms, missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod api;
pub mod artifacts;
pub mod consts;
pub mod error;
pub mod header;
pub mod identity;
mod util;

#[doc(hidden)]
pub mod test;

#[cfg(feature = "rust")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust")))]
pub mod rust;

#[cfg(feature = "web")]
#[cfg_attr(docsrs, doc(cfg(feature = "web")))]
pub mod web;

#[doc(inline)]
pub use artifacts::{PublicKey, UserSecretKey};

#[doc(hidden)]
pub use ibe::{kem, Compress};

#[doc(hidden)]
pub use consts::*;

use crate::header::Header;
use serde::{Deserialize, Serialize};

/// An IRMAseal encrypted packet.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SealedPacket<R> {
    /// The version of the header.
    pub version: u16,

    /// The header of the IRMAseal packet.
    pub header: Header,

    /// The ciphertext (encrypted plaintext).
    pub ciphertext: R,
}

/// A [`Sealer`] is used to create an IRMAseal bytestream.
#[derive(Debug)]
pub struct Sealer<W, C: SealConfig> {
    w: W,
    config: C,
}

/// An [`Unsealer`] is used to decrypt IRMAseal bytestreams.
///
/// Unsealing is a two-step process:
///
/// 1. First the header is read. This yields information about the recipients.
/// Using this information the user can retrieve a user secret key.
///
/// 2. Then, the user has input the user secret key and the recipient for which decryption should
/// take place.
#[derive(Debug)]
pub struct Unsealer<R, C: UnsealConfig> {
    /// The version found before the raw header.
    pub version: u16,

    /// The parsed header.
    pub header: Header,

    r: R,
    config: C,
}

/// Configuration for an Unsealer.
pub trait UnsealConfig {}

/// Configuration for a Sealer.
pub trait SealConfig {}

//#[cfg(any(feature = "rust_stream", feature = "web_stream"))]
//pub(crate) mod stream {
//    use crate::header::Header;
//}

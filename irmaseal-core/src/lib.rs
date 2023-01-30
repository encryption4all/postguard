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
//! _should_ be used in browser environments. This also greatly reduces the bundle size.
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
//! use std::time::SystemTime;
//! use irmaseal_core::identity::{Attribute, Policy, RecipientPolicy};
//!
//! let timestamp = SystemTime::now()
//!     .duration_since(SystemTime::UNIX_EPOCH)
//!     .unwrap()
//!     .as_secs();
//!
//! let id1 = String::from("j.doe@example.com");
//! let id2 = String::from("john.doe@example.com");
//!
//! let p1 = RecipientPolicy {
//!     timestamp,
//!     con: vec![Attribute::new(
//!         "pbdf.gemeente.personalData.bsn",
//!         Some("123456789"),
//!     )],
//! };
//!
//! let p2 = RecipientPolicy {
//!     timestamp,
//!     con: vec![
//!         Attribute::new("pbdf.gemeente.personalData.name", Some("john")),
//!         Attribute::new("pbdf.sidn-pbdf.email.email", Some("john.doe@example.com")),
//!     ],
//! };
//!
//! let policies = Policy::from([(id1, p1), (id2, p2)]);
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
//! use irmaseal_core::rust::{SealerMemoryConfig, UnsealerMemoryConfig};
//! use irmaseal_core::test::TestSetup;
//! use irmaseal_core::{SealedPacket, Sealer, Unsealer};
//!
//! # fn main() -> Result<(), Error> {
//! let mut rng = rand::thread_rng();
//! let setup = TestSetup::default();
//!
//! // Encryption & serialization.
//! let input = b"SECRET DATA";
//!
//! // Specifying the configuration is only required when there
//! // are multiple options in scope.
//! let packet =
//!     Sealer::<SealerMemoryConfig>::new(&setup.mpk, &setup.policy, &mut rng)?.seal(input)?;
//! let out_bin = packet.into_bytes()?;
//!
//! println!("out: {:?}", &out_bin);
//!
//! // Deserialization & decryption.
//! let packet2 = SealedPacket::from_bytes(&out_bin)?;
//! let id = "john.doe@example.com";
//! let usk = &setup.usks[id];
//! let original = Unsealer::<_,UnsealerMemoryConfig>::new(packet2).unseal(id, usk)?;
//!
//! assert_eq!(&input.to_vec(), &original);
//!
//! # Ok(())
//! # }
//! ```
//!
//! ### Seal a bytestream using the Rust Crypto backend.
//!
//! ```
//! use irmaseal_core::error::Error;
//! use irmaseal_core::rust::stream::{SealerStreamConfig, UnsealerStreamConfig};
//! use irmaseal_core::test::TestSetup;
//! use irmaseal_core::{Sealer, Unsealer};
//! use futures::io::Cursor;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Error> {
//! let mut rng = rand::thread_rng();
//! let setup = TestSetup::default();
//!                                                                         
//! let mut input = Cursor::new(b"SECRET DATA");
//! let mut encrypted = Vec::new();
//!                                                                         
//! Sealer::<SealerStreamConfig>::new(&setup.mpk, &setup.policy, &mut rng)?
//!     .seal(&mut input, &mut encrypted)
//!     .await?;
//!                                                                         
//! let mut original = Vec::new();
//! let id = "john.doe@example.com";
//! let usk = &setup.usks[id];
//! Unsealer::<_, UnsealerStreamConfig>::new(&mut Cursor::new(encrypted))
//!     .await?
//!     .unseal(id, usk, &mut original)
//!     .await?;
//!                                                                         
//! assert_eq!(input.into_inner().to_vec(), original);
//! # Ok(())
//! # }
//! ```
//! ### Using the Web Crypto backend.
//!
//! Using the Web Crypto backend in Rust can be useful in Rust web frameworks (e.g.,
//! Yew/Dioxus/Leptos). Otherwise, it is best to use the Javascript/Typescript, see
//! [`irmaseal-wasm-bindings`](../../irmaseal-wasm-bindings/tests/tests.rs).

#![deny(
    missing_debug_implementations,
    rust_2018_idioms,
    missing_docs,
    rustdoc::broken_intra_doc_links
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod api;
pub mod artifacts;
pub mod consts;
pub mod error;
pub mod header;
pub mod identity;
mod util;

#[cfg(feature = "rust")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust")))]
pub mod rust;

#[cfg(feature = "web")]
#[cfg_attr(docsrs, doc(cfg(feature = "web")))]
pub mod web;

#[doc(hidden)]
pub use ibe::{kem, Compress};

#[doc(hidden)]
pub use consts::*;

#[doc(hidden)]
pub mod test;

use crate::error::Error;
use crate::header::{Header, Mode};
use crate::util::*;
use serde::{Deserialize, Serialize};

extern crate alloc;

/// A Sealer is like a builder used to encrypt and optionally sign data using IRMAseal.
#[derive(Debug)]
pub struct Sealer<C: SealerConfig> {
    // The prebuilt header.
    header: Header,

    // The implementation-specific configuration.
    config: C,
}

/// An Unsealer is used to decrypt and verify data using IRMAseal.
///
/// Unsealing is a two-step process:
///
/// 1. First the header is read. This yields information for whom the message is encrypted. Using
///    this information the user can retrieve a user secret key.
///
/// 2. Then, the user has input the user secret key and the recipient for which decryption should
///    take place.
#[derive(Debug)]
pub struct Unsealer<R, C: UnsealerConfig> {
    /// The version found before the raw header.
    pub version: u16,

    /// The parsed header.
    pub header: Header,

    // The type of the input.
    r: R,

    // The implementation-specific configuration.
    config: C,
}

/// Sealer configuration.
///
/// This trait is sealed, you cannot implement it yourself.
pub trait SealerConfig: sealed::SealerConfig {}

/// Unsealer configuration.
///
/// This trait is sealed, you cannot implement it yourself.
pub trait UnsealerConfig: sealed::UnsealerConfig {}

pub(crate) mod sealed {
    pub trait UnsealerConfig {}
    pub trait SealerConfig {}
}

/// An IRMAseal encrypted packet.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SealedPacket {
    /// The version of the header.
    pub version: u16,

    /// The header of the IRMAseal packet.
    pub header: Header,

    /// The symmetric ciphertext.
    pub ciphertext: Vec<u8>,
}

impl SealedPacket {
    /// Serialize to a JSON string.
    pub fn into_json(self) -> Result<String, Error> {
        serde_json::to_string(&self).map_err(Error::Json)
    }

    /// Deserialize from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, Error> {
        serde_json::from_str(s).map_err(Error::Json)
    }

    /// Serialize to binary format.
    pub fn into_bytes(self) -> Result<Vec<u8>, Error> {
        let mut header_buf = Vec::new();
        self.header.into_bytes(&mut header_buf)?;

        let mut out = Vec::new();
        out.extend_from_slice(&PRELUDE);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(header_buf.len())
                .map_err(|_| Error::ConstraintViolation)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&header_buf);
        out.extend_from_slice(&self.ciphertext);

        Ok(out)
    }

    /// Deserialize from binary format.
    pub fn from_bytes(b: impl AsRef<[u8]>) -> Result<Self, Error> {
        let b = b.as_ref();

        let (version, header_len) = preamble_checked(&b[..PREAMBLE_SIZE])?;

        let len = b.len();
        let header_bytes = &b[PREAMBLE_SIZE..PREAMBLE_SIZE + header_len];
        let header = Header::from_bytes(header_bytes)?;

        let payload_len = match header.mode {
            Mode::InMemory { size } => size,
            _ => return Err(Error::ModeNotSupported(header.mode)),
        };

        let ct_len = payload_len as usize + TAG_SIZE;
        let ciphertext = b[len - ct_len..].to_vec();

        Ok(SealedPacket {
            version,
            header,
            ciphertext,
        })
    }
}

//! # PostGuard core library
#![doc(
    html_favicon_url = "https://postguard.eu/favicon.ico",
    html_logo_url = "https://postguard.eu/pg_logo_no_text.svg"
)]
#![doc = "<div style=\"max-width: 400px; margin: auto\">"]
#![doc = include_str!("./../../img/pg_logo.svg")]
#![doc = "</div>"]
#![deny(
    missing_debug_implementations,
    rust_2018_idioms,
    missing_docs,
    rustdoc::broken_intra_doc_links
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! PostGuard is cryptographic protocol that utilizes identity-based primitives (key
//! encapsulation and signatures) to provide confidentiality, integrity and authenticity over
//! messages.
//!
//! The library implements a hybrid Encrypt-then-Sign (EtS) approach:
//!
//! * KEM: First, a shared secret is encapsulated for all recipients using [`Multi-User Identity-Based
//! Encryption`][`ibe::kem::mkem`].
//!
//! * Sign: The ciphertext(s) and all information that is required for decryption is available in the
//! [header][`client::Header`]. The header is publicly visible and therefore all sensitive
//! content is purged. The header, ciphertexts and arbitrary-long message is signed using a
//! identity-based signature under the identity of the sender.
//!
//! * DEM: The arbitrary-sized payload stream is written either at once (in memory) using an AEAD
//! or in user-defined segments (streaming) and encrypted using the shared secret as symmetric key
//! as described in  the paper [Online Authenticated-Encryption and its Nonce-Reuse
//! Misuse-Resistance][1].
//!
//! ### Wire format
//!
//! The wire format consists of the following segments, followed by their length in bytes:
//!
//! ```text
//!                  PREAMBLE (10)                ||
//! = PRELUDE (4) || VERSION (2) || HEADER LEN (4)
//!
//!                  HEADER (*)                   ||
//! = HEADER (*) || HEADER SIG LEN (4) || HEADER SIG (*)
//!
//!                  PAYLOAD  (*)                 ||
//! = DEM.Enc(M (*) || STREAM SIG (*) || STREAM SIG LEN (4))
//! ```
//!
//! ## Symmetric Crypto Backends
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
//! ## Streaming vs In-memory
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
//! ### Setting up the encryption parameters
//!
//! The public key should be retrieved from the Private Key Generator (PKG).
//! The encryption policy can be initialized as follows:
//!
//! ```
//! use std::time::SystemTime;
//! use pg_core::identity::{Attribute, Policy, EncryptionPolicy};
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
//! let policies = EncryptionPolicy::from([(id1, p1), (id2, p2)]);
//! ```
//!
//! This will specify two recipients who can decrypt, in this case identified by their e-mail
//! address, but this identifier can be anything which uniquely represents a receiver. The
//! recipients are only able to decrypt if they are able to prove the that they own the attributes
//! specified in the `con` field.
//!
//! ### Seal a slice using the Rust Crypto backend
//!
//! ```
//! use pg_core::client::{PostGuardPacket, Sealer, Unsealer};
//! use pg_core::client::rust::{SealerMemoryConfig, UnsealerMemoryConfig};
//! use pg_core::test::TestSetup;
//! # use pg_core::error::Error;
//!
//! # fn main() -> Result<(), Error> {
//! let mut rng = rand::thread_rng();
//! let setup = TestSetup::new(&mut rng);
//!
//! // Encryption & serialization.
//! let input = b"SECRET DATA";
//!
//! // Specifying the configuration is only required when there
//! // are multiple options in scope.
//! let packet: PostGuardPacket =
//!     Sealer::<SealerMemoryConfig>::new(&setup.mpk, &setup.policy, &mut rng)?.seal(input)?;
//! let out_bin = packet.into_bytes()?;
//!
//! println!("out: {:?}", &out_bin);
//!
//! // Deserialization & decryption.
//! let packet2 = PostGuardPacket::from_bytes(&out_bin)?;
//! let id = "john.doe@example.com";
//! let usk = &setup.usks[id];
//! let original = Unsealer::<_, UnsealerMemoryConfig>::new(packet2).unseal(id, usk)?;
//!
//! assert_eq!(&input.to_vec(), &original);
//!
//! # Ok(())
//! # }
//! ```
#![cfg_attr(
    feature = "rust_stream",
    doc = r##"
 ### Seal a bytestream using the Rust Crypto backend

 ```
 use pg_core::client::rust::stream::{SealerStreamConfig, UnsealerStreamConfig};
 use pg_core::client::{Sealer, Unsealer};
 use pg_core::test::TestSetup;
 use futures::io::Cursor;
 # use pg_core::error::Error;

 # #[tokio::main]
 # async fn main() -> Result<(), Error> {
 let mut rng = rand::thread_rng();
 let setup = TestSetup::new(&mut rng);
                                                                         
 let mut input = Cursor::new(b"SECRET DATA");
 let mut sealed = Vec::new();
                                                                         
 Sealer::<SealerStreamConfig>::new(&setup.mpk, &setup.policy, &mut rng)?
     .seal(&mut input, &mut sealed)
     .await?;
                                                                         
 let mut original = Vec::new();
 let id = "john.doe@example.com";
 let usk = &setup.usks[id];
 Unsealer::<_, UnsealerStreamConfig>::new(&mut Cursor::new(sealed))
     .await?
     .unseal(id, usk, &mut original)
     .await?;
                                                                         
 assert_eq!(input.into_inner().to_vec(), original);
 # Ok(())
 # }
 ```
"##
)]
//!
//! ### Using the Web Crypto backend
//!
//! Using the Web Crypto backend in Rust can be useful in Rust web frameworks (e.g.,
//! Yew/Dioxus/Leptos).

extern crate alloc;

pub mod api;
pub mod artifacts;
pub mod consts;
pub mod error;
pub mod identity;

#[cfg(any(feature = "rust", feature = "web"))]
pub mod client;

#[doc(hidden)]
pub use ibe::{kem, Compress};

#[doc(hidden)]
pub use ibs;

#[doc(hidden)]
pub use consts::*;

#[doc(hidden)]
pub mod test;

mod util;

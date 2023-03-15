//! # PostGuard core library
#![no_std]
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
    rustdoc::broken_intra_doc_links,
    unsafe_code
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! PostGuard is cryptographic protocol that utilizes identity-based primitives (key
//! encapsulation and signatures) to provide confidentiality, integrity and authenticity over
//! messages.
//!
//! The library implements a hybrid Sign-then-Encrypt (StE) composition:
//!
//! * KEM: First, a shared secret is encapsulated for all recipients using [`Multi-User Identity-Based
//! Encryption`][`ibe::kem::mkem`]. The identity of the recipients is used in the encryption.
//!
//! * Sign: The KEM ciphertext(s) and all information that is required for decryption is available in the
//! [header][`client::Header`]. The header is publicly visible and therefore all sensitive
//! content is purged. The header, ciphertexts and arbitrary-long message is signed using a
//! identity-based signature under the identity of the sender. This identity is only visible to
//! the receivers from the previous step.
//!
//! * DEM: The arbitrary-sized payload stream is written either at once (in memory) using an AEAD
//! or in user-defined segments (streaming) and encrypted using the shared secret as symmetric key
//! as described in  the paper [Online Authenticated-Encryption and its Nonce-Reuse
//! Misuse-Resistance][1].
//!
//! [1]: https://eprint.iacr.org/2015/189.pdf
//!
//! ## Symmetric Crypto Backends
//!
//! This library offers two symmetric cryptography providers, [`Rust
//! Crypto`](https://github.com/RustCrypto) and [`Web
//! Crypto`](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). The Rust Crypto
//! backend is by default enabled using the `rust` feature. The Web Crypto backend can be enabled
//! by the `web` feature, but only when targeting `wasm32-unknown-unknown`.
//!
//! ## Streaming vs In-memory
//!
//! For large or arbitrary sized data streams, enable the `stream` feature. In this mode, during
//! decryption, each segment of the payload is seperately authenticated, this makes the data safe
//! for downstream consumers before the stream has been exhausted. Note that it is up to the
//! developer to choose which is suitable for their application. Only use the in-memory variant if
//! you are absolutely sure that you are _exclusively_ encrypting small messages.
//!
//! ## Examples
//!
//! ### Setting up the encryption parameters
//!
//! The public key and user secret keys for encryption can be retrieved from the Private Key
//! Generator (PKG).
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
//! let id1 = String::from("Alice");
//! let id2 = String::from("Bob");
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
//!         Attribute::new("pbdf.gemeente.personalData.name", Some("Bob")),
//!         Attribute::new("pbdf.sidn-pbdf.email.email", Some("bob@example.com")),
//!     ],
//! };
//!
//! let policy = EncryptionPolicy::from([(id1, p1), (id2, p2)]);
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
//! use pg_core::client::rust::{SealerMemoryConfig, UnsealerMemoryConfig};
//! use pg_core::client::{Sealer, Unsealer};
//! # use pg_core::error::Error;
//! use pg_core::test::TestSetup;
//!
//! # fn main() -> Result<(), Error> {
//! let mut rng = rand::thread_rng();
//! # let TestSetup {
//! #     mpk,
//! #     ibs_pk,
//! #     policies,
//! #     usks,
//! #     signing_keys,
//! #     ..
//! # } = TestSetup::new(&mut rng);
//! # let signing_key = signing_keys.get("Alice").unwrap();
//! # let id = "Bob";
//! # let usk = usks.get("Bob").unwrap();
//!                                                                                             
//! // Sender: retrieve public key, setup policy and signing keys.
//!                                                                                             
//! let input = b"SECRET DATA";
//! let sealed = Sealer::<_, SealerMemoryConfig>::new(&mpk, &policies, &signing_key, &mut rng)?
//!     .seal(input)?;
//!                                                                                             
//! // Receiver: retrieve USK and verifying key.
//!                                                                                             
//! let (original, verified_sender_id) =
//!     Unsealer::<_, UnsealerMemoryConfig>::new(sealed, &ibs_pk)?.unseal(id, &usk)?;
//!                                                                                             
//! assert_eq!(&input.to_vec(), &original);
//! assert_eq!(&verified_sender_id, policies.get("Alice").unwrap());
//! # Ok(())
//! # }
//! ```
#![cfg_attr(
    feature = "stream",
    doc = r##"
 ### Seal a bytestream using the Rust Crypto backend

 ```
 use pg_core::client::rust::stream::{SealerStreamConfig, UnsealerStreamConfig};
 use pg_core::client::{Sealer, Unsealer};
 # use pg_core::error::Error;
 use pg_core::test::TestSetup;
 
 use futures::io::Cursor;
                                                                                          
 # #[tokio::main]
 # async fn main() -> Result<(), Error> {
 let mut rng = rand::thread_rng();
 # let setup = TestSetup::new(&mut rng);
 # let signing_key = setup.signing_keys.get("Alice").unwrap().clone();
 # let vk = setup.ibs_pk;
 # let usk = setup.usks.get("Bob").unwrap();
 let mut input = Cursor::new(b"SECRET DATA");
 let mut sealed = Vec::new();
                                                                                      
 Sealer::<_, SealerStreamConfig>::new(
     &setup.mpk,
     &setup.policies,
     &signing_key,
     &mut rng,
 )?
 .seal(&mut input, &mut sealed)
 .await?;
                                                                                      
 let mut original = Vec::new();
 let policy = Unsealer::<_, UnsealerStreamConfig>::new(&mut Cursor::new(sealed), &vk)
     .await?
     .unseal("Bob", usk, &mut original)
     .await?;
                                                                                      
 assert_eq!(input.into_inner().to_vec(), original);
 assert_eq!(&policy, &signing_key.policy);
 # Ok(())
 # }
 ```
"##
)]
//!
//! ### Using the Web Crypto backend
//!
//! Using the Web Crypto backend in Rust can be useful in Rust web frameworks (e.g.,
//! Yew/Dioxus/Leptos). For use in JavaScript/TypeScript, there is a seperate NPM package called
//! [`pg-wasm`] which offers an FFI interface generated by `wasm-pack`.
//!
//! ### Wire format
//!
//! The wire format consists of the following segments, followed by their length in bytes:
//!
//! ```text
//!                  PREAMBLE (10)
//! = PRELUDE (4) || VERSION (2) || HEADER LEN (4)
//!
//!                  HEADER (*)
//! = HEADER (*) || HEADER SIG LEN (4) || HEADER SIG (*)
//!
//!                  PAYLOAD  (*)
//! = DEM.Enc(M (*) || STREAM SIG (*) || STREAM SIG LEN (4))
//! ```

#[cfg(test)]
extern crate std;

// We depend on alloc for String, Vec and BTreeMap/HashMap.
#[macro_use]
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

#[cfg(feature = "test")]
pub mod test;

mod util;

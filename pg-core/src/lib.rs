#![doc = include_str!("../README.md")]
#![no_std]
#![doc(
    html_favicon_url = "https://postguard.eu/favicon.ico",
    html_logo_url = "https://postguard.eu/pg_logo_no_text.svg"
)]
#![deny(
    missing_debug_implementations,
    rust_2018_idioms,
    missing_docs,
    rustdoc::broken_intra_doc_links,
    unsafe_code
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! ### Setting up the encryption parameters
//!
//! The public key and user secret keys for encryption can be retrieved from the Private Key
//! Generator (PKG).
//!
//! ```rust
//! use std::time::SystemTime;
//! use pg_core::identity::{Attribute, Policy, EncryptionPolicy};
//!
//! let timestamp = SystemTime::now()
//!     .duration_since(SystemTime::UNIX_EPOCH)
//!     .unwrap()
//!     .as_secs();
//!
//! let id1 = String::from("Bob");
//! let id2 = String::from("Charlie");
//!
//! let p1 = Policy {
//!     timestamp,
//!     con: vec![Attribute::new(
//!         "pbdf.gemeente.personalData.bsn",
//!         Some("123bob789"),
//!     )],
//! };
//!
//! let p2 = Policy {
//!     timestamp,
//!     con: vec![
//!         Attribute::new("pbdf.gemeente.personalData.name", Some("Charlie")),
//!         Attribute::new("pbdf.sidn-pbdf.email.email", Some("charlie@example.com")),
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
//! ### Seal a slice using the Rust Crypto backend
//!
//! ```rust
//! use pg_core::client::rust::{SealerMemoryConfig, UnsealerMemoryConfig};
//! use pg_core::client::{Sealer, Unsealer};
//! # use pg_core::error::Error;
//! use pg_core::test::TestSetup;
//!
//! # fn main() -> Result<(), Error> {
//! let mut rng = rand::thread_rng();
//! # let TestSetup {
//! #     ibe_pk,
//! #     ibs_pk,
//! #     policies,
//! #     usks,
//! #     signing_keys,
//! #     policy,
//! #     ..
//! # } = TestSetup::new(&mut rng);
//! # let signing_key = &signing_keys[0];
//! # let id = "Bob";
//! # let usk = &usks[2];
//!                                                                                             
//! // Sender: retrieve public key, setup policy and signing keys.
//!                                                                                             
//! let input = b"SECRET DATA";
//! let sealed = Sealer::<_, SealerMemoryConfig>::new(&ibe_pk, &policy, &signing_key, &mut rng)?
//!     .seal(input)?;
//!                                                                                             
//! // Receiver: retrieve USK and verifying key.
//!                                                                                             
//! let (original, verified_sender_id) =
//!     Unsealer::<_, UnsealerMemoryConfig>::new(sealed, &ibs_pk)?.unseal(id, &usk)?;
//!                                                                                             
//! assert_eq!(&input.to_vec(), &original);
//!
//! assert_eq!(&verified_sender_id.public, &signing_key.policy);
//! assert_eq!(verified_sender_id.private, None);
//! # Ok(())
//! # }
//! ```
//!
#![cfg_attr(
    feature = "stream",
    doc = r##"
 ### Seal a bytestream using the Rust Crypto backend

 ```rust
 use pg_core::client::rust::stream::{SealerStreamConfig, UnsealerStreamConfig};
 use pg_core::client::{Sealer, Unsealer};
 # use pg_core::error::Error;
 use pg_core::test::TestSetup;
 
 use futures::io::Cursor;
                                                                                          
 # #[tokio::main]
 # async fn main() -> Result<(), Error> {
 let mut rng = rand::thread_rng();
 # let setup = TestSetup::new(&mut rng);
 # let signing_key = &setup.signing_keys[0];
 # let vk = setup.ibs_pk;
 # let usk = &setup.usks[2];
 let mut input = Cursor::new(b"SECRET DATA");
 let mut sealed = Vec::new();
                                                                                      
 Sealer::<_, SealerStreamConfig>::new(
     &setup.ibe_pk,
     &setup.policy,
     &signing_key,
     &mut rng,
 )?
 .seal(&mut input, &mut sealed)
 .await?;
                                                                                      
 let mut original = Vec::new();
 let policy = Unsealer::<_, UnsealerStreamConfig>::new(&mut Cursor::new(sealed), &vk)
     .await?
     .unseal("Bob", &usk, &mut original)
     .await?;
                                                                                      
 assert_eq!(input.into_inner().to_vec(), original);
 assert_eq!(&policy.public, &signing_key.policy);
 assert_eq!(policy.private, None);
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
//! [`pg-wasm`](https://www.npmjs.com/package/@e4a/pg-wasm) which offers an FFI interface generated by `wasm-pack`.
//! See its documentation for examples.
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

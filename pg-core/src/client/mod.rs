//! PostGuard client API.
//!
//! Used for:
//! - Encrypting, signing, packing metadata (*sealing*),
//! - Decrypting, verifying, unpacking metadata (*unsealing*).

mod header;

pub use header::{Algorithm, Header, Mode, RecipientHeader};

#[cfg(feature = "rust")]
pub mod rust;

#[cfg(feature = "web")]
pub mod web;

use crate::artifacts::VerifyingKey;
use crate::util::*;
use crate::{artifacts::SigningKeyExt, consts::*};
use header::SignatureExt;
use ibs::gg::Verifier;
use serde::{Deserialize, Serialize};

/// A Sealer is used to encrypt and sign data using PostGuard.
#[derive(Debug)]
pub struct Sealer<'r, R, C> {
    // The prebuilt header.
    header: Header,

    // An exclusive reference to a random number generator.
    rng: &'r mut R,

    // The flavor-specific configuration.
    config: C,

    // The public signing key. Used to sign public data, such as the header.
    // The signature and claims are visible to outsiders.
    pub_sign_key: SigningKeyExt,

    // An optional private signing key.
    // The signature and claims are encrypted and not visible to outsiders.
    priv_sign_key: Option<SigningKeyExt>,
}

impl<'r, R, C> Sealer<'r, R, C> {
    /// Add a private signing key and policy.
    ///
    /// This policy is safe to include private data as it is encrypted after signing.
    pub fn with_priv_signing_key(mut self, priv_sign_key: SigningKeyExt) -> Self {
        self.priv_sign_key = Some(priv_sign_key);
        self
    }
}

/// An Unsealer is used to decrypt and verify data using PostGuard.
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

    // The message verifier.
    verifier: Verifier,

    // The message verifier key.
    vk: VerifyingKey,
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

#[cfg(any(feature = "stream", target_arch = "wasm32"))]
impl From<futures::io::Error> for crate::error::Error {
    fn from(e: futures::io::Error) -> Self {
        Self::FuturesIO(e)
    }
}

#[cfg(feature = "stream")]
pub(self) fn stream_mode_checked(
    h: &Header,
) -> Result<(u32, (u64, Option<u64>)), crate::error::Error> {
    let (segment_size, size_hint) = match h {
        Header {
            mode:
                Mode::Streaming {
                    segment_size,
                    size_hint,
                },
            ..
        } => (segment_size, size_hint),
        _ => return Err(crate::error::Error::ModeNotSupported(h.mode)),
    };

    if *segment_size > MAX_SYMMETRIC_CHUNK_SIZE {
        return Err(crate::error::Error::ConstraintViolation);
    }

    Ok((*segment_size, *size_hint))
}

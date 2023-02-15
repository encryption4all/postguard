//! PostGuard client functionality.
//!
//! Used for:
//! - Encrypting, signing, packing metadata (*sealing*),
//! - Decrypting, verifying, unpacking metdata (*unsealing*).

mod header;
pub use header::{Algorithm, Header, Mode, RecipientHeader};

#[cfg(feature = "rust")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust")))]
pub mod rust;

#[cfg(feature = "web")]
#[cfg_attr(docsrs, doc(cfg(feature = "web")))]
pub mod web;

use crate::consts::*;
use crate::error::Error;
use crate::util::*;
use serde::{Deserialize, Serialize};

/// A Sealer is used to encrypt and sign data using PostGuard.
#[derive(Debug)]
pub struct Sealer<C: SealerConfig> {
    // The prebuilt header.
    header: Header,

    // The flavor-specific configuration.
    config: C,
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

/// A PostGuard in-memory sealed packet.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PostGuardPacket {
    /// The version of the header.
    pub version: u16,

    /// The header of the PostGuard packet.
    pub header: Header,

    /// The symmetric ciphertext.
    pub ciphertext: Vec<u8>,
}

impl PostGuardPacket {
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

        Ok(PostGuardPacket {
            version,
            header,
            ciphertext,
        })
    }
}

pub(self) fn mode_checked(h: &Header) -> Result<(u32, (u64, Option<u64>)), Error> {
    let (segment_size, size_hint) = match h {
        Header {
            mode:
                Mode::Streaming {
                    segment_size,
                    size_hint,
                },
            ..
        } => (segment_size, size_hint),
        _ => return Err(Error::ModeNotSupported(h.mode)),
    };

    if *segment_size > MAX_SYMMETRIC_CHUNK_SIZE {
        return Err(Error::ConstraintViolation);
    }

    Ok((*segment_size, size_hint.clone()))
}

mod de;
mod ser;

#[cfg(test)]
mod tests;

use crate::{Attribute, Error, IV_SIZE};
use alloc::fmt::Debug;
use arrayvec::ArrayString;
use ibe::kem::cgw_fo::{CGWFO, CT_BYTES as CGWFO_CT_BYTES};
//use ibe::{kem::IBKEM, Compress};

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use ser::serialize_encaps;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecipientIdentifier(pub ArrayString<255>);

/// An IRMAseal hidden policy.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct HiddenPolicy {
    #[serde(rename = "t")]
    pub timestamp: u64,
    pub con: Vec<Attribute>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecipientInfo {
    /// (Public) Identifier of the recipient.
    /// Used to find the associated policy and ciphertext.
    #[serde(rename = "id")]
    pub identifier: RecipientIdentifier,

    /// The hidden policy associated with this identifier.
    #[serde(rename = "p")]
    pub policy: HiddenPolicy,

    /// Ciphertext for this specific recipient
    #[serde(with = "BigArray")]
    pub ct: [u8; CGWFO_CT_BYTES],
}

impl PartialEq for RecipientInfo {
    fn eq(&self, other: &Self) -> bool {
        self.identifier == other.identifier
    }
}

/// This struct _never_ needs to be in memory, unless you require the full metadata
/// containing info for all recipients, otherwise see [`RecipientMetadata`].
#[derive(Serialize, Deserialize)]
pub struct FullMetadata {
    pub recipient_info: Vec<RecipientInfo>,

    /// The initializion vector used for symmetric encryption.
    pub iv: [u8; IV_SIZE],

    /// The size of the chunks in which to process symmetric encryption.
    pub chunk_size: usize,
}

#[derive(Debug, PartialEq, Clone)]
pub struct RecipientMetadata {
    /// Info specific to one recipient, i.e., a policy and associated ciphertext.
    pub recipient_info: RecipientInfo,

    /// The initializion vector used for symmetric encryption.
    pub iv: [u8; IV_SIZE],

    /// The size of the chunks in which to process symmetric encryption.
    pub chunk_size: usize,
}

#[derive(Clone)]
pub struct Policies<'a>(&'a [(RecipientIdentifier, HiddenPolicy)]);

/// Everything that is needed to construct a serialized metadata.
///
/// Can be serialized to an output format {json, msgPack}.
#[derive(Serialize, Clone)]
pub struct MetadataArgs<'a> {
    #[serde(rename = "rs")]
    #[serde(serialize_with = "serialize_encaps")]
    recipients: Policies<'a>,
    iv: [u8; IV_SIZE],
    #[serde(rename = "cs")]
    chunk_size: usize,
}

impl RecipientIdentifier {
    pub fn new<'a>(s: &'a str) -> Result<Self, Error> {
        ArrayString::<255>::from(s)
            .map(|x| Self(x))
            .map_err(|_e| Error::FormatViolation)
    }
}

impl RecipientMetadata {
    fn default_with_id(id: &RecipientIdentifier) -> Self {
        Self {
            recipient_info: RecipientInfo {
                identifier: id.clone(),
                policy: HiddenPolicy::default(),
                ct: [0u8; CGWFO_CT_BYTES],
            },
            iv: [0u8; IV_SIZE],
            chunk_size: 0 as usize,
        }
    }
}
